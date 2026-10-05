# SPDX-License-Identifier: AGPL-3.0-only
"""Dedicated deterministic diagnostic telemetry (PR 34).

PR 34 closes the observability delivery gap: one deterministic diagnostic
process proves that ATI's **production** telemetry composition traverses the
deployed Collector and reaches the real pinned backends. This module owns the
diagnostic-only semantic names and the deterministic emitter.

The dominant architectural rule is that diagnostic telemetry is **not**
production-domain telemetry. ``Metrics``, ``DurationMetrics``, and
``SpanNames`` in :mod:`telemetry.metrics` / :mod:`telemetry.tracing` are
frozen production vocabularies (PR 29A/29B); this module deliberately keeps
its probe names in a separate diagnostic namespace (``ati.telemetry.test.*``)
so the integration probe can never pollute production semantics or confuse a
real Kafka/PostgreSQL/datasource/LLM/Investigation operation.

Every invocation carries one caller-supplied UUID (``run_id``) that
correlates the counter, duration observation, root/child spans, and
structured log. The run ID is diagnostic-only: it must never become a
dimension on normal production metrics and never carry Investigation/Evidence/
user identity, credentials, or source payloads.

The emitter reuses the canonical ATI helpers :func:`telemetry.tracing.get_tracer`
and :func:`telemetry.metrics.get_meter` with the explicit providers that
``configure_telemetry(...)`` establishes — no direct OTLP client, no second
SDK provider set, and no exporter/backend knowledge live here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from uuid import UUID

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider

from agentic_threat_investigator.telemetry.metrics import DURATION_UNIT, get_meter
from agentic_threat_investigator.telemetry.tracing import get_tracer

# Diagnostic-only metric/span/log names (PR 34). These are intentionally not
# members of the frozen production vocabulary (Metrics/DurationMetrics/
# SpanNames/COUNTER_SPECS); see the module docstring.
TELEMETRY_TEST_COUNTER = "ati.telemetry.test.counter"
"""Monotonic diagnostic counter; exactly ``+1`` per ``ati-telemetry-test`` run."""
TELEMETRY_TEST_DURATION = "ati.telemetry.test.duration"
"""Diagnostic duration histogram; exactly one deterministic ``0.125``s observation."""
TELEMETRY_TEST_ROOT_SPAN = "ati.telemetry.test"
"""Diagnostic root span name."""
TELEMETRY_TEST_CHILD_SPAN = "ati.telemetry.test.child"
"""Diagnostic child span name (always parented to the root span)."""
TELEMETRY_TEST_RUN_ID_ATTRIBUTE = "ati.telemetry.test.run_id"
"""The bounded diagnostic run-correlation attribute used on metrics and spans."""
TELEMETRY_TEST_LOG_EVENT = "telemetry_test_signal"
"""The structured diagnostic log event name carried in log body and attributes."""

# Deterministic duration observation (seconds); not a wall-clock measurement.
TELEMETRY_TEST_DURATION_VALUE = 0.125
# The structured log attribute key carrying the diagnostic event name.
_TELEMETRY_TEST_LOG_EVENT_ATTRIBUTE = "telemetry_test_event"

# Counters created here are unit "1": one diagnostic run = one increment.
_TELEMETRY_TEST_COUNTER_UNIT = "1"

_TEST_LOGGER = logging.getLogger("agentic_threat_investigator.telemetry.diagnostic")


@dataclass(frozen=True)
class TelemetryTestSignalSummary:
    """The bounded identity of one emitted diagnostic signal set.

    ``run_id`` is the canonical caller-supplied UUID; ``trace_id``,
    ``root_span_id``, and ``child_span_id`` are lowercase hexadecimal
    OpenTelemetry identities from the emitted spans. The summary is
    correlation metadata for the harness/verifier — never credentials and
    never production identities.
    """

    run_id: str
    trace_id: str
    root_span_id: str
    child_span_id: str


def canonical_run_id(value: str) -> str:
    """Canonicalize and validate a caller-supplied diagnostic run ID.

    The value must parse as a UUID; the canonical lowercase hyphenated form
    is returned so the counter, spans, and log always carry the exact same
    identity. Missing, blank, or malformed values raise ``ValueError``.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("run_id must be a UUID string")
    try:
        parsed = UUID(value.strip())
    except ValueError as exc:
        raise ValueError(f"run_id must be a UUID: {value!r}") from exc
    return str(parsed)


def emit_telemetry_test_signal(
    run_id: str,
    *,
    tracer_provider: TracerProvider | None = None,
    meter_provider: MeterProvider | None = None,
) -> TelemetryTestSignalSummary:
    """Emit the deterministic diagnostic signal set for ``run_id``.

    Emits exactly:

    - ``ati.telemetry.test.counter += 1`` with the run ID attribute;
    - one ``ati.telemetry.test.duration`` observation of ``0.125``s;
    - a root span ``ati.telemetry.test`` with a child ``ati.telemetry.test.child``
      (child parent is always the root), both carrying the run ID;
    - one structured ``telemetry_test_signal`` log inside the child span
      carrying the run ID and the active trace/span correlation.

    ``tracer_provider`` / ``meter_provider`` are the deterministic unit-test
    seam (in-memory providers). The default ``None`` resolves the
    process-global providers installed by ``configure_telemetry``, i.e. ATI's
    production composition. The emitter never knows backend topology.
    """
    canonical = canonical_run_id(run_id)
    tracer = get_tracer(tracer_provider=tracer_provider)
    meter = get_meter(meter_provider=meter_provider)

    counter = meter.create_counter(
        TELEMETRY_TEST_COUNTER,
        unit=_TELEMETRY_TEST_COUNTER_UNIT,
        description=(
            "Diagnostic integration-probe counter (PR 34): +1 per "
            "ati-telemetry-test run"
        ),
    )
    duration = meter.create_histogram(
        TELEMETRY_TEST_DURATION,
        unit=DURATION_UNIT,
        description=(
            "Diagnostic integration-probe duration observation (PR 34): "
            "one deterministic 0.125s observation per run"
        ),
    )
    counter.add(1, {TELEMETRY_TEST_RUN_ID_ATTRIBUTE: canonical})
    duration.record(
        TELEMETRY_TEST_DURATION_VALUE,
        {TELEMETRY_TEST_RUN_ID_ATTRIBUTE: canonical},
    )

    with (
        tracer.start_as_current_span(
            TELEMETRY_TEST_ROOT_SPAN,
            attributes={TELEMETRY_TEST_RUN_ID_ATTRIBUTE: canonical},
        ) as root,
        tracer.start_as_current_span(
            TELEMETRY_TEST_CHILD_SPAN,
            attributes={TELEMETRY_TEST_RUN_ID_ATTRIBUTE: canonical},
        ) as child,
    ):
        # At least one structured diagnostic log while the child span is
        # current; the record carries the run ID and the active OTel
        # trace/span context (exported through ATI's additive OTLP log
        # handler in the production composition).
        _TEST_LOGGER.info(
            "%s run_id=%s",
            TELEMETRY_TEST_LOG_EVENT,
            canonical,
            extra={
                _TELEMETRY_TEST_LOG_EVENT_ATTRIBUTE: TELEMETRY_TEST_LOG_EVENT,
                "run_id": canonical,
            },
        )
        root_context = root.get_span_context()
        child_context = child.get_span_context()
        root_span_id = f"{root_context.span_id:016x}"
        child_span_id = f"{child_context.span_id:016x}"

    return TelemetryTestSignalSummary(
        run_id=canonical,
        trace_id=f"{root_context.trace_id:032x}",
        root_span_id=root_span_id,
        child_span_id=child_span_id,
    )


__all__ = [
    "TELEMETRY_TEST_CHILD_SPAN",
    "TELEMETRY_TEST_COUNTER",
    "TELEMETRY_TEST_DURATION",
    "TELEMETRY_TEST_DURATION_VALUE",
    "TELEMETRY_TEST_LOG_EVENT",
    "TELEMETRY_TEST_ROOT_SPAN",
    "TELEMETRY_TEST_RUN_ID_ATTRIBUTE",
    "TelemetryTestSignalSummary",
    "canonical_run_id",
    "emit_telemetry_test_signal",
]
