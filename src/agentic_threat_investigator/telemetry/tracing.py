# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical OpenTelemetry tracer access and span-name vocabulary (PR 29A).

The instrumentation scope and canonical span names are frozen contracts for
the whole PR 29 series. Span names are code constants, never dynamically
derived from Python function names or domain identifiers.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.trace import Tracer, TracerProvider

INSTRUMENTATION_SCOPE = "agentic_threat_investigator"
"""The OpenTelemetry instrumentation scope used by all ATI telemetry."""

_TELEMETRY_VERSION = "0.1.0"
"""Instrumentation/library version reported to OpenTelemetry."""


class SpanNames:
    """Canonical ATI OpenTelemetry span names (frozen by PR 29A).

    Rules: lowercase stable semantic operation names; no domain/provider IDs;
    no Python class or function names.
    """

    DATASOURCE_ACQUIRE = "ati.datasource.acquire"
    DATASOURCE_CONVERT = "ati.datasource.convert"
    EVIDENCE_PUBLISH = "ati.evidence.publish"
    EVIDENCE_CONSUME = "ati.evidence.consume"
    EVIDENCE_PERSIST = "ati.evidence.persist"
    GEO_RESOLVE = "ati.geo.resolve"
    INVESTIGATION_EXECUTE = "ati.investigation.execute"
    AGENT_INVOKE = "ati.agent.invoke"
    LLM_INVOKE = "ati.llm.invoke"
    REPORT_GENERATE = "ati.report.generate"
    POSTGRES_REPOSITORY = "ati.postgres.repository"
    POSTGRES_UOW = "ati.postgres.uow"
    KAFKA_PUBLISH = "ati.kafka.publish"
    KAFKA_POLL = "ati.kafka.poll"
    KAFKA_COMMIT = "ati.kafka.commit"


CANONICAL_SPAN_NAMES: frozenset[str] = frozenset(
    {
        SpanNames.DATASOURCE_ACQUIRE,
        SpanNames.DATASOURCE_CONVERT,
        SpanNames.EVIDENCE_PUBLISH,
        SpanNames.EVIDENCE_CONSUME,
        SpanNames.EVIDENCE_PERSIST,
        SpanNames.GEO_RESOLVE,
        SpanNames.INVESTIGATION_EXECUTE,
        SpanNames.AGENT_INVOKE,
        SpanNames.LLM_INVOKE,
        SpanNames.REPORT_GENERATE,
        SpanNames.POSTGRES_REPOSITORY,
        SpanNames.POSTGRES_UOW,
        SpanNames.KAFKA_PUBLISH,
        SpanNames.KAFKA_POLL,
        SpanNames.KAFKA_COMMIT,
    }
)
"""The exact, tested set of canonical span names."""


def get_tracer(
    *,
    tracer_provider: TracerProvider | None = None,
) -> Tracer:
    """Return the canonical ATI tracer bound to ``tracer_provider``.

    When ``tracer_provider`` is ``None`` the tracer is bound to the
    process-global OTel tracer provider (a no-op proxy when none has been
    configured). Passing an explicit provider is the deterministic
    unit-test seam and the 29C composition seam; it never manipulates global
    OpenTelemetry state.
    """
    if tracer_provider is not None:
        return trace.get_tracer(
            INSTRUMENTATION_SCOPE,
            _TELEMETRY_VERSION,
            tracer_provider=tracer_provider,
        )
    return trace.get_tracer(INSTRUMENTATION_SCOPE, _TELEMETRY_VERSION)


__all__ = [
    "CANONICAL_SPAN_NAMES",
    "INSTRUMENTATION_SCOPE",
    "SpanNames",
    "get_tracer",
]
