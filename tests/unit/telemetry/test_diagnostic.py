# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic PR 34 diagnostic telemetry tests (T34-G01..G09, G15).

Proves the ``ati-telemetry-test`` diagnostic signal contract without any
Collector/backend/network: valid UUID canonicalization (G01), malformed
input rejection (G02), exact counter/duration observation (G03/G04), the
root/child trace with parentage and attributes (G05/G06/G07), the structured
in-span log (G08), trace/log correlation (G09), and the strict separation of
diagnostic names from the frozen production vocabulary (G15).

All emission runs through :func:`emit_telemetry_test_signal` with explicit
in-memory providers — the same function the production CLI calls through the
process-global composition.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import (
    InMemoryLogExporter,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics._internal.point import Histogram, Sum
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from agentic_threat_investigator.telemetry.diagnostic import (
    TELEMETRY_TEST_CHILD_SPAN,
    TELEMETRY_TEST_COUNTER,
    TELEMETRY_TEST_DURATION,
    TELEMETRY_TEST_DURATION_VALUE,
    TELEMETRY_TEST_LOG_EVENT,
    TELEMETRY_TEST_ROOT_SPAN,
    TELEMETRY_TEST_RUN_ID_ATTRIBUTE,
    TelemetryTestSignalSummary,
    canonical_run_id,
    emit_telemetry_test_signal,
)
from agentic_threat_investigator.telemetry.metrics import DurationMetrics, Metrics
from agentic_threat_investigator.telemetry.tracing import (
    CANONICAL_SPAN_NAMES,
    SpanNames,
)

RUN_ID = "01234567-89ab-cdef-0123-456789abcdef"


@pytest.fixture
def in_memory_diagnostic_telemetry() -> Iterator[SimpleNamespace]:
    """Wire the PR 34 emitter to isolated in-memory providers plus logs.

    The emitter receives explicit in-memory tracer/meter providers (the
    deterministic test seam). The OTel log transport is exercised exactly as
    in the production composition: an additive ``LoggingHandler`` on the root
    logger with an in-memory exporter, with the root level raised to INFO so
    the diagnostic INFO record actually propagates. Torn down per test.
    """
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[metric_reader])

    log_exporter = InMemoryLogExporter()  # type: ignore[no-untyped-call]  # OTel SDK ships an untyped __init__ (validated against 1.37.x)
    logger_provider = LoggerProvider()
    logger_provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
    handler = LoggingHandler(logger_provider=logger_provider)
    previous_level = logging.getLogger().level
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(handler)
    try:
        yield SimpleNamespace(
            span_exporter=span_exporter,
            metric_reader=metric_reader,
            log_exporter=log_exporter,
            tracer_provider=tracer_provider,
            meter_provider=meter_provider,
        )
    finally:
        logging.getLogger().removeHandler(handler)
        logging.getLogger().setLevel(previous_level)


def _emitted(
    namespace: SimpleNamespace,
) -> TelemetryTestSignalSummary:
    """Run the emitter against the in-memory fixture providers."""
    return emit_telemetry_test_signal(
        RUN_ID,
        tracer_provider=namespace.tracer_provider,
        meter_provider=namespace.meter_provider,
    )


def test_g01_valid_uuid_accepted_and_canonicalized() -> None:
    """T34-G01 a valid UUID is accepted and canonicalized to lower hyphenated."""
    assert canonical_run_id("01234567-89AB-CDEF-0123-456789ABCDEF") == RUN_ID
    assert canonical_run_id(f"  {RUN_ID}  ") == RUN_ID


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "not-a-uuid", "01234567-89ab-cdef-0123-456789abcde", "x" * 36],
)
def test_g02_malformed_run_id_rejected(bad: str) -> None:
    """T34-G02 missing/blank/malformed run IDs raise a bounded ValueError."""
    with pytest.raises(ValueError, match="run_id"):
        canonical_run_id(bad)


def test_g03_counter_is_exactly_plus_one_with_run_id(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G03 the counter records exactly +1 with the exact run ID."""
    summary = _emitted(in_memory_diagnostic_telemetry)
    assert summary.run_id == RUN_ID
    metrics = in_memory_diagnostic_telemetry.metric_reader.get_metrics_data()
    sums = [
        metric
        for rm in metrics.resource_metrics
        for sm in rm.scope_metrics
        for metric in sm.metrics
        if metric.name == TELEMETRY_TEST_COUNTER
    ]
    assert len(sums) == 1
    assert isinstance(sums[0].data, Sum)
    assert sums[0].data.is_monotonic
    points = list(sums[0].data.data_points)
    assert len(points) == 1
    assert points[0].value == 1
    assert dict(points[0].attributes or {}) == {TELEMETRY_TEST_RUN_ID_ATTRIBUTE: RUN_ID}


def test_g04_duration_is_one_0_125_second_observation(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G04 the duration histogram has exactly one 0.125s observation."""
    _emitted(in_memory_diagnostic_telemetry)
    metrics = in_memory_diagnostic_telemetry.metric_reader.get_metrics_data()
    histograms = [
        metric
        for rm in metrics.resource_metrics
        for sm in rm.scope_metrics
        for metric in sm.metrics
        if metric.name == TELEMETRY_TEST_DURATION
    ]
    assert len(histograms) == 1
    assert isinstance(histograms[0].data, Histogram)
    points = list(histograms[0].data.data_points)
    assert len(points) == 1
    assert points[0].count == 1
    assert points[0].sum == pytest.approx(TELEMETRY_TEST_DURATION_VALUE)
    assert dict(points[0].attributes or {}) == {TELEMETRY_TEST_RUN_ID_ATTRIBUTE: RUN_ID}


def test_g05_exactly_one_root_and_one_child_span(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G05 the trace contains exactly one root and one child span."""
    summary = _emitted(in_memory_diagnostic_telemetry)
    spans = in_memory_diagnostic_telemetry.span_exporter.get_finished_spans()
    names = {span.name for span in spans}
    assert names == {TELEMETRY_TEST_ROOT_SPAN, TELEMETRY_TEST_CHILD_SPAN}
    assert summary.trace_id != "0" * 32


def test_g06_child_parent_is_root(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G06 the child span is parented to the root span."""
    _emitted(in_memory_diagnostic_telemetry)
    spans = in_memory_diagnostic_telemetry.span_exporter.get_finished_spans()
    root = next(span for span in spans if span.name == TELEMETRY_TEST_ROOT_SPAN)
    child = next(span for span in spans if span.name == TELEMETRY_TEST_CHILD_SPAN)
    assert child.parent is not None
    assert child.parent.span_id == root.get_span_context().span_id
    assert child.get_span_context().trace_id == root.get_span_context().trace_id
    assert root.parent is None


def test_g07_spans_carry_exact_run_id(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G07 both spans carry the exact run ID attribute."""
    _emitted(in_memory_diagnostic_telemetry)
    spans = in_memory_diagnostic_telemetry.span_exporter.get_finished_spans()
    assert len(spans) == 2
    for span in spans:
        assert dict(span.attributes) == {TELEMETRY_TEST_RUN_ID_ATTRIBUTE: RUN_ID}


def test_g08_structured_in_span_log_with_exact_event_and_run_id(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G08 the in-span log carries the exact event name and run ID."""
    _emitted(in_memory_diagnostic_telemetry)
    logs = in_memory_diagnostic_telemetry.log_exporter.get_finished_logs()
    records = [log.log_record for log in logs]
    diagnostic = [
        record
        for record in records
        if record.attributes.get("telemetry_test_event") == TELEMETRY_TEST_LOG_EVENT
    ]
    assert len(diagnostic) == 1
    (record,) = diagnostic
    assert isinstance(record.body, str)
    assert record.body.startswith(TELEMETRY_TEST_LOG_EVENT)
    assert record.attributes["run_id"] == RUN_ID


def test_g09_log_correlation_matches_child_span(
    in_memory_diagnostic_telemetry: SimpleNamespace,
) -> None:
    """T34-G09 the in-span log exports the active trace/span identity.

    The log is emitted while the child span is current, so the exported log
    record must carry the same trace ID as the spans and the child span ID.
    """
    summary = _emitted(in_memory_diagnostic_telemetry)
    logs = in_memory_diagnostic_telemetry.log_exporter.get_finished_logs()
    records = [
        log.log_record
        for log in logs
        if log.log_record.attributes.get("telemetry_test_event")
        == TELEMETRY_TEST_LOG_EVENT
    ]
    assert len(records) == 1
    (record,) = records
    assert record.trace_id is not None and record.span_id is not None
    assert f"{record.trace_id:032x}" == summary.trace_id
    assert f"{record.span_id:016x}" == summary.child_span_id


def test_g15_diagnostic_names_absent_from_production_vocabulary() -> None:
    """T34-G15 diagnostic names stay separate from the frozen production sets."""
    diagnostic_names = {
        TELEMETRY_TEST_COUNTER,
        TELEMETRY_TEST_DURATION,
        TELEMETRY_TEST_ROOT_SPAN,
        TELEMETRY_TEST_CHILD_SPAN,
    }
    production_metric_names = set(Metrics.__dict__.values())
    production_metric_names.update(DurationMetrics.__dict__.values())
    assert not diagnostic_names & production_metric_names
    assert not diagnostic_names & set(CANONICAL_SPAN_NAMES)
    assert {TELEMETRY_TEST_ROOT_SPAN, TELEMETRY_TEST_CHILD_SPAN}.isdisjoint(
        set(SpanNames.__dict__.values())
    )
    # The diagnostic counter must not be resolvable through the frozen
    # canonical counter map either (COUNTER_SPECS registration gate).
    counter_spec_names = {
        spec.name
        for spec in __import__(
            "agentic_threat_investigator.telemetry.metrics", fromlist=["COUNTER_SPECS"]
        ).COUNTER_SPECS
    }
    assert TELEMETRY_TEST_COUNTER not in counter_spec_names
