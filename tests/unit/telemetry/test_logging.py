# SPDX-License-Identifier: AGPL-3.0-only
"""Trace/span logging correlation tests (PR 29A)."""

from __future__ import annotations

import logging
from typing import Protocol, cast

from opentelemetry import trace as otl_trace

from agentic_threat_investigator.telemetry.logging import (
    OtelLoggerNamespaceFilter,
    TraceCorrelationFilter,
    current_correlation,
)


class _CorrelationRecord(Protocol):
    """A ``LogRecord`` view exposing the ATI correlation fields."""

    otel_trace_id: str
    otel_span_id: str


def _as_correlated(record: logging.LogRecord) -> _CorrelationRecord:
    """Return ``record`` typed as a correlation-bearing log record."""
    return cast(_CorrelationRecord, record)


def _log_record(name: str = "ati.test") -> logging.LogRecord:
    """Build a minimal LogRecord for filter testing."""
    return logging.LogRecord(
        name=name,
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )


class TestCurrentCorrelation:
    """The correlation helper exposes only valid current IDs."""

    def test_outside_span_returns_none(self) -> None:
        """Outside any span the helper returns None (no fabricated identity)."""
        assert current_correlation() is None

    def test_inside_span_returns_ids(self, in_memory_telemetry: object) -> None:
        """Inside a sampled span the helper returns matching hex IDs."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.llm.invoke") as span:
            correlation = current_correlation()
        assert correlation is not None
        assert correlation.trace_id == f"{span.context.trace_id:032x}"
        assert correlation.span_id == f"{span.context.span_id:016x}"

    def test_nested_span_returns_innermost(self, in_memory_telemetry: object) -> None:
        """Nested spans report the innermost span ID with the same trace ID."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("outer") as outer:
            with tracer.start_as_current_span("inner") as inner:
                correlation = current_correlation()
            outer_correlation = current_correlation()
        assert correlation is not None
        assert outer_correlation is not None
        assert correlation.span_id == f"{inner.context.span_id:016x}"
        assert correlation.trace_id == f"{outer.context.trace_id:032x}"
        assert outer_correlation.span_id == f"{outer.context.span_id:016x}"

    def test_invalid_context_returns_none(self) -> None:
        """An invalid/empty context yields no fabricated ID."""
        assert current_correlation() is None
        assert otl_trace.INVALID_SPAN.get_span_context().is_valid is False

    def test_secret_sentinel_never_leaks(self, in_memory_telemetry: object) -> None:
        """Only the numeric IDs are exposed; unrelated secrets are absent."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.llm.invoke"):
            correlation = current_correlation()
        assert correlation is not None
        rendered = f"{correlation.trace_id}{correlation.span_id}"
        assert "sk-token" not in rendered
        assert "super-secret" not in rendered
        assert len(correlation.trace_id) == 32
        assert len(correlation.span_id) == 16


class TestTraceCorrelationFilter:
    """The logging filter attaches correlation without changing semantics."""

    def test_filter_sets_fields_inside_span(self, in_memory_telemetry: object) -> None:
        """Inside a span the filter sets otel_trace_id/otel_span_id."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.llm.invoke") as span:
            record = _log_record()
            assert TraceCorrelationFilter().filter(record) is True
            correlated = _as_correlated(record)
            assert correlated.otel_trace_id == f"{span.context.trace_id:032x}"
            assert correlated.otel_span_id == f"{span.context.span_id:016x}"

    def test_filter_sets_empty_outside_span(self) -> None:
        """Outside a span the filter sets empty fields and keeps the record."""
        record = _log_record()
        assert TraceCorrelationFilter().filter(record) is True
        correlated = _as_correlated(record)
        assert correlated.otel_trace_id == ""
        assert correlated.otel_span_id == ""

    def test_filter_does_not_overwrite_existing(self) -> None:
        """Existing record fields are never overwritten."""
        record = _log_record()
        correlated = _as_correlated(record)
        correlated.otel_trace_id = "existing"
        correlated.otel_span_id = "existing-span"
        assert TraceCorrelationFilter().filter(record) is True
        assert correlated.otel_trace_id == "existing"
        assert correlated.otel_span_id == "existing-span"


class TestOtelLoggerNamespaceFilter:
    """OTel internal namespaces never re-enter OTLP export (PR 29C)."""

    def test_drops_otel_internal_namespaces(self) -> None:
        """opentelemetry.* logger namespaces are excluded from OTLP export."""
        otel_filter = OtelLoggerNamespaceFilter()
        assert otel_filter.filter(_log_record("opentelemetry.sdk")) is False
        assert otel_filter.filter(_log_record("opentelemetry")) is False
        assert otel_filter.filter(_log_record("opentelemetry.exporter.otlp")) is False

    def test_allows_application_namespaces(self) -> None:
        """ATI and third-party loggers still flow to OTLP export."""
        otel_filter = OtelLoggerNamespaceFilter()
        assert otel_filter.filter(_log_record("ati.worker")) is True
        assert otel_filter.filter(_log_record("uvicorn.access")) is True
        assert otel_filter.filter(_log_record("sqlalchemy.engine")) is True
