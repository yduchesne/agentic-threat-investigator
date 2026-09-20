# SPDX-License-Identifier: AGPL-3.0-only
"""Trace/span correlation helpers for standard Python logging (PR 29A).

These helpers expose only the current valid OTel ``trace_id`` and
``span_id`` as canonical lowercase hexadecimal strings. Outside a valid
sampled context no identifiers are fabricated. The helpers are additive to
ATI's existing standard logging: nothing here reconfigures logging, and a
log record's existing attributes are never overwritten.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from opentelemetry import trace


@dataclass(frozen=True)
class TraceCorrelation:
    """A valid current trace/span identity in canonical hex form."""

    trace_id: str
    span_id: str


def current_correlation() -> TraceCorrelation | None:
    """Return the current valid trace/span identity, or ``None``.

    Returns ``None`` when there is no current span or the current context is
    invalid/non-recording, so callers can never log a fabricated identity.
    """
    context = trace.get_current_span().get_span_context()
    if not context.is_valid:
        return None
    return TraceCorrelation(
        trace_id=f"{context.trace_id:032x}",
        span_id=f"{context.span_id:016x}",
    )


class TraceCorrelationFilter(logging.Filter):
    """Attach ``otel_trace_id`` / ``otel_span_id`` to a log record.

    The filter sets the two fields on the ``LogRecord`` when a current valid
    span exists; otherwise it sets them to empty strings. It never overwrites
    a record attribute that already exists and never raises, so correlation
    can never change log semantics.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Populate the correlation fields once and allow the record through."""
        if hasattr(record, "otel_trace_id") and hasattr(record, "otel_span_id"):
            return True
        correlation = current_correlation()
        record.otel_trace_id = correlation.trace_id if correlation else ""
        record.otel_span_id = correlation.span_id if correlation else ""
        return True


__all__ = [
    "TraceCorrelation",
    "TraceCorrelationFilter",
    "current_correlation",
]
