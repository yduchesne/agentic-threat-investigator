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
from opentelemetry.sdk._logs import LoggingHandler


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


class OtelLoggerNamespaceFilter(logging.Filter):
    """Keep OpenTelemetry SDK/exporter log records out of OTLP export.

    PR 29C transports ATI application logs additively. OTel SDK/exporter
    diagnostics (``opentelemetry.*`` logger namespaces) are the transport's
    own machinery: re-exporting them through the OTLP log pipeline would
    create a feedback loop when the Collector/backend is unavailable or
    rejects a batch. This filter drops exactly those namespaces from the
    OTLP handler only; console logging remains untouched and useful warnings
    from other namespaces are not suppressed.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Drop OTel-internal records; allow every other record through."""
        return not (
            record.name == "opentelemetry" or record.name.startswith("opentelemetry.")
        )


def attach_otlp_log_handler(handler: LoggingHandler) -> None:
    """Attach an OTel ``LoggingHandler`` to the root logger additively.

    The handler is added to the root logger's existing handler set without
    removing or replacing any console handler, so developer terminal output
    and container logs are preserved and OTLP export is an additional
    pipeline. The OTel-internal namespace guard is installed on the handler
    so its own diagnostics never re-enter OTLP export. Callers must remove
    the handler through :func:`detach_otlp_log_handler` during telemetry
    shutdown so repeated test/process-local configurations never leak
    duplicate handlers.
    """
    if not any(installed is handler for installed in logging.getLogger().handlers):
        handler.addFilter(OtelLoggerNamespaceFilter())
        logging.getLogger().addHandler(handler)


def detach_otlp_log_handler(handler: LoggingHandler | None) -> None:
    """Detach one previously attached OTel ``LoggingHandler`` from the root.

    Idempotent and safe: a ``None`` handler or a handler that was never
    attached is a no-op, and removing the handler never touches console
    handlers installed by application logging configuration.
    """
    if handler is None:
        return
    root = logging.getLogger()
    for installed in list(root.handlers):
        if installed is handler:
            root.removeHandler(handler)


__all__ = [
    "TraceCorrelation",
    "TraceCorrelationFilter",
    "OtelLoggerNamespaceFilter",
    "attach_otlp_log_handler",
    "detach_otlp_log_handler",
    "current_correlation",
]
