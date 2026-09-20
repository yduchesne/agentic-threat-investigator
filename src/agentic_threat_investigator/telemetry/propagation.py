# SPDX-License-Identifier: AGPL-3.0-only
"""W3C trace-context propagation helpers for Kafka-style headers (PR 29A).

These helpers use the standard OpenTelemetry W3C ``TraceContextTextMapPropagator``
(never a hand-written ``traceparent`` parser) and operate on the
``Sequence[tuple[str, bytes]]`` header shape used by Kafka without importing
aiokafka into the telemetry package. PR 29A defines the contract only; real
Kafka producer/consumer call sites are wired in PR 29B.
"""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry.context.context import Context
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

ATI_PROPAGATION_HEADERS = frozenset({"traceparent", "tracestate"})
"""The ATI-owned W3C propagation header names this helper manages."""

_PROPAGATION_HEADER_KEYS_UPPER = frozenset(
    {name.upper() for name in ATI_PROPAGATION_HEADERS}
)
_PROPAGATOR = TraceContextTextMapPropagator()


def _is_propagation_header(key: str) -> bool:
    """Return whether ``key`` is an ATI-owned propagation header (case-folded)."""
    return key.upper() in _PROPAGATION_HEADER_KEYS_UPPER


def inject_trace_context(
    headers: Sequence[tuple[str, bytes]],
) -> list[tuple[str, bytes]]:
    """Inject the current W3C trace context into bounded message headers.

    Unrelated headers are preserved verbatim. Any existing ATI-owned
    propagation header is normalized (replaced) rather than accumulated, so
    duplicates can never accrue. With no current valid span no trace identity
    is fabricated and the propagation headers are simply removed.
    """
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)
    result = [(key, value) for key, value in headers if not _is_propagation_header(key)]
    for key, value in carrier.items():
        result.append((key, value.encode("utf-8")))
    return result


def extract_trace_context(
    headers: Sequence[tuple[str, str | bytes]],
) -> Context:
    """Extract a parent W3C context from bounded message headers.

    Header values may be ``bytes`` or ``str``; both are decoded
    deterministically to text before the standard propagator parses them.
    Malformed or missing incoming context yields a safe no-parent
    ``Context`` and never raises.
    """
    carrier: dict[str, str] = {}
    for key, value in headers:
        if _is_propagation_header(key):
            if isinstance(value, bytes):
                carrier[key] = value.decode("utf-8")
            else:
                carrier[key] = str(value)
    return _PROPAGATOR.extract(carrier)


__all__ = [
    "ATI_PROPAGATION_HEADERS",
    "extract_trace_context",
    "inject_trace_context",
]
