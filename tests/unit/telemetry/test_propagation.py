# SPDX-License-Identifier: AGPL-3.0-only
"""W3C trace-context propagation helper tests (PR 29A)."""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry import trace as otl_trace

from agentic_threat_investigator.telemetry.propagation import (
    extract_trace_context,
    inject_trace_context,
)

_IN_UNRELATED = [("content-type", b"application/json"), ("x-user", b"u1")]


def _extracted_trace_id(headers: Sequence[tuple[str, str | bytes]]) -> str:
    """Return the trace id carried by an extracted context ('' when none)."""
    ctx = extract_trace_context(headers)
    span_context = otl_trace.get_current_span(ctx).get_span_context()
    if not span_context.is_valid:
        return ""
    return f"{span_context.trace_id:032x}"


class TestInject:
    """Injection produces bounded W3C traceparent/tracestate headers."""

    def test_active_span_injects_valid_traceparent(
        self, in_memory_telemetry: object
    ) -> None:
        """With an active span, injection emits a valid traceparent."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.evidence.publish") as span:
            headers = inject_trace_context(list(_IN_UNRELATED))
            assert _extracted_trace_id(headers) == f"{span.context.trace_id:032x}"

    def test_unrelated_headers_preserved(self, in_memory_telemetry: object) -> None:
        """Unrelated headers are preserved verbatim during injection."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.evidence.publish"):
            headers = inject_trace_context(list(_IN_UNRELATED))
        keys = [key for key, _value in headers]
        assert "content-type" in keys and "x-user" in keys

    def test_no_active_span_no_fabricated_identity(self) -> None:
        """Without an active span, no trace identity is fabricated."""
        headers = inject_trace_context(list(_IN_UNRELATED))
        keys = {key for key, _value in headers}
        assert "traceparent" not in keys
        assert "tracestate" not in keys
        # Unrelated headers remain.
        assert "content-type" in keys

    def test_duplicate_propagation_headers_normalized(
        self, in_memory_telemetry: object
    ) -> None:
        """Duplicate propagation headers are normalized, not accumulated."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        messy = [
            ("traceparent", b"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-aaaaaaaaaaaaaaaa-01"),
            (
                "TraceParent",
                b"00-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bbbbbbbbbbbbbbbb-01",
            ),
            ("tracestate", b"foo=bar"),
            ("content-type", b"application/json"),
        ]
        with tracer.start_as_current_span("ati.evidence.publish"):
            headers = inject_trace_context(messy)
        traceparents = [k for k, _v in headers if k.lower() == "traceparent"]
        assert len(traceparents) == 1

    def test_baggage_and_domain_ids_not_added(
        self, in_memory_telemetry: object
    ) -> None:
        """No W3C baggage or ATI domain identifiers are injected."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.evidence.publish"):
            headers = inject_trace_context(list(_IN_UNRELATED))
        joined = "|".join(f"{k}={v.decode()}" for k, v in headers)
        assert "baggage" not in joined
        assert "investigation_id" not in joined
        assert "evidence_id" not in joined


class TestExtract:
    """Extraction is bounded and safe for malformed or missing input."""

    def test_inject_then_extract_same_trace(self, in_memory_telemetry: object) -> None:
        """Inject then extract preserves the same trace identity."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.evidence.publish") as span:
            headers = inject_trace_context(list(_IN_UNRELATED))
            assert _extracted_trace_id(headers) == f"{span.context.trace_id:032x}"

    def test_malformed_input_safe_no_parent(self) -> None:
        """Malformed incoming traceparent yields a safe no-parent context."""
        headers = [("traceparent", b"00-not-hex-0000000000000001-01")]
        assert _extracted_trace_id(headers) == ""

    def test_missing_traceparent_is_no_parent(self) -> None:
        """Missing traceparent yields a safe no-parent context."""
        assert _extracted_trace_id(list(_IN_UNRELATED)) == ""

    def test_binary_and_text_values_decode_deterministically(
        self, in_memory_telemetry: object
    ) -> None:
        """UTF-8 bytes and text values decode to the same trace identity."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.evidence.publish") as span:
            bytes_headers = inject_trace_context([("traceparent", b"stale")])
            text_headers = [(k, v.decode("utf-8")) for k, v in bytes_headers]
        ctx = extract_trace_context(text_headers)
        span_context = otl_trace.get_current_span(ctx).get_span_context()
        assert f"{span_context.trace_id:032x}" == f"{span.context.trace_id:032x}"

    def test_valid_external_traceparent_extracted(self) -> None:
        """A well-formed external traceparent is adopted as the parent."""
        headers = [
            (
                "traceparent",
                b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            )
        ]
        assert _extracted_trace_id(headers) == "4bf92f3577b34da6a3ce929d0e0e4736"
