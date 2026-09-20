# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic unit tests for inbound FastAPI/ASGI HTTP telemetry (PR 29B-1).

PR 29B-1 instruments the API at the framework boundary with official OTel
FastAPI instrumentation. These tests prove the behavioral, cardinality, trace
continuity, and privacy matrix (API-T01..API-T18) using only in-memory OTel
providers — no collector, Prometheus, Jaeger, Loki, Grafana, or live services.

Privacy assertions use unmistakable sentinels and scan every recorded span
attribute/event and metric attribute, not merely a few expected keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import SpanKind, Tracer

from agentic_threat_investigator.api.middleware import RequestContextMiddleware
from agentic_threat_investigator.telemetry.http import instrument_fastapi_http
from agentic_threat_investigator.telemetry.setup import TelemetryRuntime
from agentic_threat_investigator.telemetry.tracing import SpanNames, get_tracer
from tests.support.otel import metric_data_points, metrics_by_name

QUERY_SENTINEL = "DO_NOT_CAPTURE_QUERY_29B1"
BODY_SENTINEL = "DO_NOT_CAPTURE_BODY_29B1"
COOKIE_SENTINEL = "DO_NOT_CAPTURE_COOKIE_29B1"
AUTH_SENTINEL = "DO_NOT_CAPTURE_AUTH_29B1"
CSRF_SENTINEL = "DO_NOT_CAPTURE_CSRF_29B1"
IDEMPOTENCY_SENTINEL = "DO_NOT_CAPTURE_IDEMPOTENCY_29B1"

SENTINELS = (
    QUERY_SENTINEL,
    BODY_SENTINEL,
    COOKIE_SENTINEL,
    AUTH_SENTINEL,
    CSRF_SENTINEL,
    IDEMPOTENCY_SENTINEL,
)

ROUTE_INVESTIGATION = "/api/v1/investigations/{investigation_id}"
TRACE_ID_HEX = "4bf92f3577b34da6a3ce929d0e0e4736"
SPAN_ID_HEX = "00f067aa0ba902b7"


@dataclass
class Harness:
    """One deterministic instrumented test app with in-memory OTel readers."""

    application: FastAPI
    client: TestClient
    exporter: InMemorySpanExporter
    reader: InMemoryMetricReader
    runtime: TelemetryRuntime

    def spans(self) -> list[ReadableSpan]:
        """Return every finished span recorded since the harness was built."""
        return list(self.exporter.get_finished_spans())

    def server_spans(self) -> list[ReadableSpan]:
        """Return the finished HTTP server spans (kind SERVER).

        A server span begun from an incoming W3C ``traceparent`` still has a
        remote parent, so the filter is by span kind, never by parentage.
        """
        return [span for span in self.spans() if span.kind == SpanKind.SERVER]


def _build_app(*, child_tracer: Tracer | None = None) -> FastAPI:
    """Build the deterministic route surface for the API-T01..T18 matrix."""
    application = FastAPI()
    application.add_middleware(RequestContextMiddleware)

    @application.get(ROUTE_INVESTIGATION)
    async def get_investigation(investigation_id: str) -> dict[str, str]:
        """Echo the path parameter (used for GET/DELETE identity tests)."""
        return {"id": investigation_id}

    @application.delete(ROUTE_INVESTIGATION)
    async def delete_investigation(investigation_id: str) -> dict[str, bool]:
        """Delete contract on the same registered template as GET."""
        del investigation_id
        return {"deleted": True}

    @application.post("/api/v1/investigations")
    async def create_investigation() -> dict[str, bool]:
        """Create contract used by the method-distinction test."""
        return {"created": True}

    @application.post("/api/v1/echo")
    async def echo(payload: dict[str, Any] | None = None) -> dict[str, bool]:
        """Accept a request body that must never reach telemetry."""
        del payload
        return {"ok": True}

    @application.get("/api/v1/child/{item_id}")
    async def child(item_id: str) -> dict[str, bool]:
        """Start one canonical ATI span during request processing."""
        del item_id
        if child_tracer is not None:
            with child_tracer.start_as_current_span(SpanNames.LLM_INVOKE):
                return {"ok": True}
        return {"ok": True}

    @application.get("/api/v1/validated/{value}")
    async def validated(value: int) -> dict[str, int]:
        """Validation-constrained route producing a standard 422 on error."""
        return {"value": value}

    @application.get("/api/v1/fail")
    async def fail() -> dict[str, bool]:
        """Server failure probe producing a handled 500 response."""
        raise RuntimeError("telemetry test failure")

    @application.get("/api/v1/content")
    async def content() -> dict[str, Any]:
        """Response containing a body sentinel that must never be captured."""
        return {"token": BODY_SENTINEL, "nested": {"secret": BODY_SENTINEL}}

    async def live() -> dict[str, str]:
        """Liveness probe."""

        return {"status": "ok"}

    async def ready() -> dict[str, str]:
        """Readiness probe."""

        return {"status": "ready"}

    application.add_api_route("/health/live", live, methods=["GET"])
    application.add_api_route("/health/ready", ready, methods=["GET"])
    return application


def _make_harness(monkeypatch: pytest.MonkeyPatch, *, enabled: bool = True) -> Harness:
    """Build an instrumented (or disabled) test app with in-memory providers.

    ``OTEL_SEMCONV_STABILITY_OPT_IN`` is pinned to an empty value so the
    resolved official instrumentation deterministically emits its default
    (legacy HTTP) semantic-convention names (``http.server.duration``,
    ``http.method``, ``http.status_code``), independent of any developer
    shell environment. The metric route dimension is the registered route
    template in both default and opt-in modes.
    """
    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "")
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    reader = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=[reader])
    runtime = (
        TelemetryRuntime(tracer_provider=tracer_provider, meter_provider=meter_provider)
        if enabled
        else TelemetryRuntime()
    )
    application = _build_app(child_tracer=get_tracer(tracer_provider=tracer_provider))
    instrument_fastapi_http(application, runtime)
    return Harness(
        application=application,
        client=TestClient(application, raise_server_exceptions=False),
        exporter=exporter,
        reader=reader,
        runtime=runtime,
    )


def span_attr(span: ReadableSpan, key: str) -> Any:
    """Read one span attribute without tripping on the optional mapping."""
    return (span.attributes or {}).get(key)


def _telemetry_strings(harness: Harness) -> list[str]:
    """Flatten every recorded span/metric attribute value to strings."""
    values: list[str] = []
    for span in harness.spans():
        values.append(span.name)
        values.extend(str(value) for value in (span.attributes or {}).values())
        for event in span.events:
            values.append(event.name)
            values.extend(str(value) for value in (event.attributes or {}).values())
    for metric in metrics_by_name(harness.reader).values():
        for point in metric_data_points(metric):
            values.extend(str(value) for value in (point.attributes or {}).values())
    return values


def _assert_sentinels_absent(harness: Harness) -> None:
    """Assert no sentinel value appears in any recorded telemetry."""
    recorded = _telemetry_strings(harness)
    for sentinel in SENTINELS:
        assert not any(sentinel in value for value in recorded), (
            f"{sentinel} leaked into HTTP telemetry"
        )


def _duration_points(harness: Harness) -> list[dict[str, Any]]:
    """Return every ``http.server.duration`` data point's attributes."""
    metric = metrics_by_name(harness.reader).get("http.server.duration")
    if metric is None:
        return []
    return [dict(point.attributes or {}) for point in metric_data_points(metric)]


class TestRouteIdentityAndStatus:
    """API-T01/T02/T03/T05/T06/T07/T15/T16: identity, method, status, health."""

    def test_enabled_get_request_is_observed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T01: one standard HTTP server span per registered GET route."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/health/live")
        assert response.status_code == 200
        spans = harness.server_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "GET /health/live"
        assert span_attr(span, "http.method") == "GET"
        assert span_attr(span, "http.route") == "/health/live"
        assert span_attr(span, "http.status_code") == 200

    def test_method_dimension_distinguishes_same_template(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T02: GET and DELETE on one template stay distinguishable."""
        harness = _make_harness(monkeypatch)
        assert harness.client.get("/api/v1/investigations/aaa").status_code == 200
        assert harness.client.delete("/api/v1/investigations/aaa").status_code == 200
        points = _duration_points(harness)
        get_point = next(
            point
            for point in points
            if point.get("http.method") == "GET"
            and point.get("http.target") == ROUTE_INVESTIGATION
        )
        delete_point = next(
            point
            for point in points
            if point.get("http.method") == "DELETE"
            and point.get("http.target") == ROUTE_INVESTIGATION
        )
        assert get_point["http.status_code"] == 200
        assert delete_point["http.status_code"] == 200

    def test_dynamic_uuid_path_uses_registered_template(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T03: a UUID path becomes the route template, never the UUID."""
        harness = _make_harness(monkeypatch)
        uuid_path = "11111111-1111-1111-1111-111111111111"
        response = harness.client.get(f"/api/v1/investigations/{uuid_path}")
        assert response.status_code == 200
        points = _duration_points(harness)
        assert any(point.get("http.target") == ROUTE_INVESTIGATION for point in points)
        recorded = _telemetry_strings(harness)
        assert uuid_path not in " ".join(recorded)

    def test_2xx_status_attribute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-T05: the standard response-status attribute matches a 2xx."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/api/v1/investigations/abc")
        assert response.status_code == 200
        span = harness.server_spans()[0]
        assert span_attr(span, "http.status_code") == 200
        assert span_attr(span, "http.route") == ROUTE_INVESTIGATION

    def test_4xx_status_attribute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-T06: a 422 keeps its status and normal validation behavior."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/api/v1/validated/not-an-int")
        assert response.status_code == 422
        span = harness.server_spans()[0]
        assert span_attr(span, "http.status_code") == 422

    def test_5xx_handled_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-T07: a handled 500 is observed without changing the response."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/api/v1/fail")
        assert response.status_code == 500
        span = harness.server_spans()[0]
        assert span_attr(span, "http.status_code") == 500
        assert any(event.name == "exception" for event in span.events)

    def test_health_endpoints_observable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-T15: health probes emit bounded route-template telemetry."""
        harness = _make_harness(monkeypatch)
        assert harness.client.get("/health/live").status_code == 200
        assert harness.client.get("/health/ready").status_code == 200
        points = _duration_points(harness)
        assert any(point.get("http.target") == "/health/live" for point in points)
        assert any(point.get("http.target") == "/health/ready" for point in points)
        assert all(
            span_attr(span, "http.route") is not None for span in harness.server_spans()
        )

    def test_unknown_path_has_no_bounded_route(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T16: arbitrary unmatched paths never become route dimensions."""
        harness = _make_harness(monkeypatch)
        arbitrary = "/api/v1/aaaaaaaa/bbbbbbbb-1111-2222-3333-444444444444"
        response = harness.client.get(arbitrary)
        assert response.status_code == 404
        recorded = " ".join(_telemetry_strings(harness))
        assert arbitrary not in recorded
        span = harness.server_spans()[0]
        assert span_attr(span, "http.route") is None
        assert all("http.target" not in point for point in _duration_points(harness))


class TestTraceContinuity:
    """API-T08/T09/T10: incoming W3C context and downstream inheritance."""

    def test_valid_incoming_traceparent_continues_trace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T08: the server span adopts the upstream trace context."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get(
            "/api/v1/investigations/x",
            headers={"traceparent": f"00-{TRACE_ID_HEX}-{SPAN_ID_HEX}-01"},
        )
        assert response.status_code == 200
        span = harness.server_spans()[0]
        assert span.context.trace_id == int(TRACE_ID_HEX, 16)
        assert span.parent is not None
        assert span.parent.span_id == int(SPAN_ID_HEX, 16)
        assert span.parent.is_remote

    def test_malformed_traceparent_fails_safely(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T09: malformed trace context never breaks or poisons a request."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get(
            "/api/v1/investigations/x",
            headers={"traceparent": "00-garbage-not-a-trace-01"},
        )
        assert response.status_code == 200
        span = harness.server_spans()[0]
        assert hex(span.context.trace_id).startswith("0x")
        assert span.parent is None

    def test_child_ati_span_inherits_server_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T10: an ATI span started in a route is a server-span descendant."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/api/v1/child/item-42")
        assert response.status_code == 200
        server = harness.server_spans()[0]
        assert server.name == "GET /api/v1/child/{item_id}"
        assert span_attr(server, "http.route") == "/api/v1/child/{item_id}"
        children = [span for span in harness.spans() if span.kind != SpanKind.SERVER]
        assert len(children) == 1
        child = children[0]
        assert child.name == SpanNames.LLM_INVOKE
        assert child.context.trace_id == server.context.trace_id
        assert child.parent is not None
        assert child.parent.span_id == server.context.span_id


class TestPrivacyAndDisablement:
    """API-T04/T11/T12/T13/T14: content-free telemetry and disablement."""

    def test_query_sentinel_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """API-T04: query values never reach metric or span telemetry."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get(
            f"/api/v1/investigations/abc?{QUERY_SENTINEL}=leak"
        )
        assert response.status_code == 200
        _assert_sentinels_absent(harness)

    def test_request_body_sentinel_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T11: request bodies are never captured."""
        harness = _make_harness(monkeypatch)
        response = harness.client.post(
            "/api/v1/echo", json={"note": BODY_SENTINEL, "nested": [BODY_SENTINEL]}
        )
        assert response.status_code == 200
        _assert_sentinels_absent(harness)

    def test_auth_cookie_csrf_and_header_sentinels_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T12: authorization/cookie/CSRF/idempotency data is not captured."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get(
            "/api/v1/investigations/abc",
            headers={
                "Authorization": f"Bearer {AUTH_SENTINEL}",
                "X-CSRF-Token": CSRF_SENTINEL,
                "Idempotency-Key": IDEMPOTENCY_SENTINEL,
                "Cookie": f"ati_session={COOKIE_SENTINEL}",
            },
        )
        assert response.status_code == 200
        _assert_sentinels_absent(harness)

    def test_response_body_sentinel_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T13: response bodies are never captured."""
        harness = _make_harness(monkeypatch)
        response = harness.client.get("/api/v1/content")
        assert response.status_code == 200
        assert BODY_SENTINEL in response.text
        _assert_sentinels_absent(harness)

    def test_disabled_telemetry_installs_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T14: disabled mode installs no HTTP pipeline and changes nothing."""
        harness = _make_harness(monkeypatch, enabled=False)
        assert harness.client.get("/health/live").status_code == 200
        assert harness.client.get("/api/v1/investigations/abc").status_code == 200
        assert list(harness.exporter.get_finished_spans()) == []
        assert metrics_by_name(harness.reader) == {}


class TestCompositionLifecycle:
    """API-T17/T18: idempotent instrumentation and unchanged request-ID wiring."""

    def test_repeated_construction_never_duplicates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T17: repeated/seam re-instrumentation yields one span per request."""
        harness = _make_harness(monkeypatch)
        instrument_fastapi_http(harness.application, harness.runtime)
        assert harness.client.get("/health/live").status_code == 200
        assert len(harness.spans()) == 1

        tracer_provider = harness.runtime.tracer_provider
        assert tracer_provider is not None
        second_app = _build_app(
            child_tracer=get_tracer(tracer_provider=tracer_provider)
        )
        instrument_fastapi_http(second_app, harness.runtime)
        second_client = TestClient(second_app)
        assert second_client.get("/health/live").status_code == 200
        assert len(harness.spans()) == 2

    def test_request_id_middleware_behavior_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-T18: caller request IDs are honored through instrumented stack."""
        harness = _make_harness(monkeypatch)
        supplied = "caller-request-42"
        response = harness.client.get(
            "/api/v1/investigations/abc", headers={"X-Request-ID": supplied}
        )
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == supplied
        assert supplied not in " ".join(_telemetry_strings(harness))
