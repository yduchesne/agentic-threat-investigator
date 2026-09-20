# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic unit tests for the API telemetry lifecycle (PR 29B-2).

PR 29B-2 closes the two PR 29B-1 leftovers: the duplicate direct FastAPI
instrumentation dependency and deterministic telemetry-shutdown ownership.
These tests prove the lifecycle-ordering, failure-precedence, disabled-mode,
and exactly-once matrix (API-L01..API-L07) using the real ``create_app``
lifespan over an :class:`ApiComposition` double plus a plain seam-level
harness with in-memory OTel providers — no database, Kafka/Redpanda,
Collector, Prometheus, Jaeger, Loki, Grafana, or live services.

API-L08 (exactly one direct ``opentelemetry-instrumentation-fastapi``
declaration) is enforced by dependency review and the repository build
(``uv lock``), not by a brittle text test — consistent with repository policy.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

import agentic_threat_investigator.api.app as app_module
import agentic_threat_investigator.telemetry.setup as telemetry_setup
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.telemetry.http import instrument_fastapi_http
from agentic_threat_investigator.telemetry.lifecycle import (
    arrange_fastapi_telemetry_shutdown,
)
from agentic_threat_investigator.telemetry.setup import (
    ServiceNames,
    TelemetryRuntime,
    configure_telemetry,
    shutdown_telemetry,
)


@pytest.fixture
def fresh_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset ATI telemetry composition state between lifecycle tests."""
    monkeypatch.setattr(telemetry_setup, "_configured", None)
    monkeypatch.setattr(telemetry_setup, "_runtime", TelemetryRuntime())


def _recording_composition(
    events: list[str],
    *,
    dispose_failure: BaseException | None = None,
    startup_failure: BaseException | None = None,
) -> Any:
    """Build an ApiComposition double that records startup/disposal events.

    The double is installed on the application factory in place of the real
    repository/engine wiring; it records the exact lifecycle events so tests
    can prove ordering without any infrastructure.
    """

    class FakeBootstrap:
        """Bootstrap-admin double recording the ensure call."""

        async def ensure(self, username: str | None, password: str | None) -> None:
            """Record the bootstrap call and optionally fail startup."""
            events.append("bootstrap_admin")
            if startup_failure is not None:
                raise startup_failure

    class FakeComposition:
        """In-memory composition double replacing the real service wiring."""

        def __init__(self, settings: Settings) -> None:
            """Bind the settings installed on the application state."""
            self._settings = settings

        def install_services(self, application: Any) -> None:
            """Install only the settings the health probes read."""
            application.state.settings = self._settings

        def bootstrap_admin(self) -> FakeBootstrap:
            """Return the recording bootstrap double."""
            return FakeBootstrap()

        async def dispose(self) -> None:
            """Record the disposal and optionally fail it."""
            events.append("dispose")
            if dispose_failure is not None:
                raise dispose_failure

    return FakeComposition


def _instrumented_probe_app(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FastAPI, InMemorySpanExporter]:
    """Build one instrumented probe app with in-memory span export.

    ``OTEL_SEMCONV_STABILITY_OPT_IN`` is pinned to an empty value exactly as
    in API-T01..API-T18 so the resolved official instrumentation behaves
    identically to the PR 29B-1 matrix.
    """
    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "")
    exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(exporter))
    application = FastAPI()

    @application.get("/health/live")
    async def live() -> dict[str, str]:
        """Liveness probe used by the no-premature-shutdown test."""
        return {"status": "ok"}

    instrument_fastapi_http(
        application,
        TelemetryRuntime(
            tracer_provider=tracer_provider, meter_provider=MeterProvider()
        ),
    )
    return application, exporter


class TestLifecycleOrderingAndFailure:
    """API-L01/L02/L04/L07: ordering and failure precedence via create_app."""

    def test_normal_shutdown_disposes_api_before_telemetry_shutdown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L01/L07: dispose precedes one telemetry shutdown on normal exit."""
        events: list[str] = []
        monkeypatch.setattr(
            app_module, "ApiComposition", _recording_composition(events)
        )
        application = app_module.create_app(Settings())
        arrange_fastapi_telemetry_shutdown(
            application, lambda: events.append("telemetry_shutdown")
        )

        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
            assert events == ["bootstrap_admin"]
        assert events == ["bootstrap_admin", "dispose", "telemetry_shutdown"]
        assert events.count("telemetry_shutdown") == 1

    def test_dispose_failure_still_shuts_down_telemetry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L02: telemetry shutdown is attempted after a failed disposal."""
        events: list[str] = []
        failure = RuntimeError("api dispose failure")
        monkeypatch.setattr(
            app_module,
            "ApiComposition",
            _recording_composition(events, dispose_failure=failure),
        )
        application = app_module.create_app(Settings())
        arrange_fastapi_telemetry_shutdown(
            application, lambda: events.append("telemetry_shutdown")
        )

        with pytest.raises(RuntimeError) as exc_info, TestClient(application) as client:
            assert client.get("/health/live").status_code == 200

        assert exc_info.value is failure
        assert events == ["bootstrap_admin", "dispose", "telemetry_shutdown"]

    def test_startup_failure_keeps_finally_cleanup_and_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L04: startup failure still runs the shutdown cleanup once."""
        events: list[str] = []
        failure = RuntimeError("api startup failure")
        monkeypatch.setattr(
            app_module,
            "ApiComposition",
            _recording_composition(events, startup_failure=failure),
        )
        application = app_module.create_app(Settings())
        arrange_fastapi_telemetry_shutdown(
            application, lambda: events.append("telemetry_shutdown")
        )

        with pytest.raises(RuntimeError) as exc_info, TestClient(application):
            pass

        assert exc_info.value is failure
        assert events == ["bootstrap_admin", "telemetry_shutdown"]

    def test_normal_lifespan_shuts_down_exactly_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L07: a plain lifespan exits with exactly one shutdown callback."""
        events: list[str] = []
        application = FastAPI()

        @application.get("/probe")
        async def probe() -> dict[str, str]:
            """Probe route for the exactly-once test."""
            return {"status": "ok"}

        arrange_fastapi_telemetry_shutdown(
            application, lambda: events.append("telemetry_shutdown")
        )
        with TestClient(application) as client:
            assert client.get("/probe").status_code == 200
            assert client.get("/probe").status_code == 200
        assert events == ["telemetry_shutdown"]


class TestDisabledAndFailOpenTelemetry:
    """API-L03/L06: disabled and fail-open paths through real setup calls."""

    def test_disabled_telemetry_lifecycle_is_harmless(
        self, fresh_setup: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L03: disabled telemetry completes the lifecycle safely."""
        events: list[str] = []
        monkeypatch.setattr(
            app_module, "ApiComposition", _recording_composition(events)
        )
        runtime = configure_telemetry(
            enabled=False, service_name=ServiceNames.API, register_globals=False
        )
        assert runtime.tracer_provider is None
        assert runtime.meter_provider is None

        application = app_module.create_app(Settings())
        instrument_fastapi_http(application, runtime)  # installs nothing
        arrange_fastapi_telemetry_shutdown(application, shutdown_telemetry)

        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200

        assert events == ["bootstrap_admin", "dispose"]
        assert telemetry_setup._configured is None

    def test_provider_shutdown_failure_stays_fail_open(
        self,
        fresh_setup: None,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """API-L06: a failing provider shutdown never replaces app semantics."""
        events: list[str] = []
        monkeypatch.setattr(
            app_module, "ApiComposition", _recording_composition(events)
        )
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert runtime.tracer_provider is not None

        def breaking_shutdown() -> None:
            """Simulate a fatal tracer-provider shutdown."""
            raise RuntimeError("tracer provider shutdown failure")

        monkeypatch.setattr(runtime.tracer_provider, "shutdown", breaking_shutdown)

        application = app_module.create_app(Settings())
        instrument_fastapi_http(application, runtime)
        arrange_fastapi_telemetry_shutdown(application, shutdown_telemetry)

        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200

        assert events == ["bootstrap_admin", "dispose"]
        assert telemetry_setup._configured is None
        assert any(
            "provider shutdown failed" in record.message for record in caplog.records
        )


class TestRequestBeforeShutdown:
    """API-L05: inbound HTTP telemetry records before any shutdown."""

    def test_request_records_before_telemetry_shutdown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """API-L05: providers stay live while serving; shutdown runs at teardown."""
        events: list[str] = []
        application, exporter = _instrumented_probe_app(monkeypatch)
        arrange_fastapi_telemetry_shutdown(
            application, lambda: events.append("telemetry_shutdown")
        )

        with TestClient(application) as client:
            assert client.get("/health/live").status_code == 200
            assert len(exporter.get_finished_spans()) == 1
            assert events == []

        assert len(exporter.get_finished_spans()) == 1
        assert events == ["telemetry_shutdown"]
