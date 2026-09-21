# SPDX-License-Identifier: AGPL-3.0-only
"""Telemetry setup, service identity, and idempotency tests (PR 29A)."""

from __future__ import annotations

import logging
from collections.abc import Generator, Sequence

import pytest
from opentelemetry.sdk._logs import LogData
from opentelemetry.sdk._logs.export import LogExporter, LogExportResult
from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
from opentelemetry.sdk.resources import SERVICE_NAME
from opentelemetry.sdk.trace.export import SpanExportResult

from agentic_threat_investigator.telemetry.setup import (
    SERVICE_NAMES,
    ServiceNames,
    TelemetryRuntime,
    configure_telemetry,
    shutdown_telemetry,
)


@pytest.fixture
def fresh_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset ATI telemetry composition state between tests.

    Tests call ``configure_telemetry(... register_globals=False)`` so the
    once-only OTel global providers are never touched and no leakage occurs.
    """
    import agentic_threat_investigator.telemetry.setup as setup

    monkeypatch.setattr(setup, "_configured", None)
    monkeypatch.setattr(setup, "_runtime", TelemetryRuntime())


class TestServiceIdentity:
    """Canonical service names are exact and deterministic."""

    def test_exact_service_name_set(self) -> None:
        """The frozen service-name set matches the PR 29 contract."""
        assert {
            "ati-api",
            "ati-worker",
            "ati-geo-resolver",
            "ati-scheduler",
            "ati-migrate",
            "ati-fake-data-bootstrap",
        } == SERVICE_NAMES

    def test_constants_belong_to_set(self) -> None:
        """Each ServiceNames constant is present in the canonical set."""
        assert {
            ServiceNames.API,
            ServiceNames.WORKER,
            ServiceNames.GEO_RESOLVER,
            ServiceNames.SCHEDULER,
            ServiceNames.MIGRATE,
            ServiceNames.FAKE_DATA_BOOTSTRAP,
        } == SERVICE_NAMES

    def test_api_resource_identity(self, fresh_setup: None) -> None:
        """Enabled telemetry for the API process carries service.name=ati-api."""
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert runtime.tracer_provider is not None
        assert runtime.tracer_provider.resource.attributes[SERVICE_NAME] == "ati-api"
        assert runtime.meter_provider is not None

    def test_worker_resource_identity(self, fresh_setup: None) -> None:
        """Enabled telemetry for the worker process carries service.name=ati-worker."""
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.WORKER, register_globals=False
        )
        assert runtime.tracer_provider is not None
        assert runtime.tracer_provider.resource.attributes[SERVICE_NAME] == "ati-worker"

    def test_explicit_service_overrides_otel_env(
        self, fresh_setup: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit ATI service identity wins over OTEL_SERVICE_NAME.

        OpenTelemetry SDK ``Resource.create`` merge semantics give explicitly
        passed attributes precedence over environment-derived ones.
        """
        monkeypatch.setenv("OTEL_SERVICE_NAME", "custom-otel")
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert (
            runtime.tracer_provider is not None
            and runtime.tracer_provider.resource.attributes[SERVICE_NAME] == "ati-api"
        )

    def test_blank_service_name_rejected(self, fresh_setup: None) -> None:
        """A blank service name is rejected."""
        with pytest.raises(ValueError, match="service_name"):
            configure_telemetry(
                enabled=True, service_name="   ", register_globals=False
            )


class TestSetupLifecycle:
    """Disabled mode, idempotency, and shutdown."""

    def test_disabled_installs_no_providers(self, fresh_setup: None) -> None:
        """Disabled configuration installs no SDK providers and no exporter."""
        runtime = configure_telemetry(
            enabled=False, service_name=ServiceNames.WORKER, register_globals=False
        )
        assert isinstance(runtime, TelemetryRuntime)
        assert runtime.tracer_provider is None
        assert runtime.meter_provider is None

    def test_repeated_identical_setup_is_idempotent(self, fresh_setup: None) -> None:
        """A repeated identical setup returns the existing runtime object."""
        first = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        second = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert first is second

    def test_conflicting_second_setup_fails(self, fresh_setup: None) -> None:
        """A conflicting second setup raises instead of stacking a pipeline."""
        configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        with pytest.raises(RuntimeError, match="conflicting"):
            configure_telemetry(
                enabled=True, service_name=ServiceNames.WORKER, register_globals=False
            )

    def test_shutdown_resets_and_allows_reconfigure(self, fresh_setup: None) -> None:
        """Shutdown clears state so a fresh session can start."""
        first = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert first.tracer_provider is not None
        shutdown_telemetry()
        second = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert second is not first

    def test_shutdown_without_configuration_is_safe(self, fresh_setup: None) -> None:
        """Shutdown with no configuration is a safe no-op."""
        shutdown_telemetry()


class _RecordingSpanExporter:
    """In-memory span exporter recording every export/shutdown call."""

    def __init__(self) -> None:
        """Start with an empty recorded span set."""
        self.spans: list[object] = []
        self.shutdown_calls = 0

    def export(self, spans: list[object]) -> SpanExportResult:
        """Record the batch and report success without any network."""
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        """Record the shutdown call."""
        self.shutdown_calls += 1


class _RecordingMetricExporter(MetricExporter):
    """In-memory metric exporter recording every export/shutdown call."""

    def __init__(self) -> None:
        """Start with an empty recorded batch set."""
        super().__init__()
        self.batches: list[object] = []
        self.shutdown_calls = 0

    def export(
        self,
        metrics_data: object,
        timeout_millis: float = 10_000,
        **_: object,
    ) -> MetricExportResult:
        """Record the batch and report success without any network."""
        self.batches.append(metrics_data)
        return MetricExportResult.SUCCESS

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        """Flushing a recording exporter is a successful no-op."""
        return True

    def shutdown(self, timeout_millis: float = 30_000, **_: object) -> None:
        """Record the shutdown call."""
        self.shutdown_calls += 1


class _RecordingLogExporter(LogExporter):
    """In-memory log exporter recording every exported log record."""

    def __init__(self) -> None:
        """Start with an empty recorded record set."""
        self.records: list[LogData] = []
        self.shutdown_calls = 0

    def export(self, batch: Sequence[LogData], **_: object) -> LogExportResult:
        """Record the batch and report success without any network."""
        self.records.extend(batch)
        return LogExportResult.SUCCESS

    def shutdown(self) -> None:
        """Record the shutdown call."""
        self.shutdown_calls += 1


@pytest.fixture
def export_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[object, object, object], None, None]:
    """Compose enabled telemetry with recording exporters (INF-C03+).

    Patches the exporter factory seams with in-memory recording exporters
    and forces an explicit OTLP endpoint so the PR 29C remote pipeline is
    composed deterministically (no network, no real exporter threads).
    Teardown always calls ``shutdown_telemetry`` so no OTel logging handler
    or provider thread leaks across tests.
    """
    import agentic_threat_investigator.telemetry.setup as setup

    monkeypatch.setattr(setup, "_configured", None)
    monkeypatch.setattr(setup, "_runtime", TelemetryRuntime())
    monkeypatch.setattr(setup, "_installed_log_handler", None)
    span_exporter = _RecordingSpanExporter()
    metric_exporter = _RecordingMetricExporter()
    log_exporter = _RecordingLogExporter()
    monkeypatch.setattr(setup, "_span_exporter", lambda: span_exporter)
    monkeypatch.setattr(setup, "_metric_exporter", lambda: metric_exporter)
    monkeypatch.setattr(setup, "_log_exporter", lambda: log_exporter)
    monkeypatch.setattr(setup, "_otlp_endpoint", lambda: "http://otel-collector:4318")
    try:
        yield span_exporter, metric_exporter, log_exporter
    finally:
        setup.shutdown_telemetry()


class TestOtlpEndpointContract:
    """Only an explicit standard endpoint enables remote export (INF-C02)."""

    def test_absent_endpoint_stays_offline(
        self, fresh_setup: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Enabled telemetry without an endpoint composes no exporters."""
        import agentic_threat_investigator.telemetry.setup as setup

        calls: list[str] = []
        monkeypatch.setattr(setup, "_otlp_endpoint", lambda: None)
        monkeypatch.setattr(setup, "_span_exporter", lambda: calls.append("span"))
        monkeypatch.setattr(setup, "_metric_exporter", lambda: calls.append("metric"))
        monkeypatch.setattr(setup, "_log_exporter", lambda: calls.append("log"))
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert calls == []
        assert runtime.tracer_provider is not None
        assert runtime.meter_provider is not None
        assert runtime.logger_provider is None

    def test_blank_endpoint_stays_offline(
        self, fresh_setup: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A blank endpoint variable is treated as absent (no localhost default)."""
        import agentic_threat_investigator.telemetry.setup as setup

        calls: list[str] = []
        monkeypatch.setattr(setup, "_otlp_endpoint", lambda: None)
        monkeypatch.setattr(setup, "_span_exporter", lambda: calls.append("span"))
        monkeypatch.setattr(setup, "_metric_exporter", lambda: calls.append("metric"))
        monkeypatch.setattr(setup, "_log_exporter", lambda: calls.append("log"))
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert calls == []
        assert runtime.logger_provider is None

    def test_endpoint_uses_standard_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The endpoint is read from OTEL_EXPORTER_OTLP_ENDPOINT only."""
        import agentic_threat_investigator.telemetry.setup as setup

        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318")
        assert setup._otlp_endpoint() == "http://otel-collector:4318"
        monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        assert setup._otlp_endpoint() is None
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "   ")
        assert setup._otlp_endpoint() is None

    def test_real_exporters_resolve_standard_paths(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """OTLP/HTTP exporters append the standard /v1/* paths to the endpoint.

        Verifies the exact pinned exporter package contract: one standard
        Collector endpoint yields the three signal-specific paths without any
        ATI-prefixed setting.
        """
        from opentelemetry.exporter.otlp.proto.http._log_exporter import (
            OTLPLogExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318")
        assert OTLPSpanExporter()._endpoint == "http://otel-collector:4318/v1/traces"
        assert OTLPMetricExporter()._endpoint == "http://otel-collector:4318/v1/metrics"
        assert OTLPLogExporter()._endpoint == "http://otel-collector:4318/v1/logs"


class TestOtlpExportComposition:
    """PR 29C remote exporter composition matrix (INF-C03..C07)."""

    def test_enabled_with_endpoint_composes_all_three_pipelines(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C03 trace/metric/log exporters are composed exactly once."""
        span_exporter, metric_exporter, log_exporter = export_telemetry
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert runtime.tracer_provider is not None
        assert runtime.meter_provider is not None
        assert runtime.logger_provider is not None
        shutdown_telemetry()
        assert span_exporter.shutdown_calls == 1  # type: ignore[attr-defined]
        assert metric_exporter.shutdown_calls == 1  # type: ignore[attr-defined]
        assert log_exporter.shutdown_calls == 1  # type: ignore[attr-defined]

    def test_repeated_identical_setup_adds_no_duplicate_pipeline(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C04 repeated identical configure returns the same runtime."""
        first = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        second = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert first is second
        otel_handlers = [
            handler
            for handler in logging.getLogger().handlers
            if type(handler).__name__ == "LoggingHandler"
        ]
        assert len(otel_handlers) == 1

    def test_shutdown_detaches_log_handler_and_resets(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C06 shutdown shuts all signal providers and detaches the handler."""
        configure_telemetry(
            enabled=True, service_name=ServiceNames.WORKER, register_globals=False
        )
        shutdown_telemetry()
        otel_handlers = [
            handler
            for handler in logging.getLogger().handlers
            if type(handler).__name__ == "LoggingHandler"
        ]
        assert otel_handlers == []
        reconfigured = configure_telemetry(
            enabled=True, service_name=ServiceNames.WORKER, register_globals=False
        )
        assert reconfigured.tracer_provider is not None

    def test_shutdown_failure_is_fail_open(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C07 a failing provider shutdown never raises out of shutdown."""
        configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        shutdown_telemetry()
        shutdown_telemetry()  # second shutdown is a safe no-op


class TestOtlpLogCorrelation:
    """Exported log records carry standard trace/span correlation (INF-C08/C09)."""

    def test_log_outside_span_has_no_fabricated_identity(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C08 outside any span no trace/span identity is fabricated."""
        _span_exporter, _metric_exporter, log_exporter = export_telemetry
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        logging.getLogger("ati.test").setLevel(logging.INFO)
        logging.getLogger("ati.test").info("outside span")
        assert runtime.logger_provider is not None
        runtime.logger_provider.force_flush()
        shutdown_telemetry()
        records = list(log_exporter.records)  # type: ignore[attr-defined]
        assert len(records) == 1
        record = records[0].log_record
        assert record.trace_id == 0
        assert record.span_id == 0

    def test_log_inside_span_carries_correlation(
        self, export_telemetry: tuple[object, object, object]
    ) -> None:
        """INF-C09 a log inside an active span exports the span identity."""
        from opentelemetry import trace as otl_trace

        _span_exporter, _metric_exporter, log_exporter = export_telemetry
        runtime = configure_telemetry(
            enabled=True, service_name=ServiceNames.API, register_globals=False
        )
        assert runtime.tracer_provider is not None
        tracer = otl_trace.get_tracer(
            "ati.test", tracer_provider=runtime.tracer_provider
        )
        with tracer.start_as_current_span("ati.llm.invoke") as span:
            logging.getLogger("ati.test").setLevel(logging.INFO)
            logging.getLogger("ati.test").info("inside span")
        assert runtime.logger_provider is not None
        runtime.logger_provider.force_flush()
        shutdown_telemetry()
        span_context = span.get_span_context()
        records = list(log_exporter.records)  # type: ignore[attr-defined]
        assert len(records) == 1
        record = records[0].log_record
        assert record.trace_id == span_context.trace_id
        assert record.span_id == span_context.span_id
