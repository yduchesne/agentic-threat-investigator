# SPDX-License-Identifier: AGPL-3.0-only
"""Telemetry setup, service identity, and idempotency tests (PR 29A)."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.resources import SERVICE_NAME

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
