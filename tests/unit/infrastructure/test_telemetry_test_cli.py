# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 ``ati-telemetry-test`` CLI tests (T34-G10..G14 + refusals).

Proves the diagnostic generator's configuration/refusal contract
deterministically (no Collector, no backends, no network): the exact
``ati-telemetry-test`` service identity (G10), refusal when observability is
disabled (G11) or the standard OTLP endpoint is absent (G12), emission
failure still shutting telemetry down and returning non-zero (G13), success
shutting telemetry down exactly once (G14), the installed console-script
registration, and the signal-specific endpoint/header override refusals
(PR 34 Step 15).
"""

from __future__ import annotations

from importlib import metadata
from typing import Any

import pytest
from opentelemetry.sdk.environment_variables import (
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT,
    OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
)

import agentic_threat_investigator.cli as cli
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.telemetry.diagnostic import (
    TelemetryTestSignalSummary,
)
from agentic_threat_investigator.telemetry.setup import (
    SERVICE_NAMES,
    ServiceNames,
)

RUN_ID = "01234567-89ab-cdef-0123-456789abcdef"
_ENTRYPOINT_TARGET = "agentic_threat_investigator.cli:telemetry_test_main"


@pytest.fixture
def recording_telemetry_test_cli(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch the CLI telemetry seams and return recorded events/objects.

    ``_configure_logging`` is stubbed to a no-op so global Python logging is
    never mutated by CLI tests; ``configure_telemetry`` / ``shutdown_telemetry``
    and the emission call are replaced with recording doubles. ``get_settings``
    returns a fresh default ``Settings`` the test configures per case.
    """
    events: list[str] = []
    state: dict[str, Any] = {"shutdown_calls": 0}

    def _configure(*, enabled: bool, service_name: str, **_kwargs: object) -> object:
        """Record the composition arguments and return a sentinel runtime."""
        events.append(f"configure:{enabled}:{service_name}")
        return object()

    def _shutdown() -> None:
        """Record one shutdown invocation."""
        state["shutdown_calls"] += 1
        events.append("shutdown")

    def _emit(run_id: str, **_kwargs: object) -> TelemetryTestSignalSummary:
        """Return a bounded summary for the emitted run ID."""
        events.append(f"emit:{run_id}")
        return TelemetryTestSignalSummary(
            run_id=run_id,
            trace_id="t" * 32,
            root_span_id="r" * 16,
            child_span_id="c" * 16,
        )

    monkeypatch.setattr(cli, "_configure_logging", lambda: None)
    monkeypatch.setattr(cli, "configure_telemetry", _configure)
    monkeypatch.setattr(cli, "shutdown_telemetry", _shutdown)
    monkeypatch.setattr(cli, "emit_telemetry_test_signal", _emit)
    monkeypatch.setattr(
        cli, "get_settings", lambda: Settings(observability_enabled=True)
    )
    monkeypatch.setattr(cli, "otlp_endpoint", lambda: "http://otel-collector:4318")
    return {"events": events, "state": state}


def test_g10_service_identity_is_exact() -> None:
    """T34-G10 the diagnostic process carries the exact ATI service identity."""
    assert ServiceNames.TELEMETRY_TEST == "ati-telemetry-test"
    assert ServiceNames.TELEMETRY_TEST in SERVICE_NAMES


def test_entrypoint_registered_and_resolves() -> None:
    """The ati-telemetry-test console script is registered and resolves."""
    scripts = {
        entry.name: entry for entry in metadata.entry_points(group="console_scripts")
    }
    assert "ati-telemetry-test" in scripts
    assert scripts["ati-telemetry-test"].value == _ENTRYPOINT_TARGET
    assert scripts["ati-telemetry-test"].load() is cli.telemetry_test_main


def test_g11_observability_disabled_refuses(
    recording_telemetry_test_cli: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T34-G11 disabled observability refuses acceptance emission."""
    monkeypatch.setattr(
        cli, "get_settings", lambda: Settings(observability_enabled=False)
    )
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 2
    assert recording_telemetry_test_cli["events"] == []
    assert recording_telemetry_test_cli["state"]["shutdown_calls"] == 0


def test_g12_endpoint_absent_refuses(
    recording_telemetry_test_cli: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T34-G12 a blank OTLP endpoint refuses acceptance emission."""
    monkeypatch.setattr(cli, "otlp_endpoint", lambda: None)
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 2
    assert recording_telemetry_test_cli["events"] == []


@pytest.mark.parametrize(
    "override",
    [
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ],
)
def test_signal_specific_overrides_refuse(
    recording_telemetry_test_cli: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    """PR 34 Step 15: signal-specific endpoint/header overrides are refused."""
    monkeypatch.setenv(override, "http://bypass.invalid:4318")
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 2
    assert recording_telemetry_test_cli["events"] == []


@pytest.mark.parametrize(
    "override",
    [
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ],
)
def test_empty_but_set_overrides_are_refused(
    recording_telemetry_test_cli: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    """Empty-but-set overrides are refused (OTel prefers them over the endpoint).

    The pinned OTel exporters resolve signal-specific variables even when
    empty (``environ.get(key, default)`` returns ``""``), so a developer
    environment with ``OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=`` would silently
    redirect (or empty) the export URL. Refusing whenever the variable is
    set — set-at-all, not merely nonblank — is the safe contract.
    """
    monkeypatch.setenv(override, "")
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 2
    assert recording_telemetry_test_cli["events"] == []


def test_g14_success_shuts_down_exactly_once(
    recording_telemetry_test_cli: dict[str, Any],
) -> None:
    """T34-G14 successful emission runs configure -> emit -> shutdown once."""
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 0
    events = recording_telemetry_test_cli["events"]
    assert events == [
        f"configure:True:{ServiceNames.TELEMETRY_TEST}",
        f"emit:{RUN_ID}",
        "shutdown",
    ]
    assert recording_telemetry_test_cli["state"]["shutdown_calls"] == 1


def test_g13_emission_failure_returns_nonzero_after_shutdown(
    recording_telemetry_test_cli: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T34-G13 emission failure returns non-zero after shutdown ran once."""

    def _explode(run_id: str, **_kwargs: object) -> TelemetryTestSignalSummary:
        """Raise once emission begins."""
        raise RuntimeError("emission exploded")

    monkeypatch.setattr(cli, "emit_telemetry_test_signal", _explode)
    code = cli.telemetry_test_main(["--run-id", RUN_ID])
    assert code == 1
    events = recording_telemetry_test_cli["events"]
    assert events[-1] == "shutdown"
    assert recording_telemetry_test_cli["state"]["shutdown_calls"] == 1


def test_malformed_run_id_returns_bounded_failure(
    recording_telemetry_test_cli: dict[str, Any],
) -> None:
    """A malformed run ID returns a bounded non-zero failure before composition."""
    code = cli.telemetry_test_main(["--run-id", "not-a-uuid"])
    assert code == 2
    assert recording_telemetry_test_cli["events"] == []


def test_running_environment_refusal_uses_standard_otel_constants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned OTLP override constants match the standard OTel variable names."""
    assert cli._SIGNAL_SPECIFIC_ENDPOINT_VARIABLES == (
        OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
        OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT,
    )
    assert "OTEL_EXPORTER_OTLP_HEADERS" in cli._OTLP_HEADER_OVERRIDE_VARIABLES

    # End-to-end refusal against the real environment-variable constants.
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.setenv(
        cli._SIGNAL_SPECIFIC_ENDPOINT_VARIABLES[0],
        "http://bypass.invalid:4318",
    )
    refusals = cli._telemetry_test_refusals(
        Settings(),
        "http://otel-collector:4318",
    )
    assert any("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" in r for r in refusals)
