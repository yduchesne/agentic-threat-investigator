# SPDX-License-Identifier: AGPL-3.0-only
"""PR 29C worker/GEO process telemetry composition tests (INF-C10..C14).

Proves deterministically (no database, no Collector/backends, no network)
that ``worker_main`` and ``geo_resolver_main`` wire the canonical service
identities, that observability-disabled composition stays unchanged, and
that process-owned engines are disposed before ``shutdown_telemetry`` runs
on both normal and failure paths.
"""

from __future__ import annotations

from typing import Any

import pytest

import agentic_threat_investigator.cli as cli
from agentic_threat_investigator.config.settings import OperatingMode, Settings


class _FakeAsyncEngine:
    """Engine double recording the dispose call without any database."""

    def __init__(self) -> None:
        """Start with the disposal not yet observed."""
        self.dispose_calls = 0

    async def dispose(self) -> None:
        """Record one disposal."""
        self.dispose_calls += 1


class _FakeJobWorker:
    """InvestigationJobWorker double returning no work every round."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        """Accept the real constructor shape without composing anything."""

    async def claim_and_run_once(self) -> None:
        """Claim nothing so the loop reaches its sleep boundary."""


class _FakeGeoWorker:
    """GeoResolutionWorker double returning no work on every iteration."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        """Accept the real constructor shape without composing anything."""

    async def run_once(self) -> int:
        """Claim nothing so the loop reaches its sleep boundary."""
        return 0


def _interrupt_after(_delay: float) -> Any:
    """Raise KeyboardInterrupt from an awaited sleep double."""

    async def _raise() -> None:
        """Raise the interrupt once awaited."""
        raise KeyboardInterrupt

    return _raise()


@pytest.fixture
def recording_process_telemetry(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Patch the telemetry seams and return the recorded event list.

    ``configure_telemetry`` / ``shutdown_telemetry`` and the process-owned
    engine are replaced by recording doubles so tests observe the exact
    composition ordering without starting any provider or touching a
    database. ``_configure_logging`` is stubbed to a no-op so the global
    Python logging configuration is never mutated by CLI tests.
    """
    events: list[str] = []

    def _configure(*, enabled: bool, service_name: str, **_kwargs: object) -> None:
        """Record the telemetry composition arguments."""
        events.append(f"configure:{enabled}:{service_name}")

    def _shutdown() -> None:
        """Record the telemetry shutdown."""
        events.append("shutdown")

    def _noop() -> None:
        """Do nothing (logging configuration is not under test here)."""

    monkeypatch.setattr(cli, "_configure_logging", _noop)
    monkeypatch.setattr(cli, "configure_telemetry", _configure)
    monkeypatch.setattr(cli, "shutdown_telemetry", _shutdown)
    return events


def _settings(**overrides: Any) -> Settings:
    """Build fake-mode settings with the given overrides."""
    return Settings(operating_mode=OperatingMode.FAKE, **overrides)


def _patch_worker_composition(monkeypatch: pytest.MonkeyPatch) -> _FakeAsyncEngine:
    """Stub every worker composition seam and return the engine double."""
    engine = _FakeAsyncEngine()
    monkeypatch.setattr(cli, "_make_engine", lambda _settings: engine)

    async def _no_sources(*_args: object, **_kwargs: object) -> None:
        """Resolve the intelligence sources without any composition."""
        return

    monkeypatch.setattr(cli, "build_intelligence_sources", _no_sources)
    monkeypatch.setattr(cli, "_compose_llm", lambda _settings: None)
    monkeypatch.setattr(cli, "_compose_runner", lambda **k: None)
    monkeypatch.setattr(cli, "build_report_writer", lambda **k: None)
    monkeypatch.setattr(cli, "InvestigationJobWorker", _FakeJobWorker)
    return engine


def _patch_geo_composition(monkeypatch: pytest.MonkeyPatch) -> _FakeAsyncEngine:
    """Stub every GEO composition seam and return the engine double."""
    engine = _FakeAsyncEngine()
    monkeypatch.setattr(cli, "_make_engine", lambda _settings: engine)
    monkeypatch.setattr(cli, "_compose_geo_worker", lambda *a, **k: _FakeGeoWorker())
    return engine


class TestWorkerProcessTelemetry:
    """INF-C10/C12/C14 worker composition and teardown ordering."""

    def test_worker_disabled_observability_composes_no_providers(
        self, monkeypatch: pytest.MonkeyPatch, recording_process_telemetry: list[str]
    ) -> None:
        """INF-C10 disabled worker observability stays a no-op pipeline."""
        monkeypatch.setattr(
            cli, "get_settings", lambda: _settings(observability_enabled=False)
        )
        monkeypatch.setattr("asyncio.sleep", _interrupt_after)
        engine = _patch_worker_composition(monkeypatch)
        assert cli.worker_main(["--poll-seconds", "0.1"]) == 0
        assert engine.dispose_calls == 1
        assert recording_process_telemetry == [
            "configure:False:ati-worker",
            "shutdown",
        ]

    def test_worker_normal_exit_disposes_engine_before_telemetry_shutdown(
        self, monkeypatch: pytest.MonkeyPatch, recording_process_telemetry: list[str]
    ) -> None:
        """INF-C12 engine disposal precedes telemetry shutdown on exit."""
        monkeypatch.setattr(
            cli, "get_settings", lambda: _settings(observability_enabled=True)
        )
        monkeypatch.setattr("asyncio.sleep", _interrupt_after)
        engine = _patch_worker_composition(monkeypatch)
        assert cli.worker_main(["--poll-seconds", "0.1"]) == 0
        assert recording_process_telemetry == [
            "configure:True:ati-worker",
            "shutdown",
        ]
        assert engine.dispose_calls == 1

    def test_worker_failure_still_disposes_engine_then_telemetry(
        self, monkeypatch: pytest.MonkeyPatch, recording_process_telemetry: list[str]
    ) -> None:
        """INF-C14 failure path runs the teardown without masking the error."""
        monkeypatch.setattr(
            cli, "get_settings", lambda: _settings(observability_enabled=True)
        )
        engine = _patch_worker_composition(monkeypatch)

        def _fail(*_args: object, **_kwargs: object) -> Any:
            """Fail the intelligence-source composition step."""
            raise RuntimeError("sources failed")

        async def _fail_async(*_args: object, **_kwargs: object) -> Any:
            """Fail the awaited intelligence-source composition step."""
            raise RuntimeError("sources failed")

        monkeypatch.setattr(cli, "build_intelligence_sources", _fail_async)
        with pytest.raises(RuntimeError, match="sources failed"):
            cli.worker_main(["--poll-seconds", "0.1"])
        assert recording_process_telemetry == [
            "configure:True:ati-worker",
            "shutdown",
        ]
        assert engine.dispose_calls == 1


class TestGeoProcessTelemetry:
    """INF-C11/C13 GEO composition and teardown ordering."""

    def test_geo_disabled_returns_without_telemetry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_process_telemetry: list[str],
    ) -> None:
        """INF-C11 a resolver-disabled process creates no engine/pipeline."""
        monkeypatch.setattr(
            cli,
            "get_settings",
            lambda: _settings(observability_enabled=True, geo_resolver_enabled=False),
        )
        assert cli.geo_resolver_main(["--once"]) == 0
        assert recording_process_telemetry == []

    def test_geo_once_disposes_engine_before_telemetry_shutdown(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_process_telemetry: list[str],
    ) -> None:
        """INF-C13 engine disposal precedes telemetry shutdown on exit."""
        monkeypatch.setattr(
            cli,
            "get_settings",
            lambda: _settings(observability_enabled=True, geo_resolver_enabled=True),
        )
        engine = _patch_geo_composition(monkeypatch)
        assert cli.geo_resolver_main(["--once"]) == 0
        assert recording_process_telemetry == [
            "configure:True:ati-geo-resolver",
            "shutdown",
        ]
        assert engine.dispose_calls == 1

    def test_geo_failure_still_disposes_engine_then_telemetry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        recording_process_telemetry: list[str],
    ) -> None:
        """INF-C14 GEO failure path runs the teardown without masking the error."""
        monkeypatch.setattr(
            cli,
            "get_settings",
            lambda: _settings(observability_enabled=True, geo_resolver_enabled=True),
        )

        def _fail(*_args: object, **_kwargs: object) -> Any:
            """Fail the GEO worker composition step."""
            raise RuntimeError("geo worker failed")

        monkeypatch.setattr(cli, "_compose_geo_worker", _fail)
        with pytest.raises(RuntimeError, match="geo worker failed"):
            cli.geo_resolver_main(["--once"])
        assert recording_process_telemetry == [
            "configure:True:ati-geo-resolver",
            "shutdown",
        ]
