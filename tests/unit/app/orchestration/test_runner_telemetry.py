# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation execution telemetry tests (PR 29B, I1..I4).

Proves the ``ati.investigation.execute`` span/duration, the exact executed
counter (never for idempotent no-ops or lifecycle rejections), bounded
failures, cancellation propagation, and the absence of Investigation IDs on
metric labels.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID

import pytest
from opentelemetry.sdk.metrics.export import Metric

from agentic_threat_investigator.app.orchestration.runner import (
    InvestigationRunnerLifecycleError,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
)
from agentic_threat_investigator.telemetry.metrics import (
    DurationMetrics,
    Metrics,
)
from tests.support.otel import (
    counter_value,
    data_point_attributes,
    histogram_count,
    metrics_by_name,
)
from tests.unit.app.orchestration.test_runner import (
    INVESTIGATION_A,
    _AnalysisFactorySpy,
    _FakeGraph,
    _GraphFactorySpy,
    _runner,
    _state,
    _terminal_like,
    _UowTracker,
)


def _recorded(telemetry: SimpleNamespace) -> dict[str, Metric]:
    """Return recorded metrics indexed by name."""
    return metrics_by_name(telemetry.reader)


def _spans(telemetry: SimpleNamespace) -> list[object]:
    """Return finished span names from the in-memory exporter."""
    return [span.name for span in telemetry.exporter.get_finished_spans()]


class TestInvestigationTelemetry:
    """I1..I4: one actual runner execution is observable."""

    @pytest.mark.asyncio
    async def test_i1_success_one_execution(
        self,
        monkeypatch: pytest.MonkeyPatch,
        in_memory_persistence_telemetry: SimpleNamespace,
    ) -> None:
        """A RUNNING investigation executes once and counts one execution (I1)."""
        store: dict[UUID, InvestigationState] = {}

        async def handler(input: object, config: object) -> dict[str, object]:
            del config
            investigation = input["investigation"]  # type: ignore[index]
            terminal = _terminal_like(investigation)
            store[INVESTIGATION_A] = terminal
            return {"investigation": terminal}

        persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
        store[INVESTIGATION_A] = persisted
        tracker = _UowTracker()
        analysis_factory = _AnalysisFactorySpy()
        spy = _GraphFactorySpy(_FakeGraph(handler))
        monkeypatch.setattr(
            "agentic_threat_investigator.app.orchestration.runner"
            ".build_provider_investigation_graph",
            spy,
        )
        runner = _runner(store, tracker, analysis_factory)
        result = await runner.run(INVESTIGATION_A)
        assert result.status is not None
        spans = _spans(in_memory_persistence_telemetry)
        assert spans.count("ati.investigation.execute") == 1
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.INVESTIGATION_EXECUTED]) == 1
        assert Metrics.INVESTIGATION_EXECUTE_FAILURES not in recorded
        duration = recorded[DurationMetrics.INVESTIGATION_EXECUTE]
        assert histogram_count(duration) == 1
        assert data_point_attributes(duration)["ati.outcome"] == "success"

    @pytest.mark.asyncio
    async def test_i2_idempotent_terminal_noop_counts_nothing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        in_memory_persistence_telemetry: SimpleNamespace,
    ) -> None:
        """A terminal Investigation is a no-op and counts no execution (I2)."""
        persisted = _state(INVESTIGATION_A, status=InvestigationStatus.COMPLETED)
        store = {INVESTIGATION_A: persisted}
        tracker = _UowTracker()
        analysis_factory = _AnalysisFactorySpy()
        spy = _GraphFactorySpy(
            _FakeGraph(
                lambda _input, _config: (_ for _ in ()).throw(
                    AssertionError("graph must not run for a terminal investigation")
                )
            )
        )
        monkeypatch.setattr(
            "agentic_threat_investigator.app.orchestration.runner"
            ".build_provider_investigation_graph",
            spy,
        )
        runner = _runner(store, tracker, analysis_factory)
        result = await runner.run(INVESTIGATION_A)
        assert result == persisted
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.INVESTIGATION_EXECUTED not in recorded
        assert Metrics.INVESTIGATION_EXECUTE_FAILURES not in recorded

    @pytest.mark.asyncio
    async def test_i3_failure_counts_bounded_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        in_memory_persistence_telemetry: SimpleNamespace,
    ) -> None:
        """A lifecycle rejection counts a failure and preserves the typed error (I3)."""
        persisted = _state(INVESTIGATION_A, status=InvestigationStatus.PENDING)
        store = {INVESTIGATION_A: persisted}
        tracker = _UowTracker()
        analysis_factory = _AnalysisFactorySpy()
        spy = _GraphFactorySpy(
            _FakeGraph(
                lambda _input, _config: (_ for _ in ()).throw(
                    AssertionError("graph must not run for a pending investigation")
                )
            )
        )
        monkeypatch.setattr(
            "agentic_threat_investigator.app.orchestration.runner"
            ".build_provider_investigation_graph",
            spy,
        )
        runner = _runner(store, tracker, analysis_factory)
        with pytest.raises(InvestigationRunnerLifecycleError):
            await runner.run(INVESTIGATION_A)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert counter_value(recorded[Metrics.INVESTIGATION_EXECUTE_FAILURES]) == 1
        assert Metrics.INVESTIGATION_EXECUTED not in recorded

    @pytest.mark.asyncio
    async def test_i4_investigation_id_absent_from_labels(
        self,
        monkeypatch: pytest.MonkeyPatch,
        in_memory_persistence_telemetry: SimpleNamespace,
    ) -> None:
        """No Investigation ID ever appears as a metric label (I4)."""
        store: dict[UUID, InvestigationState] = {}

        async def handler(input: object, config: object) -> dict[str, object]:
            del config
            investigation = input["investigation"]  # type: ignore[index]
            terminal = _terminal_like(investigation)
            store[INVESTIGATION_A] = terminal
            return {"investigation": terminal}

        persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
        store[INVESTIGATION_A] = persisted
        tracker = _UowTracker()
        analysis_factory = _AnalysisFactorySpy()
        spy = _GraphFactorySpy(_FakeGraph(handler))
        monkeypatch.setattr(
            "agentic_threat_investigator.app.orchestration.runner"
            ".build_provider_investigation_graph",
            spy,
        )
        runner = _runner(store, tracker, analysis_factory)
        await runner.run(INVESTIGATION_A)
        recorded = _recorded(in_memory_persistence_telemetry)
        for metric in recorded.values():
            for point in metric.data.data_points:
                for key, value in dict(point.attributes or {}).items():
                    assert "investigation" not in key
                    assert str(INVESTIGATION_A) not in str(value)

    @pytest.mark.asyncio
    async def test_i5_cancellation_propagates(
        self,
        monkeypatch: pytest.MonkeyPatch,
        in_memory_persistence_telemetry: SimpleNamespace,
    ) -> None:
        """Cancellation propagates unchanged with no failure telemetry (I3)."""
        persisted = _state(INVESTIGATION_A, status=InvestigationStatus.RUNNING)
        store = {INVESTIGATION_A: persisted}
        tracker = _UowTracker()
        analysis_factory = _AnalysisFactorySpy()

        async def _cancel(_input: object, _config: object) -> dict[str, object]:
            del _input, _config
            raise asyncio.CancelledError()

        spy = _GraphFactorySpy(_FakeGraph(_cancel))
        monkeypatch.setattr(
            "agentic_threat_investigator.app.orchestration.runner"
            ".build_provider_investigation_graph",
            spy,
        )
        runner = _runner(store, tracker, analysis_factory)
        with pytest.raises(asyncio.CancelledError):
            await runner.run(INVESTIGATION_A)
        recorded = _recorded(in_memory_persistence_telemetry)
        assert Metrics.INVESTIGATION_EXECUTE_FAILURES not in recorded
