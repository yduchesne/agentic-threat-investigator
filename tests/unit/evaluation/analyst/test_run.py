# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C run-service tests (EA-R01..R06/R13/R14).

Exercises ``run_evidence_analyst_evaluation`` with scripted in-memory doubles
(exact typed scenarios, a recording materializer, and a recording fake
analyst). The service must load/project every case, reject non-analyst
datasets, and preserve the common runner's PASS/FAIL/ERROR aggregation and
cancellation semantics with exactly one materializer + analyst call per case.
No LangSmith, LLM, or database participates.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.assessment import Assessment, Verdict
from agentic_threat_investigator.evaluation.analyst.materializer import (
    AnalystScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.analyst.models import AnalystScenario
from agentic_threat_investigator.evaluation.analyst.run import (
    run_evidence_analyst_evaluation,
)
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationTarget,
    EvaluationVerdict,
)
from tests.support.evaluation_fixtures import (
    unit_assessment,
    unit_resolution,
    unit_scenario,
)


class _FakeUoW:
    """Async-context UnitOfWork double for run-service tests."""

    async def __aenter__(self) -> "_FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


class _RecordingMaterializer:
    """Materializer double recording the exact scenarios it is asked to reuse."""

    def __init__(self) -> None:
        """Initialize the empty call log."""
        self.calls: list[UUID] = []

    def investigation_id(self, scenario: AnalystScenario) -> UUID:
        """Record and return the deterministic investigation identity."""
        identity = AnalystScenarioMaterializer().investigation_id(scenario)
        self.calls.append(identity)
        return identity

    async def materialize_or_reuse(
        self, uow: object, scenario: AnalystScenario
    ) -> object:
        """Record one materialization/reuse request and return the unit resolution."""
        assert uow is not None
        return unit_resolution(scenario)


class _FakeAnalyst:
    """EvidenceAnalyst double scripting one persisted Assessment per case."""

    def __init__(
        self,
        *,
        assessments: dict[str, Assessment] | None = None,
        fail_for: frozenset[str] = frozenset(),
    ) -> None:
        """Bind the per-case Assessment script, failure set, and call log."""
        self.assessments = assessments or {}
        self.fail_for = fail_for
        self.calls: list[UUID] = []
        self._markers: list[tuple[str, UUID]] = []

    async def analyze(self, investigation_id: UUID) -> Assessment:
        """Record the call and return the scripted Assessment or raise."""
        self.calls.append(investigation_id)
        scenario_id = next(
            (
                marker
                for marker, identity in self._markers
                if identity == investigation_id
            ),
            "",
        )
        if scenario_id in self.fail_for:
            raise RuntimeError("analysis failed")
        return self.assessments.get(scenario_id, unit_assessment())

    def wire(self, scenarios: tuple[AnalystScenario, ...]) -> None:
        """Precompute the scenario marker -> investigation identity mapping."""
        real = AnalystScenarioMaterializer()
        self._markers = [
            (scenario.id, real.investigation_id(scenario)) for scenario in scenarios
        ]


def _scenarios(count: int = 8) -> tuple[AnalystScenario, ...]:
    """Build ``count`` distinct typed unit scenarios."""
    return tuple(
        unit_scenario().model_copy(update={"id": f"unit_scenario_{index}"})
        for index in range(1, count + 1)
    )


def _dataset() -> EvaluationDatasetId:
    """Return the canonical evidence-analyst unit dataset identity."""
    return EvaluationDatasetId(target=EvaluationTarget.EVIDENCE_ANALYST, version=1)


def _uow_factory() -> Callable[[], UnitOfWork]:
    """Return a fake UnitOfWork factory through the service's type."""
    return lambda: cast(UnitOfWork, _FakeUoW())


@pytest.mark.asyncio
async def test_r01_all_cases_supplied_to_runner() -> None:
    """R01 every loaded typed scenario is projected and executed."""
    scenarios = _scenarios()
    analyst = _FakeAnalyst()
    analyst.wire(scenarios)
    result = await run_evidence_analyst_evaluation(
        dataset_id=_dataset(),
        analyst=analyst,  # type: ignore[arg-type]
        uow_factory=_uow_factory(),
        scenarios=scenarios,
        materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
    )
    assert [case.case_id for case in result.cases] == [
        scenario.id for scenario in scenarios
    ]
    assert len(analyst.calls) == len(scenarios)


@pytest.mark.asyncio
async def test_r02_non_analyst_dataset_rejected() -> None:
    """R02 a non-evidence-analyst dataset is rejected before any execution."""
    analyst = _FakeAnalyst()
    coordinator = EvaluationDatasetId(target=EvaluationTarget.COORDINATOR, version=1)
    with pytest.raises(DatasetLoadError):
        await run_evidence_analyst_evaluation(
            dataset_id=coordinator,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory(),
            scenarios=_scenarios(1),
            materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
        )
    assert analyst.calls == []


@pytest.mark.asyncio
async def test_r03_all_pass_is_dataset_pass() -> None:
    """R03 every passing case aggregates to COMPLETED/PASS."""
    scenarios = _scenarios()
    analyst = _FakeAnalyst()
    analyst.wire(scenarios)
    result = await run_evidence_analyst_evaluation(
        dataset_id=_dataset(),
        analyst=analyst,  # type: ignore[arg-type]
        uow_factory=_uow_factory(),
        scenarios=scenarios,
        materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.PASS


@pytest.mark.asyncio
async def test_r04_one_fail_is_dataset_fail() -> None:
    """R04 one behavioral FAIL aggregates the dataset to COMPLETED/FAIL."""
    scenarios = _scenarios()
    analyst = _FakeAnalyst(
        assessments={scenarios[0].id: unit_assessment(verdict=Verdict.SUSPICIOUS)}
    )
    analyst.wire(scenarios)
    result = await run_evidence_analyst_evaluation(
        dataset_id=_dataset(),
        analyst=analyst,  # type: ignore[arg-type]
        uow_factory=_uow_factory(),
        scenarios=scenarios,
        materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
    )
    assert result.execution_status is EvaluationExecutionStatus.COMPLETED
    assert result.verdict is EvaluationVerdict.FAIL
    failed = [case for case in result.cases if case.verdict is EvaluationVerdict.FAIL]
    assert [case.case_id for case in failed] == [scenarios[0].id]


@pytest.mark.asyncio
async def test_r05_one_error_takes_dataset_error_precedence() -> None:
    """R05 one ERROR case makes the dataset ERROR regardless of other PASSes."""
    scenarios = _scenarios()
    analyst = _FakeAnalyst(fail_for=frozenset({scenarios[3].id}))
    analyst.wire(scenarios)
    result = await run_evidence_analyst_evaluation(
        dataset_id=_dataset(),
        analyst=analyst,  # type: ignore[arg-type]
        uow_factory=_uow_factory(),
        scenarios=scenarios,
        materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
    )
    assert result.execution_status is EvaluationExecutionStatus.ERROR
    assert result.verdict is None
    errored = [
        case
        for case in result.cases
        if case.execution_status is EvaluationExecutionStatus.ERROR
    ]
    assert [case.case_id for case in errored] == [scenarios[3].id]


@pytest.mark.asyncio
async def test_r06_run_module_has_no_langsmith_dependency() -> None:
    """R06 the run service composes no LangSmith client or import."""
    from agentic_threat_investigator.evaluation.analyst import run as run_module

    source = inspect.getsource(run_module)
    assert "from langsmith" not in source
    assert "import langsmith" not in source
    assert "LangSmithEvaluationClient" not in source


@pytest.mark.asyncio
async def test_r13_cancellation_propagates() -> None:
    """R13 asyncio.CancelledError propagates unchanged through the service."""

    class CancellingAnalyst:
        """Analyst double raising cancellation from analyze."""

        async def analyze(self, investigation_id: UUID) -> object:
            """Raise cancellation."""
            del investigation_id
            raise asyncio.CancelledError("cancelled")

    with pytest.raises(asyncio.CancelledError):
        await run_evidence_analyst_evaluation(
            dataset_id=_dataset(),
            analyst=CancellingAnalyst(),  # type: ignore[arg-type]
            uow_factory=_uow_factory(),
            scenarios=_scenarios(1),
            materializer=_RecordingMaterializer(),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_r14_exactly_one_execution_per_case() -> None:
    """R14 each case materializes and invokes the analyst exactly once."""
    scenarios = _scenarios(3)
    materializer = _RecordingMaterializer()
    analyst = _FakeAnalyst()
    analyst.wire(scenarios)
    result = await run_evidence_analyst_evaluation(
        dataset_id=_dataset(),
        analyst=analyst,  # type: ignore[arg-type]
        uow_factory=_uow_factory(),
        scenarios=scenarios,
        materializer=materializer,  # type: ignore[arg-type]
    )
    assert len(result.cases) == 3
    assert sorted(analyst.calls) == sorted(materializer.calls)
    assert len(set(analyst.calls)) == 3
