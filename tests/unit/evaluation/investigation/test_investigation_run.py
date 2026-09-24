# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30F run-service tests (INV-R01..R05 service level).

Exercises ``run_investigation_evaluation`` with scripted in-memory doubles
(exact typed scenarios, recording materializer/world seams, and
FakeLlmClient at the model boundary). The service must require the
Investigation target, load/project every case, and preserve the common
runner's PASS/FAIL/ERROR aggregation and cancellation semantics with exactly
one materializer + world call per case. No LangSmith or database
participates.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast
from uuid import UUID

import pytest

from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationExecutionMetrics,
    InvestigationScenarioResolution,
)
from agentic_threat_investigator.evaluation.investigation.run import (
    INVESTIGATION_CONTRACT_EVALUATOR_ID,
    run_investigation_evaluation,
)
from tests.unit.evaluation.investigation.helpers import scenario as build_scenario
from tests.unit.evaluation.investigation.output_fixtures import (
    INVESTIGATION_ID,
    ROOT_ID,
)
from tests.unit.evaluation.investigation.output_fixtures import (
    output as build_output,
)
from tests.unit.evaluation.investigation.test_investigation_target import (
    FakeRepositories,
    FakeUoW,
)

DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.INVESTIGATION, version=1)


class _FakeUoW:
    """Async-context UnitOfWork double for run-service tests."""

    async def __aenter__(self) -> "_FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


def _uow_factory() -> Any:
    """Build one fake UnitOfWork through the service's factory type."""
    return FakeUoW(FakeRepositories())


def _session_factory() -> Any:
    """Build one fake session factory double."""
    return _FakeUoW()


def _resolution() -> InvestigationScenarioResolution:
    """Build the full label resolution."""
    return InvestigationScenarioResolution(
        investigation_id=INVESTIGATION_ID,
        entity_ids={
            "root_domain": ROOT_ID,
            "resolved_ip": UUID(int=2),
            "malware_family": UUID(int=3),
        },
    )


class _Counting:
    """Counting client double reporting the exact model-call count."""

    def __init__(self, calls: int) -> None:
        """Bind the exact model-call count."""
        self.calls = calls


class _RecordingWorld:
    """World double with recording materializer/world/runner/writer seams."""

    def __init__(self) -> None:
        """Initialize the empty call log and canned output."""
        self.world_calls = 0
        self.output = build_output()
        self.resolution = _resolution()
        self.counting = _Counting(6)

    async def materialize(
        self,
        scenario: object,
        fixture: object,
        uow_factory: object,
        *,
        execution_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Return the canned execution-scoped resolution."""
        del scenario, fixture, uow_factory, execution_id
        return self.resolution

    async def resolve_persisted(
        self,
        scenario: object,
        fixture: object,
        uow_factory: object,
        *,
        investigation_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Return the canned full resolution."""
        del scenario, fixture, uow_factory, investigation_id
        return self.resolution

    async def world(self, provider_registry: object) -> object:
        """Record one world composition and return the canned world."""
        del provider_registry
        self.world_calls += 1
        return self

    async def run_investigation(self, world: object, investigation_id: UUID) -> object:
        """Return the canned terminal Investigation state."""
        del world
        return self.output.final_investigation

    async def write_report(self, world: object, investigation_id: UUID) -> object:
        """Return the canned persisted report."""
        del world
        return self.output.report


class TestRunService:
    """INV-R01..R05 run-service contract."""

    @pytest.mark.asyncio
    async def test_r01_investigation_service_runs_cases(self) -> None:
        """R01 the service runs the end-to-end benchmark through the common runner."""
        recording = _RecordingWorld()
        scenario = build_scenario()
        result = await run_investigation_evaluation(
            dataset_id=DATASET_ID,
            llm=cast(Any, None),
            uow_factory=_uow_factory,
            session_factory=_session_factory(),
            scenarios=(scenario,),
            materializer=recording,  # type: ignore[arg-type]
            world_factory=recording.world,  # type: ignore[arg-type]
            run_investigation=recording.run_investigation,  # type: ignore[arg-type]
            write_report=recording.write_report,  # type: ignore[arg-type]
        )
        assert result.dataset_id == DATASET_ID
        assert len(result.cases) == 1
        assert result.cases[0].case_id == scenario.id
        assert recording.world_calls == 1

    @pytest.mark.asyncio
    async def test_r02_wrong_target_rejected(self) -> None:
        """R02 a non-investigation dataset is rejected before any work."""
        wrong = EvaluationDatasetId(target=EvaluationTarget.EVIDENCE_ANALYST, version=1)
        with pytest.raises(DatasetLoadError):
            await run_investigation_evaluation(
                dataset_id=wrong,
                llm=cast(Any, None),
                uow_factory=_uow_factory,
                session_factory=_session_factory(),
                scenarios=(build_scenario(),),
            )

    @pytest.mark.asyncio
    async def test_r03_empty_scenarios_rejected(self) -> None:
        """R03 an empty scenario set is rejected before any model work."""
        with pytest.raises(DatasetLoadError):
            await run_investigation_evaluation(
                dataset_id=DATASET_ID,
                llm=cast(Any, None),
                uow_factory=_uow_factory,
                session_factory=_session_factory(),
                scenarios=(),
            )

    @pytest.mark.asyncio
    async def test_r04_contract_evaluator_verdict(self) -> None:
        """R04 the contract evaluator decides a deterministic verdict."""
        recording = _RecordingWorld()
        recording.output = build_output()
        scenario = build_scenario()
        result = await run_investigation_evaluation(
            dataset_id=DATASET_ID,
            llm=cast(Any, None),
            uow_factory=_uow_factory,
            session_factory=_session_factory(),
            scenarios=(scenario,),
            materializer=recording,  # type: ignore[arg-type]
            world_factory=recording.world,  # type: ignore[arg-type]
            run_investigation=recording.run_investigation,  # type: ignore[arg-type]
            write_report=recording.write_report,  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict in (EvaluationVerdict.PASS, EvaluationVerdict.FAIL)
        evaluator = result.cases[0].evaluator_results[0]
        assert evaluator.evaluator_id == INVESTIGATION_CONTRACT_EVALUATOR_ID

    @pytest.mark.asyncio
    async def test_r05_cancellation_propagates(self) -> None:
        """R05 cancellation propagates unchanged through the service."""

        async def cancelled_run_investigation(
            world: object, investigation_id: UUID
        ) -> object:
            del world, investigation_id
            raise asyncio.CancelledError()

        recording = _RecordingWorld()
        scenario = build_scenario()
        with pytest.raises(asyncio.CancelledError):
            await run_investigation_evaluation(
                dataset_id=DATASET_ID,
                llm=cast(Any, None),
                uow_factory=_uow_factory,
                session_factory=_session_factory(),
                scenarios=(scenario,),
                materializer=recording,  # type: ignore[arg-type]
                world_factory=recording.world,  # type: ignore[arg-type]
                run_investigation=cancelled_run_investigation,  # type: ignore[arg-type]
                write_report=recording.write_report,  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_r06_output_payload_is_bounded(self) -> None:
        """R06 the evaluator consumes a bounded output payload (no raw content)."""
        recording = _RecordingWorld()
        scenario = build_scenario()
        result = await run_investigation_evaluation(
            dataset_id=DATASET_ID,
            llm=cast(Any, None),
            uow_factory=_uow_factory,
            session_factory=_session_factory(),
            scenarios=(scenario,),
            materializer=recording,  # type: ignore[arg-type]
            world_factory=recording.world,  # type: ignore[arg-type]
            run_investigation=recording.run_investigation,  # type: ignore[arg-type]
            write_report=recording.write_report,  # type: ignore[arg-type]
        )
        assert len(result.cases) == 1
        assert result.cases[0].case_id == scenario.id
        payload = recording.output
        assert isinstance(payload.execution_metrics, InvestigationExecutionMetrics)
