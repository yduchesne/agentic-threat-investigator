# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the end-to-end Investigation target executor (PR 30F)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast
from uuid import UUID

import pytest

from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationTarget,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.common.evaluator import EvaluationContext
from agentic_threat_investigator.evaluation.investigation.fixtures import (
    InvestigationFixture,
    investigation_fixture,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationScenario,
    InvestigationScenarioResolution,
)
from agentic_threat_investigator.evaluation.investigation.target import (
    InvestigationScenarioLookup,
    InvestigationScenarioLookupError,
    InvestigationTargetError,
    InvestigationTargetExecutor,
)
from tests.unit.evaluation.investigation.helpers import scenario as build_scenario
from tests.unit.evaluation.investigation.output_fixtures import (
    INVESTIGATION_ID,
    RESEARCH_RESULT,
    ROOT_ID,
    terminal_state,
)
from tests.unit.evaluation.investigation.output_fixtures import (
    assessment as build_assessment,
)
from tests.unit.evaluation.investigation.output_fixtures import (
    report as build_report,
)

DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.INVESTIGATION, version=1)


class FakeRepositories:
    """Canned repository reads the fake UnitOfWork serves to the target."""

    def __init__(self, *, state: InvestigationState | None = None) -> None:
        """Bind the canned Investigation state and derived reads."""
        self.state = state or terminal_state()
        self.assessment: Assessment | None = build_assessment()
        self.report: InvestigationReport | None = build_report()
        self.metrics_calls = 0

    async def get_investigation(
        self, investigation_id: UUID
    ) -> InvestigationState | None:
        """Return the canned terminal Investigation state."""
        if investigation_id != self.state.investigation_id:
            return None
        return self.state

    async def get_assessment(self, assessment_id: UUID) -> Assessment | None:
        """Return the canned final Assessment."""
        return self.assessment if assessment_id == self.state.assessment_id else None

    async def get_report(self, report_id: UUID) -> InvestigationReport | None:
        """Return the canned persisted report."""
        return self.report if report_id == self.state.report_id else None


class FakeUoW:
    """Minimal async-context UnitOfWork double for executor tests."""

    def __init__(self, repos: FakeRepositories) -> None:
        """Bind the canned repositories."""
        self.repos = repos
        self.assessments = _AssessmentRepo(repos)
        self.investigations = _InvestigationRepo(repos)
        self.investigation_reports = _ReportRepo(repos)
        self.evidence = _EvidenceRepo(repos)
        self.entities = _EntityRepo(repos)
        self.relationships = _RelationshipRepo(repos)
        self.relationship_observations = _RelationshipObservationRepo(repos)
        self.research_results = _ResearchRepo(repos)
        self.timeline_events = _TimelineRepo(repos)

    async def __aenter__(self) -> "FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


class _AssessmentRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def get_by_id(self, assessment_id: UUID) -> Assessment | None:
        return await self._repos.get_assessment(assessment_id)


class _InvestigationRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def get_by_id(self, investigation_id: UUID) -> InvestigationState | None:
        return await self._repos.get_investigation(investigation_id)


class _ReportRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def get_by_id(self, report_id: UUID) -> InvestigationReport | None:
        return await self._repos.get_report(report_id)


class _EvidenceRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[object]:
        return []

    async def get_stable_evidence(self, evidence_id: UUID) -> object | None:
        return None


class _EntityRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def get_by_id(self, entity_id: UUID) -> object | None:
        return None


class _RelationshipRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def get_by_id(self, relationship_id: UUID) -> object | None:
        return None


class _RelationshipObservationRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def list_for_investigation(
        self, investigation_id: UUID, *, limit: int = 100, offset: int = 0
    ) -> list[object]:
        return []


class _ResearchRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def list_by_investigation(self, investigation_id: UUID) -> list[object]:
        return [RESEARCH_RESULT]


class _TimelineRepo:
    def __init__(self, repos: FakeRepositories) -> None:
        self._repos = repos

    async def list_by_investigation(self, investigation_id: UUID) -> list[object]:
        return []


class FakeWorld:
    """World double exposing the runner/writer/counting seams."""

    def __init__(
        self,
        *,
        runner: FakeRunner,
        writer: FakeWriter,
        counting: FakeCounting,
    ) -> None:
        """Bind the runner/writer doubles and the counting client."""
        self.runner = runner
        self.report_writer = writer
        self.counting = counting


class FakeRunner:
    """Runner double scripting one outcome per execution."""

    def __init__(self, outcome: object) -> None:
        """Bind the scripted terminal state or exception."""
        self.outcome = outcome
        self.investigation_ids: list[UUID] = []

    async def run(self, investigation_id: UUID) -> InvestigationState:
        """Record the invocation and return/raise the scripted outcome."""
        self.investigation_ids.append(investigation_id)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return cast(InvestigationState, self.outcome)


class FakeWriter:
    """Writer double scripting one report outcome per execution."""

    def __init__(self, outcome: object, *, llm_calls: int = 0) -> None:
        """Bind the scripted report/exception and the probe-call count."""
        self.outcome = outcome
        self.llm_calls = llm_calls
        self.investigation_ids: list[UUID] = []

    async def write(self, investigation_id: UUID) -> InvestigationReport:
        """Record the invocation and return/raise the scripted outcome."""
        self.investigation_ids.append(investigation_id)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return cast(InvestigationReport, self.outcome)


class FakeCounting:
    """Counting client double reporting the exact per-execution call count."""

    def __init__(self, calls: int) -> None:
        """Bind the exact model-call count."""
        self.calls = calls


class FakeMaterializer:
    """Materializer double recording calls and returning canned resolutions."""

    def __init__(
        self,
        resolution: InvestigationScenarioResolution | None = None,
        *,
        resolve_error: BaseException | None = None,
    ) -> None:
        """Bind the canned resolution and optional resolve error."""
        self.resolution = resolution
        self.resolve_error = resolve_error
        self.materialized: list[tuple[str, str]] = []

    async def materialize(
        self,
        scenario: InvestigationScenario,
        fixture: InvestigationFixture,
        uow_factory: Callable[[], object],
        *,
        execution_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Record one materialization and return the canned resolution."""
        del fixture, uow_factory
        self.materialized.append((scenario.id, str(execution_id)))
        if self.resolution is None:
            return InvestigationScenarioResolution(
                investigation_id=INVESTIGATION_ID,
                entity_ids={"root_domain": ROOT_ID},
            )
        return self.resolution

    async def resolve_persisted(
        self,
        scenario: InvestigationScenario,
        fixture: InvestigationFixture,
        uow_factory: Callable[[], object],
        *,
        investigation_id: UUID,
    ) -> InvestigationScenarioResolution:
        """Return the canned full resolution or raise the scripted error."""
        del scenario, fixture, uow_factory, investigation_id
        if self.resolve_error is not None:
            raise self.resolve_error
        if self.resolution is None:
            return InvestigationScenarioResolution(
                investigation_id=INVESTIGATION_ID,
                entity_ids={"root_domain": ROOT_ID},
            )
        return self.resolution


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


def build_executor(
    case: InvestigationScenario,
    *,
    runner_outcome: object,
    writer_outcome: object,
    materializer: FakeMaterializer | None = None,
    repos: FakeRepositories | None = None,
    llm_calls: int = 0,
) -> tuple[
    InvestigationTargetExecutor,
    FakeRunner,
    FakeWriter,
    FakeMaterializer,
    FakeRepositories,
]:
    """Build one executor bound to recording doubles."""
    lookup = InvestigationScenarioLookup((case,))
    materializer = materializer or FakeMaterializer(_resolution())
    repos = repos or FakeRepositories()
    fake_runner = FakeRunner(runner_outcome)
    fake_writer = FakeWriter(writer_outcome, llm_calls=llm_calls)
    counting = FakeCounting(llm_calls)

    def uow_factory() -> Any:
        return FakeUoW(repos)

    async def world_factory(
        provider_registry: object,
    ) -> FakeWorld:
        del provider_registry
        return FakeWorld(runner=fake_runner, writer=fake_writer, counting=counting)

    async def run_investigation(
        world: FakeWorld, investigation_id: UUID
    ) -> InvestigationState:
        return await world.runner.run(investigation_id)

    async def write_report(
        world: FakeWorld, investigation_id: UUID
    ) -> InvestigationReport:
        return await world.report_writer.write(investigation_id)

    executor = InvestigationTargetExecutor(
        scenario_lookup=lookup,
        uow_factory=uow_factory,
        llm_client=cast(Any, counting),
        materializer=materializer,  # type: ignore[arg-type]
        world_factory=world_factory,  # type: ignore[arg-type]
        run_investigation=run_investigation,  # type: ignore[arg-type]
        write_report=write_report,  # type: ignore[arg-type]
    )
    return executor, fake_runner, fake_writer, materializer, repos


async def _execute(
    executor: InvestigationTargetExecutor, case: InvestigationScenario
) -> InvestigationEvaluationOutput:
    """Execute one case through the bound executor."""
    common = evaluation_case_from(case)
    return await executor.execute(
        case=common,
        context=EvaluationContext(
            dataset_id=DATASET_ID.canonical,
            case_id=case.id,
        ),
    )


class TestScenarioLookup:
    """Exact typed scenario lookup contract (T01-T03)."""

    def test_exact_identity_resolves(self) -> None:
        """The exact (id, version) identity resolves to the typed scenario."""
        case = build_scenario()
        lookup = InvestigationScenarioLookup((case,))
        assert lookup.require(case.id, case.version) is case

    def test_unknown_case_fails_closed(self) -> None:
        """An unknown case identity fails closed."""
        case = build_scenario()
        lookup = InvestigationScenarioLookup((case,))
        with pytest.raises(InvestigationScenarioLookupError):
            lookup.require("no-such-case", 1)

    def test_duplicate_identity_rejected(self) -> None:
        """Duplicate scenario identities are rejected at construction."""
        case = build_scenario()
        with pytest.raises(InvestigationScenarioLookupError):
            InvestigationScenarioLookup((case, case))


class TestTargetExecution:
    """Target execution contract (T04-T15)."""

    pytestmark = [pytest.mark.asyncio]

    async def test_t04_production_runner_invoked_once(self) -> None:
        """The runner executes exactly once with the execution-scoped id."""
        case = build_scenario()
        executor, runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
        )
        result = await _execute(executor, case)
        assert len(runner.investigation_ids) == 1
        assert runner.investigation_ids[0] == INVESTIGATION_ID
        assert result.final_investigation.investigation_id == INVESTIGATION_ID

    async def test_t05_terminal_state_required(self) -> None:
        """A non-terminal runner outcome fails closed (ERROR via the runner)."""
        case = build_scenario()
        from agentic_threat_investigator.domain.investigation import (
            InvestigationStatus,
        )

        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(
                status=InvestigationStatus.RUNNING,
                stop_reason=None,
                assessment_id=None,
                report_id=None,
                entity_ids=(ROOT_ID,),
            ),
            writer_outcome=build_report(),
        )
        with pytest.raises(InvestigationTargetError):
            await _execute(executor, case)

    async def test_t06_final_assessment_required(self) -> None:
        """A missing final Assessment fails closed (ERROR via the runner)."""
        case = build_scenario()
        repos = FakeRepositories(state=terminal_state())
        repos.assessment = None
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
            repos=repos,
        )
        with pytest.raises(InvestigationTargetError):
            await _execute(executor, case)

    async def test_t07_report_written_after_terminal(self) -> None:
        """The Report Writer executes once against the same Investigation."""
        case = build_scenario()
        executor, _runner, writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
        )
        await _execute(executor, case)
        assert writer.investigation_ids == [INVESTIGATION_ID]

    async def test_t08_report_matches_durable_state(self) -> None:
        """A report whose identity disagrees with durable state fails closed."""
        case = build_scenario()
        repos = FakeRepositories(state=terminal_state())
        repos.report = build_report()
        from agentic_threat_investigator.domain.report import InvestigationReport

        mismatched = InvestigationReport(
            **{**build_report().model_dump(mode="python"), "id": UUID(int=999)}
        )
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=mismatched,
            repos=repos,
        )
        with pytest.raises(InvestigationTargetError):
            await _execute(executor, case)

    async def test_t09_metrics_captured_exactly(self) -> None:
        """The output carries bounded deterministic execution metrics."""
        case = build_scenario()
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
            llm_calls=6,
        )
        result = await _execute(executor, case)
        assert result.execution_metrics.llm_calls == 6
        assert result.execution_metrics.provider_calls == 4
        assert result.execution_metrics.report_calls == 1

    async def test_t10_runner_failure_is_error(self) -> None:
        """An unexpected runner failure propagates (ERROR via the runner)."""
        case = build_scenario()
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=RuntimeError("runner exploded"),
            writer_outcome=build_report(),
        )
        with pytest.raises(RuntimeError):
            await _execute(executor, case)

    async def test_t11_report_failure_is_error(self) -> None:
        """An unexpected Report Writer failure propagates (ERROR)."""
        case = build_scenario()
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=RuntimeError("writer exploded"),
        )
        with pytest.raises(RuntimeError):
            await _execute(executor, case)

    async def test_t12_cancellation_propagates(self) -> None:
        """Cancellation propagates unchanged through the target."""
        import asyncio

        case = build_scenario()

        async def cancelled_runner(world: object, investigation_id: UUID) -> object:
            del world, investigation_id
            raise asyncio.CancelledError()

        lookup = InvestigationScenarioLookup((case,))
        materializer = FakeMaterializer(_resolution())

        def uow_factory() -> Any:
            return FakeUoW(FakeRepositories())

        async def world_factory(provider_registry: object) -> FakeWorld:
            del provider_registry
            return FakeWorld(
                runner=FakeRunner(terminal_state()),
                writer=FakeWriter(build_report()),
                counting=FakeCounting(0),
            )

        executor = InvestigationTargetExecutor(
            scenario_lookup=lookup,
            uow_factory=uow_factory,
            llm_client=cast(Any, FakeCounting(0)),
            materializer=materializer,  # type: ignore[arg-type]
            world_factory=world_factory,  # type: ignore[arg-type]
            run_investigation=cancelled_runner,  # type: ignore[arg-type]
        )
        with pytest.raises(asyncio.CancelledError):
            await _execute(executor, case)

    async def test_t13_resolution_resolved_after_run(self) -> None:
        """The full persisted label resolution is captured in the output."""
        case = build_scenario()
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
        )
        result = await _execute(executor, case)
        assert result.resolution.investigation_id == INVESTIGATION_ID
        assert "resolved_ip" in result.resolution.entity_ids

    async def test_t14_resolution_failure_is_error(self) -> None:
        """A post-run label resolution failure propagates (ERROR)."""
        case = build_scenario()
        materializer = FakeMaterializer(
            _resolution(), resolve_error=RuntimeError("unresolved label")
        )
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
            materializer=materializer,
        )
        with pytest.raises(RuntimeError):
            await _execute(executor, case)

    async def test_t15_no_langsmith_in_output(self) -> None:
        """The output carries no LangSmith identity or raw content."""
        case = build_scenario()
        executor, _runner, _writer, _mat, _repos = build_executor(
            case,
            runner_outcome=terminal_state(),
            writer_outcome=build_report(),
        )
        result = await _execute(executor, case)
        assert "langsmith" not in result.model_dump(mode="json").__str__().lower()
        assert "api_key" not in result.model_dump(mode="json").__str__().lower()


@pytest.mark.asyncio
async def test_materializer_execution_ids_are_fresh() -> None:
    """Each execution receives a fresh execution identity (T14 isolation)."""
    case = build_scenario()
    materializer = FakeMaterializer(_resolution())
    resolution = await materializer.materialize(
        case,
        investigation_fixture(case.fixture),
        lambda: FakeUoW(FakeRepositories()),
        execution_id=UUID(int=7),
    )
    assert resolution.investigation_id == INVESTIGATION_ID
    assert materializer.materialized[-1][1] == "00000000-0000-0000-0000-000000000007"
