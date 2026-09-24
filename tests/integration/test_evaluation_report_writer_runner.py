# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E Report Writer evaluation vertical slice (real PostgreSQL).

Executes the full PR 30E target pipeline against real PostgreSQL:

.. code-block:: text

    real report-writer JSON scenarios
     -> strict typed loader
     -> repository-owned fixture + materializer (run-scoped execution identity)
     -> AssessmentPersistenceService / ResearchResultPersistenceService
     -> ReportWriterInputLoader
     -> real ReportWriter
     -> FakeLlmClient exactly at the model boundary
     -> real assembly + ReportProvenanceValidator
     -> InvestigationReportPersistenceService
     -> actual persisted report / declared no-report outcome
     -> existing ReportWriterEvaluator through the PR 30 adapter
     -> common EvaluationRunner

Covers S01..S08 (five PASS, three declared no-report PASS through real
production rejection paths), a runtime-valid-but-scenario-wrong behavioral
FAIL, an unexpected ERROR, and cancellation propagation. Asserts
persistence, run-scoped isolation, canonical Entity reuse, Assessment
authority, research claim/citation identities, and that expected no-report
outcomes never persist a report or advance the pointer. No live LLM or
LangSmith participates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel
from sqlalchemy import text

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.domain.report import (
    ReportResearchSelection,
    ReportWriterOutput,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunResult,
    EvaluationTarget,
    EvaluationVerdict,
)
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    ReportWriterFixture,
    ReportWriterScenarioMaterializer,
    build_canonical_report_output,
    build_fixture_assessment,
)
from agentic_threat_investigator.evaluation.report_writer.loader import (
    load_report_writer_scenarios_directory,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.run import (
    run_report_writer_evaluation,
)
from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    report_writer_fixture,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

SCENARIOS_DIRECTORY = Path("evals/scenarios/report_writer")

DATASET_ID = EvaluationDatasetId(target=EvaluationTarget.REPORT_WRITER, version=1)

UOW_FACTORY = Callable[[], PostgresUnitOfWork]

S01 = "rpt-s01-clearly-malicious"
S02 = "rpt-s02-inconclusive-sparse"
S03 = "rpt-s03-conflicting-evidence"
S04 = "rpt-s04-research-is-context"
S05 = "rpt-s05-no-research"
S06 = "rpt-s06-unsupported-reference"
S07 = "rpt-s07-verdict-override-attempt"
S08 = "rpt-s08-stale-assessment-race"

ResponseT = TypeVar("ResponseT", bound=BaseModel)


@pytest.fixture(scope="session")
def scenarios() -> tuple[ReportWriterScenario, ...]:
    """Load the committed report-writer scenario corpus once."""
    return load_report_writer_scenarios_directory(SCENARIOS_DIRECTORY)


def _scenario(
    scenarios: tuple[ReportWriterScenario, ...], scenario_id: str
) -> ReportWriterScenario:
    """Return one exact typed scenario from the corpus."""
    return next(scenario for scenario in scenarios if scenario.id == scenario_id)


class MaterializeOnceMaterializer:
    """Deterministic materializer seam for the vertical slice.

    Materializes one known execution world exactly once and returns the same
    execution-scoped resolution afterwards, so the test can script fake model
    outputs against the exact persisted identities without duplicate-creation
    conflicts. Production evaluation never uses this seam.
    """

    def __init__(self, uow_factory: UOW_FACTORY, *, execution_id: UUID) -> None:
        """Bind the real materializer and one fixed execution identity."""
        self._uow_factory = uow_factory
        self._execution_id = execution_id
        self._resolutions: dict[str, ReportWriterScenarioResolution] = {}

    async def materialize(
        self,
        scenario: ReportWriterScenario,
        fixture: ReportWriterFixture,
        *,
        execution_id: UUID | None = None,
    ) -> ReportWriterScenarioResolution:
        """Materialize once per scenario and return the cached resolution."""
        del execution_id
        if scenario.id not in self._resolutions:
            self._resolutions[scenario.id] = await ReportWriterScenarioMaterializer(
                self._uow_factory
            ).materialize(
                scenario,
                fixture,
                execution_id=self._execution_id,
            )
        return self._resolutions[scenario.id]

    def resolution(
        self, scenario: ReportWriterScenario
    ) -> ReportWriterScenarioResolution:
        """Return the cached resolution of one materialized scenario."""
        return self._resolutions[scenario.id]


async def _run_case(
    uow_factory: UOW_FACTORY,
    llm: LlmClient,
    scenario: ReportWriterScenario,
    materializer: MaterializeOnceMaterializer,
) -> EvaluationRunResult:
    """Run one scenario through the full PR 30E pipeline."""
    return await run_report_writer_evaluation(
        dataset_id=DATASET_ID,
        llm=llm,
        uow_factory=uow_factory,
        scenarios=(scenario,),
        materializer=materializer,  # type: ignore[arg-type]  # double implements the used surface
    )


async def _investigation_by_objective(uow_factory: UOW_FACTORY, objective: str) -> UUID:
    """Return the latest Investigation created for a fixture objective."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text(
                "SELECT id FROM ati.investigation "
                "WHERE objective = :objective ORDER BY started_at"
            ),
            {"objective": objective},
        )
        rows = result.scalars().all()
    assert rows, "no investigation found for fixture objective"
    return UUID(str(rows[-1]))


async def _report_rows(uow_factory: UOW_FACTORY, investigation_id: UUID) -> int:
    """Count durable report rows for one Investigation."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.investigation_report "
                "WHERE investigation_id = :id"
            ),
            {"id": investigation_id},
        )
        return int(result.scalar_one())


async def _report_history_rows(uow_factory: UOW_FACTORY, investigation_id: UUID) -> int:
    """Count report domain-history rows for one Investigation."""
    async with uow_factory() as uow:
        assert uow.session is not None
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'investigation_report' "
                "AND investigation_id = :id"
            ),
            {"id": investigation_id},
        )
        return int(result.scalar_one())


async def _current_state(
    uow_factory: UOW_FACTORY, investigation_id: UUID
) -> InvestigationState:
    """Return the durable InvestigationState of one Investigation."""
    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
    assert state is not None
    return state


def canonical_output(
    scenario: ReportWriterScenario,
    resolution: ReportWriterScenarioResolution,
) -> ReportWriterOutput:
    """Build the deterministic output satisfying one scenario envelope."""
    return build_canonical_report_output(
        scenario,
        resolution,
        report_writer_fixture(scenario.fixture),
    )


def unsupported_reference_output() -> ReportWriterOutput:
    """Build a schema-valid output carrying an unsupported research reference."""
    return ReportWriterOutput(
        title="Unsupported reference attempt",
        executive_summary=(),
        finding_order=(),
        research_context=(
            ReportResearchSelection(
                research_result_id=uuid4(),
                research_claim_id=uuid4(),
            ),
        ),
    )


def empty_output() -> ReportWriterOutput:
    """Build a runtime-valid output that violates the scenario envelope."""
    return ReportWriterOutput(title="Canonical report")


class RacingFakeLlmClient(FakeLlmClient):
    """FakeLlmClient that advances the Assessment before returning output.

    The race injection is a transparent wrapper: input loading has already
    materialized Assessment A, the Investigation advances to Assessment B
    before the model output is returned, and the real report persistence
    revalidates the stale generation under lock.
    """

    def __init__(self, advance: Callable[[], Awaitable[None]]) -> None:
        """Bind the async advance hook."""
        super().__init__()
        self._advance = advance

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Advance the Assessment, then return the scripted output unchanged."""
        del system_prompt, user_prompt, operation_name
        await self._advance()
        return await super().generate_structured(
            system_prompt="",
            user_prompt="",
            response_model=response_model,
            operation_name="",
        )


class TestNormalExecution:
    """I01..I05: S01..S05 execute and PASS on the actual persisted report."""

    @pytest.mark.parametrize("scenario_id", [S01, S02, S03, S04, S05])
    async def test_pass_cases(
        self,
        uow_factory: UOW_FACTORY,
        scenarios: tuple[ReportWriterScenario, ...],
        scenario_id: str,
    ) -> None:
        """I01..I05 each PASS case persists exactly one report and advances the pointer."""
        scenario = _scenario(scenarios, scenario_id)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        # The output is derived from the exact persisted world lazily, once
        # the executor has materialized it (before the LLM boundary fires).
        llm.set_response_factory(
            lambda _call: canonical_output(scenario, materializer.resolution(scenario))
        )

        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        case = result.cases[0]
        assert case.verdict is EvaluationVerdict.PASS, case.evaluator_results
        fixture = report_writer_fixture(scenario.fixture)
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        # Exactly one report persisted and the pointer advanced to it.
        assert await _report_rows(uow_factory, investigation_id) == 1
        state = await _current_state(uow_factory, investigation_id)
        assert state.report_id is not None
        # Verdict/confidence/assessment authority preserved.
        assert state.assessment_id is not None
        async with uow_factory() as uow:
            assessment = await uow.assessments.get_by_id(state.assessment_id)
            report = await uow.investigation_reports.get_by_id(state.report_id)
        assert assessment is not None and report is not None
        assert report.verdict is assessment.verdict
        assert report.confidence is assessment.confidence
        assert report.assessment_id == assessment.id
        assert report.investigation_id == investigation_id
        # Exact model attempts for the current execution.
        assert len(llm.calls) == 1


class TestExpectedNoReport:
    """I06..I08: declared no-report outcomes exercise real production rejection."""

    async def test_i06_unsupported_reference_rejected(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I06 the real provenance boundary rejects an unsupported reference."""
        scenario = _scenario(scenarios, S06)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        llm.set_default(unsupported_reference_output())
        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        fixture = report_writer_fixture(scenario.fixture)
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        # No report row, no report history, no pointer advancement.
        assert await _report_rows(uow_factory, investigation_id) == 0
        assert await _report_history_rows(uow_factory, investigation_id) == 0
        state = await _current_state(uow_factory, investigation_id)
        assert state.report_id is None
        assert len(llm.calls) == 1

    async def test_i07_invalid_structured_output_exhaustion(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I07 real structured-output repair exhaustion yields the typed code."""
        scenario = _scenario(scenarios, S07)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        # Both attempts are schema-invalid; the second exhausts the budget.
        llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
        llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        assert len(llm.calls) == 2
        fixture = report_writer_fixture(scenario.fixture)
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        assert await _report_rows(uow_factory, investigation_id) == 0
        state = await _current_state(uow_factory, investigation_id)
        assert state.report_id is None

    async def test_i08_stale_assessment_race(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I08 real stale-Assessment persistence protection rejects the write."""
        scenario = _scenario(scenarios, S08)
        fixture = report_writer_fixture(scenario.fixture)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        advanced_b: list[UUID] = []

        async def advance_to_assessment_b() -> None:
            """Persist a new current Assessment B for the running world."""
            resolution = materializer.resolution(scenario)
            assessment_b = build_fixture_assessment(fixture, resolution).model_copy(
                update={
                    "id": uuid4(),
                    "verdict": Verdict.INCONCLUSIVE,
                    "confidence": AssessmentConfidence.LOW,
                    "findings": (),
                    "limitations": ("no evidence was available",),
                    "unresolved_questions": (),
                    "recommended_next_steps": (),
                }
            )
            persisted = await AssessmentPersistenceService(
                uow_factory
            ).persist_assessment(assessment_b)
            assert persisted.id is not None
            advanced_b.append(persisted.id)

        llm = RacingFakeLlmClient(advance_to_assessment_b)
        llm.set_response_factory(
            lambda _call: canonical_output(scenario, materializer.resolution(scenario))
        )
        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS
        assert len(advanced_b) == 1
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        # B is current; no report/history/pointer for the failed write.
        state = await _current_state(uow_factory, investigation_id)
        assert state.assessment_id == advanced_b[0]
        assert state.report_id is None
        assert await _report_rows(uow_factory, investigation_id) == 0
        assert await _report_history_rows(uow_factory, investigation_id) == 0
        assert len(llm.calls) == 1


class TestFailAndError:
    """I09..I11: FAIL is distinct from ERROR; cancellation propagates."""

    async def test_i09_scenario_wrong_output_is_fail(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I09 a runtime-valid but scenario-wrong output is COMPLETED/FAIL."""
        scenario = _scenario(scenarios, S01)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        llm.set_default(empty_output())
        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL
        case = result.cases[0]
        assert case.verdict is EvaluationVerdict.FAIL
        explanation = case.evaluator_results[0].explanation
        assert "required_assessment_finding_missing" in explanation
        # The provenance-valid but behaviorally-wrong report still persisted:
        # behavioral FAIL is not persistence failure.
        fixture = report_writer_fixture(scenario.fixture)
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        assert await _report_rows(uow_factory, investigation_id) == 1

    async def test_i10_unexpected_model_failure_is_error(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I10 an unexpected model/provider failure is ERROR, never FAIL."""
        scenario = _scenario(scenarios, S01)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False))
        result = await _run_case(uow_factory, llm, scenario, materializer)
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None
        case = result.cases[0]
        assert case.execution_status is EvaluationExecutionStatus.ERROR
        assert case.verdict is None
        # No partial report persists for the failed invocation.
        fixture = report_writer_fixture(scenario.fixture)
        investigation_id = await _investigation_by_objective(
            uow_factory, fixture.objective
        )
        assert await _report_rows(uow_factory, investigation_id) == 0
        assert len(llm.calls) == 1

    async def test_i11_cancellation_propagates(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """I11 asyncio.CancelledError propagates unchanged through the runner."""
        scenario = _scenario(scenarios, S01)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        llm = FakeLlmClient()
        llm.enqueue(asyncio.CancelledError("cancelled"))
        with pytest.raises(asyncio.CancelledError):
            await _run_case(uow_factory, llm, scenario, materializer)


class TestRunScopedIdentities:
    """F05..F08: canonical reuse, planned identities, and no destructive reset."""

    async def test_f06_f07_assessment_and_research_identities(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """F06/F07 the planned Assessment/Research identities are persisted exactly."""
        scenario = _scenario(scenarios, S04)
        materializer = MaterializeOnceMaterializer(uow_factory, execution_id=uuid4())
        resolution = await materializer.materialize(
            scenario, report_writer_fixture(scenario.fixture)
        )
        state = await _current_state(uow_factory, resolution.investigation_id)
        assert state.assessment_id == resolution.assessment_id
        async with uow_factory() as uow:
            results = await uow.research_results.list_by_investigation(
                resolution.investigation_id
            )
        claims = {claim.id for result in results for claim in result.claims}
        citations = {
            citation.citation_id for result in results for citation in result.citations
        }
        assert claims == set(resolution.research_claim_ids.values())
        assert citations == set(resolution.citation_ids.values())

    async def test_f05_f08_repeated_run_canonical_reuse_no_destructive_reset(
        self, uow_factory: UOW_FACTORY, scenarios: tuple[ReportWriterScenario, ...]
    ) -> None:
        """F05/F08 repeated runs reuse canonical entities without hard deletion."""
        scenario = _scenario(scenarios, S01)
        fixture = report_writer_fixture(scenario.fixture)
        first_materializer = MaterializeOnceMaterializer(
            uow_factory, execution_id=uuid4()
        )
        second_materializer = MaterializeOnceMaterializer(
            uow_factory, execution_id=uuid4()
        )
        first = await first_materializer.materialize(scenario, fixture)
        second = await second_materializer.materialize(scenario, fixture)
        # Execution-owned worlds are isolated; canonical Entities are reused.
        assert first.investigation_id != second.investigation_id
        assert first.entity_ids == second.entity_ids
        assert first.evidence_ids != second.evidence_ids
        # The first world still exists untouched (no destructive reset).
        first_state = await _current_state(uow_factory, first.investigation_id)
        assert first_state.assessment_id == first.assessment_id
        second_state = await _current_state(uow_factory, second.investigation_id)
        assert second_state.assessment_id == second.assessment_id
