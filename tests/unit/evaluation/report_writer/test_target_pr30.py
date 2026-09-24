# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E Report Writer target executor tests (RPT-T01..T14).

Deterministic and offline: the exact typed scenario lookup, run-scoped
identity enforcement, and the executor's materialize-then-write
orchestration are exercised with in-memory doubles (a fake UnitOfWork, a
recording materializer, a recording writer, and FakeLlmClient at the model
boundary). The common runner converts unexpected exceptions into case ERROR;
declared no-report scenarios convert only allowlisted typed failures into
evaluation inputs; cancellation propagates unchanged. No LangSmith or
database participates.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from typing import cast
from uuid import UUID

import pytest
from pydantic import BaseModel

from agentic_threat_investigator.app.llm import LlmClient, LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    StaleReportInputError,
    UnitOfWork,
)
from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.evaluation.common import (
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationTarget,
    EvaluationVerdict,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    ReportWriterFixture,
    report_scenario_resolution,
)
from agentic_threat_investigator.evaluation.report_writer.models import (
    ReportWriterScenario,
    ReportWriterScenarioResolution,
)
from agentic_threat_investigator.evaluation.report_writer.pr30 import (
    ReportWriterContractEvaluator,
)
from agentic_threat_investigator.evaluation.report_writer.target import (
    ReportWriterEvaluationOutput,
    ReportWriterScenarioLookup,
    ReportWriterScenarioLookupError,
    ReportWriterTargetExecutor,
)
from tests.support.llm_fixtures import FakeLlmClient
from tests.support.report_writer_evaluation import (
    corpus_scenario,
)

S01 = "rpt-s01-clearly-malicious"
S05 = "rpt-s05-no-research"
S06 = "rpt-s06-unsupported-reference"
S07 = "rpt-s07-verdict-override-attempt"
S08 = "rpt-s08-stale-assessment-race"


class _Probe(BaseModel):
    """Minimal pydantic response model for fake model-boundary probes."""


class FakeUoW:
    """Minimal async-context UnitOfWork double for executor tests."""

    async def __aenter__(self) -> "FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


def _uow_factory() -> UnitOfWork:
    """Build one fake UnitOfWork through the executor's factory type."""
    return cast(UnitOfWork, FakeUoW())


def unit_report() -> InvestigationReport:
    """Build one minimal persisted-report double for executor plumbing tests."""
    return InvestigationReport(
        investigation_id=UUID(int=1),
        assessment_id=UUID(int=2),
        verdict=Verdict.MALICIOUS,
        confidence=AssessmentConfidence.HIGH,
        title="Unit report",
    )


class RecordingMaterializer:
    """Recording materializer double exposing the executor's call shape."""

    def __init__(self) -> None:
        """Initialize the empty call log."""
        self.execution_ids: list[UUID | None] = []
        self.scenarios: list[ReportWriterScenario] = []

    async def materialize(
        self,
        scenario: ReportWriterScenario,
        fixture: ReportWriterFixture,
        *,
        execution_id: UUID | None = None,
    ) -> ReportWriterScenarioResolution:
        """Record one execution and return the execution-scoped resolution."""
        self.execution_ids.append(execution_id)
        self.scenarios.append(scenario)
        return report_scenario_resolution(scenario, fixture, execution_id=execution_id)


class RecordingWriter:
    """Recording ReportWriter double scripting one outcome per execution."""

    def __init__(
        self,
        llm: LlmClient,
        outcome: object,
        *,
        llm_calls: int = 0,
    ) -> None:
        """Bind the counting client, scripted outcome, and probe call count."""
        self._llm = llm
        self._outcome = outcome
        self._llm_calls = llm_calls
        self.investigation_ids: list[UUID] = []

    async def write(self, investigation_id: UUID) -> object:
        """Record the invocation, probe the model boundary, then return/raise."""
        self.investigation_ids.append(investigation_id)
        for _ in range(self._llm_calls):
            await self._llm.generate_structured(
                system_prompt="",
                user_prompt="",
                response_model=_Probe,
                operation_name="unit-probe",
            )
        if isinstance(self._outcome, BaseException):
            raise self._outcome
        return self._outcome


def writer_factory(
    outcome: object, *, llm_calls: int = 0
) -> tuple[list[RecordingWriter], Callable[[LlmClient], RecordingWriter]]:
    """Return a writer factory scripting one outcome and probe-call count.

    The shared ``writers`` list lets tests inspect the exact writer instances
    created per execution.
    """
    writers: list[RecordingWriter] = []

    def build(llm: LlmClient) -> RecordingWriter:
        """Build one recording writer bound to the counting client."""
        writer = RecordingWriter(llm, outcome, llm_calls=llm_calls)
        writers.append(writer)
        return writer

    return writers, build


def build_executor(
    scenario: ReportWriterScenario,
    *,
    outcome: object,
    llm_calls: int = 0,
    fake_llm: FakeLlmClient | None = None,
) -> tuple[
    ReportWriterTargetExecutor,
    RecordingMaterializer,
    FakeLlmClient,
    list[RecordingWriter],
]:
    """Build one executor bound to recording doubles."""
    lookup = ReportWriterScenarioLookup((scenario,))
    materializer = RecordingMaterializer()
    fake = fake_llm or FakeLlmClient()
    fake.set_default(_Probe())
    writers, build = writer_factory(outcome, llm_calls=llm_calls)
    target = ReportWriterTargetExecutor(
        scenario_lookup=lookup,
        uow_factory=_uow_factory,
        llm_client=fake,
        materializer=materializer,  # type: ignore[arg-type]  # recording double implements the used surface
        writer_factory=build,  # type: ignore[arg-type]  # recording double returns the recording writer
    )
    return target, materializer, fake, writers


def _dataset() -> EvaluationDatasetId:
    """Build the canonical report-writer dataset identity for runner tests."""
    return EvaluationDatasetId(target=EvaluationTarget.REPORT_WRITER, version=1)


async def _execute(
    executor: ReportWriterTargetExecutor,
    scenario: ReportWriterScenario,
) -> ReportWriterEvaluationOutput:
    """Execute the executor once on one scenario case."""
    case = evaluation_case_from(scenario)
    context = EvaluationContext(dataset_id="report-writer/v1", case_id=case.case_id)
    return await executor.execute(case=case, context=context)


class TestScenarioLookup:
    """RPT-T01..T03 exact typed scenario identity resolution."""

    def test_t01_exact_identity_resolves(self) -> None:
        """T01 an exact (case_id, version) identity resolves the typed scenario."""
        scenario = corpus_scenario(S01)
        lookup = ReportWriterScenarioLookup((scenario,))
        assert lookup.require(S01, 1) is scenario

    def test_t02_unknown_case_fails_closed(self) -> None:
        """T02 an unknown case raises ScenarioLookupError (runner -> ERROR)."""
        lookup = ReportWriterScenarioLookup((corpus_scenario(S01),))
        with pytest.raises(ReportWriterScenarioLookupError):
            lookup.require("no_such_case", 1)

    def test_t02b_version_mismatch_fails_closed(self) -> None:
        """T02 a version mismatch never resolves to a typed scenario."""
        lookup = ReportWriterScenarioLookup((corpus_scenario(S01),))
        with pytest.raises(ReportWriterScenarioLookupError):
            lookup.require(S01, 2)

    def test_t03_duplicate_identity_rejected(self) -> None:
        """T03 duplicate scenario identities are rejected at construction."""
        with pytest.raises(ReportWriterScenarioLookupError):
            ReportWriterScenarioLookup((corpus_scenario(S01), corpus_scenario(S01)))


class TestTargetExecution:
    """RPT-T04..T14 executor orchestration."""

    @pytest.mark.asyncio
    async def test_t04_normal_scenario_writer_once(self) -> None:
        """T04 a normal scenario runs the production writer exactly once."""
        scenario = corpus_scenario(S01)
        executor, materializer, _fake, writers = build_executor(
            scenario, outcome=unit_report()
        )
        output = await _execute(executor, scenario)
        assert isinstance(output, ReportWriterEvaluationOutput)
        assert len(materializer.scenarios) == 1
        assert materializer.scenarios[0] is scenario
        assert len(writers) == 1
        assert writers[0].investigation_ids == [output.resolution.investigation_id]

    @pytest.mark.asyncio
    async def test_t05_success_returns_persisted_report(self) -> None:
        """T05 a successful execution carries the persisted report."""
        scenario = corpus_scenario(S01)
        scripted = unit_report()
        executor, _materializer, _fake, _writers = build_executor(
            scenario, outcome=scripted
        )
        output = await _execute(executor, scenario)
        assert output.evaluation_input.report is scripted
        assert output.evaluation_input.execution_error_code is None

    @pytest.mark.asyncio
    async def test_t06_llm_calls_exact_count(self) -> None:
        """T06 the output carries the exact current-execution model count."""
        scenario = corpus_scenario(S05)
        fake = FakeLlmClient()
        fake.set_default(_Probe())
        executor, _materializer, fake, _writers = build_executor(
            scenario, outcome=unit_report(), llm_calls=2, fake_llm=fake
        )
        output = await _execute(executor, scenario)
        assert output.evaluation_input.llm_calls == 2
        # The counting wrapper delegated exactly twice to the real boundary.
        assert len(fake.calls) == 2

    @pytest.mark.asyncio
    async def test_t07_expected_no_report_is_input_not_error(self) -> None:
        """T07 a declared no-report failure becomes an evaluation input (PASS)."""
        scenario = corpus_scenario(S06)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=ReportProvenanceError("unsupported reference"),
        )
        output = await _execute(executor, scenario)
        assert output.evaluation_input.report is None
        assert output.evaluation_input.execution_error_code == "report_provenance_error"
        result = await EvaluationRunner().run(
            dataset_id=_dataset(),
            cases=(evaluation_case_from(scenario),),
            target=executor,
            evaluators=(  # type: ignore[arg-type]
                ReportWriterContractEvaluator(
                    scenario_lookup=ReportWriterScenarioLookup((scenario,))
                ),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS

    @pytest.mark.asyncio
    async def test_t08_unexpected_exception_is_error(self) -> None:
        """T08 an unexpected exception becomes a case ERROR, never FAIL."""
        scenario = corpus_scenario(S01)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False),
        )
        result = await EvaluationRunner().run(
            dataset_id=_dataset(),
            cases=(evaluation_case_from(scenario),),
            target=executor,
            evaluators=(  # type: ignore[arg-type]
                ReportWriterContractEvaluator(
                    scenario_lookup=ReportWriterScenarioLookup((scenario,))
                ),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None
        assert result.cases[0].evaluator_results[0].evaluator_id == "target-execution"

    @pytest.mark.asyncio
    async def test_t09_provenance_failure_stable_code(self) -> None:
        """T09 an unsupported-reference rejection maps to the stable code."""
        scenario = corpus_scenario(S06)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=ReportProvenanceError("unsupported reference"),
        )
        output = await _execute(executor, scenario)
        assert output.evaluation_input.execution_error_code == "report_provenance_error"

    @pytest.mark.asyncio
    async def test_t10_invalid_structured_output_stable_code(self) -> None:
        """T10 bounded structured-output failure maps to the stable code."""
        scenario = corpus_scenario(S07)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False),
        )
        output = await _execute(executor, scenario)
        assert (
            output.evaluation_input.execution_error_code == "invalid_structured_output"
        )

    @pytest.mark.asyncio
    async def test_t11_stale_input_stable_code(self) -> None:
        """T11 the stale-Assessment conflict maps to the stable code."""
        scenario = corpus_scenario(S08)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=StaleReportInputError(UUID(int=1), UUID(int=2)),
        )
        output = await _execute(executor, scenario)
        assert output.evaluation_input.execution_error_code == "stale_report_input"

    @pytest.mark.asyncio
    async def test_t12_cancellation_propagates(self) -> None:
        """T12 asyncio.CancelledError propagates unchanged from the writer."""
        scenario = corpus_scenario(S01)
        executor, _materializer, _fake, _writers = build_executor(
            scenario, outcome=asyncio.CancelledError("cancelled")
        )
        with pytest.raises(asyncio.CancelledError):
            await _execute(executor, scenario)

    @pytest.mark.asyncio
    async def test_t13_unexpected_provenance_error_is_error(self) -> None:
        """T13 an unexpected provenance error on a normal scenario is ERROR."""
        scenario = corpus_scenario(S01)
        executor, _materializer, _fake, _writers = build_executor(
            scenario,
            outcome=ReportProvenanceError("unexpected on normal scenario"),
        )
        result = await EvaluationRunner().run(
            dataset_id=_dataset(),
            cases=(evaluation_case_from(scenario),),
            target=executor,
            evaluators=(  # type: ignore[arg-type]
                ReportWriterContractEvaluator(
                    scenario_lookup=ReportWriterScenarioLookup((scenario,))
                ),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_t14_repeated_run_isolated_world(self) -> None:
        """T14 repeated runs of one case use isolated execution identities."""
        scenario = corpus_scenario(S01)
        executor, materializer, _fake, writers = build_executor(
            scenario, outcome=unit_report()
        )
        first = await _execute(executor, scenario)
        second = await _execute(executor, scenario)
        assert len(materializer.execution_ids) == 2
        assert materializer.execution_ids[0] is not None
        assert materializer.execution_ids[1] is not None
        assert materializer.execution_ids[0] != materializer.execution_ids[1]
        assert first.resolution.investigation_id != second.resolution.investigation_id
        assert first.resolution.assessment_id != second.resolution.assessment_id
        # Canonical Entity/Relationship identities stay global across runs.
        assert first.resolution.entity_ids == second.resolution.entity_ids
        assert first.resolution.relationship_ids == second.resolution.relationship_ids

    def test_t13_local_target_module_has_no_langsmith(self) -> None:
        """T13 the target boundary never imports or depends on LangSmith."""
        from agentic_threat_investigator.evaluation.report_writer import (
            target as target_module,
        )

        source = inspect.getsource(target_module)
        assert "from langsmith" not in source
        assert "import langsmith" not in source
        assert "LangSmithEvaluationClient" not in source


class TestStableErrorMapping:
    """T09..T11 category mapping never parses exception messages."""

    def test_stable_mapping_typed_only(self) -> None:
        """The mapping recognizes only the three allowlisted typed categories."""
        from agentic_threat_investigator.evaluation.report_writer.target import (
            stable_report_execution_error,
        )

        assert (
            stable_report_execution_error(ReportProvenanceError("anything at all"))
            == "report_provenance_error"
        )
        assert (
            stable_report_execution_error(
                StaleReportInputError(UUID(int=1), UUID(int=2))
            )
            == "stale_report_input"
        )
        assert (
            stable_report_execution_error(
                LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
            )
            == "invalid_structured_output"
        )
        assert (
            stable_report_execution_error(
                LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False)
            )
            is None
        )
        assert stable_report_execution_error(RuntimeError("anything")) is None
