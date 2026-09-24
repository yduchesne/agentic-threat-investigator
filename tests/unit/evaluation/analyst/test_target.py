# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30C Evidence Analyst target executor tests (EA-T01..T12).

Deterministic and offline: the exact typed scenario lookup, run-scoped
identity enforcement, and the executor's materialize-then-analyze
orchestration are exercised with in-memory doubles (a fake UnitOfWork, a
recording fake materializer, and a recording fake analyst). The common
runner converts target exceptions into case ERROR and cancellation
propagates unchanged; no LangSmith, LLM, or database participates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.evaluation.analyst.materializer import (
    AnalystScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.analyst.models import AnalystScenario
from agentic_threat_investigator.evaluation.analyst.pr30 import (
    EvidenceAnalystContractEvaluator,
)
from agentic_threat_investigator.evaluation.analyst.target import (
    AnalystScenarioLookup,
    EvidenceAnalystEvaluationOutput,
    EvidenceAnalystTargetExecutor,
    ScenarioLookupError,
)
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationContext,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationTarget,
    evaluation_case_from,
)
from tests.support.evaluation_common import unit_dataset
from tests.support.evaluation_fixtures import (
    UNIT_SCENARIO_ID,
    unit_assessment,
    unit_resolution,
    unit_scenario,
)


class FakeUoW:
    """Minimal async-context UnitOfWork double for executor tests."""

    async def __aenter__(self) -> "FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        """Close the double."""
        return


def _uow_factory() -> UnitOfWork:
    """Build one fake UnitOfWork through the executor's factory type."""
    return cast(UnitOfWork, FakeUoW())


class RecordingMaterializer:
    """Recording materializer double exposing the executor's call shape."""

    def __init__(self) -> None:
        """Initialize the empty call log."""
        self.investigation_ids: list[UUID] = []
        self.materialized: list[AnalystScenario] = []

    def investigation_id(self, scenario: AnalystScenario) -> UUID:
        """Record and mirror the deterministic investigation identity."""
        self.investigation_ids.append(
            AnalystScenarioMaterializer().investigation_id(scenario)
        )
        return self.investigation_ids[-1]

    async def materialize_or_reuse(
        self, uow: object, scenario: AnalystScenario
    ) -> object:
        """Record one materialization/reuse call and return the unit resolution."""
        self.materialized.append(scenario)
        assert uow is not None
        return unit_resolution(scenario)


class RecordingAnalyst:
    """Recording EvidenceAnalyst double returning a scripted persisted Assessment."""

    def __init__(self, *, fail: BaseException | None = None) -> None:
        """Bind the optional scripted failure and the call log."""
        self.calls: list[UUID] = []
        self.fail = fail

    async def analyze(self, investigation_id: UUID) -> object:
        """Record the invocation and return the unit Assessment or raise."""
        self.calls.append(investigation_id)
        if self.fail is not None:
            raise self.fail
        return unit_assessment()


def _output(
    executor: EvidenceAnalystTargetExecutor,
) -> Callable[[], Awaitable[EvidenceAnalystEvaluationOutput]]:
    """Return a callable that executes the executor once on the unit case.

    Kept as a helper so ordering tests can invoke the same target repeatedly.
    """
    scenario = unit_scenario()
    case = evaluation_case_from(scenario)
    context = EvaluationContext(
        dataset_id=unit_dataset().canonical, case_id=case.case_id
    )

    async def run() -> EvidenceAnalystEvaluationOutput:
        return await executor.execute(case=case, context=context)

    return run


def build_executor() -> tuple[
    EvidenceAnalystTargetExecutor, RecordingMaterializer, RecordingAnalyst
]:
    """Build one executor bound to recording doubles."""
    scenario = unit_scenario()
    lookup = AnalystScenarioLookup([scenario])
    materializer = RecordingMaterializer()
    analyst = RecordingAnalyst()
    target = EvidenceAnalystTargetExecutor(
        scenario_lookup=lookup,
        analyst=analyst,  # type: ignore[arg-type]  # recording double implements the used surface
        uow_factory=_uow_factory,
        materializer=materializer,  # type: ignore[arg-type]
    )
    return target, materializer, analyst
    return target, materializer, analyst


class TestScenarioLookup:
    """EA-T01..T03 exact typed scenario identity resolution."""

    def test_t01_exact_identity_resolves(self) -> None:
        """T01 an exact (case_id, version) identity resolves the typed scenario."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        assert lookup.require(UNIT_SCENARIO_ID, 1) is scenario

    def test_t02_unknown_case_fails_closed(self) -> None:
        """T02 an unknown case raises ScenarioLookupError (runner -> ERROR)."""
        lookup = AnalystScenarioLookup([unit_scenario()])
        with pytest.raises(ScenarioLookupError):
            lookup.require("no_such_case", 1)

    def test_t03_version_mismatch_fails_closed(self) -> None:
        """T03 a version mismatch never resolves to a typed scenario."""
        lookup = AnalystScenarioLookup([unit_scenario()])
        with pytest.raises(ScenarioLookupError):
            lookup.require(UNIT_SCENARIO_ID, 2)

    def test_t03b_duplicate_identity_rejected(self) -> None:
        """T03 duplicate scenario identities are rejected at construction."""
        with pytest.raises(ScenarioLookupError):
            AnalystScenarioLookup([unit_scenario(), unit_scenario()])


class TestTargetExecution:
    """EA-T04..T12 executor orchestration."""

    @pytest.mark.asyncio
    async def test_t04_target_mismatch_never_executes(self) -> None:
        """T04 a case whose target differs from the dataset refuses before any model call."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        materializer = RecordingMaterializer()
        analyst = RecordingAnalyst()
        target = EvidenceAnalystTargetExecutor(
            scenario_lookup=lookup,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory,
            materializer=materializer,  # type: ignore[arg-type]
        )
        from tests.support.evaluation_common import unit_specification

        mismatched = evaluation_case_from(scenario).model_copy(
            update={
                "specification": unit_specification(target=EvaluationTarget.COORDINATOR)
            }
        )
        runner = EvaluationRunner()
        with pytest.raises(DatasetLoadError):
            await runner.run(
                dataset_id=unit_dataset(),
                cases=[mismatched],
                target=target,
                evaluators=(  # type: ignore[arg-type]
                    EvidenceAnalystContractEvaluator(scenario_lookup=lookup),
                ),
            )
        assert analyst.calls == []
        assert materializer.materialized == []

    @pytest.mark.asyncio
    async def test_t05_materialization_then_one_analyst_call(self) -> None:
        """T05 successful materialization is followed by exactly one analyst call."""
        target, materializer, analyst = build_executor()
        output = await _output(target)()
        assert isinstance(output, EvidenceAnalystEvaluationOutput)
        assert len(materializer.materialized) == 1
        assert materializer.materialized[0].id == UNIT_SCENARIO_ID
        assert len(analyst.calls) == 1

    @pytest.mark.asyncio
    async def test_t06_persisted_assessment_and_resolution_returned(self) -> None:
        """T06 the executor returns the persisted Assessment plus the resolution."""
        target, _materializer, _analyst = build_executor()
        output = await _output(target)()
        assert isinstance(output, EvidenceAnalystEvaluationOutput)
        assert output.assessment.verdict is not None
        for label in ("provider_a", "provider_b"):
            assert label in output.resolution.evidence_ids

    @pytest.mark.asyncio
    async def test_t07_llm_failure_is_error_not_fail(self) -> None:
        """T07 an LLM failure surfaces as a runner ERROR, never a behavioral FAIL."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode

        analyst = RecordingAnalyst(
            fail=LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False)
        )
        target = EvidenceAnalystTargetExecutor(
            scenario_lookup=lookup,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory,
            materializer=RecordingMaterializer(),  # type: ignore[arg-type]
        )
        case = evaluation_case_from(scenario)
        runner = EvaluationRunner()
        result = await runner.run(
            dataset_id=unit_dataset(),
            cases=[case],
            target=target,
            # PR 30A freezes the runner seam as Evaluator[object]; see run.py.
            evaluators=(  # type: ignore[arg-type]
                EvidenceAnalystContractEvaluator(scenario_lookup=lookup),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None
        case_result = result.cases[0]
        assert case_result.execution_status is EvaluationExecutionStatus.ERROR
        assert case_result.verdict is None
        assert case_result.evaluator_results[0].evaluator_id == ("target-execution")

    @pytest.mark.asyncio
    async def test_t08_persistence_failure_is_error(self) -> None:
        """T08 a persistence failure during analysis is a case ERROR."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        analyst = RecordingAnalyst(fail=RuntimeError("persistence blew up"))
        target = EvidenceAnalystTargetExecutor(
            scenario_lookup=lookup,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory,
            materializer=RecordingMaterializer(),  # type: ignore[arg-type]
        )
        case = evaluation_case_from(scenario)
        result = await EvaluationRunner().run(
            dataset_id=unit_dataset(),
            cases=[case],
            target=target,
            # PR 30A freezes the runner seam as Evaluator[object]; see run.py.
            evaluators=(  # type: ignore[arg-type]
                EvidenceAnalystContractEvaluator(scenario_lookup=lookup),
            ),
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR

    @pytest.mark.asyncio
    async def test_t09_cancellation_propagates(self) -> None:
        """T09 asyncio.CancelledError propagates unchanged from the target."""
        scenario = unit_scenario()
        lookup = AnalystScenarioLookup([scenario])
        analyst = RecordingAnalyst(fail=asyncio.CancelledError("cancelled"))
        target = EvidenceAnalystTargetExecutor(
            scenario_lookup=lookup,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory,
            materializer=RecordingMaterializer(),  # type: ignore[arg-type]
        )
        with pytest.raises(asyncio.CancelledError):
            await _output(target)()

    @pytest.mark.asyncio
    async def test_t10_two_cases_no_resolution_cross_contamination(self) -> None:
        """T10 two cases each get their own materialization and assessment."""
        from tests.support.evaluation_fixtures import unit_scenario as build

        scenario_a = build()
        scenario_b = build().model_copy(update={"id": "unit_scenario_b"})

        lookup = AnalystScenarioLookup([scenario_a, scenario_b])
        materializer = RecordingMaterializer()
        analyst = RecordingAnalyst()
        target = EvidenceAnalystTargetExecutor(
            scenario_lookup=lookup,
            analyst=analyst,  # type: ignore[arg-type]
            uow_factory=_uow_factory,
            materializer=materializer,  # type: ignore[arg-type]
        )
        for scenario in (scenario_a, scenario_b):
            output = await target.execute(
                case=evaluation_case_from(scenario),
                context=EvaluationContext(
                    dataset_id=unit_dataset().canonical, case_id=scenario.id
                ),
            )
            assert isinstance(output, EvidenceAnalystEvaluationOutput)
            assert (
                output.resolution.evidence_ids["provider_a"]
                != (output.resolution.entity_ids["target_ip"])
            )
        assert len(materializer.materialized) == 2
        assert len(analyst.calls) == 2

    @pytest.mark.asyncio
    async def test_t11_same_case_rerun_is_deterministic(self) -> None:
        """T11 rerunning one case reuses the scenario and re-invokes the analyst once per run."""
        target, materializer, analyst = build_executor()
        first = await _output(target)()
        second = await _output(target)()
        assert isinstance(first, EvidenceAnalystEvaluationOutput)
        assert isinstance(second, EvidenceAnalystEvaluationOutput)
        assert first.resolution == second.resolution
        assert [scenario.id for scenario in materializer.materialized] == [
            UNIT_SCENARIO_ID,
            UNIT_SCENARIO_ID,
        ]
        assert len(analyst.calls) == 2

    def test_t12_target_has_no_langsmith_dependency(self) -> None:
        """T12 the target boundary never imports or depends on LangSmith."""
        import inspect

        from agentic_threat_investigator.evaluation.analyst import (
            target as target_module,
        )

        source = inspect.getsource(target_module)
        assert "from langsmith" not in source
        assert "import langsmith" not in source
        assert "LangSmithEvaluationClient" not in source
