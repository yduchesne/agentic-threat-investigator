# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Coordinator target + evaluator adapter tests (C-T01..T14, C-E01..E10).

Deterministic and offline: the exact typed scenario lookup, the executor's
materialize->execute->capture orchestration (with an injected run seam and a
fake UnitOfWork/timeline), and the thin PR 30 adapter mapping over the
existing :class:`CoordinatorTrajectoryEvaluator`. Behavioral FAIL semantics
(policy-invalid pivots, duplicate research, wrong stop reason) are proven
through the real existing evaluator inside the adapter with hand-built
trajectories; exceptions and cancellation map to ERROR/propagation. No
LangSmith or live Coordinator run participates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.evaluation.common import (
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunner,
    EvaluationTarget,
    EvaluationVerdict,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.coordinator import (
    ACTION_INVESTIGATION_STOPPED,
    ACTION_PIVOT_ENQUEUED,
    ACTION_PIVOT_EXECUTED,
    ACTION_PROVIDER_QUERY,
    ACTION_RESEARCH_REQUESTED,
    CoordinatorActionRecord,
    CoordinatorFixtureReference,
    CoordinatorScenario,
    CoordinatorScenarioResolution,
    ExpectedCoordinatorTrajectory,
    ExpectedPivot,
)
from agentic_threat_investigator.evaluation.coordinator_pr30 import (
    COORDINATOR_TRAJECTORY_CONTRACT_EVALUATOR_ID,
    CoordinatorEvaluationOutput,
    CoordinatorScenarioLookup,
    CoordinatorScenarioLookupError,
    CoordinatorScenarioTargetExecutor,
    CoordinatorTrajectoryContractEvaluator,
    run_coordinator_evaluation,
)
from tests.support.evaluation_common import unit_specification

_ROOT = UUID("00000000-0000-0000-0000-0000000000a1")
_IP = UUID("00000000-0000-0000-0000-0000000000a2")
_MALWARE = UUID("00000000-0000-0000-0000-0000000000a3")


def _state(
    *, stop_reason: str = "sufficient_evidence", **overrides: Any
) -> InvestigationState:
    """Build a minimal terminal InvestigationState."""
    params: dict[str, Any] = {
        "investigation_id": UUID("00000000-0000-0000-0000-0000000000e1"),
        "status": InvestigationStatus.COMPLETED,
        "trigger_type": InvestigationTriggerType.MANUAL,
        "root_entity_ids": [_ROOT],
        "objective": "Assess the root indicator.",
        "budget": default_investigation_budget(),
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "stop_reason": stop_reason,
        "discovered_entity_ids": [_IP],
    }
    params.update(overrides)
    return InvestigationState(**params)


def _scenario(
    *, expected: ExpectedCoordinatorTrajectory | None = None
) -> CoordinatorScenario:
    """Build the canonical one-pivot sufficient-stop scenario."""
    return CoordinatorScenario(
        id="scenario.domain-dns-ip",
        version=1,
        specification=unit_specification(target=EvaluationTarget.COORDINATOR),
        fixture=CoordinatorFixtureReference(name="domain-dns-ip"),
        expected=expected
        or ExpectedCoordinatorTrajectory(
            allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
            required_pivots=("resolved_ip",),
            expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
        ),
    )


def _resolution() -> CoordinatorScenarioResolution:
    """Build a simple label resolution."""
    return CoordinatorScenarioResolution(
        entities={"resolved_ip": _IP, "root_domain": _ROOT},
        provider_work={
            "abuseipdb_resolved_ip": (SourceId.ABUSEIPDB.value, _IP, 1),
        },
    )


def _passing_actions() -> tuple[CoordinatorActionRecord, ...]:
    """Build the canonical well-formed action records."""
    return (
        CoordinatorActionRecord(
            action=ACTION_PROVIDER_QUERY,
            entity_id=_ROOT,
            provider=SourceId.GOOGLE_PUBLIC_DNS.value,
            depth=0,
        ),
        CoordinatorActionRecord(action=ACTION_PIVOT_ENQUEUED, entity_id=_IP, depth=1),
        CoordinatorActionRecord(action=ACTION_PIVOT_EXECUTED, entity_id=_IP, depth=1),
        CoordinatorActionRecord(
            action=ACTION_INVESTIGATION_STOPPED, reason="sufficient_evidence"
        ),
    )


def _output(
    *,
    final_state: InvestigationState | None = None,
    actions: tuple[CoordinatorActionRecord, ...] | None = None,
) -> CoordinatorEvaluationOutput:
    """Build one typed output for the canonical scenario."""
    return CoordinatorEvaluationOutput(
        final_state=final_state or _state(),
        resolution=_resolution(),
        actions=actions if actions is not None else _passing_actions(),
        observed_transitions=1,
    )


class _FakeUoW:
    """Async-context UnitOfWork double exposing a scripted timeline."""

    def __init__(self, *, events: list[object]) -> None:
        """Bind the scripted durable timeline events."""
        self.timeline_events = _FakeTimeline(events)

    async def __aenter__(self) -> "_FakeUoW":
        """Return the double as its own context."""
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        """Close the double."""
        return


class _FakeTimeline:
    """Scripted timeline repository double."""

    def __init__(self, events: list[object]) -> None:
        """Bind the events."""
        self._events = events

    async def list_by_investigation(self, investigation_id: UUID) -> list[object]:
        """Return the scripted events."""
        del investigation_id
        return list(self._events)


class _FakeMaterialized:
    """Minimal materialized-fixture double carrying resolution/identity."""

    def __init__(
        self, *, resolution: CoordinatorScenarioResolution, version: int = 1
    ) -> None:
        """Bind the resolution and initial version."""
        self.resolution = resolution
        self.initial_state = _state().model_copy(update={"version": version})


class _FakeMaterializer:
    """Recording materializer double."""

    def __init__(self, *, resolution: CoordinatorScenarioResolution) -> None:
        """Bind the resolution and an empty call log."""
        self._resolution = resolution
        self.calls: list[tuple[CoordinatorScenario, UUID | None]] = []

    async def materialize(
        self,
        scenario: CoordinatorScenario,
        uow_factory: Callable[[], object],
        *,
        execution_id: UUID | None = None,
    ) -> _FakeMaterialized:
        """Record the execution-scoped materialization and return a fixture."""
        assert uow_factory is not None
        self.calls.append((scenario, execution_id))
        return _FakeMaterialized(resolution=self._resolution)


async def _noop_async_analysis_factory(
    investigation_id: UUID, materialized: object
) -> object:
    """Return a no-op analysis executor."""
    del investigation_id, materialized
    return object()


def _context(case_id: str) -> EvaluationContext:
    """Build one minimal evaluation context."""
    return EvaluationContext(dataset_id="coordinator/v1", case_id=case_id)


def _terminal_stop_actions() -> tuple[CoordinatorActionRecord, ...]:
    """Build the well-formed actions carrying a matching stop reason."""
    return _passing_actions()


class TestCoordinatorScenarioLookup:
    """C-T01..T04 exact typed scenario identity resolution."""

    def test_t01_exact_identity_resolves(self) -> None:
        """T01 an exact (case_id, version) identity resolves the typed scenario."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        assert lookup.require(scenario.id, 1) is scenario

    def test_t02_unknown_case_fails_closed(self) -> None:
        """T02 an unknown case fails closed."""
        lookup = CoordinatorScenarioLookup([_scenario()])
        with pytest.raises(CoordinatorScenarioLookupError):
            lookup.require("no_such_case", 1)

    def test_t03_version_mismatch_fails_closed(self) -> None:
        """T03 a version mismatch never resolves."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        with pytest.raises(CoordinatorScenarioLookupError):
            lookup.require(scenario.id, 2)

    def test_t03b_duplicate_identity_rejected(self) -> None:
        """T03 duplicate identities are rejected at construction."""
        with pytest.raises(CoordinatorScenarioLookupError):
            CoordinatorScenarioLookup([_scenario(), _scenario()])


class TestCoordinatorTarget:
    """C-T05..T14 executor orchestration."""

    def _executor(
        self,
        *,
        final_state: InvestigationState | None = None,
        actions: list[object] | None = None,
        fail: BaseException | None = None,
        materializer: _FakeMaterializer | None = None,
    ) -> tuple[CoordinatorScenarioTargetExecutor, _FakeMaterializer]:
        """Build one executor bound to deterministic doubles."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        m = _FakeMaterializer(resolution=_resolution())
        bound_m = materializer or m

        async def run_fixture(materialized: object) -> InvestigationState:
            """Return the scripted terminal state or raise."""
            if fail is not None:
                raise fail
            final = final_state or _state()
            return final.model_copy(update={"version": 5})

        target = CoordinatorScenarioTargetExecutor(
            scenario_lookup=lookup,
            materializer=bound_m,  # type: ignore[arg-type]
            uow_factory=lambda: cast(UnitOfWork, _FakeUoW(events=actions or [])),
            analysis_factory=cast(Any, _noop_async_analysis_factory),
            run_fixture=run_fixture,
        )
        return target, bound_m

    @pytest.mark.asyncio
    async def test_t05_materialization_executes_once(self) -> None:
        """T05 the case materializes and executes a production investigation."""
        target, materializer = self._executor()
        scenario = _scenario()
        await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert len(materializer.calls) == 1
        assert materializer.calls[0][1] is not None  # execution-scoped identity

    @pytest.mark.asyncio
    async def test_t06_07_durable_terminal_state_actions_captured(self) -> None:
        """T06/T07/T08 the durable final state and structured actions are captured."""
        target, _ = self._executor()
        scenario = _scenario()
        output = await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert output.final_state.status is InvestigationStatus.COMPLETED
        assert output.observed_transitions >= 1
        assert all(isinstance(item, CoordinatorActionRecord) for item in output.actions)

    @pytest.mark.asyncio
    async def test_t09_transition_span_from_versions(self) -> None:
        """T09 the transition count follows the durable-version semantics."""
        target, _ = self._executor()
        scenario = _scenario()
        output = await target.execute(
            case=evaluation_case_from(scenario), context=_context(scenario.id)
        )
        assert output.observed_transitions == 5  # version 1 -> 5 span

    @pytest.mark.asyncio
    async def test_t10_provider_failure_is_error(self) -> None:
        """T10 a provider/execution failure surfaces as a runner ERROR."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        target = CoordinatorScenarioTargetExecutor(
            scenario_lookup=lookup,
            materializer=_FakeMaterializer(resolution=_resolution()),  # type: ignore[arg-type]
            uow_factory=lambda: cast(UnitOfWork, _FakeUoW(events=[])),
            analysis_factory=cast(Any, _noop_async_analysis_factory),
            run_fixture=self._failing_run(RuntimeError("provider outage")),
        )
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.COORDINATOR, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=target,
            evaluators=(
                CoordinatorTrajectoryContractEvaluator(scenario_lookup=lookup),
            ),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_t11_analysis_failure_is_error(self) -> None:
        """T11 an analysis/research execution failure is a case ERROR."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        target = CoordinatorScenarioTargetExecutor(
            scenario_lookup=lookup,
            materializer=_FakeMaterializer(resolution=_resolution()),  # type: ignore[arg-type]
            uow_factory=lambda: cast(UnitOfWork, _FakeUoW(events=[])),
            analysis_factory=cast(Any, _noop_async_analysis_factory),
            run_fixture=self._failing_run(RuntimeError("analysis execution failed")),
        )
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.COORDINATOR, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=target,
            evaluators=(
                CoordinatorTrajectoryContractEvaluator(scenario_lookup=lookup),
            ),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR

    @pytest.mark.asyncio
    async def test_t12_cancellation_propagates(self) -> None:
        """T12 asyncio.CancelledError propagates unchanged."""
        scenario = _scenario()
        lookup = CoordinatorScenarioLookup([scenario])
        target = CoordinatorScenarioTargetExecutor(
            scenario_lookup=lookup,
            materializer=_FakeMaterializer(resolution=_resolution()),  # type: ignore[arg-type]
            uow_factory=lambda: cast(UnitOfWork, _FakeUoW(events=[])),
            analysis_factory=cast(Any, _noop_async_analysis_factory),
            run_fixture=self._failing_run(asyncio.CancelledError("cancelled")),
        )
        with pytest.raises(asyncio.CancelledError):
            await target.execute(
                case=evaluation_case_from(scenario), context=_context(scenario.id)
            )

    @pytest.mark.asyncio
    async def test_t13_repeated_case_uses_fresh_execution_identity(self) -> None:
        """T13 repeated cases materialize into isolated run-scoped identities."""
        target, materializer = self._executor()
        scenario = _scenario()
        case = evaluation_case_from(scenario)
        await target.execute(case=case, context=_context(scenario.id))
        second_out = await target.execute(case=case, context=_context(scenario.id))
        assert second_out.final_state is not None
        first, second = (execution_id for _, execution_id in materializer.calls)
        assert first is not None and second is not None
        assert first != second

    def test_t14_target_has_no_langsmith_dependency(self) -> None:
        """T14 the target boundary never imports LangSmith."""
        import inspect

        from agentic_threat_investigator.evaluation import coordinator_pr30 as module

        source = inspect.getsource(module)
        assert "from langsmith" not in source
        assert "import langsmith" not in source
        assert "LangSmithEvaluationClient" not in source

    @staticmethod
    def _failing_run(fail: BaseException) -> Any:
        """Build a run seam raising the scripted failure."""

        async def run_fixture(materialized: object) -> object:
            """Raise the scripted failure."""
            del materialized
            raise fail

        return run_fixture


class TestCoordinatorEvaluatorAdapter:
    """C-E01..E10 PR 30 adapter mapping over the existing evaluator."""

    @staticmethod
    def _adapter() -> CoordinatorTrajectoryContractEvaluator:
        """Build the adapter over the canonical scenario."""
        return CoordinatorTrajectoryContractEvaluator(
            scenario_lookup=CoordinatorScenarioLookup([_scenario()])
        )

    @pytest.mark.asyncio
    async def test_e01_existing_evaluator_pass_maps_to_pass(self) -> None:
        """E01 a passing trajectory maps to COMPLETED/PASS."""
        adapter = self._adapter()
        scenario = _scenario()
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(),
            context=_context(scenario.id),
        )
        assert result.evaluator_id == COORDINATOR_TRAJECTORY_CONTRACT_EVALUATOR_ID
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.PASS

    @pytest.mark.asyncio
    async def test_e02_existing_evaluator_fail_maps_to_fail(self) -> None:
        """E02 a failing trajectory maps to COMPLETED/FAIL."""
        adapter = self._adapter()
        scenario = _scenario()
        # Wrong stop reason: the terminal INVESTIGATION_STOPPED mismatch.
        wrong = _output(final_state=_state(stop_reason="no_eligible_pivots"))
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert result.execution_status is EvaluationExecutionStatus.COMPLETED
        assert result.verdict is EvaluationVerdict.FAIL

    @pytest.mark.asyncio
    async def test_e03_explanation_deterministic_and_bounded(self) -> None:
        """E03 the FAIL explanation is deterministic and bounded."""
        adapter = self._adapter()
        scenario = _scenario()
        wrong = _output(final_state=_state(stop_reason="no_eligible_pivots"))
        first = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        second = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert first.explanation == second.explanation
        assert first.explanation.strip()
        assert len(first.explanation) <= 2000

    @pytest.mark.asyncio
    async def test_e04_metrics_are_diagnostics_only(self) -> None:
        """E04 metrics surface as JSON-safe descriptive diagnostics."""
        adapter = self._adapter()
        scenario = _scenario()
        wrong = _output(final_state=_state(stop_reason="no_eligible_pivots"))
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert "termination" in result.diagnostics
        import json

        json.dumps(dict(result.diagnostics))

    @pytest.mark.asyncio
    async def test_e05_metric_only_variation_never_decides_verdict(self) -> None:
        """E05 diagnostic variation never flips a FAIL to PASS."""
        adapter = self._adapter()
        scenario = _scenario()
        wrong = _output(final_state=_state(stop_reason="no_eligible_pivots"))
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert result.diagnostics["stop_decision_accuracy"] == 0.0

    @pytest.mark.asyncio
    async def test_e06_evaluator_exception_is_error(self) -> None:
        """E06 an exception inside the existing evaluator surfaces as ERROR."""

        class ExplodingEvaluator:
            """Existing-evaluator double raising from evaluate."""

            def evaluate(self, **kwargs: object) -> object:
                """Raise a bounded failure."""
                del kwargs
                raise RuntimeError("evaluator blew up")

        scenario = _scenario()
        adapter = CoordinatorTrajectoryContractEvaluator(
            scenario_lookup=CoordinatorScenarioLookup([scenario]),
            evaluator=ExplodingEvaluator(),  # type: ignore[arg-type]
        )
        result = await EvaluationRunner().run(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.COORDINATOR, version=1
            ),
            cases=[evaluation_case_from(scenario)],
            target=self._passing_target(scenario),
            evaluators=(adapter,),  # type: ignore[arg-type]
        )
        assert result.execution_status is EvaluationExecutionStatus.ERROR
        assert result.verdict is None

    @pytest.mark.asyncio
    async def test_e07_cancellation_propagates(self) -> None:
        """E07 asyncio.CancelledError propagates unchanged through the adapter."""

        class CancellingEvaluator:
            """Existing-evaluator double raising cancellation."""

            def evaluate(self, **kwargs: object) -> object:
                """Raise cancellation."""
                del kwargs
                raise asyncio.CancelledError("cancelled")

        scenario = _scenario()
        adapter = CoordinatorTrajectoryContractEvaluator(
            scenario_lookup=CoordinatorScenarioLookup([scenario]),
            evaluator=CancellingEvaluator(),  # type: ignore[arg-type]
        )
        with pytest.raises(asyncio.CancelledError):
            await adapter.evaluate(
                case=evaluation_case_from(scenario),
                output=_output(),
                context=_context(scenario.id),
            )

    @pytest.mark.asyncio
    async def test_e08_policy_invalid_pivot_is_fail(self) -> None:
        """E08 an unauthorized executed pivot FAILs through the adapter."""
        adapter = self._adapter()
        scenario = _scenario()
        invalid_actions = _passing_actions() + (
            CoordinatorActionRecord(
                action=ACTION_PIVOT_EXECUTED, entity_id=_MALWARE, depth=1
            ),
        )
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(
                final_state=_state(discovered_entity_ids=[_IP, _MALWARE]),
                actions=invalid_actions,
            ),
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "policy_invalid_pivot" in result.explanation

    @pytest.mark.asyncio
    async def test_e09_duplicate_research_request_is_fail(self) -> None:
        """E09 a duplicate research request FAILs through the adapter."""
        scenario = _scenario(
            expected=ExpectedCoordinatorTrajectory(
                allowed_pivots=(ExpectedPivot(entity="resolved_ip", depth=1),),
                required_pivots=("resolved_ip",),
                expected_stop_reason=StopReason.SUFFICIENT_EVIDENCE,
                max_research_requests=1,
            )
        )
        adapter = CoordinatorTrajectoryContractEvaluator(
            scenario_lookup=CoordinatorScenarioLookup([scenario])
        )
        state = _state(
            research_executions=(),
            research_required_for_entity_ids=(_MALWARE,),
        )
        duplicate_actions = _passing_actions() + (
            CoordinatorActionRecord(
                action=ACTION_RESEARCH_REQUESTED, entity_id=_MALWARE
            ),
            CoordinatorActionRecord(
                action=ACTION_RESEARCH_REQUESTED, entity_id=_MALWARE
            ),
        )
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=_output(final_state=state, actions=duplicate_actions),
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "duplicate_research_request" in result.explanation

    @pytest.mark.asyncio
    async def test_e10_wrong_stop_reason_is_fail(self) -> None:
        """E10 a mismatched stop reason FAILs through the adapter."""
        adapter = self._adapter()
        scenario = _scenario()
        wrong = _output(
            final_state=_state(stop_reason="provider_budget_exhausted"),
            actions=_terminal_stop_actions(),
        )
        result = await adapter.evaluate(
            case=evaluation_case_from(scenario),
            output=wrong,
            context=_context(scenario.id),
        )
        assert result.verdict is EvaluationVerdict.FAIL
        assert "stop_reason_mismatch" in result.explanation

    @staticmethod
    def _passing_target(scenario: CoordinatorScenario) -> Any:
        """Build a target double that returns a passing output."""

        class ReturningTarget:
            """Target double returning a typed output for any case."""

            async def execute(self, *, case: object, context: object) -> object:
                """Return the canonical output."""
                del case, context
                return _output()

        return ReturningTarget()


@pytest.mark.asyncio
async def test_run_service_rejects_non_coordinator() -> None:
    """The run service rejects non-Coordinator datasets before any execution."""
    analysed = False
    from agentic_threat_investigator.evaluation.common import DatasetLoadError

    async def analysis_factory(investigation_id: UUID, materialized: object) -> object:
        """Noop (never reached)."""
        nonlocal analysed
        del investigation_id, materialized
        analysed = True
        return object()

    with pytest.raises(DatasetLoadError):
        await run_coordinator_evaluation(
            dataset_id=EvaluationDatasetId(
                target=EvaluationTarget.EVIDENCE_ANALYST, version=1
            ),
            uow_factory=lambda: cast(UnitOfWork, _FakeUoW(events=[])),
            analysis_factory=cast(Any, analysis_factory),
        )
    assert not analysed
