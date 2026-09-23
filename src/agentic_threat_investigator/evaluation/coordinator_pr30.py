# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30D Coordinator evaluation execution adapters.

Executes repository-owned :class:`CoordinatorScenario` cases through the
**production Coordinator graph/policy** (materialized fixture world,
:class:`~agentic_threat_investigator.app.orchestration.runner.LocalInvestigationRunner`,
durable transitions/timeline) and evaluates the durable final
:class:`~agentic_threat_investigator.domain.investigation.InvestigationState`
plus structured action records with the existing
:class:`~agentic_threat_investigator.evaluation.coordinator.CoordinatorTrajectoryEvaluator`:

.. code-block:: text

    common EvaluationCase
     -> exact typed CoordinatorScenario lookup
     -> run-scoped fixture materialization (execution identity)
     -> production Coordinator graph/policy (fixture world)
     -> durable terminal InvestigationState
     -> structured timeline actions (never logs)
     -> CoordinatorTrajectoryEvaluator (PR 30 adapter)
     -> common EvaluationRunner
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.investigation import InvestigationState
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationCase,
    EvaluationContext,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationResult,
    EvaluationRunner,
    EvaluationRunResult,
    EvaluationTarget,
    EvaluationVerdict,
    evaluation_case_from,
)
from agentic_threat_investigator.evaluation.common.evaluator import (
    Evaluator,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.coordinator import (
    CoordinatorActionRecord,
    CoordinatorEvaluationResult,
    CoordinatorScenario,
    CoordinatorScenarioResolution,
    CoordinatorTrajectoryEvaluator,
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.coordinator_fixtures import (
    CoordinatorFixtureRunner,
)
from agentic_threat_investigator.evaluation.scenario_fixtures import (
    CoordinatorMaterializedFixture,
    CoordinatorScenarioMaterializer,
)

ScenarioIdentity = tuple[str, int]
"""One exact scenario identity: ``(case_id, case_version)``."""

AnalysisExecutorFactory = Callable[
    [UUID, CoordinatorMaterializedFixture],
    Awaitable[EvidenceAnalystAnalysisExecutor],
]
"""Build one production analysis executor for an Investigation + fixture."""

ResearchExecutorFactory = Callable[
    [UUID, CoordinatorMaterializedFixture],
    Awaitable[ResearchAgentResearchExecutor],
]
"""Build one production research executor for an Investigation + fixture."""


class CoordinatorScenarioLookupError(ValueError):
    """A common case cannot be resolved to exactly one typed Coordinator scenario."""


class CoordinatorScenarioLookup:
    """Immutable run-scoped ``(case_id, version) -> CoordinatorScenario`` map."""

    def __init__(self, scenarios: Sequence[CoordinatorScenario]) -> None:
        """Index every scenario by its exact ``(id, version)`` identity."""
        index: dict[ScenarioIdentity, CoordinatorScenario] = {}
        for scenario in scenarios:
            identity = (scenario.id, scenario.version)
            if identity in index:
                raise CoordinatorScenarioLookupError(
                    f"duplicate scenario identity {scenario.id}@v{scenario.version}"
                )
            index[identity] = scenario
        self._index = index

    def require(self, case_id: str, version: int) -> CoordinatorScenario:
        """Return the exact typed scenario or fail closed."""
        try:
            return self._index[(case_id, version)]
        except KeyError as exc:
            raise CoordinatorScenarioLookupError(
                f"no typed coordinator scenario resolves {case_id}@v{version}"
            ) from exc


class CoordinatorEvaluationOutput(BaseModel):
    """Typed payload one evaluator consumes for one executed Coordinator case.

    Carries the durable terminal Investigation, the runtime label
    resolution, the structured action records converted from the durable
    timeline (never logs), and the deterministic transition span. No
    LangSmith identity, log text, or raw provider output ever appears.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    final_state: InvestigationState
    """The durable terminal InvestigationState of the current run."""

    resolution: CoordinatorScenarioResolution
    """Runtime semantic-label resolution of the executed fixture."""

    actions: tuple[CoordinatorActionRecord, ...]
    """Structured action records from the durable timeline."""

    observed_transitions: int
    """Deterministic durable-version transition span of the run."""


def observed_transition_span(*, initial_version: int, final_version: int) -> int:
    """Return the deterministic durable-version transition span of one run.

    Mirrors the canonical PR 22C evaluation slice: the span is at least one
    and bounded by the scenario's ``max_transitions`` envelope.
    """
    return max(1, (final_version or 0) - (initial_version or 0) + 1)


class CoordinatorScenarioTargetExecutor(TargetExecutor[CoordinatorEvaluationOutput]):
    """Run one common Coordinator case through the production graph/policy.

    Each case materializes into a **run-scoped** Investigation (semantic
    labels preserved; execution-scoped identity so repeated runs never
    collide) and executes the production graph through the composed fixture
    runner with the caller-supplied analysis and research executor factories.
    No fake Coordinator policy is used.
    """

    def __init__(
        self,
        *,
        scenario_lookup: CoordinatorScenarioLookup,
        materializer: CoordinatorScenarioMaterializer,
        uow_factory: Callable[[], UnitOfWork],
        analysis_factory: AnalysisExecutorFactory,
        research_factory: ResearchExecutorFactory | None = None,
        clock: Callable[[], datetime] | None = None,
        recursion_limit: int = 40,
        run_fixture: Callable[
            [CoordinatorMaterializedFixture], Awaitable[InvestigationState]
        ]
        | None = None,
    ) -> None:
        """Bind the lookup, materializer, persistence, and executor seams.

        ``run_fixture`` is an optional composition seam (tests inject a
        deterministic double); the default binds the production fixture
        runner to the caller's analysis/research executor factories.
        """
        self._scenario_lookup = scenario_lookup
        self._materializer = materializer
        self._uow_factory = uow_factory
        self._analysis_factory = analysis_factory
        self._research_factory = research_factory
        self._clock = clock
        self._recursion_limit = recursion_limit
        self._run_fixture = run_fixture

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> CoordinatorEvaluationOutput:
        """Materialize, execute, and capture one durable trajectory."""
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        execution_id = uuid4()
        materialized = await self._materializer.materialize(
            scenario, self._uow_factory, execution_id=execution_id
        )
        investigation_id = materialized.initial_state.investigation_id
        analysis_executor = await self._analysis_factory(investigation_id, materialized)
        research_executor = (
            await self._research_factory(investigation_id, materialized)
            if self._research_factory is not None
            else None
        )
        run_fixture = self._run_fixture
        if run_fixture is None:
            runner = CoordinatorFixtureRunner(
                uow_factory=self._uow_factory,
                analysis_executor_factory=lambda _investigation_id: analysis_executor,
                research_executor_factory=(
                    (lambda _investigation_id: research_executor)
                    if research_executor is not None
                    else None
                ),
                clock=self._clock,
                recursion_limit=self._recursion_limit,
            )

            async def run_fixture(
                materialized: CoordinatorMaterializedFixture,
            ) -> InvestigationState:
                """Run the bound production fixture world once."""
                return await runner.run(materialized)

        final_state = await run_fixture(materialized)
        events = await _load_timeline_events(
            self._uow_factory, investigation_id=investigation_id
        )
        actions = _coordinator_actions(events)
        return CoordinatorEvaluationOutput(
            final_state=final_state,
            resolution=materialized.resolution,
            actions=actions,
            observed_transitions=observed_transition_span(
                initial_version=materialized.initial_state.version or 0,
                final_version=(final_state.version or 0),
            ),
        )


async def _load_timeline_events(
    uow_factory: Callable[[], UnitOfWork], *, investigation_id: UUID
) -> tuple[object, ...]:
    """Load one investigation's durable timeline events."""

    async with uow_factory() as uow:
        events = await uow.timeline_events.list_by_investigation(investigation_id)
    return tuple(events)


def _coordinator_actions(
    events: tuple[object, ...],
) -> tuple[CoordinatorActionRecord, ...]:
    """Convert durable timeline events into structured action records."""
    from agentic_threat_investigator.app.orchestration.timeline_actions import (
        convert_timeline_actions,
    )
    from agentic_threat_investigator.domain.investigation_timeline import (
        InvestigationTimelineEvent,
    )

    typed = tuple(
        event for event in events if isinstance(event, InvestigationTimelineEvent)
    )
    return convert_timeline_actions(typed)


COORDINATOR_TRAJECTORY_CONTRACT_EVALUATOR_ID = "coordinator-trajectory-contract"
"""Stable evaluator id for the Coordinator trajectory-contract adapter."""

_PASS_EXPLANATION = (  # nosec B105 - canonical PR 30 PASS explanation text, never a credential
    "the durable trajectory satisfies the scenario's expected-coordinator contract"
)
"""Deterministic nonblank PASS explanation of the PR 30D adapter."""

_MAX_FAILURE_MESSAGE_LENGTH = 2000
"""Bounded length of one concatenated FAIL explanation."""


def _metrics_diagnostics(result: CoordinatorEvaluationResult) -> dict[str, Any]:
    """Project deterministic Coordinator metrics onto JSON-safe diagnostics.

    Metrics are descriptive only; no recall/coverage threshold ever
    determines a verdict.
    """
    return {
        key: float(value) if isinstance(value, (int, float)) else value
        for key, value in result.metrics.items()
    }


def _failure_explanation(result: CoordinatorEvaluationResult) -> str:
    """Render the deterministic nonblank FAIL explanation from stable codes."""
    joined = ", ".join(code.value for code in result.failures)
    if not joined:  # pragma: no cover - passed == (not failures)
        return "the durable trajectory violates the scenario's expected-coordinator contract"
    if len(joined) > _MAX_FAILURE_MESSAGE_LENGTH:
        return joined[:_MAX_FAILURE_MESSAGE_LENGTH].rstrip() + "[truncated]"
    return joined


class CoordinatorTrajectoryContractEvaluator(Evaluator[CoordinatorEvaluationOutput]):
    """PR 30 adapter deciding PASS/FAIL from the existing evaluator result.

    Stateless: every input arrives through :meth:`evaluate`; the exact typed
    scenario comes from the run-scoped lookup; the existing
    :class:`CoordinatorTrajectoryEvaluator` remains the semantic authority.
    No LangSmith, provider SDK, or LLM client is ever touched here.
    """

    def __init__(
        self,
        *,
        scenario_lookup: CoordinatorScenarioLookup,
        evaluator: CoordinatorTrajectoryEvaluator | None = None,
    ) -> None:
        """Bind the lookup and the existing deterministic evaluator."""
        self._scenario_lookup = scenario_lookup
        self._evaluator = evaluator or CoordinatorTrajectoryEvaluator()

    @property
    def evaluator_id(self) -> str:
        """Return the stable PR 30 Coordinator evaluator identifier."""
        return COORDINATOR_TRAJECTORY_CONTRACT_EVALUATOR_ID

    async def evaluate(
        self,
        *,
        case: EvaluationCase,
        output: CoordinatorEvaluationOutput,
        context: EvaluationContext,
    ) -> EvaluationResult:
        """Decide PASS/FAIL for one durable trajectory (ERROR on exceptions)."""
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        result = self._evaluator.evaluate(
            scenario=scenario,
            resolution=output.resolution,
            final_state=output.final_state,
            actions=output.actions,
            observed_transitions=output.observed_transitions,
        )
        if result.passed:
            return EvaluationResult(
                evaluator_id=self.evaluator_id,
                execution_status=EvaluationExecutionStatus.COMPLETED,
                verdict=EvaluationVerdict.PASS,
                explanation=_PASS_EXPLANATION,
                diagnostics=_metrics_diagnostics(result),
            )
        return EvaluationResult(
            evaluator_id=self.evaluator_id,
            execution_status=EvaluationExecutionStatus.COMPLETED,
            verdict=EvaluationVerdict.FAIL,
            explanation=_failure_explanation(result),
            diagnostics=_metrics_diagnostics(result),
        )


async def run_coordinator_evaluation(
    *,
    dataset_id: EvaluationDatasetId,
    uow_factory: Callable[[], UnitOfWork],
    analysis_factory: AnalysisExecutorFactory,
    research_factory: ResearchExecutorFactory | None = None,
    scenarios: Sequence[CoordinatorScenario] | None = None,
    corpus_root: Path = Path("evals/scenarios/coordinator"),
    materializer: CoordinatorScenarioMaterializer | None = None,
    clock: Callable[[], datetime] | None = None,
    recursion_limit: int = 40,
) -> EvaluationRunResult:
    """Run the Coordinator benchmark and return the canonical result.

    Requires the Coordinator target; loads typed repository scenarios (or
    accepts an explicit tuple), builds the exact lookup, binds the target and
    evaluator, and invokes the common runner. No LangSmith dependency.
    """
    if dataset_id.target is not EvaluationTarget.COORDINATOR:
        raise DatasetLoadError(
            f"PR 30D supports only coordinator datasets, got {dataset_id.canonical}"
        )
    if scenarios is None:
        scenarios = load_coordinator_scenarios_directory(corpus_root)
    if not scenarios:
        raise DatasetLoadError(
            f"no typed coordinator scenarios loaded for {dataset_id.canonical}"
        )

    lookup = CoordinatorScenarioLookup(scenarios)
    bound_materializer = materializer or CoordinatorScenarioMaterializer()
    target: TargetExecutor[CoordinatorEvaluationOutput] = (
        CoordinatorScenarioTargetExecutor(
            scenario_lookup=lookup,
            materializer=bound_materializer,
            uow_factory=uow_factory,
            analysis_factory=analysis_factory,
            research_factory=research_factory,
            clock=clock,
            recursion_limit=recursion_limit,
        )
    )
    evaluator = CoordinatorTrajectoryContractEvaluator(scenario_lookup=lookup)
    runner = EvaluationRunner()
    cases = tuple(evaluation_case_from(scenario) for scenario in scenarios)
    return await runner.run(
        dataset_id=dataset_id,
        cases=cases,
        target=target,
        # PR 30A freezes the runner seam as Evaluator[object]; the concrete
        # typed evaluator is accepted at runtime through the contravariant
        # protocol boundary (see analyst/run.py).
        evaluators=(evaluator,),  # type: ignore[arg-type]
    )
