# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30F end-to-end Investigation target execution adapter.

Executes repository-owned :class:`InvestigationScenario` cases through the
**real production end-to-end path** and returns the typed payload the PR 30F
evaluator consumes:

.. code-block:: text

    common EvaluationCase
     -> exact typed InvestigationScenario lookup
     -> run-scoped fixture materialization (execution identity)
     -> production LocalInvestigationRunner (production Coordinator graph)
     -> production providers/extractors/persistence (fixture world truth)
     -> production Evidence Analyst (injected LlmClient)
     -> production Research Agent when authorized (injected LlmClient)
     -> terminal durable InvestigationState
     -> final current Assessment (persistence)
     -> production ReportWriter after terminal state (injected LlmClient)
     -> persisted InvestigationReport
     -> authoritative durable snapshot + structured trajectory actions
     -> InvestigationEvaluationOutput(resolution, metrics, snapshot)

The target never calls the LLM client directly (the production components
own that), never evaluates before persistence, never touches LangSmith, and
never performs any aggregation. Unexpected production failures (including
Report Writer failures) propagate and become a case ERROR through the common
runner; cancellation always propagates unchanged.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    ACTION_ASSESSMENT_REQUESTED,
    ACTION_PIVOT_EXECUTED,
    ACTION_PROVIDER_QUERY,
    ACTION_RESEARCH_REQUESTED,
    convert_timeline_actions,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    Evidence,
    EvidenceObservation,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    is_terminal_status,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
)
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
)
from agentic_threat_investigator.domain.report import InvestigationReport
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.evaluation.common.evaluator import (
    EvaluationContext,
    TargetExecutor,
)
from agentic_threat_investigator.evaluation.common.models import EvaluationCase
from agentic_threat_investigator.evaluation.coordinator import CoordinatorActionRecord
from agentic_threat_investigator.evaluation.investigation.composition import (
    InvestigationWorld,
    compose_investigation_world,
)
from agentic_threat_investigator.evaluation.investigation.fixtures import (
    InvestigationFixture,
    build_investigation_provider_registry,
    investigation_fixture,
)
from agentic_threat_investigator.evaluation.investigation.materialization import (
    InvestigationScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.investigation.models import (
    InvestigationEvaluationOutput,
    InvestigationExecutionMetrics,
    InvestigationScenario,
)

ScenarioIdentity = tuple[str, int]
"""One exact scenario identity: ``(case_id, case_version)``."""

WorldFactory = Callable[
    [Mapping[SourceId, EvidenceProvider]], Awaitable[InvestigationWorld]
]
"""Build one production-composed investigation world for a fixture registry."""

RunnerInvoker = Callable[[InvestigationWorld, UUID], Awaitable[InvestigationState]]
"""Run one composed world's production runner for an Investigation."""

ReportInvoker = Callable[[InvestigationWorld, UUID], Awaitable[InvestigationReport]]
"""Write one composed world's production report for an Investigation."""


class InvestigationScenarioLookupError(ValueError):
    """A common case cannot be resolved to exactly one typed scenario.

    The target fails closed on unknown cases, duplicate identities, and any
    identity that does not exactly match the loaded repository corpus. The
    repository is the executable source of scenarios; no identity is ever
    reconstructed from LangSmith or remote example metadata.
    """


class InvestigationScenarioLookup:
    """Immutable run-scoped ``(case_id, version) -> InvestigationScenario`` map."""

    def __init__(self, scenarios: Sequence[InvestigationScenario]) -> None:
        """Index every scenario by its exact ``(id, version)`` identity."""
        index: dict[ScenarioIdentity, InvestigationScenario] = {}
        for scenario in scenarios:
            identity = (scenario.id, scenario.version)
            if identity in index:
                raise InvestigationScenarioLookupError(
                    f"duplicate scenario identity {scenario.id}@v{scenario.version}"
                )
            index[identity] = scenario
        self._index = index

    def require(self, case_id: str, version: int) -> InvestigationScenario:
        """Return the exact typed scenario or fail closed."""
        try:
            return self._index[(case_id, version)]
        except KeyError as exc:
            raise InvestigationScenarioLookupError(
                f"no typed investigation scenario resolves {case_id}@v{version}"
            ) from exc


class InvestigationTargetError(ValueError):
    """A typed execution-stage failure of the end-to-end target.

    The message is a fixed safe string that never embeds identifiers,
    prompts, model output, or provider payloads.
    """

    def __init__(self, message: str) -> None:
        """Record the fixed safe execution-stage message."""
        super().__init__(message)


class InvestigationSnapshot(BaseModel):
    """Authoritative durable snapshot consumed by the evaluator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    final_state: InvestigationState
    final_assessment: Assessment
    report: InvestigationReport | None
    evidence_observations: tuple[EvidenceObservation, ...] = ()
    stable_evidence: tuple[Evidence, ...] = ()
    entities: tuple[Entity, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    relationship_observations: tuple[RelationshipObservation, ...] = ()
    research_results: tuple[ResearchResult, ...] = ()
    actions: tuple[CoordinatorActionRecord, ...] = ()


def derive_execution_metrics(
    *,
    final_state: InvestigationState,
    actions: Sequence[CoordinatorActionRecord],
    llm_calls: int,
) -> InvestigationExecutionMetrics:
    """Derive bounded deterministic observations from durable state/actions.

    Provider/replan counters come from the persisted Investigation budget;
    pivots, duplicates, depth, and total actions come from the structured
    timeline actions; the model-call count comes from the transparent
    ``LlmClient`` counter. Logs are never inspected.
    """
    pivots = [action for action in actions if action.action is ACTION_PIVOT_EXECUTED]
    queries = [action for action in actions if action.action is ACTION_PROVIDER_QUERY]
    executed_entity_ids = [pivot.entity_id for pivot in pivots]
    maximum_depth = max((pivot.depth or 0) for pivot in pivots) if pivots else 0
    return InvestigationExecutionMetrics(
        provider_calls=final_state.budget.provider_calls_used,
        llm_calls=llm_calls,
        analysis_calls=_action_count(actions, ACTION_ASSESSMENT_REQUESTED),
        research_calls=_action_count(actions, ACTION_RESEARCH_REQUESTED),
        report_calls=1 if final_state.report_id is not None else 0,
        replans=final_state.budget.replans_used,
        pivot_count=len(pivots),
        duplicate_provider_calls=_duplicate_count(
            (query.provider, query.entity_id) for query in queries
        ),
        duplicate_entity_investigations=_duplicate_count(executed_entity_ids),
        total_actions=len(actions),
        maximum_depth_observed=maximum_depth,
    )


def _action_count(actions: Sequence[CoordinatorActionRecord], action: str) -> int:
    """Return the number of structured actions with the exact URN."""
    return sum(1 for record in actions if record.action == action)


def _duplicate_count(keys: Iterable[object]) -> int:
    """Count keys that appeared earlier in the sequence (extra occurrences).

    Duplicates are counted per extra occurrence: one repeated key adds one,
    three repeated keys add three. This matches the envelope semantics
    ``observed_duplicates <= authored_max`` where a healthy trajectory has
    zero.
    """
    seen: list[object] = []
    duplicates = 0
    for key in keys:
        if key in seen:
            duplicates += 1
        seen.append(key)
    return duplicates


class InvestigationTargetExecutor(TargetExecutor[InvestigationEvaluationOutput]):
    """Run one common Investigation case through the production end-to-end path.

    Materialization runs in a short UnitOfWork transaction and closes before
    the runner's own short transactions (provider work, analysis, research,
    persistence), so no database transaction is ever held across provider or
    model I/O. Each execution gets a fresh run-scoped identity
    (``execution_id``), so repeated runs of the same case never collide and
    never destructively reset history; canonical Entity identities may be
    reused.
    """

    def __init__(
        self,
        *,
        scenario_lookup: InvestigationScenarioLookup,
        uow_factory: Callable[[], UnitOfWork],
        llm_client: LlmClient,
        materializer: InvestigationScenarioMaterializer | None = None,
        world_factory: WorldFactory | None = None,
        run_investigation: RunnerInvoker | None = None,
        write_report: ReportInvoker | None = None,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
        batch_size: int = 100,
        max_structured_output_attempts: int = 2,
        clock: Callable[[], datetime] | None = None,
        recursion_limit: int = 120,
    ) -> None:
        """Bind the lookup, persistence, model, and composition seams.

        ``world_factory`` builds one production investigation world per case
        (defaults to the existing composition); ``run_investigation`` and
        ``write_report`` invoke the composed runner/writer (defaults to the
        production implementations); tests inject deterministic doubles.
        """
        self._scenario_lookup = scenario_lookup
        self._uow_factory = uow_factory
        self._llm_client = llm_client
        self._materializer = materializer or InvestigationScenarioMaterializer()
        self._world_factory = world_factory
        self._run_investigation = run_investigation
        self._write_report = write_report
        self._session_factory = session_factory
        self._batch_size = batch_size
        self._max_structured_output_attempts = max_structured_output_attempts
        self._clock = clock
        self._recursion_limit = recursion_limit

    async def execute(
        self,
        *,
        case: EvaluationCase,
        context: EvaluationContext,
    ) -> InvestigationEvaluationOutput:
        """Materialize, execute, report, and capture one end-to-end case.

        ``context`` carries stable identity only and is validated by the
        runner before the case executes; the exact typed scenario comes from
        the run-scoped lookup. The production runner must reach a terminal
        durable state and a final current Assessment must exist before the
        production Report Writer runs; the report must persist. Any failure
        propagates as ERROR through the common runner and cancellation
        propagates unchanged.
        """
        del context
        scenario = self._scenario_lookup.require(case.case_id, case.version)
        fixture = investigation_fixture(scenario.fixture)
        execution_id = uuid4()
        resolution = await self._materializer.materialize(
            scenario,
            fixture,
            self._uow_factory,
            execution_id=execution_id,
        )
        world = await self._build_world(fixture)
        final_state = await self._invoke_runner(world, resolution.investigation_id)
        if not is_terminal_status(final_state.status):
            raise InvestigationTargetError(
                "investigation target requires a terminal durable state"
            )
        assessment = await self._load_assessment(final_state)
        if assessment is None:
            raise InvestigationTargetError(
                "investigation target requires a final current assessment"
            )
        report = await self._invoke_writer(world, resolution.investigation_id)
        snapshot = await self._load_snapshot(
            resolution.investigation_id,
            assessment=assessment,
            report=report,
        )
        persisted_resolution = await self._materializer.resolve_persisted(
            scenario,
            fixture,
            self._uow_factory,
            investigation_id=resolution.investigation_id,
        )
        metrics = derive_execution_metrics(
            final_state=snapshot.final_state,
            actions=snapshot.actions,
            llm_calls=world.counting.calls,
        )
        return InvestigationEvaluationOutput(
            final_investigation=snapshot.final_state,
            final_assessment=snapshot.final_assessment,
            report=snapshot.report,
            evidence_observations=snapshot.evidence_observations,
            stable_evidence=snapshot.stable_evidence,
            entities=snapshot.entities,
            relationships=snapshot.relationships,
            relationship_observations=snapshot.relationship_observations,
            research_results=snapshot.research_results,
            actions=snapshot.actions,
            execution_metrics=metrics,
            resolution=persisted_resolution,
        )

    async def _build_world(self, fixture: InvestigationFixture) -> InvestigationWorld:
        """Compose (or inject) the production investigation world."""
        registry = build_investigation_provider_registry(fixture)
        world_factory = self._world_factory
        if world_factory is None:
            if self._session_factory is None:
                raise InvestigationTargetError(
                    "investigation target requires a session factory for composition"
                )
            bound_session_factory = self._session_factory

            async def world_factory(
                provider_registry: Mapping[SourceId, EvidenceProvider],
            ) -> InvestigationWorld:
                """Compose the production world over the fixture registry."""
                return compose_investigation_world(
                    uow_factory=self._uow_factory,
                    session_factory=bound_session_factory,
                    llm_client=self._llm_client,
                    provider_registry=provider_registry,
                    batch_size=self._batch_size,
                    max_structured_output_attempts=(
                        self._max_structured_output_attempts
                    ),
                    clock=self._clock,
                    recursion_limit=self._recursion_limit,
                )

        return await world_factory(registry)

    async def _invoke_runner(
        self, world: InvestigationWorld, investigation_id: UUID
    ) -> InvestigationState:
        """Execute the production runner (or the injected double)."""
        invoker = self._run_investigation
        if invoker is None:

            async def invoker(
                bound: InvestigationWorld, investigation_id: UUID
            ) -> InvestigationState:
                """Run the composed production runner once."""
                return await bound.runner.run(investigation_id)

        return await invoker(world, investigation_id)

    async def _invoke_writer(
        self, world: InvestigationWorld, investigation_id: UUID
    ) -> InvestigationReport:
        """Write the production report (or the injected double)."""
        writer = self._write_report
        if writer is None:

            async def writer(
                bound: InvestigationWorld, investigation_id: UUID
            ) -> InvestigationReport:
                """Write one production report after terminal state."""
                return await bound.report_writer.write(investigation_id)

        return await writer(world, investigation_id)

    async def _load_assessment(
        self, final_state: InvestigationState
    ) -> Assessment | None:
        """Load the final current Assessment from its durable pointer."""
        if final_state.assessment_id is None:
            return None
        async with self._uow_factory() as uow:
            return await uow.assessments.get_by_id(final_state.assessment_id)

    async def _load_snapshot(
        self,
        investigation_id: UUID,
        *,
        assessment: Assessment,
        report: InvestigationReport | None,
    ) -> InvestigationSnapshot:
        """Reload the authoritative durable snapshot through one short UoW.

        The reloaded Investigation is authoritative: the Report Writer's
        report-pointer update and any final version advance are observed
        here. The loaded report must match the writer's return value identity
        (the writer persists atomically before returning).
        """
        async with self._uow_factory() as uow:
            state = await uow.investigations.get_by_id(investigation_id)
            if state is None:
                raise InvestigationTargetError(
                    "investigation target cannot reload its investigation"
                )
            persisted_report = (
                await uow.investigation_reports.get_by_id(state.report_id)
                if state.report_id is not None
                else None
            )
            evidence_observations = await uow.evidence.list_for_investigation(
                investigation_id, limit=1000
            )
            stable_evidence: list[Evidence] = []
            for evidence_observation in evidence_observations:
                evidence = await uow.evidence.get_stable_evidence(
                    evidence_observation.evidence_id
                )
                if evidence is not None:
                    stable_evidence.append(evidence)
            entities: list[Entity] = []
            for entity_id in state.root_entity_ids + state.discovered_entity_ids:
                entity = await uow.entities.get_by_id(entity_id)
                if entity is not None:
                    entities.append(entity)
            relationship_observations = (
                await uow.relationship_observations.list_for_investigation(
                    investigation_id, limit=1000
                )
            )
            relationships: list[Relationship] = []
            # The current Coordinator persists relationship observations rather
            # than the legacy Investigation-level relationship-id list, so the
            # authoritative durable relationship set is derived from the
            # observations' exact relationship identities (deduplicated).
            seen_relationship_ids: set[UUID] = set()
            for relationship_observation in relationship_observations:
                if relationship_observation.relationship_id in seen_relationship_ids:
                    continue
                seen_relationship_ids.add(relationship_observation.relationship_id)
                relationship = await uow.relationships.get_by_id(
                    relationship_observation.relationship_id
                )
                if relationship is not None:
                    relationships.append(relationship)
            research_results = await uow.research_results.list_by_investigation(
                investigation_id
            )
            events = await uow.timeline_events.list_by_investigation(investigation_id)
        typed_events = tuple(
            event for event in events if isinstance(event, InvestigationTimelineEvent)
        )
        actions = convert_timeline_actions(typed_events)
        if (
            report is not None
            and persisted_report is not None
            and report.id != persisted_report.id
        ):
            raise InvestigationTargetError(
                "investigation target report identity differs from durable state"
            )
        return InvestigationSnapshot(
            final_state=state,
            final_assessment=assessment,
            report=persisted_report,
            evidence_observations=tuple(evidence_observations),
            stable_evidence=tuple(stable_evidence),
            entities=tuple(entities),
            relationships=tuple(relationships),
            relationship_observations=tuple(relationship_observations),
            research_results=tuple(research_results),
            actions=actions,
        )
