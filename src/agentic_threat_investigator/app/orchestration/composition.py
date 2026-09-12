# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Production composition seam for the provider-backed investigation graph.

One public factory assembles the PR 21 coordinator-driven execution path from
the injected UnitOfWork factory, provider registry, planner, analysis
executor, and execution context, then wires it into the coordinator graph. A
later worker/bootstrap entry point calls this factory; no worker, HTTP
client, provider instance, settings object, engine, or global registry is
constructed here — those remain bootstrap and infrastructure concerns.

Production composition always builds the coordinator topology; queue
exhaustion never terminates the graph.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from langgraph.graph.state import CompiledStateGraph

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.investigation_timeline import (
    UnitOfWorkInvestigationTimelineSink,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    AnalysisExecutor,
    CoordinatorEntityView,
    CoordinatorPolicy,
    ProviderWorkPlanner,
    ResearchRequestPlanner,
)
from agentic_threat_investigator.app.orchestration.dispatcher import LocalTaskDispatcher
from agentic_threat_investigator.app.orchestration.graph import (
    OrchestrationGraphState,
    build_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
    ProviderWorkExecutor,
    UowEntityReader,
)
from agentic_threat_investigator.app.orchestration.research import (
    DeterministicResearchRequestPlanner,
    ResearchExecutionReconciler,
    ResearchExecutor,
    UowResearchExecutionReconciler,
)
from agentic_threat_investigator.app.orchestration.services import (
    CoordinatorContextLoader,
    CoordinatorTransitionService,
    FatalStopService,
    InvestigationStatusWriter,
    UowCoordinatorContextLoader,
    UowCoordinatorTransitionService,
    UowFatalStopService,
    UowInvestigationStatusWriter,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    DeterministicTimelineActionService,
    TimelineActionService,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.app.providers import EvidenceProvider
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    ProviderWorkItem,
)

# Deterministic provider source order for v0.1 production planning. The
# planner derives entity-type applicability from each enabled provider's own
# deterministic supports(Entity) contract — never from a second capability
# table that can drift. Providers absent from the injected registry are never
# scheduled.
PROVIDER_SOURCE_ORDER: tuple[SourceId, ...] = (
    SourceId.GOOGLE_PUBLIC_DNS,
    SourceId.RDAP,
    SourceId.ABUSEIPDB,
    SourceId.THREATFOX,
    SourceId.URLHAUS,
    SourceId.IPINFO_LITE,
    SourceId.DBIP_CITY_LITE,
    SourceId.MITRE_ATTACK,
    SourceId.CISA_KEV,
)


class RegistryProviderWorkPlanner(ProviderWorkPlanner):
    """Deterministic planner over the ordered enabled provider registry.

    Applicability is evaluated per candidate against each enabled provider's
    own ``supports(Entity)`` contract using the exact persisted Entity
    identity (ID, type, and canonical value) carried by the coordinator view:
    no cached type matrix, no canonical-sample probing, and no drift from
    execution-time support. Provider order follows :data:`PROVIDER_SOURCE_ORDER`
    (a stable source-URN tie-break for sources outside that explicit order),
    and a registry key whose provider ID disagrees with the key is never
    scheduled. No network, clock, or provider execution happens during
    planning.
    """

    def __init__(
        self,
        registry: Mapping[SourceId, EvidenceProvider],
        source_order: Sequence[SourceId] = (),
    ) -> None:
        """Copy the enabled provider registry and optional explicit order."""
        self._registry = dict(registry)
        self._order = tuple(source_order)
        ordered_keys = {source: index for index, source in enumerate(self._order)}

        def sort_key(source: SourceId) -> tuple[int, str]:
            return (ordered_keys.get(source, len(self._order)), source.value)

        self._ordered_sources: tuple[SourceId, ...] = tuple(
            sorted(self._registry, key=sort_key)
        )

    def plan(
        self, *, entity: CoordinatorEntityView, depth: int, state: InvestigationState
    ) -> tuple[ProviderWorkItem, ...]:
        """Produce work in provider order for the real candidate Entity.

        Only enabled providers whose ``supports(Entity)`` accepts the exact
        persisted entity value are scheduled; a provider whose ``id`` does not
        match its registry key is skipped.
        """
        del state
        real_entity = Entity(
            id=entity.entity_id,
            type=entity.entity_type,
            value=entity.value,
            display_name=entity.value,
        )
        items: list[ProviderWorkItem] = []
        for source in self._ordered_sources:
            provider = self._registry[source]
            if provider.id != source.value:
                continue
            if provider.supports(real_entity):
                items.append(
                    ProviderWorkItem(
                        provider=source,
                        entity_id=entity.entity_id,
                        depth=depth,
                    )
                )
        return tuple(items)


def build_provider_investigation_graph(
    *,
    uow_factory: Callable[[], UnitOfWork],
    provider_registry: Mapping[SourceId, EvidenceProvider],
    context: ProviderExecutionContext,
    analysis_executor: AnalysisExecutor,
    planner: ProviderWorkPlanner | None = None,
    research_request_planner: ResearchRequestPlanner | None = None,
    research_executor: ResearchExecutor | None = None,
    research_reconciler: ResearchExecutionReconciler | None = None,
    context_loader: CoordinatorContextLoader | None = None,
    transition_service: CoordinatorTransitionService | None = None,
    status_writer: InvestigationStatusWriter | None = None,
    timeline_action_service: TimelineActionService | None = None,
    fatal_stop_service: FatalStopService | None = None,
) -> CompiledStateGraph[
    OrchestrationGraphState, None, OrchestrationGraphState, OrchestrationGraphState
]:
    """Build the compiled PR 21 coordinator-driven investigation graph.

    Assembles the short-transaction entity reader, the PR 18B extraction
    dispatcher, the PR 18C atomic persistence service, the UnitOfWork-backed
    timeline sink, the provider executor, the coordinator policy (with the
    deterministic production planner), the context loader, the transition
    service, and the status writer, then wires them into the coordinator
    graph. No global state is created.

    The compiled graph is bound to exactly one investigation ID
    (``context.investigation_id``): every invocation validates the wrapped
    state's investigation ID during ``initialize`` and raises
    ``InvestigationGraphContextMismatchError`` before work selection, target
    lookup, timeline emission, provider I/O, extraction, or persistence when
    the state belongs to a different investigation. The analysis executor is
    validated against the same binding before any LLM/persistence work.
    """
    if (
        analysis_executor.bound_investigation_id is not None
        and analysis_executor.bound_investigation_id != context.investigation_id
    ):
        raise ValueError(
            "analysis executor binding conflicts with investigation context"
        )
    effective_reconciler = research_reconciler or (
        UowResearchExecutionReconciler(uow_factory)
        if research_executor is not None
        else None
    )
    if (research_executor is not None) != (effective_reconciler is not None):
        raise ValueError("research executor and reconciler must be provided together")
    if research_request_planner is not None and research_executor is None:
        raise ValueError("research request planner requires a research executor")
    coordinator_planner = planner or RegistryProviderWorkPlanner(
        provider_registry, source_order=PROVIDER_SOURCE_ORDER
    )
    policy = CoordinatorPolicy(
        coordinator_planner,
        research_planner=(
            research_request_planner
            or (DeterministicResearchRequestPlanner() if research_executor else None)
        ),
    )

    executor = ProviderWorkExecutor(
        entity_reader=UowEntityReader(uow_factory),
        provider_registry=provider_registry,
        extractor=extract,
        persistence_service=ProviderObservationPersistenceService(uow_factory),
        timeline_service=UnitOfWorkInvestigationTimelineSink(uow_factory),
        context=context,
    )
    dispatcher = LocalTaskDispatcher(executor)
    return build_investigation_graph(
        dispatcher,
        coordinator_policy=policy,
        context_loader=context_loader
        or UowCoordinatorContextLoader(
            uow_factory, bound_investigation_id=context.investigation_id
        ),
        analysis_executor=analysis_executor,
        transition_service=transition_service
        or UowCoordinatorTransitionService(
            uow_factory, bound_investigation_id=context.investigation_id
        ),
        status_writer=status_writer
        or UowInvestigationStatusWriter(
            uow_factory, bound_investigation_id=context.investigation_id
        ),
        timeline_action_service=timeline_action_service
        or DeterministicTimelineActionService(),
        fatal_stop_service=fatal_stop_service
        or UowFatalStopService(
            uow_factory, bound_investigation_id=context.investigation_id
        ),
        research_executor=research_executor,
        research_reconciler=effective_reconciler,
        expected_investigation_id=context.investigation_id,
    )
