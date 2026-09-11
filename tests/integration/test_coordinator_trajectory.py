# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 21 coordinator trajectory on real PostgreSQL (Phase 8).

Runs the domain -> DNS -> discovered IP -> IP pivot -> malware research
marker -> typed SUFFICIENT -> stop trajectory through the real coordinator
services (context loader, transition service, status writer, timeline action
service, fatal stop service, coordinator transition SQL), real providers
through real extraction/persistence, the real Evidence Analyst with a
FakeLlmClient, and finally the loaded canonical scenario evaluator.

No empty or no-op coordinator dependency is injected; only the synthetic
provider HTTP transport and the scripted LLM are fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.orchestration.composition import (
    build_provider_investigation_graph,
)
from agentic_threat_investigator.app.orchestration.coordinator import (
    FakeAnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.models import (
    record_provider_outcome,
)
from agentic_threat_investigator.app.orchestration.provider_executor import (
    ProviderExecutionContext,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    convert_timeline_actions,
)
from agentic_threat_investigator.app.persistence.repositories import (
    CoordinatorTransitionPersistenceError,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AssessmentConfidence,
    Verdict,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    AnalysisDisposition,
    CoordinatorTransitionKind,
    EntityTraversalState,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    PivotRequest,
    PivotStatus,
    ProviderExecutionOutcome,
    ProviderExecutionStatus,
    ProviderWorkItem,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.evaluation.coordinator import (
    CoordinatorTrajectoryEvaluator,
    load_coordinator_scenarios_directory,
)
from agentic_threat_investigator.evaluation.scenario_fixtures import (
    CoordinatorScenarioMaterializer,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from tests.integration.test_provider_execution_pipeline import (
    HostAllowlistASGITransport,
    _build_stub_app,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_GOOGLE_DNS_HOST = "dns.google"
_DOMAIN_VALUE = "malicious-domain.test"
_RESOLVED_IP = "203.0.113.42"
_MALWARE_ID = "asyncrat"


def _dns_a_response() -> dict[str, object]:
    """Build the synthetic A-record response for the canonical trajectory."""
    return {
        "Status": 0,
        "TC": False,
        "RD": True,
        "RA": True,
        "Question": [{"name": f"{_DOMAIN_VALUE}.", "type": 1}],
        "Answer": [
            {"name": f"{_DOMAIN_VALUE}.", "type": 1, "TTL": 300, "data": _RESOLVED_IP}
        ],
    }


def _dns_empty_response() -> dict[str, object]:
    """Build an empty NOERROR response for the remaining RR types."""
    return {"Status": 0, "TC": False, "RD": True, "RA": True, "Answer": []}


class _DomainDnsProvider(EvidenceProvider):
    """Wrap the real Google DNS provider with a DOMAIN-only applicability.

    The production Google DNS provider also serves IP PTR queries; for the
    canonical trajectory we scope it to the root DOMAIN so the IP pivot plans
    exactly the ThreatFox malware call (keeping the trajectory to two
    provider calls).
    """

    def __init__(self, inner: EvidenceProvider) -> None:
        self._inner = inner
        self.calls: list[tuple[UUID, Entity]] = []

    @property
    def id(self) -> str:
        """Return the underlying DNS source URN."""
        return self._inner.id

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to DOMAIN entities only."""
        return entity.type is EntityType.DOMAIN

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Delegate to the real DNS provider and record the call."""
        self.calls.append((investigation_id, entity))
        return await self._inner.investigate(investigation_id, entity)


class _ThreatFoxIpProvider(EvidenceProvider):
    """Scripted IP provider associating the queried IOC with a malware family."""

    def __init__(self, malware: str) -> None:
        self._malware = malware
        self.calls: list[tuple[UUID, Entity]] = []

    @property
    def id(self) -> str:
        """Return the stable ThreatFox source URN."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Restrict applicability to IP-address entities."""
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return one ThreatFox Evidence discovering the malware family."""
        self.calls.append((investigation_id, entity))
        evidence = Evidence(
            id=uuid4(),
            investigation_id=investigation_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            subject=EntityRef(
                id=entity.id,
                type=entity.type,
                value=entity.value,
            ),
            source=SourceId.THREATFOX,
            retrieved_at=_FIXED_TS,
            observed_at=_FIXED_TS,
            facts={
                "matches": [{"malware": self._malware, "malware_printable": "AsyncRAT"}]
            },
        )
        return ProviderResult(provider=SourceId.THREATFOX.value, evidence=(evidence,))


class _NeverCalledDomainProvider(EvidenceProvider):
    """Expose DOMAIN applicability while failing if provider I/O is attempted."""

    @property
    def id(self) -> str:
        """Return the deterministic source identity."""
        return SourceId.GOOGLE_PUBLIC_DNS.value

    def supports(self, entity: Entity) -> bool:
        """Support only the root DOMAIN type."""
        return entity.type is EntityType.DOMAIN

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        del investigation_id, entity
        raise AssertionError("budget-stop trajectory must not call provider")


class _NeverCalledIpProvider(EvidenceProvider):
    """Expose IP applicability while failing if blocked work is dispatched."""

    @property
    def id(self) -> str:
        """Return the deterministic source identity."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Support only IP entities."""
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Fail because depth/entity policy must stop before dispatch."""
        del investigation_id, entity
        raise AssertionError("blocked trajectory must not call provider")


class _RecordingThreatFoxProvider(EvidenceProvider):
    """Deterministic offline IP provider that records every invocation.

    Returns no evidence so the executed work stays a pure bookkeeping round:
    the provider-call count and the investigated/traversal transitions are
    observed without adding analysis or research steps.
    """

    def __init__(self) -> None:
        self.calls: list[UUID] = []

    @property
    def id(self) -> str:
        """Return the stable ThreatFox source URN."""
        return SourceId.THREATFOX.value

    def supports(self, entity: Entity) -> bool:
        """Support only IP-address entities."""
        return entity.type is EntityType.IP_ADDRESS

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Record the call and return an empty deterministic result."""
        assert entity.id is not None
        self.calls.append(entity.id)
        return ProviderResult(provider=SourceId.THREATFOX.value, evidence=())


def _analyst_for(
    session_factory: async_sessionmaker[AsyncSession], llm: FakeLlmClient
) -> EvidenceAnalyst:
    """Build a real Evidence Analyst wired to real persistence services."""
    return EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            lambda: PostgresUnitOfWork(session_factory), batch_size=100
        ),
        llm_accounting=LlmAccountingService(
            lambda: PostgresUnitOfWork(session_factory)
        ),
        max_structured_output_attempts=2,
    )


async def test_canonical_domain_ip_sufficient_trajectory(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The canonical trajectory passes with real PR 21 services and evaluator."""
    app = _build_stub_app()
    app.state.dns_responses.update(
        {
            (_DOMAIN_VALUE, "A"): _dns_a_response(),
            (_DOMAIN_VALUE, "AAAA"): _dns_empty_response(),
            (_DOMAIN_VALUE, "CNAME"): _dns_empty_response(),
            (_DOMAIN_VALUE, "MX"): _dns_empty_response(),
            (_DOMAIN_VALUE, "NS"): _dns_empty_response(),
            (_DOMAIN_VALUE, "TXT"): _dns_empty_response(),
            (_DOMAIN_VALUE, "SOA"): _dns_empty_response(),
        }
    )
    transport = HostAllowlistASGITransport(app, allowed_hosts={_GOOGLE_DNS_HOST})
    scenario = next(
        item
        for item in load_coordinator_scenarios_directory("evals/scenarios/coordinator")
        if item.id == "domain-discovers-ip"
    )
    materializer = CoordinatorScenarioMaterializer()
    materialized = await materializer.materialize(scenario, uow_factory)
    state = materialized.initial_state
    investigation_id = state.investigation_id
    root_id = state.root_entity_ids[0]

    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client)
        dns_provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)

        llm = FakeLlmClient()
        for index, disposition in enumerate(materialized.analyst_dispositions):
            llm.enqueue(
                EvidenceAnalystDecision(
                    verdict=Verdict.SUSPICIOUS,
                    confidence=(
                        AssessmentConfidence.MEDIUM
                        if disposition is AnalysisDisposition.SUFFICIENT
                        else AssessmentConfidence.LOW
                    ),
                    summary=f"Fixture-owned analysis step {index + 1}.",
                    disposition=disposition,
                )
            )
        analyst = _analyst_for(session_factory, llm)
        executor = EvidenceAnalystAnalysisExecutor(
            analyst, bound_investigation_id=investigation_id
        )
        available: dict[SourceId, EvidenceProvider] = {
            SourceId.GOOGLE_PUBLIC_DNS: _DomainDnsProvider(dns_provider),
            SourceId.THREATFOX: _ThreatFoxIpProvider(_MALWARE_ID),
        }
        registry = {
            script.provider: available[script.provider]
            for script in materialized.provider_scripts
        }
        graph = build_provider_investigation_graph(
            uow_factory=uow_factory,
            provider_registry=registry,
            context=ProviderExecutionContext(
                investigation_id=investigation_id,
                clock=lambda: _FIXED_TS,
            ),
            analysis_executor=executor,
        )
        observed_transitions = 0
        recorded: InvestigationState | None = None
        async for snapshot in graph.astream(
            {"investigation": state},
            stream_mode="values",
            config={"recursion_limit": 40},
        ):
            observed_transitions += 1
            candidate = snapshot.get("investigation")
            if isinstance(candidate, InvestigationState):
                recorded = candidate

    assert recorded is not None
    assert observed_transitions > 0
    assert observed_transitions <= 40
    assert recorded.status is InvestigationStatus.COMPLETED
    assert recorded.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert recorded.completed_at is not None
    # Exactly two provider calls: DNS + ThreatFox IP pivot.
    assert recorded.budget.provider_calls_used == 2
    # Exactly one authorized additional collection round (the replan).
    assert recorded.budget.replans_used == 1
    # Malware was only marked research-required; no research results exist.
    assert len(recorded.research_required_for_entity_ids) == 1
    assert not recorded.research_result_ids
    root_entry = next(e for e in recorded.traversal if e.entity_id == root_id)
    assert root_entry.best_investigated_depth == 0
    assert all(
        pivot.status is PivotStatus.COMPLETED for pivot in recorded.pending_pivots
    ), [pivot.status for pivot in recorded.pending_pivots]

    async with uow_factory() as uow:
        events = await uow.timeline_events.list_by_investigation(investigation_id)
    event_types = {event.type for event in events}
    assert InvestigationTimelineEventType.PIVOT_ENQUEUED in event_types
    assert InvestigationTimelineEventType.PIVOT_EXECUTED in event_types
    assert InvestigationTimelineEventType.ENTITIES_DISCOVERED in event_types
    assert InvestigationTimelineEventType.ASSESSMENT_REQUESTED in event_types
    assert InvestigationTimelineEventType.INVESTIGATION_STOPPED in event_types

    # Bind semantic labels to exact runtime identities through the fixture
    # materializer; missing/ambiguous labels fail closed.
    executed = [
        event
        for event in events
        if event.type is InvestigationTimelineEventType.PIVOT_EXECUTED
    ]
    # The IP pivot is the executed pivot at depth 1 (the root is depth 0).
    ip_pivot = next((e for e in executed if e.pivot_depth and e.pivot_depth >= 1), None)
    assert ip_pivot is not None
    ip_entity_id = ip_pivot.entity_ids[0]
    resolution = await materializer.resolve_persisted(scenario, uow_factory)
    assert resolution.entities["resolved_ip"] == ip_entity_id
    actions = tuple(convert_timeline_actions(tuple(events)))
    evaluator = CoordinatorTrajectoryEvaluator()
    result = evaluator.evaluate(
        scenario=scenario,
        resolution=resolution,
        final_state=recorded,
        actions=actions,  # type: ignore[arg-type]
        observed_transitions=observed_transitions,
    )
    assert result.passed, result.failures
    assert result.metrics["termination"] == 1.0


@pytest.mark.parametrize(
    ("case", "expected_reason"),
    [
        ("provider_budget", StopReason.PROVIDER_BUDGET_EXHAUSTED),
        ("replan_limit", StopReason.REPLAN_LIMIT_REACHED),
        ("no_eligible", StopReason.NO_ELIGIBLE_PIVOTS),
        ("depth_limit", StopReason.DEPTH_LIMIT_REACHED),
        ("entity_budget", StopReason.ENTITY_BUDGET_EXHAUSTED),
    ],
)
async def test_postgresql_terminal_policy_trajectories(
    uow_factory: Callable[[], PostgresUnitOfWork],
    case: str,
    expected_reason: StopReason,
) -> None:
    """Specific terminal policies execute through the complete durable graph."""
    investigation_id = uuid4()
    root_id = uuid4()
    budget = default_investigation_budget()
    disposition: AnalysisDisposition | None = None
    providers: dict[SourceId, EvidenceProvider] = {}
    discovered: list[UUID] = []
    traversal: list[EntityTraversalState] = []
    investigated: list[UUID] = []
    discovered_id: UUID | None = None
    if case == "provider_budget":
        budget = budget.model_copy(update={"max_provider_calls": 0})
        providers[SourceId.GOOGLE_PUBLIC_DNS] = _NeverCalledDomainProvider()
    elif case == "replan_limit":
        budget = budget.model_copy(update={"max_replans": 1, "replans_used": 1})
        disposition = AnalysisDisposition.NEEDS_MORE_EVIDENCE
    elif case in {"depth_limit", "entity_budget"}:
        discovered_id = uuid4()
        discovered = [discovered_id]
        investigated = [root_id]
        depth = 3 if case == "depth_limit" else 1
        traversal = [
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            ),
            EntityTraversalState(
                entity_id=discovered_id,
                first_discovery_ordinal=1,
                minimum_depth=depth,
            ),
        ]
        providers[SourceId.THREATFOX] = _NeverCalledIpProvider()
        budget = budget.model_copy(
            update={
                "max_depth": 1 if case == "depth_limit" else 2,
                "max_entities": 1 if case == "entity_budget" else 10,
            }
        )

    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        discovered_entity_ids=discovered,
        traversal=traversal,
        investigated_entity_ids=investigated,
        objective=f"Exercise durable {case} stop.",
        budget=budget,
        analysis_disposition=disposition,
        started_at=_FIXED_TS,
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value=f"{case}.example")
        )
        if discovered_id is not None:
            await uow.entities.upsert(
                Entity(
                    id=discovered_id,
                    type=EntityType.IP_ADDRESS,
                    value="203.0.113.99",
                )
            )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry=providers,
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    final: InvestigationState | None = None
    transitions = 0
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": 20},
    ):
        transitions += 1
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            final = candidate
    assert final is not None
    assert 0 < transitions <= 20
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == expected_reason.value
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    assert durable.stop_reason == expected_reason.value
    assert durable.completed_at is not None


async def test_postgresql_selected_work_resume_fails_without_reissue(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A durable selected item fatalizes without a second provider call."""
    investigation_id = uuid4()
    root_id = uuid4()
    work = ProviderWorkItem(
        provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root_id, depth=0
    )
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective="Do not reissue uncertain selected work.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        pending_provider_work=[work],
        current_provider_work=work,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            )
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="resume.example")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    provider = _NeverCalledDomainProvider()
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    result = await graph.ainvoke({"investigation": state})
    final = result["investigation"]
    assert isinstance(final, InvestigationState)
    assert final.status is InvestigationStatus.FAILED
    assert final.stop_reason == StopReason.FATAL_ERROR.value
    assert any(error.code == "persisted_provider_work_resume" for error in final.errors)


async def test_postgresql_completed_outcome_resume_does_not_reissue(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A durable completed item resumes to stop without provider replay."""
    investigation_id = uuid4()
    root_id = uuid4()
    work = ProviderWorkItem(
        provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root_id, depth=0
    )
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective="Resume after durable provider outcome.",
        budget=default_investigation_budget().model_copy(
            update={"provider_calls_used": 1}
        ),
        started_at=_FIXED_TS,
        completed_provider_work=[work],
        investigated_entity_ids=[root_id],
        analysis_disposition=AnalysisDisposition.SUFFICIENT,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            )
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="resumed.example")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    provider = _NeverCalledDomainProvider()
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry={SourceId.GOOGLE_PUBLIC_DNS: provider},
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    result = await graph.ainvoke({"investigation": state})
    final = result["investigation"]
    assert isinstance(final, InvestigationState)
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert final.budget.provider_calls_used == 1


async def test_postgresql_analysis_failure_fatalizes_bounded(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An unrecoverable analyst failure persists FAILED/FATAL_ERROR once."""
    investigation_id = uuid4()
    root_id = uuid4()
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        evidence_ids=[uuid4()],
        objective="Fatalize an unavailable analyst.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="fatal.example")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry={},
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    result = await graph.ainvoke({"investigation": state})
    final = result["investigation"]
    assert isinstance(final, InvestigationState)
    assert final.status is InvestigationStatus.FAILED
    assert final.stop_reason == StopReason.FATAL_ERROR.value
    assert sum(error.code == "analysis_execution_error" for error in final.errors) == 1


async def test_coordinator_sql_rejects_invented_pivot_without_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Repository-bypassing authorization cannot persist an unknown target."""
    investigation_id = uuid4()
    root_id = uuid4()
    invented_id = uuid4()
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="root.example")
        )
        created = await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                objective="Reject invented coordinator targets.",
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
            )
        )
        await uow.commit()

    proposed = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective="Reject invented coordinator targets.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        pending_pivots=[
            PivotRequest(entity_id=invented_id, reason="eligible_pivot", depth=1)
        ],
        pending_provider_work=[
            ProviderWorkItem(
                provider=SourceId.THREATFOX,
                entity_id=invented_id,
                depth=1,
            )
        ],
        investigated_entity_ids=[invented_id],
        version=created.version,
    )
    async with uow_factory() as uow:
        with pytest.raises(
            CoordinatorTransitionPersistenceError, match="invalid coordinator"
        ):
            await uow.investigations.update_coordinator_state(
                investigation_id,
                CoordinatorTransitionKind.AUTHORIZE_PIVOT,
                proposed,
                expected_version=created.version,
            )

    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    assert durable.version == created.version
    assert durable.pending_pivots == []
    assert durable.pending_provider_work == []


async def _seed_transition_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    pending_work: list[ProviderWorkItem] | None = None,
    current_work: ProviderWorkItem | None = None,
) -> InvestigationState:
    """Persist a minimal RUNNING state for direct transition rejection tests."""
    investigation_id = uuid4()
    root_id = uuid4()
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective="Validate coordinator transition rejection.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        pending_provider_work=pending_work or [],
        current_provider_work=current_work,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0 if current_work else None,
            )
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value=f"{root_id}.example")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    return state.model_copy(update={"version": created.version})


async def test_coordinator_sql_rejects_depth_research_and_status_tampering(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Authorization, research, and non-final status invariants fail closed."""
    state = await _seed_transition_state(uow_factory)
    assert state.version is not None
    root_id = state.root_entity_ids[0]

    over_depth = state.model_copy(
        update={
            "pending_pivots": [
                PivotRequest(
                    entity_id=root_id,
                    reason="eligible_pivot",
                    depth=state.budget.max_depth + 1,
                )
            ],
            "pending_provider_work": [
                ProviderWorkItem(
                    provider=SourceId.GOOGLE_PUBLIC_DNS,
                    entity_id=root_id,
                    depth=state.budget.max_depth + 1,
                )
            ],
            "investigated_entity_ids": [root_id],
        }
    )
    invalid_research = state.model_copy(
        update={"research_required_for_entity_ids": [root_id]}
    )
    terminal_mark = invalid_research.model_copy(
        update={"status": InvestigationStatus.COMPLETED}
    )
    cases = (
        (CoordinatorTransitionKind.AUTHORIZE_PIVOT, over_depth),
        (CoordinatorTransitionKind.MARK_RESEARCH_REQUIRED, invalid_research),
        (CoordinatorTransitionKind.MARK_RESEARCH_REQUIRED, terminal_mark),
    )
    for kind, proposed in cases:
        async with uow_factory() as uow:
            with pytest.raises(CoordinatorTransitionPersistenceError):
                await uow.investigations.update_coordinator_state(
                    state.investigation_id,
                    kind,
                    proposed,
                    expected_version=state.version,
                )
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(state.investigation_id)
    assert durable is not None
    assert durable.version == state.version


async def test_coordinator_sql_rejects_foreign_outcome_and_active_stop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Outcome provenance and ordinary-stop active-work checks fail closed."""
    root_id = uuid4()
    work = ProviderWorkItem(
        provider=SourceId.GOOGLE_PUBLIC_DNS, entity_id=root_id, depth=0
    )
    # Build the state with one consistent root/work identity directly.
    investigation_id = uuid4()
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective="Reject unproven outcome references.",
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
        pending_provider_work=[work],
        current_provider_work=work,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            )
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="outcome.example")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})
    outcome = ProviderExecutionOutcome(
        work_item=work,
        status=ProviderExecutionStatus.SUCCEEDED,
        evidence_ids=(uuid4(),),
    )
    proposed_outcome = record_provider_outcome(state, outcome)
    active_stop = state.model_copy(
        update={
            "status": InvestigationStatus.COMPLETED,
            "stop_reason": StopReason.NO_ELIGIBLE_PIVOTS.value,
        }
    )
    for kind, proposed in (
        (CoordinatorTransitionKind.RECORD_PROVIDER_OUTCOME, proposed_outcome),
        (CoordinatorTransitionKind.FINALIZE_STOP, active_stop),
    ):
        async with uow_factory() as uow:
            with pytest.raises(CoordinatorTransitionPersistenceError):
                await uow.investigations.update_coordinator_state(
                    investigation_id,
                    kind,
                    proposed,
                    expected_version=created.version,
                )
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    assert durable.version == created.version


async def test_postgresql_exact_capacity_discovered_pivot_executes(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """I1/U1: an admitted discovered IP pivots at exact capacity (PR 21B).

    max_entities=2 with one root DOMAIN (already investigated) and one
    discovered IP: the IP is the second unique entity and therefore admitted,
    so its depth-1 pivot is authorized, selected, and executed with a single
    provider call, and the durable state records the investigated transition
    exactly once at selection time.
    """
    investigation_id = uuid4()
    root_id = uuid4()
    ip_id = uuid4()
    budget = default_investigation_budget().model_copy(update={"max_entities": 2})
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        discovered_entity_ids=[ip_id],
        investigated_entity_ids=[root_id],
        objective="Pivot the admitted discovered IP at exact capacity.",
        budget=budget,
        started_at=_FIXED_TS,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            ),
            EntityTraversalState(
                entity_id=ip_id,
                first_discovery_ordinal=1,
                minimum_depth=1,
            ),
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="exact-capacity.test")
        )
        await uow.entities.upsert(
            Entity(id=ip_id, type=EntityType.IP_ADDRESS, value="203.0.113.10")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})

    ip_provider = _RecordingThreatFoxProvider()
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry={SourceId.THREATFOX: ip_provider},
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    recorded: InvestigationState | None = None
    transitions = 0
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": 24},
    ):
        transitions += 1
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            recorded = candidate
    assert recorded is not None
    assert 0 < transitions <= 24
    # The admitted IP executed exactly once; the entity budget never stopped.
    assert ip_provider.calls == [ip_id]
    assert recorded.budget.provider_calls_used == 1
    assert recorded.stop_reason != StopReason.ENTITY_BUDGET_EXHAUSTED.value
    # IP is investigated exactly once and its execution depth is durable.
    assert recorded.investigated_entity_ids == [root_id, ip_id]
    assert len(recorded.investigated_entity_ids) == len(
        set(recorded.investigated_entity_ids)
    )
    ip_entry = next(entry for entry in recorded.traversal if entry.entity_id == ip_id)
    assert ip_entry.best_investigated_depth == 1

    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    assert (
        durable.stop_reason
        == recorded.stop_reason
        == StopReason.NO_ELIGIBLE_PIVOTS.value
    )
    assert durable.investigated_entity_ids == recorded.investigated_entity_ids
    durable_ip = next(entry for entry in durable.traversal if entry.entity_id == ip_id)
    assert durable_ip.best_investigated_depth == 1
    assert all(
        pivot.status is PivotStatus.COMPLETED for pivot in durable.pending_pivots
    ), [pivot.status for pivot in durable.pending_pivots]


async def test_postgresql_overflow_discovery_persisted_but_not_pivoted(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """I2/U2: a persisted overflow discovery never authorizes a pivot (PR 21B).

    max_entities=2 with root + ip_a admitted (both investigated) and ip_b
    overflowing: ip_b remains durable in the Entity repository, in
    ``discovered_entity_ids``, and in traversal, but receives no pivot or
    provider work and the entity budget is the sole blocker.
    """
    investigation_id = uuid4()
    root_id = uuid4()
    ip_a_id = uuid4()
    ip_b_id = uuid4()
    budget = default_investigation_budget().model_copy(update={"max_entities": 2})
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        discovered_entity_ids=[ip_a_id, ip_b_id],
        investigated_entity_ids=[root_id, ip_a_id],
        objective="Persist overflow discoveries without authorizing them.",
        budget=budget,
        started_at=_FIXED_TS,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            ),
            EntityTraversalState(
                entity_id=ip_a_id,
                first_discovery_ordinal=1,
                minimum_depth=1,
                best_investigated_depth=1,
            ),
            EntityTraversalState(
                entity_id=ip_b_id,
                first_discovery_ordinal=2,
                minimum_depth=1,
            ),
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="overflow-root.test")
        )
        await uow.entities.upsert(
            Entity(id=ip_a_id, type=EntityType.IP_ADDRESS, value="203.0.113.20")
        )
        await uow.entities.upsert(
            Entity(id=ip_b_id, type=EntityType.IP_ADDRESS, value="203.0.113.21")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})

    ip_provider = _NeverCalledIpProvider()
    graph = build_provider_investigation_graph(
        uow_factory=uow_factory,
        provider_registry={SourceId.THREATFOX: ip_provider},
        context=ProviderExecutionContext(
            investigation_id=investigation_id, clock=lambda: _FIXED_TS
        ),
        analysis_executor=FakeAnalysisExecutor(
            (), bound_investigation_id=investigation_id
        ),
    )
    recorded: InvestigationState | None = None
    async for snapshot in graph.astream(
        {"investigation": state},
        stream_mode="values",
        config={"recursion_limit": 12},
    ):
        candidate = snapshot.get("investigation")
        if isinstance(candidate, InvestigationState):
            recorded = candidate
    assert recorded is not None
    assert recorded.status is InvestigationStatus.COMPLETED
    assert recorded.stop_reason == StopReason.ENTITY_BUDGET_EXHAUSTED.value
    assert recorded.pending_pivots == []
    assert recorded.pending_provider_work == []
    assert ip_b_id not in recorded.investigated_entity_ids
    assert ip_b_id in recorded.discovered_entity_ids
    assert any(entry.entity_id == ip_b_id for entry in recorded.traversal)

    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
        overflow = await uow.entities.get_by_id(ip_b_id)
    assert durable is not None
    assert durable.stop_reason == StopReason.ENTITY_BUDGET_EXHAUSTED.value
    assert ip_b_id in durable.discovered_entity_ids
    assert any(entry.entity_id == ip_b_id for entry in durable.traversal)
    assert ip_b_id not in durable.investigated_entity_ids
    assert durable.pending_pivots == []
    assert durable.pending_provider_work == []
    # Persisted != admitted: the overflow Entity row still exists.
    assert overflow is not None
    assert overflow.deleted_at is None


async def test_postgresql_authorization_does_not_prematurely_investigate(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """I3/I4: durable authorization precedes the investigated transition (PR 21B).

    Persisting an AUTHORIZE_PIVOT transition leaves the target absent from
    ``investigated_entity_ids`` with no best depth; the subsequent
    SELECT_PROVIDER_WORK transition marks it investigated exactly once, sets
    the execution depth, and moves the pivot to IN_PROGRESS in the same
    durable write.
    """
    from agentic_threat_investigator.app.orchestration.models import (
        apply_work_selection,
        authorize_pivot,
        select_provider_work,
    )
    from agentic_threat_investigator.app.orchestration.services import (
        UowCoordinatorTransitionService,
    )

    investigation_id = uuid4()
    root_id = uuid4()
    ip_id = uuid4()
    work = ProviderWorkItem(provider=SourceId.THREATFOX, entity_id=ip_id, depth=1)
    state = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        discovered_entity_ids=[ip_id],
        investigated_entity_ids=[root_id],
        objective="Authorize without marking investigated.",
        budget=default_investigation_budget().model_copy(update={"max_entities": 2}),
        started_at=_FIXED_TS,
        traversal=[
            EntityTraversalState(
                entity_id=root_id,
                first_discovery_ordinal=0,
                minimum_depth=0,
                best_investigated_depth=0,
            ),
            EntityTraversalState(
                entity_id=ip_id,
                first_discovery_ordinal=1,
                minimum_depth=1,
            ),
        ],
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value="auth-only.test")
        )
        await uow.entities.upsert(
            Entity(id=ip_id, type=EntityType.IP_ADDRESS, value="203.0.113.30")
        )
        created = await uow.investigations.create(state)
        await uow.commit()
    state = state.model_copy(update={"version": created.version})

    service = UowCoordinatorTransitionService(
        uow_factory, bound_investigation_id=investigation_id
    )
    authorized = authorize_pivot(
        state,
        PivotRequest(entity_id=ip_id, reason="eligible_pivot", depth=1),
        [work],
    )
    persisted_auth = await service.persist(
        investigation_id,
        CoordinatorTransitionKind.AUTHORIZE_PIVOT,
        authorized,
        expected_version=created.version,
    )
    # Authorization persisted: pivot + work queued, target not investigated.
    assert [pivot.entity_id for pivot in persisted_auth.pending_pivots] == [ip_id]
    assert persisted_auth.pending_provider_work == [work]
    assert persisted_auth.investigated_entity_ids == [root_id]
    auth_ip = next(
        entry for entry in persisted_auth.traversal if entry.entity_id == ip_id
    )
    assert auth_ip.best_investigated_depth is None
    assert persisted_auth.version is not None

    selected = select_provider_work(persisted_auth)
    applied = apply_work_selection(selected)
    validated = InvestigationState.model_validate(applied.model_dump())
    persisted_sel = await service.persist(
        investigation_id,
        CoordinatorTransitionKind.SELECT_PROVIDER_WORK,
        validated,
        expected_version=persisted_auth.version,
    )
    # Selection persisted: investigated exactly once, depth recorded, pivot
    # IN_PROGRESS — all in the same durable transition.
    assert persisted_sel.investigated_entity_ids == [root_id, ip_id]
    assert persisted_sel.investigated_entity_ids.count(ip_id) == 1
    sel_ip = next(
        entry for entry in persisted_sel.traversal if entry.entity_id == ip_id
    )
    assert sel_ip.best_investigated_depth == 1
    pivot = next(p for p in persisted_sel.pending_pivots if p.entity_id == ip_id)
    assert pivot.status is PivotStatus.IN_PROGRESS

    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(investigation_id)
    assert durable is not None
    assert durable.investigated_entity_ids == [root_id, ip_id]
    durable_ip = next(entry for entry in durable.traversal if entry.entity_id == ip_id)
    assert durable_ip.best_investigated_depth == 1
