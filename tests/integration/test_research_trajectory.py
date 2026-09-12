# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22C research-execution PostgreSQL trajectories (I01-I08).

The canonical slice exercises real Investigation persistence, real
CoordinatorPolicy, the real production LangGraph, LocalInvestigationRunner,
the real-format MITRE ATT&CK STIX fixture, the production parser/document
builder, DocumentIndexingService, real PostgreSQL/pgvector, real
PgVectorResearchRetriever, the real Research Agent, real ResearchResult
persistence, and real coordinator transitions/timeline. FakeLlmClient is
used ONLY at the model boundary; no live Internet or live LLM participates.
Provider execution uses the existing deterministic production-compatible
test seam to create the RESEARCHABLE entity; the research path itself is
never faked.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

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
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.orchestration.coordinator import (
    CoordinatorEntityView,
)
from agentic_threat_investigator.app.orchestration.research import (
    RESEARCH_QUERY_TEMPLATE,
    DeterministicResearchRequestPlanner,
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.orchestration.timeline_actions import (
    ACTION_RESEARCH_REQUESTED,
    convert_timeline_actions,
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
    EntityTraversalState,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    ResearchExecutionState,
    ResearchExecutionStatus,
    StopReason,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)
from agentic_threat_investigator.domain.research import ResearchResult
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.google_dns import (
    GooglePublicDnsProvider,
)
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from tests.integration.test_provider_execution_pipeline import (
    HostAllowlistASGITransport,
    _build_stub_app,
)
from tests.integration.test_research_agent import (
    FIXTURE,
    _index,
    _ingest_fixture,
)
from tests.support.llm_fixtures import FakeLlmClient

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
_GOOGLE_DNS_HOST = "dns.google"
_DOMAIN_VALUE = "malicious-domain.test"
_RESOLVED_IP = "203.0.113.42"
_MALWARE_VALUE = "asyncrat"
_OBJECTIVE = "Assess the malware family and its infrastructure."


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
    """Wrap the real Google DNS provider with a DOMAIN-only applicability."""

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

    def __init__(self) -> None:
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
                "matches": [
                    {"malware": _MALWARE_VALUE, "malware_printable": "AsyncRAT"}
                ]
            },
        )
        return ProviderResult(provider=SourceId.THREATFOX.value, evidence=(evidence,))


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


def _research_query(entity_value: str = _MALWARE_VALUE) -> str:
    """Return the deterministic planned query for the researchable entity."""
    return RESEARCH_QUERY_TEMPLATE.format(
        entity_type=EntityType.MALWARE.value,
        value=entity_value,
        objective=_OBJECTIVE,
    )


async def _seed_investigation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    *,
    research_required: bool = True,
    root_domain_id: UUID | None = None,
) -> tuple[UUID, UUID]:
    """Persist the root domain and a RUNNING investigation; return both IDs."""
    investigation_id = uuid4()
    root_id = root_domain_id or uuid4()
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value=_DOMAIN_VALUE)
        )
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                objective=_OBJECTIVE,
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
            )
        )
    return investigation_id, root_id


async def _top_chunk_for_query(
    session_factory: async_sessionmaker[AsyncSession], query: str
) -> tuple[UUID, str] | None:
    """Return the top (citation_id, source_record_id) for one query, if any."""
    from agentic_threat_investigator.domain.research import ResearchQuery

    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    chunks = await retriever.retrieve(
        ResearchQuery(
            investigation_id=uuid4(),
            query=query,
            max_results=8,
        )
    )
    if not chunks:
        return None
    return chunks[0].citation_id, chunks[0].source_record_id


async def _research_executor_factory(
    session_factory: async_sessionmaker[AsyncSession],
    research_llm: FakeLlmClient,
) -> Callable[[UUID], ResearchAgentResearchExecutor]:
    """Return a factory producing the production research executor seam."""

    def factory(
        investigation_id: UUID,
    ) -> ResearchAgentResearchExecutor:
        agent = build_research_agent(
            uow_factory=lambda: PostgresUnitOfWork(session_factory),
            session_factory=session_factory,
            embedding_client=HashingEmbeddingClient(),
            llm_client=research_llm,
            max_structured_output_attempts=2,
        )
        return ResearchAgentResearchExecutor(
            agent, bound_investigation_id=investigation_id
        )

    return factory


def _configure_analyst_llm(llm: FakeLlmClient) -> None:
    """Enqueue the canonical NEEDS_MORE_EVIDENCE then SUFFICIENT decisions."""
    llm.enqueue(
        EvidenceAnalystDecision(
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.LOW,
            summary="First analysis round.",
            disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE,
        )
    )
    llm.enqueue(
        EvidenceAnalystDecision(
            verdict=Verdict.SUSPICIOUS,
            confidence=AssessmentConfidence.MEDIUM,
            summary="Final analysis round.",
            disposition=AnalysisDisposition.SUFFICIENT,
        )
    )


async def _run_canonical_trajectory(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    *,
    research_llm: FakeLlmClient,
) -> tuple[InvestigationState, FakeLlmClient]:
    """Run the canonical trajectory and return (final, analyst_llm)."""
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
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client)
        dns_provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
        analyst_llm = FakeLlmClient()
        _configure_analyst_llm(analyst_llm)
        analyst = _analyst_for(session_factory, analyst_llm)
        dns_wrapper = _DomainDnsProvider(dns_provider)
        threatfox = _ThreatFoxIpProvider()
        registry: dict[SourceId, EvidenceProvider] = {
            SourceId.GOOGLE_PUBLIC_DNS: dns_wrapper,
            SourceId.THREATFOX: threatfox,
        }
        investigation_id, root_id = await _seed_investigation(uow_factory)
        research_executor_factory = await _research_executor_factory(
            session_factory, research_llm
        )
        runner = LocalInvestigationRunner(
            uow_factory=uow_factory,
            provider_registry=registry,
            analysis_executor_factory=lambda investigation_id: (
                EvidenceAnalystAnalysisExecutor(
                    analyst, bound_investigation_id=investigation_id
                )
            ),
            research_executor_factory=research_executor_factory,
            clock=lambda: _FIXED_TS,
            recursion_limit=40,
        )
        final: InvestigationState = await runner.run(investigation_id)
    return final, analyst_llm


async def _count_rows(engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with engine.connect() as connection:
        return int(
            (await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))) or 0
        )


async def _timeline(
    uow_factory: Callable[[], PostgresUnitOfWork], investigation_id: UUID
) -> tuple[InvestigationTimelineEvent, ...]:
    """Return the durable timeline events for one investigation."""
    async with uow_factory() as uow:
        return tuple(await uow.timeline_events.list_by_investigation(investigation_id))


async def _index_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> list[SourceRecord]:
    """Ingest and index the real-format MITRE ATT&CK fixture."""
    records = await _ingest_fixture(uow_factory, tmp_path, fixture=FIXTURE)
    await _index(records, uow_factory)
    return records


async def _assert_research_completed(
    final: InvestigationState,
    *,
    malware_id: UUID,
    result_id: UUID,
    query: str,
) -> None:
    """Assert the durable research execution COMPLETED state and linkage."""
    assert len(final.research_required_for_entity_ids) == 1
    assert final.research_required_for_entity_ids[0] == malware_id
    assert final.research_result_ids == [result_id]
    [execution] = final.research_executions
    assert execution.subject_entity_id == malware_id
    assert execution.query == query
    assert execution.status is ResearchExecutionStatus.COMPLETED
    assert execution.result_id == result_id


async def test_i01_complete_research_trajectory(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """I01: the full production research lifecycle with real retrieval."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    query = _research_query()
    top = await _top_chunk_for_query(session_factory, query)
    assert top is not None, "the canonical corpus must retrieve for the query"

    research_llm = FakeLlmClient()
    research_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The malware family is associated with the technique.",
                    citation_ids=(top[0],),
                ),
            ),
        )
    )
    final, _analyst_llm = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    malware_id = final.research_required_for_entity_ids[0]
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert final.budget.provider_calls_used == 2
    [execution] = final.research_executions
    result_id = execution.result_id
    assert result_id is not None
    await _assert_research_completed(
        final, malware_id=malware_id, result_id=result_id, query=query
    )

    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
    assert len(results) == 1
    [result] = results
    assert result.id == result_id
    assert result.subject_entity_id == malware_id
    assert result.query == query
    assert result.claims
    assert result.citations
    # Valid citation provenance: the cited citation_id equals the top chunk.
    assert result.citations[0].citation_id == top[0]

    # Research never becomes Evidence or Assessment: the only Assessment
    # rows are the two analyst rounds (NEEDS_MORE_EVIDENCE + SUFFICIENT),
    # and no research result identity ever enters evidence_ids.
    assert await _count_rows(integration_engine, "research_result") == 1
    assert final.assessment_id is not None
    assert await _count_rows(integration_engine, "assessment") == 2
    assert result_id not in final.evidence_ids
    assert await _count_rows(integration_engine, "evidence") == len(final.evidence_ids)
    assert len(research_llm.calls) == 1

    # Ordered durable behavior: MARK_RESEARCH_REQUIRED marker was consumed,
    # RESEARCH_REQUESTED fired, result persisted, execution COMPLETED, then
    # normal Coordinator stop (no pivot authorized after research).
    events = await _timeline(uow_factory, final.investigation_id)
    event_types = [event.type for event in events]
    research_indexes = [
        index
        for index, event_type in enumerate(event_types)
        if event_type is InvestigationTimelineEventType.RESEARCH_REQUESTED
    ]
    assert research_indexes == [len(event_types) - 2]
    assert event_types[-1] is InvestigationTimelineEventType.INVESTIGATION_STOPPED
    pivot_after_research = [
        event
        for event in events
        if event.type
        in (
            InvestigationTimelineEventType.PIVOT_ENQUEUED,
            InvestigationTimelineEventType.PIVOT_EXECUTED,
        )
        and events.index(event) > research_indexes[0]
    ]
    assert pivot_after_research == []
    actions = convert_timeline_actions(events)
    assert any(action.action == ACTION_RESEARCH_REQUESTED for action in actions)


async def test_i02_no_context_result_is_completion(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """I02: an empty corpus produces a zero-claim result without any LLM call."""
    # Deliberately no corpus indexing: retrieval returns zero chunks.
    del tmp_path
    research_llm = FakeLlmClient()  # no outcomes: must never be called
    final, _analyst_llm = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert research_llm.calls == []
    [execution] = final.research_executions
    assert execution.status is ResearchExecutionStatus.COMPLETED
    assert execution.result_id is not None
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
    assert len(results) == 1
    [result] = results
    assert result.claims == ()
    assert result.citations == ()
    # The no-context result is still completed research and linked once.
    assert final.research_result_ids == [result.id]
    assert await _count_rows(integration_engine, "research_result") == 1


async def test_i03_unchanged_context_rerun_is_idempotent(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I03: re-running against durable state repeats no research work."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    query = _research_query()
    top = await _top_chunk_for_query(session_factory, query)
    assert top is not None
    research_llm = FakeLlmClient()
    research_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The malware family is associated with the technique.",
                    citation_ids=(top[0],),
                ),
            ),
        )
    )
    final, _ = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    assert final.status is InvestigationStatus.COMPLETED
    async with uow_factory() as uow:
        before_results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
        before_events = await uow.timeline_events.list_by_investigation(
            final.investigation_id
        )
    before_requested = len(
        [
            event
            for event in before_events
            if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
        ]
    )
    assert len(before_results) == 1
    assert before_requested == 1

    # Re-running the runner against the terminal durable state is an
    # idempotent no-op: no Research Agent call, no new ResearchResult, no new
    # RESEARCH_REQUESTED event.
    research_rerun_llm = FakeLlmClient()
    transport = HostAllowlistASGITransport(
        _build_stub_app(), allowed_hosts={_GOOGLE_DNS_HOST}
    )
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client)
        dns_provider = GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
        analyst_llm = FakeLlmClient()
        _configure_analyst_llm(analyst_llm)
        analyst = _analyst_for(session_factory, analyst_llm)
        research_executor_factory = await _research_executor_factory(
            session_factory, research_rerun_llm
        )
        runner = LocalInvestigationRunner(
            uow_factory=uow_factory,
            provider_registry={
                SourceId.GOOGLE_PUBLIC_DNS: _DomainDnsProvider(dns_provider),
                SourceId.THREATFOX: _ThreatFoxIpProvider(),
            },
            analysis_executor_factory=lambda investigation_id: (
                EvidenceAnalystAnalysisExecutor(
                    analyst, bound_investigation_id=investigation_id
                )
            ),
            research_executor_factory=research_executor_factory,
            clock=lambda: _FIXED_TS,
            recursion_limit=40,
        )
        rerun: InvestigationState = await runner.run(final.investigation_id)
    assert rerun == final
    assert research_rerun_llm.calls == []
    async with uow_factory() as uow:
        after_results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
        after_events = await uow.timeline_events.list_by_investigation(
            final.investigation_id
        )
    assert len(after_results) == 1
    after_requested = len(
        [
            event
            for event in after_events
            if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
        ]
    )
    assert after_requested == before_requested


async def test_i04_crash_window_reconciliation(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """I04: a persisted result with REQUESTED state is adopted without LLM.

    Durable crash-window state: a REQUESTED execution entry plus an
    already-persisted matching ResearchResult that is not yet linked into the
    Investigation research execution state. The runner reconciles the exact
    context against the persisted result and adopts it: zero Research Agent
    calls, no duplicate result, COMPLETED, result linked exactly once.
    """
    investigation_id = uuid4()
    root_id = uuid4()
    malware_id = uuid4()
    query = _research_query()
    # Compute the true planner fingerprint so the coordinator selects the
    # context as due.
    probe = InvestigationState(
        investigation_id=investigation_id,
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[root_id],
        objective=_OBJECTIVE,
        budget=default_investigation_budget(),
        started_at=_FIXED_TS,
    )
    planned = DeterministicResearchRequestPlanner().plan(
        investigation=probe,
        entity=CoordinatorEntityView(
            entity_id=malware_id, entity_type=EntityType.MALWARE, value=_MALWARE_VALUE
        ),
    )
    async with uow_factory() as uow:
        await uow.entities.upsert(
            Entity(id=root_id, type=EntityType.DOMAIN, value=_DOMAIN_VALUE)
        )
        await uow.entities.upsert(
            Entity(id=malware_id, type=EntityType.MALWARE, value=_MALWARE_VALUE)
        )
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[root_id],
                discovered_entity_ids=[malware_id],
                investigated_entity_ids=[root_id],
                research_required_for_entity_ids=[malware_id],
                research_executions=[
                    ResearchExecutionState(
                        subject_entity_id=malware_id,
                        context_fingerprint=planned.context_fingerprint,
                        query=query,
                        status=ResearchExecutionStatus.REQUESTED,
                        attempts=1,
                    )
                ],
                objective=_OBJECTIVE,
                budget=default_investigation_budget(),
                started_at=_FIXED_TS,
                traversal=[
                    EntityTraversalState(
                        entity_id=root_id,
                        first_discovery_ordinal=0,
                        minimum_depth=0,
                        best_investigated_depth=0,
                    ),
                    EntityTraversalState(
                        entity_id=malware_id,
                        first_discovery_ordinal=1,
                        minimum_depth=1,
                    ),
                ],
            )
        )
        result_id = uuid4()
        await uow.research_results.add(
            ResearchResult(
                id=result_id,
                investigation_id=investigation_id,
                subject_entity_id=malware_id,
                query=query,
                claims=(),
                citations=(),
                created_at=_FIXED_TS,
            )
        )
    research_llm = FakeLlmClient()
    transport = HostAllowlistASGITransport(
        _build_stub_app(), allowed_hosts={_GOOGLE_DNS_HOST}
    )
    async with httpx.AsyncClient(transport=transport) as client:
        http = ProviderHttpClient(client=client)
        analyst_llm = FakeLlmClient()
        _configure_analyst_llm(analyst_llm)
        analyst = _analyst_for(session_factory, analyst_llm)
        research_executor_factory = await _research_executor_factory(
            session_factory, research_llm
        )
        runner = LocalInvestigationRunner(
            uow_factory=uow_factory,
            provider_registry={
                SourceId.GOOGLE_PUBLIC_DNS: _DomainDnsProvider(
                    GooglePublicDnsProvider(http, clock=lambda: _FIXED_TS)
                ),
                SourceId.THREATFOX: _ThreatFoxIpProvider(),
            },
            analysis_executor_factory=lambda investigation_id: (
                EvidenceAnalystAnalysisExecutor(
                    analyst, bound_investigation_id=investigation_id
                )
            ),
            research_executor_factory=research_executor_factory,
            clock=lambda: _FIXED_TS,
            recursion_limit=40,
        )
        final: InvestigationState = await runner.run(investigation_id)
    assert research_llm.calls == []
    assert final.status is InvestigationStatus.COMPLETED
    assert final.research_result_ids == [result_id]
    [execution] = final.research_executions
    assert execution.status is ResearchExecutionStatus.COMPLETED
    assert execution.result_id == result_id
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(investigation_id)
    assert len(results) == 1
    assert results[0].id == result_id
    # The adopted result was never re-executed: exactly one RESEARCH_REQUESTED
    # event (the reconciliation re-authorization), zero new rows.
    async with uow_factory() as uow:
        events = await uow.timeline_events.list_by_investigation(investigation_id)
    requested = [
        event
        for event in events
        if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
    ]
    assert len(requested) == 1


async def test_i05_llm_accounting_version_interaction(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I05: research LLM reservations advance the Investigation version and
    the completion transition reloads the authoritative version."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    query = _research_query()
    top = await _top_chunk_for_query(session_factory, query)
    assert top is not None
    research_llm = FakeLlmClient()
    research_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The malware family is associated with the technique.",
                    citation_ids=(top[0],),
                ),
            ),
        )
    )
    final, _ = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    # Analyst: two accounted invocations (NEEDS_MORE_EVIDENCE + SUFFICIENT);
    # Research Agent: one accounted invocation. Total = 3.
    assert final.budget.llm_calls_used == 3
    # The completion succeeded against the post-accounting version: the
    # Investigation completed and history/version remain coherent.
    assert final.status is InvestigationStatus.COMPLETED
    [execution] = final.research_executions
    assert execution.status is ResearchExecutionStatus.COMPLETED
    async with uow_factory() as uow:
        durable = await uow.investigations.get_by_id(final.investigation_id)
    assert durable is not None
    assert durable.budget.llm_calls_used == 3
    assert durable.version == final.version


async def test_i06_bounded_recoverable_retry(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I06: one recoverable failure then success yields exactly two
    RESEARCH_REQUESTED events, attempts == 2, and one result."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    query = _research_query()
    top = await _top_chunk_for_query(session_factory, query)
    assert top is not None
    research_llm = FakeLlmClient()
    research_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True))
    research_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The malware family is associated with the technique.",
                    citation_ids=(top[0],),
                ),
            ),
        )
    )
    final, _ = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    [execution] = final.research_executions
    assert execution.status is ResearchExecutionStatus.COMPLETED
    assert execution.attempts == 2
    assert execution.result_id is not None
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
        events = await uow.timeline_events.list_by_investigation(final.investigation_id)
    assert len(results) == 1
    requested = [
        event
        for event in events
        if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
    ]
    assert len(requested) == 2
    # No third attempt was ever issued.
    assert len(research_llm.calls) == 2


async def test_i07_exhaustion_after_two_recoverable_failures(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """I07: two recoverable orchestration failures exhaust the context."""
    await _index_corpus(uow_factory, session_factory, tmp_path)
    research_llm = FakeLlmClient()
    research_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True))
    research_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True))
    final, _ = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    [execution] = final.research_executions
    assert execution.status is ResearchExecutionStatus.EXHAUSTED
    assert execution.attempts == 2
    assert execution.result_id is None
    assert final.research_result_ids == []
    async with uow_factory() as uow:
        results = await uow.research_results.list_by_investigation(
            final.investigation_id
        )
        events = await uow.timeline_events.list_by_investigation(final.investigation_id)
    assert len(results) == 0
    requested = [
        event
        for event in events
        if event.type is InvestigationTimelineEventType.RESEARCH_REQUESTED
    ]
    assert len(requested) == 2
    assert len(research_llm.calls) == 2


async def test_i08_research_cannot_authorize_pivot(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """I08: research completion never enqueues or executes a pivot.

    The canonical trajectory's malware is RESEARCHABLE and has no provider
    path; after research completes the Coordinator stops with SUFFICIENT
    evidence. No pivot is authorized for the malware (or anything else) as a
    consequence of research.
    """
    await _index_corpus(uow_factory, session_factory, tmp_path)
    query = _research_query()
    top = await _top_chunk_for_query(session_factory, query)
    assert top is not None
    research_llm = FakeLlmClient()
    research_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The malware family is associated with the technique.",
                    citation_ids=(top[0],),
                ),
            ),
        )
    )
    final, _ = await _run_canonical_trajectory(
        uow_factory, session_factory, research_llm=research_llm
    )
    assert final.status is InvestigationStatus.COMPLETED
    assert final.stop_reason == StopReason.SUFFICIENT_EVIDENCE.value
    assert len(research_llm.calls) == 1
    # Only the pre-research IP pivot exists (authorized by normal Coordinator
    # policy before the malware was marked); nothing was enqueued after
    # research and the malware was never pivoted.
    assert all(
        pivot.entity_id not in set(final.research_required_for_entity_ids)
        for pivot in final.pending_pivots
    )
    assert not final.pending_provider_work
    assert await _count_rows(integration_engine, "research_result") == 1
    # No Assessment was created or modified by research: only the two analyst
    # rounds exist.
    assert await _count_rows(integration_engine, "assessment") == 2
    assert final.assessment_id is not None
