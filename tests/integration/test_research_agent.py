# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical PR 22B Research Agent PostgreSQL vertical slices.

The canonical path exercises the real production research stack — real-format
MITRE ATT&CK STIX fixture, production parser, document builder, indexing
service, real PostgreSQL persistence, real pgvector retrieval, the real
``LlmAccountingService``, the real ``ResearchResultPersistenceService``, and
the real ``ResearchResultRepository`` — with ``FakeLlmClient`` used ONLY at
the model boundary. No live Internet or live LLM participates.
"""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from agentic_threat_investigator.app.document_indexing import (
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.ingestion import IngestionService
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import (
    ResearchResultReferenceError,
)
from agentic_threat_investigator.app.research_agent.agent import ResearchAgent
from agentic_threat_investigator.app.research_agent.errors import (
    ResearchAgentCitationError,
)
from agentic_threat_investigator.app.sources import ArtifactReference
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import (
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
)
from agentic_threat_investigator.domain.research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
    ResearchAgentRequest,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient
from agentic_threat_investigator.infrastructure.object_store import (
    FileSystemObjectStore,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack import (
    MitreAttackBatchSource,
)
from agentic_threat_investigator.infrastructure.sources.mitre_attack_documents import (
    MitreAttackDocumentBuilder,
)
from tests.support.llm_fixtures import FakeLlmClient

FIXTURE = Path("tests/fixtures/mitre_attack/enterprise_attack_small.json")
CONTRADICTION_FIXTURE = Path(
    "tests/fixtures/mitre_attack/enterprise_contradiction_small.json"
)
RETRIEVED_AT = datetime(2026, 1, 15, tzinfo=UTC)
# One distinctive technique whose description words are unique to it; the
# deterministic hashing representation ranks it first for the query below.
TECHNIQUE_RECORD_ID = "attack-pattern--8a8e9e5e-2b4c-4d6e-8f0a-112233445566"
DISTINCTIVE_QUERY = "obfuscate command-and-control traffic conceal exfiltrated data"
# Words shared verbatim by both contradictory descriptions.
CONTRADICTION_QUERY = "detection visibility fixture telemetry statement"


def _document_records(records: Sequence[SourceRecord]) -> list[SourceRecord]:
    """Return only the persisted records the MITRE document builder supports."""
    builder = MitreAttackDocumentBuilder()
    return [
        record
        for record in records
        if record.record_type in builder.document_record_types
    ]


async def _ingest_fixture(
    uow_factory: Callable[[], PostgresUnitOfWork],
    tmp_path: Path,
    *,
    fixture: Path,
) -> list[SourceRecord]:
    """Write one fixture into the production filesystem store and ingest it."""
    store = FileSystemObjectStore(tmp_path)
    uri = f"file://{tmp_path / 'datasets/mitre/enterprise.json'}"
    await store.write(uri, fixture.read_bytes())
    artifact = ArtifactReference("urn:ati:source:mitre_attack", uri, RETRIEVED_AT)
    ingestion = IngestionService(uow_factory, batch_size=20)
    result = await ingestion.ingest(
        MitreAttackBatchSource(store, batch_size=20), artifact
    )
    async with uow_factory() as uow:
        records = [
            record
            for result_item in result.changed
            if (record := await uow.source_records.get_by_id(result_item.record_id))
            is not None
        ]
    return _document_records(records)


async def _index(
    records: Sequence[SourceRecord], uow_factory: Callable[[], PostgresUnitOfWork]
) -> None:
    """Index the persisted records through the production indexing service."""
    indexing = DocumentIndexingService(
        uow_factory,
        MitreAttackDocumentBuilder(),
        TokenBoundedChunker(400, 800),
        HashingEmbeddingClient(),
        batch_size=20,
        embedding_batch_size=4,
    )
    await indexing.index(records)


async def _seed_subject(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> tuple[UUID, UUID]:
    """Create one investigation and one subject entity, returning both IDs."""
    investigation_id = uuid4()
    entity_id = uuid4()
    async with uow_factory() as uow:
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[entity_id],
                objective="Explain the contextual question.",
                budget=default_investigation_budget(),
                started_at=RETRIEVED_AT,
            )
        )
        await uow.entities.upsert(
            Entity(id=entity_id, type=EntityType.DOMAIN, value="example.test")
        )
    return investigation_id, entity_id


async def _indexed_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
    tmp_path: Path,
    *,
    fixture: Path = FIXTURE,
) -> None:
    """Ingest and index one fixture into real PostgreSQL."""
    records = await _ingest_fixture(uow_factory, tmp_path, fixture=fixture)
    await _index(records, uow_factory)


def _agent(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    fake_llm: FakeLlmClient,
) -> ResearchAgent:
    """Build the production-composed Research Agent with a fake model boundary."""
    return build_research_agent(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=HashingEmbeddingClient(),
        llm_client=fake_llm,
        max_structured_output_attempts=2,
    )


def _request(
    investigation_id: UUID, entity_id: UUID, **overrides: object
) -> ResearchAgentRequest:
    """Build one bounded integration request."""
    values: dict[str, object] = {
        "investigation_id": investigation_id,
        "subject_entity_id": entity_id,
        "query": DISTINCTIVE_QUERY,
        "max_results": 3,
    }
    values.update(overrides)
    return ResearchAgentRequest.model_validate(values)


async def _top_chunk(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    investigation_id: UUID,
    *,
    query: str = DISTINCTIVE_QUERY,
    max_results: int = 3,
) -> list[RetrievedChunk]:
    """Return the deterministic real-retrieval result for one query."""
    del uow_factory
    retriever = PgVectorResearchRetriever(session_factory, HashingEmbeddingClient())
    return await retriever.retrieve(
        ResearchQuery(
            investigation_id=investigation_id,
            query=query,
            max_results=max_results,
        )
    )


async def _research_result_count(
    uow_factory: Callable[[], PostgresUnitOfWork], investigation_id: UUID
) -> int:
    """Return the persisted research-result count for one investigation."""
    async with uow_factory() as uow:
        return len(await uow.research_results.list_by_investigation(investigation_id))


async def _count_rows(integration_engine: AsyncEngine, table: str) -> int:
    """Return the row count of one ati table."""
    async with integration_engine.connect() as connection:
        return int(
            (await connection.scalar(text(f"SELECT count(*) FROM ati.{table}"))) or 0
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relevant_context_persists_with_real_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """RI-01: real retrieval + synthesis persists one fully provenanced result."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    retrieved = await _top_chunk(uow_factory, session_factory, investigation_id)
    assert retrieved, "the canonical corpus must retrieve"
    top = retrieved[0]
    assert top.source_record_id == TECHNIQUE_RECORD_ID

    fake_llm = FakeLlmClient()
    fake_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="The technique obscures command-and-control traffic.",
                    citation_ids=(top.citation_id,),
                ),
            ),
        )
    )
    agent = _agent(uow_factory, session_factory, fake_llm)

    result = await agent.research(_request(investigation_id, entity_id))

    assert isinstance(result, ResearchResult)
    assert result.investigation_id == investigation_id
    assert result.subject_entity_id == entity_id
    assert result.query == DISTINCTIVE_QUERY
    assert [claim.citation_ids for claim in result.claims] == [(top.citation_id,)]
    [citation] = result.citations
    assert citation.citation_id == top.citation_id
    assert citation.source_record_id == TECHNIQUE_RECORD_ID
    assert citation.document_type == "attack_technique"
    assert citation.chunk_sequence == top.chunk_sequence
    assert citation.text == top.text
    assert citation.title == top.title
    assert citation.chunk_id == top.chunk_id

    # The model-visible prompt exposes exactly the supplied stable citation.
    [call] = fake_llm.calls
    assert f"citation_id: {top.citation_id}" in call.user_prompt
    assert "chunk_id" not in call.user_prompt
    assert str(top.chunk_id) not in call.user_prompt

    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
    assert reloaded == result
    assert await _research_result_count(uow_factory, investigation_id) == 1
    assert await _count_rows(integration_engine, "evidence") == 0
    assert await _count_rows(integration_engine, "assessment") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_unsupported_citation_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """RI-02: a citation outside the supplied set is rejected before persistence."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    # The supplied prompt contains exactly the top-1 chunk.
    supplied = await _top_chunk(
        uow_factory, session_factory, investigation_id, max_results=1
    )
    assert len(supplied) == 1
    # A real stable citation that exists in the corpus but was NOT supplied.
    all_chunks = await _top_chunk(
        uow_factory, session_factory, investigation_id, max_results=10
    )
    supplied_ids = {chunk.citation_id for chunk in supplied}
    unsupplied = next(
        chunk for chunk in all_chunks if chunk.citation_id not in supplied_ids
    )

    fake_llm = FakeLlmClient()
    fake_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="Cites a corpus chunk outside the prompt.",
                    citation_ids=(unsupplied.citation_id,),
                ),
            ),
        )
    )
    agent = _agent(uow_factory, session_factory, fake_llm)

    with pytest.raises(ResearchAgentCitationError) as holder:
        await agent.research(_request(investigation_id, entity_id, max_results=1))

    assert holder.value.citation_ids == (unsupplied.citation_id,)
    assert await _research_result_count(uow_factory, investigation_id) == 0
    assert await _count_rows(integration_engine, "research_result") == 0
    assert await _count_rows(integration_engine, "evidence") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_no_retrieval_results_persists_empty(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """RI-03: empty retrieval persists a zero-claim result with zero LLM calls."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    fake_llm = FakeLlmClient()
    agent = _agent(uow_factory, session_factory, fake_llm)

    result = await agent.research(
        _request(
            investigation_id,
            entity_id,
            source_ids=("urn:ati:source:missing",),
        )
    )

    assert result.claims == ()
    assert result.citations == ()
    assert fake_llm.calls == []
    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
    assert reloaded == result
    assert await _count_rows(integration_engine, "evidence") == 0
    assert await _count_rows(integration_engine, "assessment") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_irrelevant_context_yields_empty_result(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RI-04: retrieved-but-irrelevant context persists claims=() without snapshots."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    retrieved = await _top_chunk(uow_factory, session_factory, investigation_id)
    assert retrieved

    fake_llm = FakeLlmClient()
    fake_llm.set_default(ResearchAgentDecision())
    agent = _agent(uow_factory, session_factory, fake_llm)

    result = await agent.research(_request(investigation_id, entity_id))

    assert len(fake_llm.calls) == 1
    assert result.claims == ()
    assert result.citations == ()
    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
    assert reloaded == result


@pytest.mark.asyncio
@pytest.mark.integration
async def test_contradictory_context_is_represented_not_resolved(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """RI-05: conflicting sources persist as separately cited claims."""
    await _indexed_corpus(uow_factory, tmp_path, fixture=CONTRADICTION_FIXTURE)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    retrieved = await _top_chunk(
        uow_factory,
        session_factory,
        investigation_id,
        query=CONTRADICTION_QUERY,
        max_results=2,
    )
    assert len(retrieved) == 2, "both contradictory chunks must be retrieved"
    first, second = retrieved[0], retrieved[1]

    fake_llm = FakeLlmClient()
    fake_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="Alpha states the technique increases detection visibility.",
                    citation_ids=(first.citation_id,),
                ),
                ResearchAgentClaim(
                    text="Beta states the technique decreases detection visibility.",
                    citation_ids=(second.citation_id,),
                ),
            ),
        )
    )
    agent = _agent(uow_factory, session_factory, fake_llm)

    result = await agent.research(
        _request(investigation_id, entity_id, query=CONTRADICTION_QUERY, max_results=2)
    )

    assert [claim.citation_ids for claim in result.claims] == [
        (first.citation_id,),
        (second.citation_id,),
    ]
    assert [citation.citation_id for citation in result.citations] == [
        first.citation_id,
        second.citation_id,
    ]
    assert "verdict" not in ResearchResult.model_fields
    assert "confidence" not in ResearchResult.model_fields
    assert await _count_rows(integration_engine, "assessment") == 0
    assert await _research_result_count(uow_factory, investigation_id) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_persistence_reference_validation_rolls_back(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    """RI-06: missing Investigation/Entity references fail through the real seam."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    agent = _agent(uow_factory, session_factory, FakeLlmClient())

    with pytest.raises(ResearchResultReferenceError):
        await agent.research(
            _request(investigation_id, uuid4(), source_ids=("urn:ati:source:missing",))
        )
    with pytest.raises(ResearchResultReferenceError):
        await agent.research(
            _request(uuid4(), entity_id, source_ids=("urn:ati:source:missing",))
        )

    assert await _research_result_count(uow_factory, investigation_id) == 0
    assert await _count_rows(integration_engine, "research_result") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_structured_output_repair_persists_exactly_once(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    tmp_path: Path,
) -> None:
    """RI-07: one retryable invalid output triggers one repair and one result."""
    await _indexed_corpus(uow_factory, tmp_path)
    investigation_id, entity_id = await _seed_subject(uow_factory)
    top = (await _top_chunk(uow_factory, session_factory, investigation_id))[0]

    fake_llm = FakeLlmClient()
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.set_default(
        ResearchAgentDecision(
            claims=(
                ResearchAgentClaim(
                    text="Repaired contextual statement.",
                    citation_ids=(top.citation_id,),
                ),
            ),
        )
    )
    agent = _agent(uow_factory, session_factory, fake_llm)

    result = await agent.research(_request(investigation_id, entity_id))

    assert len(fake_llm.calls) == 2
    assert "failed structured-schema validation" in fake_llm.calls[1].user_prompt
    assert await _research_result_count(uow_factory, investigation_id) == 1
    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
        state = await uow.investigations.get_by_id(investigation_id)
    assert reloaded == result
    assert state is not None and state.budget.llm_calls_used == 2
