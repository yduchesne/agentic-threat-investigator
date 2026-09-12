# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL integration coverage for immutable ResearchResult persistence."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.embeddings import (
    EmbeddedText,
    EmbeddingClient,
)
from agentic_threat_investigator.app.persistence.repositories import (
    DocumentBatchItem,
    DocumentChunkBatchItem,
    ResearchResultDuplicateIdentityError,
    ResearchResultReferenceError,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.app.research_persistence import (
    ResearchResultPersistenceService,
)
from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    EmbeddingModelInfo,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.research import (
    ResearchCitation,
    ResearchClaim,
    ResearchQuery,
    ResearchResult,
    research_citation_from_retrieved_chunk,
)
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


class _IdentityEmbeddingClient(EmbeddingClient):
    """Deterministic test embedding client with a configurable identity."""

    def __init__(self, *, provider: str, model: str) -> None:
        self._info = EmbeddingModelInfo(
            provider=provider, model=model, model_version=1, dimension=1536
        )

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return the configured embedding identity."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Return the first-axis unit vector for every query."""
        return [
            EmbeddedText(index, [1.0] + [0.0] * 1535)
            for index, _ in enumerate(texts, 1)
        ]


def _research_result(
    investigation_id: UUID,
    subject_entity_id: UUID,
    citation_ids: tuple[UUID, ...] | None = None,
    *,
    result_id: UUID | None = None,
    citation: ResearchCitation | None = None,
) -> ResearchResult:
    """Build a deterministic valid research result for one subject entity."""
    citation = citation or ResearchCitation(
        citation_id=citation_ids[0] if citation_ids else uuid4(),
        document_id=uuid4(),
        source_id="urn:ati:source:test",
        source_record_id="attack-pattern--one",
        document_type="attack_technique",
        chunk_sequence=1,
        text="Cited chunk text",
        title="Example technique",
        source_url="https://attack.mitre.org/techniques/T1001",
        published_at=_RETRIEVED_AT,
        similarity_score=0.9,
        metadata={"section": "Details"},
    )
    claim_citation_ids = (citation.citation_id,)
    return ResearchResult(
        id=result_id or uuid4(),
        investigation_id=investigation_id,
        subject_entity_id=subject_entity_id,
        query="Which persistence techniques apply?",
        claims=(
            ResearchClaim(
                id=uuid4(),
                text="Example technique enables persistence.",
                citation_ids=claim_citation_ids,
            ),
        ),
        citations=(citation,),
        created_at=_RETRIEVED_AT,
    )


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
                objective="Assess the root indicator.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        )
        await uow.entities.upsert(
            Entity(id=entity_id, type=EntityType.DOMAIN, value="example.test")
        )
    return investigation_id, entity_id


async def _seed_chunk(
    uow_factory: Callable[[], PostgresUnitOfWork], embedding_model: str = "model-a"
) -> tuple[UUID, UUID, DocumentChunk]:
    """Persist a source-document-chunk chain and return its identities."""
    async with uow_factory() as uow:
        await uow.source_records.upsert_batch(
            [
                SourceRecordBatchItem(
                    SourceRecord(
                        source_id="urn:ati:source:test",
                        source_record_id="attack-pattern--one",
                        record_type="attack_technique",
                        normalization_version=1,
                        retrieved_at=_RETRIEVED_AT,
                        canonical_payload={"name": "Example"},
                    )
                )
            ]
        )
        document = await uow.documents.upsert_batch(
            [
                DocumentBatchItem(
                    Document(
                        source_id="urn:ati:source:test",
                        source_record_id="attack-pattern--one",
                        document_type="attack_technique",
                        title="Example technique",
                        source_url="https://attack.mitre.org/techniques/T1001",
                        retrieved_at=_RETRIEVED_AT,
                        content="## Overview\nExample technique description.",
                        normalization_version=1,
                        chunking_version=1,
                    )
                )
            ]
        )
        document_id = document[0].document_id
        vector = [0.0] * 1536
        vector[0] = 1.0
        chunk = DocumentChunk(
            document_id=document_id,
            sequence=1,
            text="Example technique enables persistence.",
            token_count=5,
            embedding_provider="hashing",
            embedding_model=embedding_model,
            embedding_model_version=1,
            embedding_dimension=1536,
            embedding=tuple(vector),
            metadata={"section": "Details"},
        )
        chunks = await uow.document_chunks.replace_batch(
            [document_id], [DocumentChunkBatchItem(chunk)]
        )
    return document_id, chunks[0].chunk_id, chunk


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_round_trips_exactly(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P1/I3: add/get round trip preserves the complete typed model."""
    investigation_id, entity_id = await _seed_subject(uow_factory)
    result = _research_result(investigation_id, entity_id)
    async with uow_factory() as uow:
        await uow.research_results.add(result)
    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
    assert reloaded == result
    assert reloaded is not None
    assert reloaded.claims[0].citation_ids == result.claims[0].citation_ids
    assert reloaded.citations[0].citation_id == result.citations[0].citation_id
    assert reloaded.citations[0].title == "Example technique"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_list_is_deterministic_and_isolated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P2/P3: listing orders by (created_at, id) and other investigations isolate."""
    first_id, entity_id = await _seed_subject(uow_factory)
    second_id, _ = await _seed_subject(uow_factory)
    result_a = _research_result(first_id, entity_id, result_id=uuid4())
    result_b = _research_result(first_id, entity_id, result_id=uuid4())
    other = _research_result(second_id, entity_id)
    async with uow_factory() as uow:
        await uow.research_results.add(result_b)
        await uow.research_results.add(result_a)
        await uow.research_results.add(other)
    async with uow_factory() as uow:
        listed = await uow.research_results.list_by_investigation(first_id)
        isolated = await uow.research_results.list_by_investigation(second_id)
    assert [result.id for result in listed] == sorted(
        [result_a.id, result_b.id], key=lambda item: (item,)
    )
    assert [result.id for result in isolated] == [other.id]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_duplicate_identity_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P4: a duplicate result identity is rejected and never updates a row."""
    investigation_id, entity_id = await _seed_subject(uow_factory)
    result = _research_result(investigation_id, entity_id)
    async with uow_factory() as uow:
        await uow.research_results.add(result)
    with pytest.raises(ResearchResultDuplicateIdentityError):
        async with uow_factory() as uow:
            await uow.research_results.add(result)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_service_validates_root_references(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P5/P6: missing Investigation or Entity references fail closed."""
    service = ResearchResultPersistenceService(uow_factory)
    _, entity_id = await _seed_subject(uow_factory)

    missing_investigation = _research_result(uuid4(), entity_id)
    with pytest.raises(ResearchResultReferenceError):
        await service.persist(missing_investigation)

    investigation_id, _ = await _seed_subject(uow_factory)
    missing_entity = _research_result(investigation_id, uuid4())
    with pytest.raises(ResearchResultReferenceError):
        await service.persist(missing_entity)
    async with uow_factory() as uow:
        assert await uow.research_results.get_by_id(missing_entity.id) is None

    valid = _research_result(investigation_id, entity_id)
    await service.persist(valid)
    async with uow_factory() as uow:
        assert (await uow.research_results.get_by_id(valid.id)) == valid


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_rolls_back_with_same_unit_of_work(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """P7: a failing sibling operation rolls back the inserted result."""
    investigation_id, entity_id = await _seed_subject(uow_factory)
    result = _research_result(investigation_id, entity_id)
    with pytest.raises(DBAPIError):
        async with uow_factory() as uow:
            await uow.research_results.add(result)
            await uow.document_chunks.replace_batch(
                [uuid4()], [DocumentChunkBatchItem(_dangling_chunk())]
            )
    async with uow_factory() as uow:
        assert await uow.research_results.get_by_id(result.id) is None


def _dangling_chunk() -> DocumentChunk:
    """Build a chunk referencing a nonexistent document to force a DB failure."""
    vector = [0.0] * 1536
    vector[0] = 1.0
    return DocumentChunk(
        document_id=uuid4(),
        sequence=1,
        text="dangling chunk",
        token_count=2,
        embedding_provider="hashing",
        embedding_model="model-a",
        embedding_model_version=1,
        embedding_dimension=1536,
        embedding=tuple(vector),
        metadata={},
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_persistence_creates_no_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork], integration_engine: AsyncEngine
) -> None:
    """P8: persisting research context never creates Evidence rows."""
    investigation_id, entity_id = await _seed_subject(uow_factory)
    result = _research_result(investigation_id, entity_id)
    async with uow_factory() as uow:
        await uow.research_results.add(result)
    async with integration_engine.connect() as connection:
        count = await connection.scalar(text("SELECT count(*) FROM ati.evidence"))
        relationship_count = await connection.scalar(
            text("SELECT count(*) FROM ati.relationship_observation")
        )
    assert count == 0 and relationship_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_result_snapshot_survives_chunk_replacement(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: Any,
) -> None:
    """I4: a persisted result stays interpretable after active chunks change."""
    investigation_id, entity_id = await _seed_subject(uow_factory)
    document_id, chunk_id, chunk = await _seed_chunk(uow_factory, "model-a")
    retriever = PgVectorResearchRetriever(
        session_factory, _IdentityEmbeddingClient(provider="hashing", model="model-a")
    )
    retrieved = await retriever.retrieve(
        ResearchQuery(
            investigation_id=investigation_id,
            query="Example technique",
            max_results=1,
        )
    )
    assert len(retrieved) == 1
    assert retrieved[0].citation_id == chunk.citation_id
    citation = research_citation_from_retrieved_chunk(retrieved[0])
    result = _research_result(
        investigation_id,
        entity_id,
        citation=citation,
    )
    async with uow_factory() as uow:
        await uow.research_results.add(result)

    # Replace the active chunk set under a different embedding identity.
    reembed_document_id, new_chunk_id, reembedded = await _seed_chunk(
        uow_factory, "model-b"
    )
    assert reembed_document_id == document_id
    assert reembedded.citation_id == chunk.citation_id
    assert new_chunk_id != chunk_id

    # The old identity retriever no longer sees the corpus; the new one does.
    old_corpus = await PgVectorResearchRetriever(
        session_factory,
        _IdentityEmbeddingClient(provider="hashing", model="model-a"),
    ).retrieve(
        ResearchQuery(
            investigation_id=investigation_id, query="Example technique", max_results=1
        )
    )
    assert old_corpus == []
    new_corpus = await PgVectorResearchRetriever(
        session_factory,
        _IdentityEmbeddingClient(provider="hashing", model="model-b"),
    ).retrieve(
        ResearchQuery(
            investigation_id=investigation_id, query="Example technique", max_results=1
        )
    )
    assert [item.citation_id for item in new_corpus] == [chunk.citation_id]

    async with uow_factory() as uow:
        reloaded = await uow.research_results.get_by_id(result.id)
    assert reloaded == result
    assert reloaded is not None
    assert reloaded.citations[0].citation_id == chunk.citation_id
    assert reloaded.claims[0].citation_ids == (chunk.citation_id,)
    # The snapshot no longer depends on the old active row identity.
    assert reloaded.citations[0].chunk_id == chunk_id
