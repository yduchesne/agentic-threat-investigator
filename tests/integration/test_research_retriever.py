# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for PostgreSQL/pgvector research retrieval."""

import json
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.embeddings import EmbeddedText, EmbeddingClient
from agentic_threat_investigator.app.persistence import (
    DocumentBatchItem,
    DocumentChunkBatchItem,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    EmbeddingModelInfo,
)
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.evaluation.retrieval import (
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)


class AxisEmbeddingClient(EmbeddingClient):
    """Return one deterministic unit vector for integration queries."""

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Identify the compatible synthetic representation."""
        return EmbeddingModelInfo(
            provider="test-provider",
            model="test-model",
            model_version=1,
            dimension=1536,
        )

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Embed exactly one query on the first synthetic axis."""
        assert len(texts) == 1
        return [EmbeddedText(1, [1.0] + [0.0] * 1535)]


def _source(source_id: str, record_id: str, document_type: str) -> SourceRecord:
    return SourceRecord(
        source_id=source_id,
        source_record_id=record_id,
        record_type=document_type,
        normalization_version=1,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"fixture": record_id},
    )


def _document(source_id: str, record_id: str, document_type: str) -> Document:
    return Document(
        source_id=source_id,
        source_record_id=record_id,
        document_type=document_type,
        title=f"Title {record_id}",
        source_url=f"https://example.test/{record_id}",
        published_at=datetime(2026, 1, 2, tzinfo=UTC),
        retrieved_at=datetime(2026, 1, 3, tzinfo=UTC),
        content=f"Synthetic content {record_id}",
        normalization_version=1,
        chunking_version=1,
        metadata={"record": record_id},
    )


def _chunk(
    document_id: UUID,
    record_id: str,
    vector: tuple[float, ...],
    *,
    text_value: str | None = None,
    model_version: int = 1,
) -> DocumentChunk:
    return DocumentChunk(
        document_id=document_id,
        sequence=1,
        text=text_value or f"Synthetic chunk {record_id}",
        token_count=3,
        embedding_provider="test-provider",
        embedding_model="test-model",
        embedding_model_version=model_version,
        embedding_dimension=1536,
        embedding=vector,
        metadata={"section": record_id},
    )


async def _persist_corpus(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> dict[str, UUID]:
    entries = [
        ("urn:test:allowed", "best", "advisory", (1.0, 0.0)),
        ("urn:test:allowed", "second", "technique", (0.8, 0.6)),
        ("urn:test:other", "third", "advisory", (0.6, 0.8)),
    ]
    identifiers: dict[str, UUID] = {}
    for source_id, record_id, document_type, components in entries:
        async with uow_factory() as uow:
            await uow.source_records.upsert_batch(
                [SourceRecordBatchItem(_source(source_id, record_id, document_type))]
            )
            result = await uow.documents.upsert_batch(
                [DocumentBatchItem(_document(source_id, record_id, document_type))]
            )
            document_id = result[0].document_id
            vector = components + (0.0,) * 1534
            chunks = await uow.document_chunks.replace_batch(
                [document_id],
                [DocumentChunkBatchItem(_chunk(document_id, record_id, vector))],
            )
            identifiers[f"document-{record_id}"] = document_id
            identifiers[f"chunk-{record_id}"] = chunks[0].chunk_id
    return identifiers


def _query(**values: object) -> ResearchQuery:
    return ResearchQuery.model_validate(
        {
            "investigation_id": uuid4(),
            "query": "'; DROP TABLE ati.document; --",
            **values,
        }
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pgvector_retrieval_orders_bounds_and_maps_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
) -> None:
    """Real pgvector SQL returns bounded cosine order and complete provenance."""
    identifiers = await _persist_corpus(uow_factory)
    retriever = PgVectorResearchRetriever(session_factory, AxisEmbeddingClient())

    chunks = await retriever.retrieve(_query(max_results=2))

    assert [chunk.chunk_id for chunk in chunks] == [
        identifiers["chunk-best"],
        identifiers["chunk-second"],
    ]
    assert chunks[0].similarity_score == pytest.approx(1.0)
    assert chunks[1].similarity_score == pytest.approx(0.8)
    assert chunks[0].title == "Title best"
    assert chunks[0].published_at == datetime(2026, 1, 2, tzinfo=UTC)
    assert chunks[0].metadata == {
        "document_type": "advisory",
        "chunk_sequence": 1,
        "document": {"record": "best"},
        "chunk": {"section": "best"},
    }
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE ati.document SET title=NULL, source_url=NULL, published_at=NULL "
                "WHERE id=:id"
            ),
            {"id": identifiers["document-best"]},
        )
    nullable = await retriever.retrieve(
        _query(source_ids=["urn:test:allowed"], max_results=1)
    )
    assert nullable[0].title is None
    assert nullable[0].source_url is None
    assert nullable[0].published_at is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_retrieval_filters_embedding_space_and_deleted_parents(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
) -> None:
    """Source/type filters combine with compatibility and visibility predicates."""
    identifiers = await _persist_corpus(uow_factory)
    retriever = PgVectorResearchRetriever(session_factory, AxisEmbeddingClient())

    source_only = await retriever.retrieve(_query(source_ids=["urn:test:other"]))
    type_only = await retriever.retrieve(_query(document_types=["technique"]))
    combined = await retriever.retrieve(
        _query(source_ids=["urn:test:allowed"], document_types=["advisory"])
    )
    assert [chunk.chunk_id for chunk in source_only] == [identifiers["chunk-third"]]
    assert [chunk.chunk_id for chunk in type_only] == [identifiers["chunk-second"]]
    assert [chunk.chunk_id for chunk in combined] == [identifiers["chunk-best"]]
    multi_value = await retriever.retrieve(
        _query(
            source_ids=["urn:test:allowed", "urn:test:other"],
            document_types=["advisory", "technique"],
        )
    )
    assert len(multi_value) == 3

    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE ati.document_chunk SET embedding_model_version=2 WHERE id=:id"
            ),
            {"id": identifiers["chunk-best"]},
        )
        await connection.execute(
            text("UPDATE ati.document SET deleted_at=now() WHERE id=:id"),
            {"id": identifiers["document-second"]},
        )
    remaining = await retriever.retrieve(_query())
    assert [chunk.chunk_id for chunk in remaining] == [identifiers["chunk-third"]]
    assert await retriever.retrieve(_query(source_ids=["urn:test:missing"])) == []


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.parametrize(
    ("column", "value"),
    [("embedding_provider", "other-provider"), ("embedding_model", "other-model")],
)
async def test_each_embedding_identity_mismatch_is_excluded(
    column: str,
    value: str,
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
) -> None:
    """Provider and model mismatches are independently excluded."""
    identifiers = await _persist_corpus(uow_factory)
    statements = {
        "embedding_provider": (
            "UPDATE ati.document_chunk SET embedding_provider=:value WHERE id=:id"
        ),
        "embedding_model": (
            "UPDATE ati.document_chunk SET embedding_model=:value WHERE id=:id"
        ),
    }
    async with integration_engine.begin() as connection:
        await connection.execute(
            text(statements[column]), {"value": value, "id": identifiers["chunk-best"]}
        )
    chunks = await PgVectorResearchRetriever(
        session_factory, AxisEmbeddingClient()
    ).retrieve(_query(source_ids=["urn:test:allowed"], document_types=["advisory"]))
    assert chunks == []


VECTOR_COMPONENTS = {
    "axis-0": (1.0, 0.0),
    "axis-0-best": (0.95, 0.3122498999),
    "axis-0-near": (0.8, 0.6),
    "axis-1": (0.0, 1.0),
}


async def _persist_fixture_rows(
    fixture: dict[str, Any], uow_factory: Callable[[], PostgresUnitOfWork]
) -> dict[str, UUID]:
    """Persist fixture rows and return their database identities."""
    identifiers: dict[str, UUID] = {}
    for row in fixture["corpus"] + fixture["setup_variants"]:
        async with uow_factory() as uow:
            await uow.source_records.upsert_batch(
                [
                    SourceRecordBatchItem(
                        _source(
                            row["source_id"],
                            row["source_record_id"],
                            row["document_type"],
                        )
                    )
                ]
            )
            documents = await uow.documents.upsert_batch(
                [
                    DocumentBatchItem(
                        _document(
                            row["source_id"],
                            row["source_record_id"],
                            row["document_type"],
                        )
                    )
                ]
            )
            document_id = documents[0].document_id
            vector = VECTOR_COMPONENTS[row["vector_label"]] + (0.0,) * 1534
            chunk = _chunk(
                document_id,
                row["id"],
                vector,
                text_value=row["text"],
                model_version=row.get("embedding_model_version", 1),
            )
            chunks = await uow.document_chunks.replace_batch(
                [document_id], [DocumentChunkBatchItem(chunk)]
            )
            identifiers[row["id"]] = chunks[0].chunk_id
            identifiers[f"document:{row['id']}"] = document_id
    return identifiers


@pytest.mark.asyncio
@pytest.mark.integration
async def test_committed_fixture_drives_real_retrieval_and_exact_metrics(
    uow_factory: Callable[[], PostgresUnitOfWork],
    session_factory: async_sessionmaker[AsyncSession],
    integration_engine: AsyncEngine,
) -> None:
    """Committed cases exercise real filters, gaps, isolation, and metrics."""
    fixture: dict[str, Any] = json.loads(
        Path("evals/fixtures/research/retrieval_cases.json").read_text(encoding="utf-8")
    )
    identifiers = await _persist_fixture_rows(fixture, uow_factory)
    async with integration_engine.begin() as connection:
        await connection.execute(
            text("UPDATE ati.document SET deleted_at=now() WHERE id=:id"),
            {"id": identifiers["document:chunk-deleted"]},
        )
    retriever = PgVectorResearchRetriever(session_factory, AxisEmbeddingClient())
    reverse_ids = {
        value: key
        for key, value in identifiers.items()
        if not key.startswith("document:")
    }
    for case in fixture["cases"]:
        chunks = await retriever.retrieve(
            ResearchQuery(
                investigation_id=uuid5(NAMESPACE_URL, case["id"]),
                query=case["query"],
                source_ids=case["source_ids"],
                document_types=case["document_types"],
                max_results=case["k"],
            )
        )
        retrieved_ids = [reverse_ids[chunk.chunk_id] for chunk in chunks]
        assert not set(retrieved_ids) & set(case["forbidden_chunk_ids"])
        assert set(case["expected_relevant_chunk_ids"]) <= set(retrieved_ids)
        metrics = case["expected_metrics"]
        if metrics is not None:
            relevant = case["expected_relevant_chunk_ids"]
            assert recall_at_k(retrieved_ids, relevant, case["k"]) == pytest.approx(
                metrics["recall_at_k"]
            )
            assert precision_at_k(retrieved_ids, relevant, case["k"]) == pytest.approx(
                metrics["precision_at_k"]
            )
            assert reciprocal_rank(retrieved_ids, relevant) == pytest.approx(
                metrics["mrr"]
            )
