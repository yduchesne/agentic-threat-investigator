# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests for PostgreSQL RAG document and chunk persistence."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.persistence import (
    BatchOutcome,
    DocumentBatchItem,
    DocumentChunkBatchItem,
    SourceRecordBatchItem,
)
from agentic_threat_investigator.domain.documents import Document, DocumentChunk
from agentic_threat_investigator.domain.source import SourceRecord
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)


def _source_record() -> SourceRecord:
    return SourceRecord(
        source_id="urn:ati:source:test",
        source_record_id="record-1",
        record_type="attack_technique",
        normalization_version=1,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"name": "Synthetic"},
    )


def _document(content: str = "## Overview\nSynthetic") -> Document:
    return Document(
        source_id="urn:ati:source:test",
        source_record_id="record-1",
        document_type="attack_technique",
        title="Synthetic",
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        content=content,
        normalization_version=1,
        chunking_version=1,
        metadata={"fixture": True},
    )


def _chunk(
    document_id: UUID, sequence: int, *, first: float = 1.0, axis: int = 0
) -> DocumentChunk:
    values = [0.0] * 1536
    values[axis] = first
    vector = tuple(values)
    return DocumentChunk(
        document_id=document_id,
        sequence=sequence,
        text=f"chunk {sequence}",
        token_count=2,
        embedding_provider="hashing",
        embedding_model="ati-hashing-v1",
        embedding_model_version=1,
        embedding_dimension=1536,
        embedding=vector,
        metadata={"section": "Overview"},
    )


async def _insert_source(uow_factory: Callable[[], PostgresUnitOfWork]) -> None:
    async with uow_factory() as uow:
        await uow.source_records.upsert_batch([SourceRecordBatchItem(_source_record())])


@pytest.mark.asyncio
@pytest.mark.integration
async def test_document_versioning_history_and_batch_dedupe(
    uow_factory: Callable[[], PostgresUnitOfWork], integration_engine: AsyncEngine
) -> None:
    """Documents classify changes, allocate versions, and append history."""
    await _insert_source(uow_factory)
    async with uow_factory() as uow:
        inserted = await uow.documents.upsert_batch([DocumentBatchItem(_document())])
    assert inserted[0].outcome is BatchOutcome.INSERTED

    async with uow_factory() as uow:
        unchanged = await uow.documents.upsert_batch([DocumentBatchItem(_document())])
    assert unchanged[0].outcome is BatchOutcome.UNCHANGED
    assert unchanged[0].version == inserted[0].version

    async with uow_factory() as uow:
        updated = await uow.documents.upsert_batch(
            [DocumentBatchItem(_document("## Overview\nChanged"))]
        )
    assert updated[0].outcome is BatchOutcome.UPDATED
    assert updated[0].version > inserted[0].version

    async with uow_factory() as uow:
        duplicate = await uow.documents.upsert_batch(
            [DocumentBatchItem(_document()), DocumentBatchItem(_document())]
        )
    assert [item.outcome for item in duplicate] == [
        BatchOutcome.UPDATED,
        BatchOutcome.CONFLICT,
    ]

    async with integration_engine.connect() as connection:
        history_count = await connection.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type='document'"
            )
        )
    assert history_count == 3


@pytest.mark.asyncio
@pytest.mark.integration
async def test_chunk_replacement_physically_removes_stale_rows(
    uow_factory: Callable[[], PostgresUnitOfWork], integration_engine: AsyncEngine
) -> None:
    """Complete replacement removes stale sequences and preserves metadata."""
    await _insert_source(uow_factory)
    async with uow_factory() as uow:
        document_result = await uow.documents.upsert_batch(
            [DocumentBatchItem(_document())]
        )
        document_id = document_result[0].document_id
        first = await uow.document_chunks.replace_batch(
            [document_id],
            [
                DocumentChunkBatchItem(_chunk(document_id, 1)),
                DocumentChunkBatchItem(_chunk(document_id, 2)),
                DocumentChunkBatchItem(_chunk(document_id, 2)),
            ],
        )
    assert [item.outcome for item in first] == [
        BatchOutcome.INSERTED,
        BatchOutcome.INSERTED,
        BatchOutcome.CONFLICT,
    ]

    async with uow_factory() as uow:
        second = await uow.document_chunks.replace_batch(
            [document_id], [DocumentChunkBatchItem(_chunk(document_id, 1, first=0.5))]
        )
        chunks = await uow.document_chunks.list_by_document(document_id)
    assert len(second) == 1 and second[0].version > first[-1].version
    assert [chunk.sequence for chunk in chunks] == [1]
    assert chunks[0].metadata["section"] == "Overview"
    assert len(chunks[0].embedding) == 1536

    async with integration_engine.connect() as connection:
        history_count = await connection.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type='document_chunk'"
            )
        )
    assert history_count == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pgvector_cosine_ordering(
    uow_factory: Callable[[], PostgresUnitOfWork], integration_engine: AsyncEngine
) -> None:
    """Known vectors are ordered by cosine distance through the HNSW contract."""
    await _insert_source(uow_factory)
    async with uow_factory() as uow:
        document = await uow.documents.upsert_batch([DocumentBatchItem(_document())])
        document_id = document[0].document_id
        await uow.document_chunks.replace_batch(
            [document_id],
            [
                DocumentChunkBatchItem(_chunk(document_id, 1, axis=0)),
                DocumentChunkBatchItem(_chunk(document_id, 2, axis=1)),
            ],
        )
    query = "[1," + ",".join("0" for _ in range(1535)) + "]"
    async with integration_engine.connect() as connection:
        rows = await connection.execute(
            text(
                "SELECT sequence FROM ati.document_chunk "
                "ORDER BY embedding <=> CAST(:query AS vector) LIMIT 2"
            ),
            {"query": query},
        )
    assert [row[0] for row in rows] == [1, 2]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_failed_chunk_replace_rolls_back_document_update(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A replacement failure rolls back the preceding document mutation."""
    await _insert_source(uow_factory)
    async with uow_factory() as uow:
        document = await uow.documents.upsert_batch([DocumentBatchItem(_document())])
        document_id = document[0].document_id
        await uow.document_chunks.replace_batch(
            [document_id], [DocumentChunkBatchItem(_chunk(document_id, 1))]
        )

    with pytest.raises(DBAPIError):
        async with uow_factory() as uow:
            await uow.documents.upsert_batch(
                [DocumentBatchItem(_document("## Overview\nMust roll back"))]
            )
            await uow.document_chunks.replace_batch(
                [document_id], [DocumentChunkBatchItem(_chunk(uuid4(), 1))]
            )

    async with uow_factory() as uow:
        current = await uow.documents.get_by_identity("urn:ati:source:test", "record-1")
        chunks = await uow.document_chunks.list_by_document(document_id)
    assert current is not None and current.content == "## Overview\nSynthetic"
    assert [chunk.sequence for chunk in chunks] == [1]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_chunk_replacement_validates_document_set(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Unknown and out-of-set document IDs abort replacement."""
    await _insert_source(uow_factory)
    async with uow_factory() as uow:
        document = await uow.documents.upsert_batch([DocumentBatchItem(_document())])
    document_id = document[0].document_id

    with pytest.raises(DBAPIError):
        async with uow_factory() as uow:
            await uow.document_chunks.replace_batch(
                [uuid4()], [DocumentChunkBatchItem(_chunk(document_id, 1))]
            )

    with pytest.raises(DBAPIError):
        async with uow_factory() as uow:
            await uow.document_chunks.replace_batch(
                [document_id], [DocumentChunkBatchItem(_chunk(uuid4(), 1))]
            )
