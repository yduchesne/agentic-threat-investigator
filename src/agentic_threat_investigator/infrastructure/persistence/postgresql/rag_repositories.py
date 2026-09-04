# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapters for RAG documents and chunks."""

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    DocumentBatchItem,
    DocumentBatchResult,
    DocumentChunkBatchItem,
    DocumentChunkBatchResult,
    DocumentChunkRepository,
    DocumentRepository,
)
from agentic_threat_investigator.config.settings import (
    DOCUMENT_CHUNK_EMBEDDING_DIMENSION,
)
from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    document_chunk_content_hash,
    document_content_hash,
)
from agentic_threat_investigator.domain.immutable_json import thaw_json


def _vector_values(value: object) -> tuple[float, ...]:
    """Parse pgvector's text/list result without leaking it above infrastructure."""
    if isinstance(value, str):
        body = value.strip()[1:-1]
        return tuple(float(component) for component in body.split(",")) if body else ()
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(float(component) for component in value)
    raise ValueError("PostgreSQL returned an unsupported vector representation")


class PostgresDocumentRepository(DocumentRepository):
    """Submit documents to the authoritative PostgreSQL batch function."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        self._session = session
        self._batch_size = batch_size

    async def upsert_batch(
        self, items: Sequence[DocumentBatchItem]
    ) -> list[DocumentBatchResult]:
        """Validate hashes and invoke database-owned document reconciliation."""
        if len(items) > self._batch_size:
            raise BatchSizeLimitExceededError("document batch exceeds configured limit")
        composite: list[tuple[Any, ...]] = []
        for ordinal, item in enumerate(items, 1):
            document = item.document
            if document.content_hash != document_content_hash(document):
                raise ValueError(
                    "document content_hash does not match semantic content"
                )
            composite.append(
                (
                    ordinal,
                    document.source_id,
                    document.source_record_id,
                    document.document_type,
                    document.title,
                    document.source_url,
                    document.published_at,
                    document.retrieved_at,
                    document.content,
                    document.normalization_version,
                    document.chunking_version,
                    bytes.fromhex(document.content_hash),
                    Jsonb(thaw_json(document.metadata)),
                    item.expected_version,
                )
            )
        result = await self._session.execute(
            text("SELECT * FROM ati.upsert_documents(:items)"),
            {"items": composite},
        )
        return [
            DocumentBatchResult(row[0], row[1], row[2], BatchOutcome(row[3]))
            for row in result.fetchall()
        ]

    @staticmethod
    def _document_from_row(row: Any) -> Document:
        """Map one PostgreSQL row to the infrastructure-neutral domain model."""
        values = dict(row)
        values["content_hash"] = bytes(row["content_hash"]).hex()
        return Document(**values)

    async def get_by_identity(
        self, source_id: str, source_record_id: str
    ) -> Document | None:
        """Return a visible document by durable source identity."""
        result = await self._session.execute(
            text(
                """
                SELECT id, source_id, source_record_id, document_type, title,
                       source_url, published_at, retrieved_at, content,
                       normalization_version, chunking_version, content_hash,
                       metadata
                FROM ati.document
                WHERE source_id=:source_id AND source_record_id=:record_id
                  AND deleted_at IS NULL
                """
            ),
            {"source_id": source_id, "record_id": source_record_id},
        )
        row = result.mappings().first()
        return None if row is None else self._document_from_row(row)


class PostgresDocumentChunkRepository(DocumentChunkRepository):
    """Replace and read pgvector-backed document indexing artifacts."""

    def __init__(self, session: AsyncSession, batch_size: int = 100) -> None:
        self._session = session
        self._batch_size = batch_size

    async def replace_batch(
        self, document_ids: Sequence[UUID], items: Sequence[DocumentChunkBatchItem]
    ) -> list[DocumentChunkBatchResult]:
        """Validate and replace complete chunk sets through one SQL function."""
        if len(document_ids) > self._batch_size or len(items) > self._batch_size:
            raise BatchSizeLimitExceededError("chunk batch exceeds configured limit")
        composite: list[tuple[Any, ...]] = []
        for ordinal, item in enumerate(items, 1):
            chunk = item.chunk
            if (
                chunk.embedding_dimension != DOCUMENT_CHUNK_EMBEDDING_DIMENSION
                or len(chunk.embedding) != DOCUMENT_CHUNK_EMBEDDING_DIMENSION
            ):
                raise ValueError("embedding dimension does not match database schema")
            if chunk.content_hash != document_chunk_content_hash(chunk):
                raise ValueError("chunk content_hash does not match semantic content")
            embedding_literal = (
                "[" + ",".join(repr(component) for component in chunk.embedding) + "]"
            )
            composite.append(
                (
                    ordinal,
                    chunk.document_id,
                    chunk.sequence,
                    chunk.text,
                    chunk.token_count,
                    embedding_literal,
                    chunk.embedding_provider,
                    chunk.embedding_model,
                    chunk.embedding_model_version,
                    chunk.embedding_dimension,
                    bytes.fromhex(chunk.content_hash),
                    Jsonb(thaw_json(chunk.metadata)),
                )
            )
        result = await self._session.execute(
            text(
                "SELECT ordinal,id,version,outcome "
                "FROM ati.replace_document_chunks(:document_ids,:items)"
            ),
            {"document_ids": list(document_ids), "items": composite},
        )
        return [
            DocumentChunkBatchResult(row[0], row[1], row[2], BatchOutcome(row[3]))
            for row in result.fetchall()
        ]

    async def list_by_document(self, document_id: UUID) -> list[DocumentChunk]:
        """Return all current chunks in deterministic sequence order."""
        result = await self._session.execute(
            text(
                """
                SELECT id, document_id, sequence, text, token_count, embedding,
                       embedding_provider, embedding_model,
                       embedding_model_version, embedding_dimension,
                       content_hash, metadata
                FROM ati.document_chunk
                WHERE document_id=:document_id
                ORDER BY sequence
                """
            ),
            {"document_id": document_id},
        )
        chunks: list[DocumentChunk] = []
        for row in result.mappings():
            values = dict(row)
            values["embedding"] = _vector_values(row["embedding"])
            values["content_hash"] = bytes(row["content_hash"]).hex()
            chunks.append(DocumentChunk(**values))
        return chunks
