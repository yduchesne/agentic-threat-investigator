# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL/pgvector adapter for narrative research retrieval."""

from __future__ import annotations

import math
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.research import (
    ResearchRetrievalError,
    ResearchRetriever,
)
from agentic_threat_investigator.config.settings import (
    DOCUMENT_CHUNK_EMBEDDING_DIMENSION,
)
from agentic_threat_investigator.domain.research import ResearchQuery, RetrievedChunk


def _vector_literal(vector: list[float]) -> str:
    """Serialize a validated vector for pgvector without SQL interpolation."""
    return "[" + ",".join(repr(value) for value in vector) + "]"


def _finite_vector(vector: list[float], dimension: int) -> None:
    """Validate the shape and numeric values of one query vector."""
    if len(vector) != dimension or any(not math.isfinite(value) for value in vector):
        raise ResearchRetrievalError("embedding result has an invalid vector")


class PgVectorResearchRetriever(
    ResearchRetriever
):  # pylint: disable=too-few-public-methods
    """Retrieve compatible, visible chunks using PostgreSQL cosine distance."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        embedding_client: EmbeddingClient,
    ) -> None:
        self._session_factory = session_factory
        self._embedding_client = embedding_client

    async def retrieve(  # pylint: disable=too-many-locals
        self, query: ResearchQuery
    ) -> list[RetrievedChunk]:
        """Embed the query first, then execute one bounded filtered SQL query."""
        model_info = self._embedding_client.model_info
        if model_info.dimension != DOCUMENT_CHUNK_EMBEDDING_DIMENSION:
            raise ResearchRetrievalError(
                "embedding dimension is incompatible with schema"
            )

        embedded = await self._embedding_client.embed_texts([query.query])
        if len(embedded) != 1 or embedded[0].text_ordinal != 1:
            raise ResearchRetrievalError("embedding result is not one ordinal-1 vector")
        vector = embedded[0].vector
        _finite_vector(vector, model_info.dimension)
        literal = _vector_literal(vector)

        predicates = [
            "document.deleted_at IS NULL",
            "chunk.embedding_provider = :embedding_provider",
            "chunk.embedding_model = :embedding_model",
            "chunk.embedding_model_version = :embedding_model_version",
            "chunk.embedding_dimension = :embedding_dimension",
        ]
        params: dict[str, Any] = {
            "query_embedding": literal,
            "embedding_provider": model_info.provider,
            "embedding_model": model_info.model,
            "embedding_model_version": model_info.model_version,
            "embedding_dimension": model_info.dimension,
            "max_results": query.max_results,
        }
        if query.source_ids:
            predicates.append("document.source_id = ANY(CAST(:source_ids AS text[]))")
            params["source_ids"] = query.source_ids
        if query.document_types:
            predicates.append(
                "document.document_type = ANY(CAST(:document_types AS text[]))"
            )
            params["document_types"] = query.document_types

        statement = text(
            """SELECT chunk.id AS chunk_id, chunk.document_id,
                       document.source_id, chunk.text, document.title,
                       document.source_url, document.published_at,
                       1.0 - (chunk.embedding <=> CAST(:query_embedding AS vector))
                         AS similarity_score,
                       document.document_type, chunk.sequence AS chunk_sequence,
                       document.metadata AS document_metadata,
                       chunk.metadata AS chunk_metadata
                FROM ati.document_chunk AS chunk
                JOIN ati.document AS document ON document.id = chunk.document_id
                WHERE """
            + " AND ".join(predicates)
            + " ORDER BY chunk.embedding <=> CAST(:query_embedding AS vector)"
            + " LIMIT :max_results"
        )
        async with self._session_factory() as session:
            result = await session.execute(statement, params)
            rows = result.mappings().all()

        chunks: list[RetrievedChunk] = []
        for row in rows:
            values = row
            try:
                raw_score = float(values["similarity_score"])
            except (TypeError, ValueError) as exc:
                raise ResearchRetrievalError(
                    "database returned an invalid similarity"
                ) from exc
            if (
                not math.isfinite(raw_score)
                or raw_score < -1.0000001
                or raw_score > 1.0000001
            ):
                raise ResearchRetrievalError("database returned an invalid similarity")
            score = min(1.0, max(-1.0, raw_score))
            try:
                chunks.append(
                    RetrievedChunk(
                        chunk_id=values["chunk_id"],
                        document_id=values["document_id"],
                        source_id=values["source_id"],
                        text=values["text"],
                        title=values["title"],
                        source_url=values["source_url"],
                        published_at=values["published_at"],
                        similarity_score=score,
                        metadata={
                            "document_type": values["document_type"],
                            "chunk_sequence": values["chunk_sequence"],
                            "document": values["document_metadata"] or {},
                            "chunk": values["chunk_metadata"] or {},
                        },
                    )
                )
            except (TypeError, ValueError) as exc:
                raise ResearchRetrievalError(
                    "database row violates retrieval contract"
                ) from exc
        return chunks
