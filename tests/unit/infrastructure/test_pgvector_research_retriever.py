# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the PostgreSQL research retrieval boundary."""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.embeddings import (
    EmbeddedText,
    EmbeddingClient,
    EmbeddingError,
)
from agentic_threat_investigator.app.research import ResearchRetrievalError
from agentic_threat_investigator.domain.documents import EmbeddingModelInfo
from agentic_threat_investigator.domain.research import ResearchQuery
from agentic_threat_investigator.infrastructure.research import (
    PgVectorResearchRetriever,
)


class StubEmbeddingClient(EmbeddingClient):
    """Return configurable embeddings while recording operation order."""

    def __init__(
        self,
        events: list[str],
        *,
        dimension: int = 1536,
        results: list[EmbeddedText] | None = None,
        error: EmbeddingError | None = None,
    ) -> None:
        self.events = events
        self._info = EmbeddingModelInfo(
            provider="test-provider",
            model="test-model",
            model_version=7,
            dimension=dimension,
        )
        self.results = results
        self.error = error
        self.inputs: list[str] = []

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return configured test embedding metadata."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Record and return the configured deterministic response."""
        self.events.append("embed")
        self.inputs = list(texts)
        if self.error is not None:
            raise self.error
        if self.results is not None:
            return self.results
        return [EmbeddedText(1, [1.0] + [0.0] * 1535)]


def _query(**values: Any) -> ResearchQuery:
    return ResearchQuery.model_validate(
        {"investigation_id": uuid4(), "query": "persistence", **values}
    )


def _session_factory(
    rows: list[dict[str, Any]], events: list[str]
) -> tuple[async_sessionmaker[AsyncSession], AsyncMock]:
    result = MagicMock()
    result.mappings.return_value.all.return_value = rows
    session = MagicMock()

    async def execute(*_args: object, **_kwargs: object) -> MagicMock:
        events.append("sql")
        return result

    session.execute = AsyncMock(side_effect=execute)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=None)

    def create_session() -> MagicMock:
        events.append("session")
        return context

    factory = MagicMock(side_effect=create_session)
    return cast(async_sessionmaker[AsyncSession], factory), session.execute


@pytest.mark.asyncio
async def test_retrieve_embeds_before_session_and_maps_provenance() -> None:
    """Retrieval embeds first and maps rows without leaking vector internals."""
    events: list[str] = []
    chunk_id, document_id = uuid4(), uuid4()
    published_at = datetime(2026, 1, 1, tzinfo=UTC)
    factory, execute = _session_factory(
        [
            {
                "chunk_id": chunk_id,
                "document_id": document_id,
                "source_id": "urn:test:source",
                "text": "untrusted text",
                "title": "Title",
                "source_url": "https://example.test/doc",
                "published_at": published_at,
                "similarity_score": 1.00000001,
                "document_type": "advisory",
                "chunk_sequence": 2,
                "document_metadata": {"publisher": "ATI"},
                "chunk_metadata": {"section": "Details"},
            }
        ],
        events,
    )
    client = StubEmbeddingClient(events)
    retriever = PgVectorResearchRetriever(factory, client)

    chunks = await retriever.retrieve(
        _query(
            source_ids=["urn:test:source"],
            document_types=["advisory"],
            max_results=3,
        )
    )

    assert events == ["embed", "session", "sql"]
    assert client.inputs == ["persistence"]
    assert execute.await_args is not None
    statement, params = execute.await_args.args
    sql = str(statement)
    assert "embedding <=> CAST(:query_embedding AS vector)" in sql
    assert "source_id = ANY" in sql and "document_type = ANY" in sql
    assert params["max_results"] == 3
    assert params["source_ids"] == ["urn:test:source"]
    assert params["document_types"] == ["advisory"]
    assert params["embedding_provider"] == "test-provider"
    assert params["embedding_model"] == "test-model"
    assert params["embedding_model_version"] == 7
    assert chunks[0].chunk_id == chunk_id
    assert chunks[0].similarity_score == 1.0
    assert chunks[0].metadata == {
        "document_type": "advisory",
        "chunk_sequence": 2,
        "document": {"publisher": "ATI"},
        "chunk": {"section": "Details"},
    }
    assert "embedding" not in chunks[0].metadata


@pytest.mark.asyncio
async def test_retrieve_without_filters_returns_empty_rows() -> None:
    """Empty filter lists omit array predicates and empty rows return a list."""
    events: list[str] = []
    factory, execute = _session_factory([], events)
    chunks = await PgVectorResearchRetriever(
        factory, StubEmbeddingClient(events)
    ).retrieve(_query())
    assert execute.await_args is not None
    statement, params = execute.await_args.args
    assert chunks == []
    assert "ANY" not in str(statement)
    assert "source_ids" not in params and "document_types" not in params


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "results",
    [
        [],
        [EmbeddedText(2, [0.0] * 1536)],
        [EmbeddedText(1, [0.0] * 1536), EmbeddedText(2, [0.0] * 1536)],
        [EmbeddedText(1, [0.0] * 2)],
        [EmbeddedText(1, [float("nan")] + [0.0] * 1535)],
    ],
)
async def test_invalid_embedding_response_fails_before_session(
    results: list[EmbeddedText],
) -> None:
    """Malformed embedding responses never open a database session."""
    events: list[str] = []
    factory, _execute = _session_factory([], events)
    with pytest.raises(ResearchRetrievalError):
        await PgVectorResearchRetriever(
            factory, StubEmbeddingClient(events, results=results)
        ).retrieve(_query())
    assert "session" not in events


@pytest.mark.asyncio
async def test_wrong_model_dimension_fails_before_embedding() -> None:
    """A model incompatible with fixed DDL is rejected before all I/O."""
    events: list[str] = []
    factory, _execute = _session_factory([], events)
    with pytest.raises(ResearchRetrievalError):
        await PgVectorResearchRetriever(
            factory, StubEmbeddingClient(events, dimension=2)
        ).retrieve(_query())
    assert not events


@pytest.mark.asyncio
async def test_embedding_error_propagates_without_session() -> None:
    """Typed embedding failures retain their cause and avoid database I/O."""
    events: list[str] = []
    factory, _execute = _session_factory([], events)
    error = EmbeddingError("failed")
    with pytest.raises(EmbeddingError) as captured:
        await PgVectorResearchRetriever(
            factory, StubEmbeddingClient(events, error=error)
        ).retrieve(_query())
    assert captured.value is error
    assert events == ["embed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("score", [1.1, -1.1, float("nan"), "invalid"])
async def test_invalid_database_score_raises(score: object) -> None:
    """Materially invalid and non-finite database scores are rejected."""
    events: list[str] = []
    factory, _execute = _session_factory(
        [
            {
                "chunk_id": uuid4(),
                "document_id": uuid4(),
                "source_id": "source",
                "text": "text",
                "title": None,
                "source_url": None,
                "published_at": None,
                "similarity_score": score,
                "document_type": "advisory",
                "chunk_sequence": 1,
                "document_metadata": {},
                "chunk_metadata": {},
            }
        ],
        events,
    )
    with pytest.raises(ResearchRetrievalError):
        await PgVectorResearchRetriever(factory, StubEmbeddingClient(events)).retrieve(
            _query()
        )
