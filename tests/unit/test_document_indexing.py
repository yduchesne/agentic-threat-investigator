# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for document indexing orchestration."""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.document_indexing import (
    DocumentBuilder,
    DocumentIndexingConflictError,
    DocumentIndexingError,
    DocumentIndexingService,
    TokenBoundedChunker,
)
from agentic_threat_investigator.app.embeddings import EmbeddedText, EmbeddingClient
from agentic_threat_investigator.app.persistence import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    DocumentBatchItem,
    DocumentBatchResult,
    DocumentChunkBatchItem,
    DocumentChunkBatchResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.documents import Document, EmbeddingModelInfo
from agentic_threat_investigator.domain.source import SourceRecord


@dataclass
class _State:
    outcomes: list[BatchOutcome] = field(default_factory=list)
    active: int = 0
    embed_calls: list[tuple[str, ...]] = field(default_factory=list)
    document_items: list[DocumentBatchItem] = field(default_factory=list)
    chunk_calls: list[tuple[tuple[UUID, ...], tuple[DocumentChunkBatchItem, ...]]] = (
        field(default_factory=list)
    )
    rollbacks: int = 0


class _Builder(DocumentBuilder):
    source_id = "source"
    document_record_types = frozenset({"narrative"})

    def build(self, record: SourceRecord) -> Document:
        """Build a minimal document from synthetic payload content."""
        return Document(
            source_id=record.source_id,
            source_record_id=record.source_record_id,
            document_type=record.record_type,
            retrieved_at=record.retrieved_at,
            content=str(record.canonical_payload["content"]),
            normalization_version=record.normalization_version,
            chunking_version=1,
        )


class _Embedder(EmbeddingClient):
    def __init__(self, state: _State) -> None:
        self._state = state

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return synthetic fixed model metadata."""
        return EmbeddingModelInfo(
            provider="fake", model="fake", model_version=1, dimension=2
        )

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Record calls and prove embedding occurs before transaction entry."""
        assert self._state.active == 0
        self._state.embed_calls.append(tuple(texts))
        return [EmbeddedText(index, [1.0, 0.0]) for index, _ in enumerate(texts, 1)]


class _Documents:  # pylint: disable=too-few-public-methods
    def __init__(self, state: _State) -> None:
        self._state = state

    async def upsert_batch(
        self, items: list[DocumentBatchItem]
    ) -> list[DocumentBatchResult]:
        """Return configured outcomes with database-assigned IDs."""
        self._state.document_items.extend(items)
        return [
            DocumentBatchResult(index, uuid4(), index, outcome)
            for index, outcome in enumerate(self._state.outcomes, 1)
        ]


class _Chunks:  # pylint: disable=too-few-public-methods
    def __init__(self, state: _State) -> None:
        self._state = state

    async def replace_batch(
        self, document_ids: list[UUID], items: list[DocumentChunkBatchItem]
    ) -> list[DocumentChunkBatchResult]:
        """Record one complete replacement and return inserted ordinals."""
        self._state.chunk_calls.append((tuple(document_ids), tuple(items)))
        return [
            DocumentChunkBatchResult(index, uuid4(), index, BatchOutcome.INSERTED)
            for index, _ in enumerate(items, 1)
        ]


class _Uow(UnitOfWork):
    def __init__(self, state: _State) -> None:
        self._state = state
        self.documents = _Documents(state)  # type: ignore[assignment]
        self.document_chunks = _Chunks(state)  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Open the fake transaction."""
        self._state.active += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Record rollback behavior and close the fake transaction."""
        if exc_type is not None:
            self._state.rollbacks += 1
        self._state.active -= 1

    async def commit(self) -> None:
        """Satisfy the unit-of-work contract."""

    async def rollback(self) -> None:
        """Satisfy the unit-of-work contract."""
        self._state.rollbacks += 1


def _record(identity: str = "one", content: str = "alpha beta") -> SourceRecord:
    return SourceRecord(
        source_id="source",
        source_record_id=identity,
        record_type="narrative",
        normalization_version=1,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        canonical_payload={"content": content},
    )


def _service(
    state: _State, batch_size: int = 10, embedding_batch_size: int = 2
) -> DocumentIndexingService:
    return DocumentIndexingService(
        lambda: _Uow(state),
        _Builder(),
        TokenBoundedChunker(3, 5),
        _Embedder(state),
        batch_size,
        embedding_batch_size,
    )


@pytest.mark.asyncio
async def test_index_embeds_before_one_atomic_replacement() -> None:
    """Inserted and updated documents bind chunks to returned document IDs."""
    state = _State([BatchOutcome.INSERTED, BatchOutcome.UPDATED])
    summary = await _service(state).index([_record(), _record("two")])
    assert summary.documents_inserted == 1
    assert summary.documents_updated == 1
    assert summary.chunks_replaced == 2
    assert len(state.chunk_calls) == 1
    ids, chunks = state.chunk_calls[0]
    assert set(ids) == {item.chunk.document_id for item in chunks}


@pytest.mark.asyncio
async def test_unchanged_documents_do_not_replace_chunks() -> None:
    """UNCHANGED classification preserves the existing complete chunk set."""
    state = _State([BatchOutcome.UNCHANGED])
    summary = await _service(state).index([_record()])
    assert summary.documents_unchanged == 1
    assert summary.chunks_replaced == 0
    assert not state.chunk_calls


@pytest.mark.asyncio
async def test_empty_indexing_is_a_complete_noop() -> None:
    """An empty changed-record list does not embed or open a transaction."""
    state = _State()
    summary = await _service(state).index([])
    assert (
        summary.documents_inserted,
        summary.documents_updated,
        summary.documents_unchanged,
        summary.chunks_replaced,
    ) == (0, 0, 0, 0)
    assert not state.embed_calls and state.active == 0


@pytest.mark.asyncio
async def test_conflict_rolls_back_without_replacing_chunks() -> None:
    """A document conflict aborts the document/chunk transaction."""
    state = _State([BatchOutcome.CONFLICT])
    with pytest.raises(DocumentIndexingConflictError):
        await _service(state).index([_record()])
    assert state.rollbacks == 1 and not state.chunk_calls


@pytest.mark.asyncio
async def test_embedding_groups_and_independent_batch_limits() -> None:
    """Embedding groups are bounded and generated chunk count has its own cap."""
    state = _State([BatchOutcome.INSERTED, BatchOutcome.INSERTED])
    await _service(state, embedding_batch_size=1).index([_record(), _record("two")])
    assert len(state.embed_calls) == 2

    oversized = _State([BatchOutcome.INSERTED])
    with pytest.raises(BatchSizeLimitExceededError):
        await _service(oversized, batch_size=1).index(
            [_record(content="one two three four five six")]
        )
    assert not oversized.embed_calls and oversized.active == 0


@pytest.mark.asyncio
async def test_wrong_source_or_type_is_rejected_before_embedding() -> None:
    """Unsupported records fail at the deterministic application boundary."""
    state = _State()
    wrong = _record().model_copy(update={"source_id": "other"})
    with pytest.raises(DocumentIndexingError):
        await _service(state).index([wrong])
    assert not state.embed_calls
