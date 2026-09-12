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
from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    EmbeddingModelInfo,
)
from agentic_threat_investigator.domain.source import SourceRecord


@dataclass
class _State:
    forced_document_outcomes: list[BatchOutcome] = field(default_factory=list)
    active: int = 0
    embed_calls: list[tuple[str, ...]] = field(default_factory=list)
    document_items: list[DocumentBatchItem] = field(default_factory=list)
    chunk_calls: list[tuple[tuple[UUID, ...], tuple[DocumentChunkBatchItem, ...]]] = (
        field(default_factory=list)
    )
    chunk_list_calls: list[UUID] = field(default_factory=list)
    rollbacks: int = 0
    documents_by_identity: dict[tuple[str, str], Document] = field(default_factory=dict)
    document_ids_by_identity: dict[tuple[str, str], UUID] = field(default_factory=dict)
    chunk_sets: dict[UUID, list[DocumentChunk]] = field(default_factory=dict)


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
    """Deterministic embedder whose embedding identity is configurable."""

    def __init__(
        self,
        state: _State,
        *,
        provider: str = "fake",
        model: str = "fake",
        model_version: int = 1,
        dimension: int = 2,
    ) -> None:
        self._state = state
        self._info = EmbeddingModelInfo(
            provider=provider,
            model=model,
            model_version=model_version,
            dimension=dimension,
        )

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return the configured embedding metadata."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Record calls and prove embedding occurs before transaction entry."""
        assert self._state.active == 0
        self._state.embed_calls.append(tuple(texts))
        return [
            EmbeddedText(index, [1.0] + [0.0] * (self._info.dimension - 1))
            for index, _ in enumerate(texts, 1)
        ]


class _Documents:
    def __init__(self, state: _State) -> None:
        self._state = state

    async def upsert_batch(
        self, items: list[DocumentBatchItem]
    ) -> list[DocumentBatchResult]:
        """Reconcile documents like the SQL function and assign stable IDs."""
        self._state.document_items.extend(items)
        results: list[DocumentBatchResult] = []
        for ordinal, item in enumerate(items, 1):
            document = item.document
            key = (document.source_id, document.source_record_id)
            identity = self._state.document_ids_by_identity.setdefault(key, uuid4())
            frozen_outcome = (
                self._state.forced_document_outcomes.pop(0)
                if self._state.forced_document_outcomes
                else None
            )
            current = self._state.documents_by_identity.get(key)
            if frozen_outcome is not None:
                outcome = frozen_outcome
            elif current is None:
                outcome = BatchOutcome.INSERTED
            elif current.content_hash == document.content_hash:
                outcome = BatchOutcome.UNCHANGED
            else:
                outcome = BatchOutcome.UPDATED
            self._state.documents_by_identity[key] = document
            results.append(DocumentBatchResult(ordinal, identity, ordinal, outcome))
        return results


class _Chunks:
    def __init__(self, state: _State) -> None:
        self._state = state

    async def replace_batch(
        self, document_ids: list[UUID], items: list[DocumentChunkBatchItem]
    ) -> list[DocumentChunkBatchResult]:
        """Record one complete replacement and update the fake chunk sets."""
        self._state.chunk_calls.append((tuple(document_ids), tuple(items)))
        fresh: dict[UUID, list[DocumentChunk]] = {}
        for item in items:
            fresh.setdefault(item.chunk.document_id, []).append(item.chunk)
        for document_id, chunks in fresh.items():
            self._state.chunk_sets[document_id] = chunks
        return [
            DocumentChunkBatchResult(index, uuid4(), index, BatchOutcome.INSERTED)
            for index, _ in enumerate(items, 1)
        ]

    async def list_by_document(self, document_id: UUID) -> list[DocumentChunk]:
        """Return the current fake chunk set for one document."""
        self._state.chunk_list_calls.append(document_id)
        return self._state.chunk_sets.get(document_id, [])


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
    state: _State,
    batch_size: int = 10,
    embedding_batch_size: int = 2,
    *,
    provider: str = "fake",
    model: str = "fake",
    model_version: int = 1,
    dimension: int = 2,
) -> DocumentIndexingService:
    return DocumentIndexingService(
        lambda: _Uow(state),
        _Builder(),
        TokenBoundedChunker(3, 5),
        _Embedder(
            state,
            provider=provider,
            model=model,
            model_version=model_version,
            dimension=dimension,
        ),
        batch_size,
        embedding_batch_size,
    )


@pytest.mark.asyncio
async def test_index_embeds_before_one_atomic_replacement() -> None:
    """Inserted and updated documents bind chunks to returned document IDs."""
    state = _State()
    summary = await _service(state).index([_record(), _record("two")])
    assert summary.documents_inserted == 2
    assert summary.chunks_replaced == 2
    assert len(state.chunk_calls) == 1
    ids, chunks = state.chunk_calls[0]
    assert set(ids) == {item.chunk.document_id for item in chunks}


@pytest.mark.asyncio
async def test_unchanged_compatible_documents_are_a_true_noop() -> None:
    """UNCHANGED with a complete compatible chunk set replaces nothing."""
    state = _State()
    first = await _service(state).index([_record()])
    assert (first.documents_inserted, first.documents_unchanged) == (1, 0)
    second = await _service(state).index([_record()])
    assert second.documents_unchanged == 1
    assert second.chunks_replaced == 0
    assert len(state.chunk_calls) == 1
    assert len(state.chunk_list_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "identity",
    ["provider", "model", "model_version", "dimension"],
)
async def test_unchanged_documents_reindex_when_identity_changes(
    identity: str,
) -> None:
    """Any embedding identity mismatch on an unchanged document re-indexes."""
    state = _State()
    first = await _service(state).index([_record()])
    assert first.documents_inserted == 1 and first.chunks_replaced == 1
    if identity == "provider":
        rebuild = _service(state, provider="other-provider")
    elif identity == "model":
        rebuild = _service(state, model="other-model")
    elif identity == "model_version":
        rebuild = _service(state, model_version=2)
    else:
        rebuild = _service(state, dimension=3)
    second = await rebuild.index([_record()])
    assert second.documents_unchanged == 1
    assert second.chunks_replaced == 1
    assert len(state.chunk_calls) == 2


@pytest.mark.asyncio
async def test_unchanged_documents_rebuild_missing_chunks() -> None:
    """An unchanged document with no current chunks is rebuilt."""
    state = _State()
    first = await _service(state).index([_record()])
    assert first.documents_inserted == 1
    # Simulate a persisted document whose chunk set was cleared externally.
    document_id = state.document_ids_by_identity[("source", "one")]
    state.chunk_sets.pop(document_id)
    second = await _service(state).index([_record()])
    assert second.documents_unchanged == 1
    assert second.chunks_replaced == 1
    assert len(state.chunk_calls) == 2


@pytest.mark.asyncio
async def test_pure_reembedding_preserves_citation_identity() -> None:
    """Re-indexing unchanged semantics under a new embedding identity keeps citations."""
    state = _State()
    await _service(state).index([_record()])
    first_items = state.chunk_calls[0][1]
    assert first_items and first_items[0].chunk.citation_id is not None
    original_citation = first_items[0].chunk.citation_id
    assert original_citation is not None

    second = await _service(
        state, provider="openai", model="text-embedding-3-small", model_version=2
    ).index([_record()])
    assert second.documents_unchanged == 1 and second.chunks_replaced == 1
    second_items = state.chunk_calls[1][1]
    assert second_items[0].chunk.citation_id == original_citation
    assert second_items[0].chunk.embedding_provider == "openai"


@pytest.mark.asyncio
async def test_content_update_changes_citation_where_semantics_change() -> None:
    """A document content update replaces chunks whose citations change."""
    state = _State()
    await _service(state).index([_record(content="alpha beta")])
    original_citation = state.chunk_calls[0][1][0].chunk.citation_id

    second = await _service(state).index([_record(content="gamma delta")])
    assert second.documents_updated == 1 and second.chunks_replaced == 1
    updated_citation = state.chunk_calls[1][1][0].chunk.citation_id
    assert updated_citation != original_citation


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
    state = _State()
    state.forced_document_outcomes = [BatchOutcome.CONFLICT]
    with pytest.raises(DocumentIndexingConflictError):
        await _service(state).index([_record()])
    assert state.rollbacks == 1 and not state.chunk_calls


@pytest.mark.asyncio
async def test_embedding_groups_and_independent_batch_limits() -> None:
    """Embedding groups are bounded and generated chunk count has its own cap."""
    state = _State()
    await _service(state, embedding_batch_size=1).index([_record(), _record("two")])
    assert len(state.embed_calls) == 2

    oversized = _State()
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
