# SPDX-License-Identifier: AGPL-3.0-only
"""Document construction, deterministic chunking, and indexing orchestration."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.persistence.repositories import (
    BatchOutcome,
    BatchSizeLimitExceededError,
    DocumentBatchItem,
    DocumentBatchResult,
    DocumentChunkBatchItem,
    DocumentChunkBatchResult,
    UnitOfWork,
)
from agentic_threat_investigator.domain.documents import Document, DocumentChunk
from agentic_threat_investigator.domain.source import SourceRecord

CHUNKING_VERSION = 1


class DocumentBuilder(ABC):
    """Build a narrative document for one supported source record."""

    @property
    @abstractmethod
    def source_id(self) -> str:
        """Return the supported source identity."""

    @property
    @abstractmethod
    def document_record_types(self) -> frozenset[str]:
        """Return supported source-record types."""

    @abstractmethod
    def build(self, record: SourceRecord) -> Document:
        """Build a deterministic document from a supported source record."""


@dataclass(frozen=True)
class ChunkDraft:
    """Domain-independent chunk produced before embedding."""

    sequence: int
    text: str
    token_count: int
    metadata: dict[str, Any]


@dataclass(frozen=True)
class _EmbeddedDraft:
    """Application-internal correlation between a draft and its vector."""

    document_ordinal: int
    draft: ChunkDraft
    vector: tuple[float, ...]


def _token_count(text: str) -> int:
    """Estimate tokens deterministically without model-specific dependencies."""
    return max(1, math.ceil(len(text.split()) * 4 / 3))


class TokenBoundedChunker:  # pylint: disable=too-few-public-methods
    """Deterministic section-aware paragraph chunker."""

    def __init__(self, target_tokens: int, max_tokens: int) -> None:
        if not 1 <= target_tokens <= max_tokens:
            raise ValueError("target_tokens must be between 1 and max_tokens")
        self._target_tokens = target_tokens
        self._max_tokens = max_tokens

    def _word_windows(self, text: str) -> list[str]:
        """Split an oversized sentence into maximal whitespace word windows."""
        pieces: list[str] = []
        current: list[str] = []
        for word in text.split():
            candidate = " ".join((*current, word))
            if current and _token_count(candidate) > self._max_tokens:
                pieces.append(" ".join(current))
                current = [word]
            else:
                current.append(word)
        if current:
            pieces.append(" ".join(current))
        return pieces

    def _sentence_pieces(self, line: str) -> list[str]:
        """Split one oversized line at sentence-ish boundaries, then words."""
        sentences = line.split(". ")
        pieces: list[str] = []
        for index, sentence in enumerate(sentences):
            rendered = sentence + ("." if index < len(sentences) - 1 else "")
            rendered = rendered.strip()
            if not rendered:
                continue
            if _token_count(rendered) <= self._max_tokens:
                pieces.append(rendered)
            else:
                pieces.extend(self._word_windows(rendered))
        return pieces

    def _paragraph_pieces(self, paragraph: str) -> list[str]:
        """Split one oversized paragraph without unbounded recursion."""
        if _token_count(paragraph) <= self._max_tokens:
            return [paragraph]
        pieces: list[str] = []
        for line in paragraph.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if _token_count(stripped) <= self._max_tokens:
                pieces.append(stripped)
            else:
                pieces.extend(self._sentence_pieces(stripped))
        return pieces

    def _section_paragraphs(self, content: str) -> list[tuple[str, str]]:
        """Parse structural headings and return bounded body paragraphs."""
        section = "Overview"
        parsed: list[tuple[str, str]] = []
        for raw_paragraph in content.split("\n\n"):
            paragraph = raw_paragraph.strip()
            if not paragraph:
                continue
            if paragraph.startswith("## "):
                heading, separator, body = paragraph.partition("\n")
                section = heading[3:].strip() or section
                paragraph = body.strip() if separator else ""
            if paragraph:
                parsed.extend(
                    (piece, section)
                    for piece in self._paragraph_pieces(paragraph)
                    if piece
                )
        return parsed

    @staticmethod
    def _draft(
        sequence: int, paragraphs: Sequence[str], section: str, document_type: str
    ) -> ChunkDraft:
        """Create one draft and compute its count from final rendered text."""
        text = "\n\n".join(paragraphs)
        return ChunkDraft(
            sequence=sequence,
            text=text,
            token_count=_token_count(text),
            metadata={"section": section, "document_type": document_type},
        )

    def split(self, document: Document) -> list[ChunkDraft]:
        """Split a document into contiguous 1-based deterministic chunks."""
        if not document.content.strip():
            raise ValueError("document content must not be blank")
        drafts: list[ChunkDraft] = []
        current: list[str] = []
        current_section = "Overview"
        for paragraph, section in self._section_paragraphs(document.content):
            candidate = "\n\n".join((*current, paragraph))
            if current and _token_count(candidate) > self._target_tokens:
                drafts.append(
                    self._draft(
                        len(drafts) + 1,
                        current,
                        current_section,
                        document.document_type,
                    )
                )
                current = []
            if not current:
                current_section = section
            current.append(paragraph)
        if current:
            drafts.append(
                self._draft(
                    len(drafts) + 1,
                    current,
                    current_section,
                    document.document_type,
                )
            )
        return drafts


class DocumentIndexingError(RuntimeError):
    """Base error raised for an invalid document indexing operation."""


class DocumentIndexingConflictError(DocumentIndexingError):
    """Raised when persistence cannot atomically reconcile an indexing batch."""


@dataclass(frozen=True)
class DocumentIndexingSummary:
    """Deterministic counts from one indexing operation."""

    documents_inserted: int
    documents_updated: int
    documents_unchanged: int
    chunks_replaced: int


class DocumentIndexingService:  # pylint: disable=too-few-public-methods
    """Build and persist documents with embedding I/O outside transactions."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        uow_factory: Callable[[], UnitOfWork],
        builder: DocumentBuilder,
        chunker: TokenBoundedChunker,
        embedding_client: EmbeddingClient,
        batch_size: int,
        embedding_batch_size: int,
    ) -> None:
        if batch_size < 1 or embedding_batch_size < 1:
            raise ValueError("batch sizes must be positive")
        self._uow_factory = uow_factory
        self._builder = builder
        self._chunker = chunker
        self._embedding_client = embedding_client
        self._batch_size = batch_size
        self._embedding_batch_size = embedding_batch_size

    def _build_documents(
        self, records: Sequence[SourceRecord]
    ) -> tuple[list[Document], list[tuple[int, ChunkDraft]]]:
        """Validate records, build documents, and produce bounded drafts."""
        documents: list[Document] = []
        drafts: list[tuple[int, ChunkDraft]] = []
        for document_ordinal, record in enumerate(records, 1):
            if (
                record.source_id != self._builder.source_id
                or record.record_type not in self._builder.document_record_types
            ):
                raise DocumentIndexingError(
                    "unsupported indexing record "
                    f"{record.source_id}/{record.source_record_id}"
                )
            document = self._builder.build(record)
            document_drafts = self._chunker.split(document)
            if not document_drafts:
                raise DocumentIndexingError(
                    "document produced no chunks: "
                    f"{record.source_id}/{record.source_record_id}"
                )
            documents.append(document)
            drafts.extend((document_ordinal, draft) for draft in document_drafts)
        if len(drafts) > self._batch_size:
            raise BatchSizeLimitExceededError("chunk batch exceeds configured limit")
        return documents, drafts

    async def _embed_drafts(
        self, drafts: Sequence[tuple[int, ChunkDraft]]
    ) -> list[_EmbeddedDraft]:
        """Embed bounded groups and verify complete ordinal correlation."""
        embedded: list[_EmbeddedDraft] = []
        dimension = self._embedding_client.model_info.dimension
        for start in range(0, len(drafts), self._embedding_batch_size):
            group = drafts[start : start + self._embedding_batch_size]
            results = await self._embedding_client.embed_texts(
                [draft.text for _, draft in group]
            )
            expected_ordinals = set(range(1, len(group) + 1))
            if (
                len(results) != len(group)
                or {result.text_ordinal for result in results} != expected_ordinals
            ):
                raise DocumentIndexingError("embedding returned invalid ordinals")
            by_ordinal = {result.text_ordinal: result for result in results}
            for ordinal, (document_ordinal, draft) in enumerate(group, 1):
                vector = by_ordinal[ordinal].vector
                if len(vector) != dimension:
                    raise DocumentIndexingError("embedding dimension mismatch")
                embedded.append(_EmbeddedDraft(document_ordinal, draft, tuple(vector)))
        return embedded

    @staticmethod
    def _verify_document_results(
        results: Sequence[DocumentBatchResult], expected_count: int
    ) -> None:
        """Reject conflicts and incomplete or duplicated document ordinals."""
        expected = set(range(1, expected_count + 1))
        if (
            len(results) != expected_count
            or {result.ordinal for result in results} != expected
            or any(result.outcome is BatchOutcome.CONFLICT for result in results)
        ):
            raise DocumentIndexingConflictError(
                "document batch conflict or invalid ordinals"
            )

    @staticmethod
    def _verify_chunk_results(
        results: Sequence[DocumentChunkBatchResult], expected_count: int
    ) -> None:
        """Reject conflicts and incomplete or duplicated chunk ordinals."""
        expected = set(range(1, expected_count + 1))
        if (
            len(results) != expected_count
            or {result.ordinal for result in results} != expected
            or any(result.outcome is BatchOutcome.CONFLICT for result in results)
        ):
            raise DocumentIndexingConflictError(
                "chunk batch conflict or invalid ordinals"
            )

    def _changed_chunks(
        self,
        results: Sequence[DocumentBatchResult],
        embedded: Sequence[_EmbeddedDraft],
    ) -> tuple[list[UUID], list[DocumentChunkBatchItem]]:
        """Bind embedded drafts to database-assigned changed document IDs."""
        by_ordinal = {result.ordinal: result for result in results}
        changed = {
            result.ordinal: result
            for result in results
            if result.outcome in (BatchOutcome.INSERTED, BatchOutcome.UPDATED)
        }
        chunks: list[DocumentChunkBatchItem] = []
        info = self._embedding_client.model_info
        for item in embedded:
            result = by_ordinal[item.document_ordinal]
            if item.document_ordinal not in changed:
                continue
            chunks.append(
                DocumentChunkBatchItem(
                    DocumentChunk(
                        document_id=result.document_id,
                        sequence=item.draft.sequence,
                        text=item.draft.text,
                        token_count=item.draft.token_count,
                        embedding_provider=info.provider,
                        embedding_model=info.model,
                        embedding_model_version=info.model_version,
                        embedding_dimension=info.dimension,
                        embedding=item.vector,
                        metadata=item.draft.metadata,
                    )
                )
            )
        changed_ids = [result.document_id for result in changed.values()]
        if changed_ids and not chunks:
            raise DocumentIndexingError("changed documents produced no chunks")
        return changed_ids, chunks

    async def index(self, records: Sequence[SourceRecord]) -> DocumentIndexingSummary:
        """Build, embed, and atomically persist one bounded record sequence."""
        if not records:
            return DocumentIndexingSummary(0, 0, 0, 0)
        if len(records) > self._batch_size:
            raise BatchSizeLimitExceededError("document batch exceeds configured limit")

        documents, drafts = self._build_documents(records)
        embedded = await self._embed_drafts(drafts)

        async with self._uow_factory() as uow:
            document_results = await uow.documents.upsert_batch(
                [DocumentBatchItem(document=document) for document in documents]
            )
            self._verify_document_results(document_results, len(documents))
            changed_ids, chunks = self._changed_chunks(document_results, embedded)
            if changed_ids:
                chunk_results = await uow.document_chunks.replace_batch(
                    changed_ids, chunks
                )
                self._verify_chunk_results(chunk_results, len(chunks))

        return DocumentIndexingSummary(
            documents_inserted=sum(
                result.outcome is BatchOutcome.INSERTED for result in document_results
            ),
            documents_updated=sum(
                result.outcome is BatchOutcome.UPDATED for result in document_results
            ),
            documents_unchanged=sum(
                result.outcome is BatchOutcome.UNCHANGED for result in document_results
            ),
            chunks_replaced=len(chunks),
        )
