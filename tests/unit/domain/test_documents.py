# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for immutable RAG document domain models."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    document_chunk_content_hash,
    document_content_hash,
)


def _document_values() -> dict[str, object]:
    return {
        "source_id": "urn:ati:source:test",
        "source_record_id": "record-1",
        "document_type": "attack_technique",
        "title": "Example",
        "source_url": "https://example.test/one",
        "published_at": datetime(2026, 1, 1, tzinfo=UTC),
        "retrieved_at": datetime(2026, 1, 2, tzinfo=UTC),
        "content": "## Overview\nExample content",
        "normalization_version": 1,
        "chunking_version": 1,
        "metadata": {"nested": {"value": 1}},
    }


def _chunk_values() -> dict[str, object]:
    return {
        "document_id": uuid4(),
        "sequence": 1,
        "text": "Example chunk",
        "token_count": 3,
        "embedding_provider": "test",
        "embedding_model": "test-v1",
        "embedding_model_version": 1,
        "embedding_dimension": 2,
        "embedding": (1.0, 0.0),
        "metadata": {"section": "Overview"},
    }


def test_document_hash_is_deterministic_and_covers_chunking_contract() -> None:
    """Covered semantic fields, including chunking version, affect the digest."""
    values = _document_values()
    assert document_content_hash(values) == document_content_hash(dict(values))
    changed = dict(values)
    changed["chunking_version"] = 2
    assert document_content_hash(values) != document_content_hash(changed)
    retrieved = dict(values)
    retrieved["retrieved_at"] = datetime(2027, 1, 1, tzinfo=UTC)
    assert document_content_hash(values) == document_content_hash(retrieved)


def test_document_derives_hash_and_freezes_metadata() -> None:
    """Construction snapshots nested metadata and derives the semantic hash."""
    values = _document_values()
    document = Document.model_validate(values)
    assert document.content_hash == document_content_hash(document)
    with pytest.raises(TypeError):
        document.metadata["new"] = True
    with pytest.raises(TypeError):
        document.metadata["nested"]["value"] = 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", " "),
        ("source_record_id", ""),
        ("document_type", " "),
        ("content", ""),
        ("normalization_version", 0),
        ("chunking_version", 0),
        ("retrieved_at", datetime(2026, 1, 1)),
        ("published_at", datetime(2026, 1, 1)),
    ],
)
def test_document_rejects_invalid_fields(field: str, value: object) -> None:
    """Invalid identity, version, content, and timestamp values are rejected."""
    values = _document_values()
    values[field] = value
    with pytest.raises((ValidationError, ValueError)):
        Document.model_validate(values)


def test_document_rejects_tampered_hash() -> None:
    """A supplied digest must match semantic content."""
    with pytest.raises(ValidationError, match="content_hash"):
        values = _document_values()
        values["content_hash"] = "0" * 64
        Document.model_validate(values)


def test_chunk_hash_excludes_vector_but_covers_embedding_metadata() -> None:
    """Re-embedding values do not alter semantics, while model metadata does."""
    values = _chunk_values()
    alternate = dict(values)
    alternate["embedding"] = (0.0, 1.0)
    assert document_chunk_content_hash(values) == document_chunk_content_hash(alternate)
    alternate["embedding_model_version"] = 2
    assert document_chunk_content_hash(values) != document_chunk_content_hash(alternate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sequence", 0),
        ("text", " "),
        ("token_count", 0),
        ("embedding_provider", ""),
        ("embedding_model", " "),
        ("embedding_model_version", 0),
        ("embedding_dimension", 0),
        ("embedding", (float("nan"), 0.0)),
        ("embedding", (float("inf"), 0.0)),
        ("embedding", (1.0,)),
    ],
)
def test_chunk_rejects_invalid_fields(field: str, value: object) -> None:
    """Chunk shape, text, counters, metadata, and finite values are validated."""
    values = _chunk_values()
    values[field] = value
    with pytest.raises(ValidationError):
        DocumentChunk.model_validate(values)


def test_chunk_rejects_tampered_hash() -> None:
    """A supplied chunk digest must match semantic content."""
    with pytest.raises(ValidationError, match="content_hash"):
        values = _chunk_values()
        values["content_hash"] = "0" * 64
        DocumentChunk.model_validate(values)
