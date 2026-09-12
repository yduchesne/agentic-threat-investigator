# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for immutable RAG document domain models."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.domain.documents import (
    Document,
    DocumentChunk,
    document_chunk_citation_id,
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


_CITATION_DOCUMENT_ID = uuid4()


def _cited_chunk(**overrides: object) -> DocumentChunk:
    """Build a deterministic chunk for citation-identity cases."""
    values: dict[str, object] = {
        "document_id": _CITATION_DOCUMENT_ID,
        "sequence": 1,
        "text": "Same semantic chunk",
        "token_count": 3,
        "embedding_provider": "test",
        "embedding_model": "test-v1",
        "embedding_model_version": 1,
        "embedding_dimension": 2,
        "embedding": (1.0, 0.0),
        "metadata": {"section": "Overview", "document_type": "advisory"},
    }
    values.update(overrides)
    return DocumentChunk.model_validate(values)


def test_citation_is_stable_across_identity_and_embedding_variation() -> None:
    """Row identity, vector, and embedding identity never alter citation ID."""
    baseline = _cited_chunk()
    row_replaced = _cited_chunk(id=uuid4())
    re_embedded = _cited_chunk(
        embedding=(0.0, 1.0, 0.0),
        embedding_provider="openai",
        embedding_model="text-embedding-3-small",
        embedding_model_version=2,
        embedding_dimension=3,
    )
    assert baseline.citation_id is not None
    assert baseline.id is None  # citation identity is not the row identity
    assert baseline.citation_id == row_replaced.citation_id
    assert baseline.citation_id == re_embedded.citation_id
    assert baseline.content_hash != re_embedded.content_hash


def test_citation_changes_with_every_semantic_coordinate() -> None:
    """Each semantic chunk coordinate independently changes the citation ID."""
    baseline = _cited_chunk()
    other_document = _cited_chunk(document_id=uuid4())
    other_sequence = _cited_chunk(sequence=2)
    other_text = _cited_chunk(text="Different chunk text")
    other_metadata = _cited_chunk(metadata={"section": "Details"})
    assert baseline.citation_id != other_document.citation_id
    assert baseline.citation_id != other_sequence.citation_id
    assert baseline.citation_id != other_text.citation_id
    assert baseline.citation_id != other_metadata.citation_id


def test_citation_is_deterministic_across_process_instances() -> None:
    """Reconstruction from the semantic dump reproduces the same UUID."""
    baseline = _cited_chunk()
    rebuilt = _cited_chunk(**baseline.model_dump(mode="python"))
    assert baseline.citation_id == rebuilt.citation_id
    assert document_chunk_citation_id(baseline) == baseline.citation_id


def test_citation_accepts_explicit_valid_identity() -> None:
    """A supplied citation ID equal to the derivation is accepted unchanged."""
    baseline = _cited_chunk()
    accepted = DocumentChunk.model_validate(
        {
            **_cited_chunk().model_dump(mode="python"),
            "citation_id": baseline.citation_id,
        }
    )
    assert accepted.citation_id == baseline.citation_id


def test_citation_rejects_explicit_wrong_identity() -> None:
    """A supplied citation ID that disagrees with semantics is rejected."""
    with pytest.raises(ValidationError, match="citation_id"):
        DocumentChunk.model_validate(
            {
                **_cited_chunk().model_dump(mode="python"),
                "citation_id": uuid4(),
            }
        )
