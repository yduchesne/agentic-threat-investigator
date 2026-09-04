# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic section-aware chunking."""

from datetime import UTC, datetime

import pytest

from agentic_threat_investigator.app.document_indexing import TokenBoundedChunker
from agentic_threat_investigator.domain.documents import Document


def _document(content: str) -> Document:
    return Document(
        source_id="urn:ati:source:test",
        source_record_id="one",
        document_type="attack_technique",
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        content=content,
        normalization_version=1,
        chunking_version=1,
    )


def test_chunker_excludes_headers_and_tracks_sections() -> None:
    """Structural headings do not enter text and section metadata is retained."""
    chunks = TokenBoundedChunker(5, 8).split(
        _document("## Overview\nshort text\n\n## Detection\ndetect this behavior")
    )
    assert [chunk.sequence for chunk in chunks] == list(range(1, len(chunks) + 1))
    assert all("##" not in chunk.text for chunk in chunks)
    assert chunks[0].metadata == {
        "section": "Overview",
        "document_type": "attack_technique",
    }
    assert chunks[-1].metadata["section"] == "Detection"


def test_chunker_splits_oversized_heading_body_and_sentence() -> None:
    """Heading bodies use the same line, sentence, and word fallback path."""
    words = " ".join(f"word{i}" for i in range(20))
    chunks = TokenBoundedChunker(6, 6).split(_document(f"## Details\n{words}"))
    assert len(chunks) > 1
    assert all(chunk.token_count <= 6 for chunk in chunks)
    assert " ".join(chunk.text for chunk in chunks).split() == words.split()


def test_chunker_is_deterministic_and_rejects_invalid_bounds() -> None:
    """Equivalent input is stable and invalid target/max bounds fail."""
    chunker = TokenBoundedChunker(8, 10)
    document = _document("one two three\n\nfour five six")
    assert chunker.split(document) == chunker.split(document)
    with pytest.raises(ValueError):
        TokenBoundedChunker(0, 10)
    with pytest.raises(ValueError):
        TokenBoundedChunker(11, 10)
