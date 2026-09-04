# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for deterministic offline embeddings."""

import math

import pytest

from agentic_threat_investigator.app.embeddings import EmbeddingInputError
from agentic_threat_investigator.infrastructure.embeddings import HashingEmbeddingClient


@pytest.mark.asyncio
async def test_hashing_embedding_is_deterministic_normalized_and_ordered() -> None:
    """Independent clients produce normalized vectors and 1-based ordinals."""
    first = HashingEmbeddingClient(8)
    second = HashingEmbeddingClient(8)
    first_results = await first.embed_texts(["alpha beta", "gamma"])
    second_results = await second.embed_texts(["alpha beta", "gamma"])
    assert first_results == second_results
    assert [item.text_ordinal for item in first_results] == [1, 2]
    assert all(len(item.vector) == 8 for item in first_results)
    assert math.sqrt(
        sum(value * value for value in first_results[0].vector)
    ) == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_hashing_embedding_rejects_blank_text() -> None:
    """Blank embedding input has a typed application error."""
    with pytest.raises(EmbeddingInputError):
        await HashingEmbeddingClient().embed_texts([" "])


def test_hashing_embedding_rejects_invalid_dimension() -> None:
    """Embedding dimensions must be positive."""
    with pytest.raises(ValueError):
        HashingEmbeddingClient(0)
