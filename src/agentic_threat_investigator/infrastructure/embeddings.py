# SPDX-License-Identifier: AGPL-3.0-only
"""Offline deterministic embedding implementation."""
from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence

from agentic_threat_investigator.app.embeddings import (
    EmbeddedText,
    EmbeddingClient,
    EmbeddingInputError,
)
from agentic_threat_investigator.domain.documents import EmbeddingModelInfo


class HashingEmbeddingClient(EmbeddingClient):
    """Produce deterministic hash vectors for offline tests, not semantic similarity."""

    def __init__(self, dimension: int = 1536) -> None:
        if dimension < 1:
            raise ValueError("dimension must be positive")
        self._info = EmbeddingModelInfo(
            provider="hashing",
            model="ati-hashing-v1",
            model_version=1,
            dimension=dimension,
        )

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return hashing model metadata."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Hash words into normalized vectors without I/O or randomized hashing."""
        result: list[EmbeddedText] = []
        for ordinal, text in enumerate(texts, 1):
            words = text.lower().split()
            if not words:
                raise EmbeddingInputError("cannot embed blank text")
            vector = [0.0] * self._info.dimension
            for word in words:
                digest = hashlib.sha256(word.encode("utf-8")).digest()
                index = int.from_bytes(digest[:8], "big") % self._info.dimension
                vector[index] += -1.0 if digest[8] & 1 else 1.0
            norm = math.sqrt(sum(value * value for value in vector))
            if norm:
                vector = [value / norm for value in vector]
            result.append(EmbeddedText(ordinal, vector))
        return result
