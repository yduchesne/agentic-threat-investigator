# SPDX-License-Identifier: AGPL-3.0-only
"""Application port for deterministic or remote text embeddings."""
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from agentic_threat_investigator.domain.documents import EmbeddingModelInfo


class EmbeddingError(RuntimeError):
    """Base error raised by an embedding client."""


class EmbeddingInputError(EmbeddingError, ValueError):
    """Raised when text cannot be embedded."""


@dataclass(frozen=True)
class EmbeddedText:
    """One embedding correlated to a request ordinal."""

    text_ordinal: int
    vector: list[float]


class EmbeddingClient(ABC):
    """Bounded text embedding port whose results preserve input order."""

    @property
    @abstractmethod
    def model_info(self) -> EmbeddingModelInfo:
        """Return the provider/model metadata for produced vectors."""

    @abstractmethod
    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Embed non-blank texts and return 1-based correlated ordinals."""
