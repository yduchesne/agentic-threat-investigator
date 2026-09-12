# SPDX-License-Identifier: AGPL-3.0-only
"""Concrete embedding implementations behind the ``EmbeddingClient`` port.

``HashingEmbeddingClient`` is a deterministic offline utility used by tests:
its vectors are NOT semantically meaningful and must never be described as
production-quality retrieval. ``LangChainEmbeddingClient`` adapts any
injected LangChain ``Embeddings`` object (normally a production semantic
model) to the ATI embedding contract and validates count, ordinal
correlation, dimension, and finite values. ``build_openai_embedding_client``
is the narrow production construction helper for the installed
``langchain-openai`` provider; the API key is an injected resolved secret
and is never stored or logged by configuration or the adapter.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from collections.abc import Sequence

from langchain_core.embeddings import Embeddings
from langchain_openai import OpenAIEmbeddings
from pydantic import SecretStr

from agentic_threat_investigator.app.embeddings import (
    EmbeddedText,
    EmbeddingClient,
    EmbeddingError,
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


class LangChainEmbeddingClient(EmbeddingClient):
    """Adapt an injected LangChain ``Embeddings`` instance to the ATI contract.

    The adapter never constructs a provider model, never reads configuration
    or environment variables, and never persists anything: the concrete
    ``Embeddings`` object and its ``EmbeddingModelInfo`` identity are injected
    during composition. Provider/framework failures are mapped to the
    content-free ``EmbeddingError`` taxonomy; ``asyncio.CancelledError``
    always propagates unchanged.
    """

    def __init__(self, embeddings: Embeddings, model_info: EmbeddingModelInfo) -> None:
        self._embeddings = embeddings
        self._info = model_info

    @property
    def model_info(self) -> EmbeddingModelInfo:
        """Return the embedding identity of the injected model."""
        return self._info

    async def embed_texts(self, texts: Sequence[str]) -> list[EmbeddedText]:
        """Embed texts in input order and validate count/ordinal/dimension/finiteness."""
        if not texts:
            raise EmbeddingInputError("cannot embed an empty text sequence")
        try:
            vectors = await self._embeddings.aembed_documents(list(texts))
        except asyncio.CancelledError:
            # Cooperative cancellation must propagate unchanged.
            raise
        except Exception:  # noqa: BLE001 - unexpected provider/framework failures map securely
            # Content-free translation: prompts, provider error text, and
            # credentials never appear in the mapped error.
            raise EmbeddingError("semantic embedding request failed") from None
        if len(vectors) != len(texts):
            raise EmbeddingError("semantic embedding returned an invalid count")
        results: list[EmbeddedText] = []
        for ordinal, vector in enumerate(vectors, 1):
            if not isinstance(vector, Sequence) or isinstance(vector, (str, bytes)):
                raise EmbeddingError("semantic embedding returned an invalid vector")
            components = [float(component) for component in vector]
            if len(components) != self._info.dimension:
                raise EmbeddingError("semantic embedding dimension mismatch")
            if any(not math.isfinite(component) for component in components):
                raise EmbeddingError("semantic embedding contains non-finite values")
            results.append(EmbeddedText(ordinal, components))
        return results


def build_openai_embedding_client(
    *,
    model: str,
    model_version: int,
    dimension: int,
    api_key: str,
    timeout_seconds: float | None = None,
) -> LangChainEmbeddingClient:
    """Compose the production OpenAI semantic embedding adapter.

    ``api_key`` is a resolved secret injected by bootstrap/composition; it is
    never stored, logged, or placed in configuration. ``model_version`` is
    the ATI-owned representation version consumed by the embedding identity
    contract, independent of the provider model name.
    """
    if not model.strip():
        raise ValueError("embedding model must not be blank")
    if model_version < 1 or dimension < 1:
        raise ValueError("embedding model version and dimension must be positive")
    embeddings = OpenAIEmbeddings(
        model=model,
        dimensions=dimension,
        api_key=SecretStr(api_key),
        timeout=timeout_seconds,
    )
    return LangChainEmbeddingClient(
        embeddings,
        EmbeddingModelInfo(
            provider="openai",
            model=model,
            model_version=model_version,
            dimension=dimension,
        ),
    )
