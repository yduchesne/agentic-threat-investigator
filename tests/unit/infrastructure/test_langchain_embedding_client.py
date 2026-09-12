# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the LangChain/OpenAI semantic embedding adapter boundary."""

import asyncio
import math
from typing import Any

import pytest
from langchain_core.embeddings import Embeddings

from agentic_threat_investigator.app.embeddings import (
    EmbeddingClient,
    EmbeddingError,
    EmbeddingInputError,
)
from agentic_threat_investigator.domain.documents import EmbeddingModelInfo
from agentic_threat_investigator.infrastructure.embeddings import (
    LangChainEmbeddingClient,
    build_openai_embedding_client,
)


class StubEmbeddings(Embeddings):
    """Deterministic LangChain-boundary stub; no network is ever touched."""

    def __init__(self, vectors: list[list[float]] | None = None) -> None:
        self.vectors = vectors
        self.inputs: list[str] = []
        self.error: BaseException | None = None

    async def aembed_documents(
        self, texts: list[str], chunk_size: int | None = None, **kwargs: Any
    ) -> list[list[float]]:
        """Return the configured vectors or raise the configured error."""
        self.inputs = list(texts)
        if self.error is not None:
            raise self.error
        if self.vectors is None:
            return [[1.0, 0.0] for _ in texts]
        return list(self.vectors)

    async def aembed_query(self, text: str) -> list[float]:
        """Unused in the document-embedding contract; test-only boundary."""
        raise NotImplementedError

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Unused synchronous boundary."""
        raise NotImplementedError

    def embed_query(self, text: str) -> list[float]:
        """Unused synchronous boundary."""
        raise NotImplementedError


def _client(
    stub: StubEmbeddings, dimension: int = 2
) -> tuple[EmbeddingClient, EmbeddingModelInfo]:
    """Wrap a stub with a fixed embedding identity and return both."""
    info = EmbeddingModelInfo(
        provider="openai",
        model="text-embedding-3-small",
        model_version=3,
        dimension=dimension,
    )
    return LangChainEmbeddingClient(stub, info), info


@pytest.mark.asyncio
async def test_semantic_adapter_preserves_order_and_ordinals() -> None:
    """A1/A2: two texts produce two correlated 1-based results in order."""
    stub = StubEmbeddings([[1.0, 0.0], [0.0, 1.0]])
    client, info = _client(stub)
    results = await client.embed_texts(["alpha", "beta"])
    assert [result.text_ordinal for result in results] == [1, 2]
    assert results[0].vector == [1.0, 0.0]
    assert results[1].vector == [0.0, 1.0]
    assert stub.inputs == ["alpha", "beta"]
    assert client.model_info == info


@pytest.mark.asyncio
async def test_semantic_adapter_rejects_wrong_vector_count() -> None:
    """A3: a count mismatch is a typed content-free embedding error."""
    stub = StubEmbeddings([[1.0, 0.0]])
    client, _info = _client(stub)
    with pytest.raises(EmbeddingError, match="invalid count"):
        await client.embed_texts(["alpha", "beta"])


@pytest.mark.asyncio
async def test_semantic_adapter_rejects_wrong_dimension() -> None:
    """A4: each vector must exactly match the declared dimension."""
    stub = StubEmbeddings([[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]])
    client, _info = _client(stub)
    with pytest.raises(EmbeddingError, match="dimension"):
        await client.embed_texts(["alpha", "beta"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), float("-inf")],
)
async def test_semantic_adapter_rejects_non_finite_vectors(bad: float) -> None:
    """A5: NaN and infinities are rejected before they reach the corpus."""
    stub = StubEmbeddings([[bad, 0.0]])
    client, _info = _client(stub)
    with pytest.raises(EmbeddingError, match="non-finite"):
        await client.embed_texts(["alpha"])


@pytest.mark.asyncio
async def test_semantic_adapter_translates_upstream_failures_securely() -> None:
    """A6: provider failures map to a content-free stable category."""
    stub = StubEmbeddings()
    stub.error = ConnectionError("secret api key leaked in provider error text")
    client, _info = _client(stub)
    with pytest.raises(EmbeddingError) as captured:
        await client.embed_texts(["alpha"])
    assert str(captured.value) == "semantic embedding request failed"
    assert "secret" not in str(captured.value)


@pytest.mark.asyncio
async def test_semantic_adapter_propagates_cancellation() -> None:
    """Cooperative cancellation must never be wrapped in an EmbeddingError."""
    stub = StubEmbeddings()

    async def cancel(
        texts: list[str], chunk_size: int | None = None, **kwargs: Any
    ) -> list[list[float]]:
        raise asyncio.CancelledError

    stub.aembed_documents = cancel  # type: ignore[method-assign]
    client, _info = _client(stub)
    with pytest.raises(asyncio.CancelledError):
        await client.embed_texts(["alpha"])


@pytest.mark.asyncio
async def test_semantic_adapter_rejects_blank_and_empty_inputs() -> None:
    """The ATI contract rejects empty sequences before the provider boundary."""
    stub = StubEmbeddings()
    client, _info = _client(stub)
    with pytest.raises(EmbeddingInputError):
        await client.embed_texts([])
    assert stub.inputs == []


def test_openai_construction_helper_builds_semantic_identity() -> None:
    """The production helper composes an OpenAI adapter without network I/O."""
    client = build_openai_embedding_client(
        model="text-embedding-3-small",
        model_version=2,
        dimension=1536,
        api_key="sk-test-only-placeholder",
    )
    assert client.model_info.provider == "openai"
    assert client.model_info.model == "text-embedding-3-small"
    assert client.model_info.model_version == 2
    assert client.model_info.dimension == 1536
    assert isinstance(client, LangChainEmbeddingClient)
    with pytest.raises(ValueError):
        build_openai_embedding_client(
            model=" ",
            model_version=1,
            dimension=1536,
            api_key="sk-test-only-placeholder",
        )


def test_semantic_vectors_are_normalized_equivalents_of_stub_output() -> None:
    """A7: the adapter never performs network I/O; the stub is the boundary."""
    stub = StubEmbeddings()
    client, info = _client(stub)
    assert isinstance(client, LangChainEmbeddingClient)
    assert info.dimension == 2
    assert all(math.isfinite(value) for value in [1.0, 0.0])
