# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable domain models for the narrative RAG corpus."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping
from agentic_threat_investigator.domain.source import (
    canonical_json_bytes,
    canonical_timestamp_text,
    validate_utc_timestamp,
)


def document_content_hash(document: Document | Mapping[str, Any]) -> str:
    """Compute the SHA-256 digest of semantic document content.

    Internal identity and retrieval time are operational values and therefore
    do not participate in deterministic change detection.
    """
    values: Mapping[str, Any]
    if isinstance(document, Document):
        values = document.model_dump(mode="python")
    else:
        values = document
    semantic = {
        "document_type": values["document_type"],
        "title": values.get("title"),
        "source_url": values.get("source_url"),
        "published_at": canonical_timestamp_text(values.get("published_at")),
        "content": values["content"],
        "normalization_version": values["normalization_version"],
        "chunking_version": values["chunking_version"],
        "metadata": values.get("metadata", {}),
    }
    return hashlib.sha256(canonical_json_bytes(semantic)).hexdigest().lower()


def document_chunk_content_hash(chunk: DocumentChunk | Mapping[str, Any]) -> str:
    """Compute the chunk semantic digest without including its vector."""
    values: Mapping[str, Any]
    if isinstance(chunk, DocumentChunk):
        values = chunk.model_dump(mode="python")
    else:
        values = chunk
    semantic = {
        "document_id": str(values["document_id"]),
        "sequence": values["sequence"],
        "text": values["text"],
        "token_count": values["token_count"],
        "embedding_provider": values["embedding_provider"],
        "embedding_model": values["embedding_model"],
        "embedding_model_version": values["embedding_model_version"],
        "embedding_dimension": values["embedding_dimension"],
        "metadata": values.get("metadata", {}),
    }
    return hashlib.sha256(canonical_json_bytes(semantic)).hexdigest().lower()


class Document(BaseModel):
    """A versioned narrative document derived from one source record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID | None = None
    source_id: str
    source_record_id: str
    document_type: str
    title: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    retrieved_at: datetime
    content: str
    normalization_version: int = Field(ge=1)
    chunking_version: int = Field(ge=1)
    content_hash: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    _validate_timestamps = field_validator(
        "published_at", "retrieved_at", mode="after"
    )(validate_utc_timestamp)

    @field_validator("source_id", "source_record_id", "document_type", "content")
    @classmethod
    def validate_nonblank_fields(cls, value: str) -> str:
        """Reject blank identity, type, and narrative content."""
        if not value.strip():
            raise ValueError("document identity, type, and content must not be blank")
        return value

    @model_validator(mode="before")
    @classmethod
    def validate_content_hash(cls, data: Any) -> Any:
        """Derive or verify the document semantic digest."""
        if not isinstance(data, Mapping):
            return data
        values = dict(data)
        required = {
            "source_id",
            "source_record_id",
            "document_type",
            "content",
            "normalization_version",
            "chunking_version",
        }
        if not required.issubset(values):
            return values
        expected = document_content_hash(values)
        supplied = values.get("content_hash", "")
        if not isinstance(supplied, str) or supplied.lower() not in ("", expected):
            raise ValueError("content_hash does not match document content")
        values["content_hash"] = expected
        return values

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: dict[str, Any]) -> FrozenDict:
        """Store metadata as a recursively immutable snapshot."""
        return freeze_mapping(value)


class EmbeddingModelInfo(BaseModel):
    """Metadata identifying one embedding vector representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    model_version: int = Field(ge=1)
    dimension: int = Field(ge=1)

    @field_validator("provider", "model")
    @classmethod
    def validate_nonblank_identifiers(cls, value: str) -> str:
        """Reject incomplete embedding identifiers."""
        if not value.strip():
            raise ValueError("embedding provider and model must not be blank")
        return value


class DocumentChunk(BaseModel):
    """A replaceable embedded segment of a narrative document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID | None = None
    document_id: UUID
    sequence: int = Field(ge=1)
    text: str
    token_count: int = Field(ge=1)
    embedding_provider: str
    embedding_model: str
    embedding_model_version: int = Field(ge=1)
    embedding_dimension: int = Field(ge=1)
    embedding: tuple[float, ...]
    content_hash: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("text", "embedding_provider", "embedding_model")
    @classmethod
    def validate_nonblank_fields(cls, value: str) -> str:
        """Reject blank chunk text and embedding identifiers."""
        if not value.strip():
            raise ValueError("chunk text and embedding identifiers must not be blank")
        return value

    @field_validator("embedding", mode="after")
    @classmethod
    def validate_finite_vector(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        """Reject NaN and infinite vector components."""
        if any(not math.isfinite(item) for item in value):
            raise ValueError("embedding values must be finite")
        return value

    @model_validator(mode="before")
    @classmethod
    def validate_vector_and_hash(cls, data: Any) -> Any:
        """Verify vector shape and derive or verify semantic content hash."""
        if not isinstance(data, Mapping):
            return data
        values = dict(data)
        vector = values.get("embedding")
        dimension = values.get("embedding_dimension")
        if (
            isinstance(vector, Sequence)
            and not isinstance(vector, (str, bytes))
            and isinstance(dimension, int)
            and len(vector) != dimension
        ):
            raise ValueError("embedding length does not match embedding_dimension")
        required = {
            "document_id",
            "sequence",
            "text",
            "token_count",
            "embedding_provider",
            "embedding_model",
            "embedding_model_version",
            "embedding_dimension",
        }
        if not required.issubset(values):
            return values
        expected = document_chunk_content_hash(values)
        supplied = values.get("content_hash", "")
        if not isinstance(supplied, str) or supplied.lower() not in ("", expected):
            raise ValueError("content_hash does not match chunk content")
        values["content_hash"] = expected
        return values

    @model_validator(mode="after")
    def validate_embedding_dimension(self) -> DocumentChunk:
        """Require exactly the declared number of vector components."""
        if len(self.embedding) != self.embedding_dimension:
            raise ValueError("embedding length does not match embedding_dimension")
        return self

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: dict[str, Any]) -> FrozenDict:
        """Store metadata as a recursively immutable snapshot."""
        return freeze_mapping(value)
