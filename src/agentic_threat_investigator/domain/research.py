# SPDX-License-Identifier: AGPL-3.0-only
"""Pure domain contracts for contextual research retrieval."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping
from agentic_threat_investigator.domain.source import validate_utc_timestamp


def _unique_strings(value: list[str]) -> list[str]:
    """Strip and stably deduplicate a list of filter values."""
    result: list[str] = []
    for item in value:
        stripped = item.strip()
        if not stripped:
            raise ValueError("filter values must not be blank")
        if stripped not in result:
            result.append(stripped)
    return result


def _unique_uuids(value: list[UUID]) -> list[UUID]:
    """Stably deduplicate contextual entity identifiers."""
    return list(dict.fromkeys(value))


class ResearchQuery(BaseModel):
    """A bounded, contextual query over the narrative research corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    investigation_id: UUID
    query: str
    entity_ids: list[UUID] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    document_types: list[str] = Field(default_factory=list)
    max_results: int = Field(default=8, ge=1, le=100)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        """Reject blank queries and retain their trimmed representation."""
        value = value.strip()
        if not value:
            raise ValueError("query must not be blank")
        return value

    _normalize_sources = field_validator("source_ids", "document_types")(
        _unique_strings
    )
    _normalize_entities = field_validator("entity_ids")(_unique_uuids)


class RetrievedChunk(BaseModel):
    """One persisted chunk returned in database relevance order."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk_id: UUID
    document_id: UUID
    source_id: str
    text: str
    title: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    similarity_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    _validate_timestamp = field_validator("published_at", mode="after")(
        validate_utc_timestamp
    )

    @field_validator("source_id", "text")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Reject empty provenance identifiers and chunk text."""
        if not value.strip():
            raise ValueError("source_id and text must not be blank")
        return value

    @field_validator("similarity_score")
    @classmethod
    def validate_score(cls, value: float | None) -> float | None:
        """Require finite cosine similarity within its mathematical bounds."""
        if value is not None and (not math.isfinite(value) or not -1 <= value <= 1):
            raise ValueError("similarity_score must be finite and between -1 and 1")
        return value

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: dict[str, Any]) -> FrozenDict:
        """Store returned metadata as a recursively immutable snapshot."""
        return freeze_mapping(value)
