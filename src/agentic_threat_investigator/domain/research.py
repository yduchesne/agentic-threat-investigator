# SPDX-License-Identifier: AGPL-3.0-only
"""Pure domain contracts for contextual research retrieval."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    """One persisted chunk returned in database relevance order.

    The provenance surface is sufficient to create a durable
    ``ResearchCitation`` snapshot without reopening the vector index:
    ``chunk_id`` remains the operational persistence-row identity while
    ``citation_id`` is the stable semantic citation identity that survives
    pure re-embedding and active chunk replacement.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk_id: UUID
    citation_id: UUID
    document_id: UUID
    source_id: str
    source_record_id: str
    document_type: str
    chunk_sequence: int = Field(ge=1)
    text: str
    title: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    similarity_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    _validate_timestamp = field_validator("published_at", mode="after")(
        validate_utc_timestamp
    )

    @field_validator("source_id", "source_record_id", "document_type", "text")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Reject empty provenance identifiers and chunk text."""
        if not value.strip():
            raise ValueError("provenance identifiers and text must not be blank")
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


class ResearchCitation(BaseModel):
    """An immutable citation snapshot of one retrieved chunk.

    A persisted ``ResearchCitation`` remains interpretable even when the
    active ``DocumentChunk`` row it cited is later replaced or removed: it
    copies the full provenance surface needed for an audit-neutral citation.
    ``chunk_id`` is retained only as non-authoritative operational debugging
    provenance and is deliberately not the citation foreign identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    citation_id: UUID
    document_id: UUID
    source_id: str
    source_record_id: str
    document_type: str
    chunk_sequence: int = Field(ge=1)
    text: str
    title: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    similarity_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    chunk_id: UUID | None = None

    _validate_timestamp = field_validator("published_at", mode="after")(
        validate_utc_timestamp
    )

    @field_validator("source_id", "source_record_id", "document_type", "text")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Reject empty provenance identifiers and citation text."""
        if not value.strip():
            raise ValueError("provenance identifiers and text must not be blank")
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
        """Store citation metadata as a recursively immutable snapshot."""
        return freeze_mapping(value)


class ResearchClaim(BaseModel):
    """A claims-level citation reference inside one immutable ResearchResult.

    Research claims carry no verdict, confidence, severity, Evidence identity,
    or Relationship identity: those belong to Evidence/Assessment and are
    deliberately out of scope for research artifacts. Every claim must
    reference at least one citation snapshot included in its result.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    text: str
    citation_ids: tuple[UUID, ...]

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """Trim and reject blank claim text."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("claim text must not be blank")
        return stripped

    @field_validator("citation_ids")
    @classmethod
    def validate_citation_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        """Require at least one citation and reject duplicates."""
        if not value:
            raise ValueError("a research claim must cite at least one chunk")
        if len(set(value)) != len(value):
            raise ValueError("claim citation_ids must be unique")
        return value


class ResearchResult(BaseModel):
    """An immutable, append-only contextual research artifact (PR 22A).

    A persisted ``ResearchResult`` is a contextual synthesis/provenance
    container; it is deliberately NOT Evidence and NOT Assessment. Repeat
    research executions create a new result rather than mutating a prior
    one: there is no update/delete operation. Zero-claim/zero-citation
    results are valid so research can represent "no relevant context"
    without inventing Evidence. Citation closure is deterministic: every
    claim citation ID must exist in the result's citation snapshots.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    investigation_id: UUID
    subject_entity_id: UUID
    query: str
    claims: tuple[ResearchClaim, ...] = Field(default_factory=tuple)
    citations: tuple[ResearchCitation, ...] = Field(default_factory=tuple)
    created_at: datetime

    _validate_timestamp = field_validator("created_at", mode="after")(
        validate_utc_timestamp
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        """Trim and reject blank research queries."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("research query must not be blank")
        return stripped

    @model_validator(mode="after")
    def validate_citation_closure(self) -> ResearchResult:
        """Enforce unique identities and claim-to-citation closure."""
        citation_ids = [citation.citation_id for citation in self.citations]
        if len(set(citation_ids)) != len(citation_ids):
            raise ValueError("research citations must have unique citation_ids")
        claim_ids = [claim.id for claim in self.claims]
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("research claims must have unique ids")
        available = set(citation_ids)
        for claim in self.claims:
            missing = [str(cid) for cid in claim.citation_ids if cid not in available]
            if missing:
                raise ValueError(
                    "research claims reference unknown citations: " + ", ".join(missing)
                )
        return self


def research_citation_from_retrieved_chunk(chunk: RetrievedChunk) -> ResearchCitation:
    """Snapshot a retrieved chunk into a durable immutable citation.

    The snapshot is intentionally self-contained so a persisted result stays
    interpretable after the active chunk row is replaced or removed.
    """
    return ResearchCitation(
        citation_id=chunk.citation_id,
        document_id=chunk.document_id,
        source_id=chunk.source_id,
        source_record_id=chunk.source_record_id,
        document_type=chunk.document_type,
        chunk_sequence=chunk.chunk_sequence,
        text=chunk.text,
        title=chunk.title,
        source_url=chunk.source_url,
        published_at=chunk.published_at,
        similarity_score=chunk.similarity_score,
        metadata=dict(chunk.metadata),
        chunk_id=chunk.chunk_id,
    )
