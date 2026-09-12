# SPDX-License-Identifier: AGPL-3.0-only
"""Public Research DTOs.

Structured claims and citation snapshots preserve claim->citation closure;
embedding/vector internals, prompts, raw model responses, and hidden
reasoning are never exposed.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ResearchCitationResponse(BaseModel):
    """An immutable citation snapshot of one retrieved chunk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    citation_id: UUID
    document_id: UUID
    source_id: str
    source_record_id: str
    document_type: str
    chunk_sequence: int
    text: str
    title: str | None
    source_url: str | None
    published_at: datetime | None
    similarity_score: float | None


class ResearchClaimResponse(BaseModel):
    """One claims-level citation reference inside a research result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    text: str
    citation_ids: tuple[UUID, ...]


class ResearchResultResponse(BaseModel):
    """One immutable contextual research artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    subject_entity_id: UUID
    query: str
    claims: tuple[ResearchClaimResponse, ...]
    citations: tuple[ResearchCitationResponse, ...]
    created_at: datetime
