# SPDX-License-Identifier: AGPL-3.0-only
"""Public support-presentation request/response DTOs (PR 31F-5).

One bounded Investigation-scoped batch resolution: the frontend collects
the finite support-ID sets of one loaded Report/Assessment and asks once;
the response carries semantic presentation metadata only. Raw provider
payloads never cross this boundary.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.app.query.support_presentations import (
    MAX_SUPPORT_IDS_PER_KIND,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType


class SupportPresentationRequest(BaseModel):
    """The finite requested support-ID sets of one loaded artifact."""

    model_config = ConfigDict(extra="forbid")

    evidence_observation_ids: list[UUID] = Field(
        default_factory=list, max_length=MAX_SUPPORT_IDS_PER_KIND
    )
    relationship_observation_ids: list[UUID] = Field(
        default_factory=list, max_length=MAX_SUPPORT_IDS_PER_KIND
    )


class EvidenceSupportPresentationResponse(BaseModel):
    """One Evidence support presentation (semantic description first)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_observation_id: UUID
    evidence_type: EvidenceType
    source: str
    subject_entity_id: UUID | None = None
    subject_entity_type: EntityType | None = None
    subject_entity_value: str | None = None


class RelationshipObservationSupportPresentationResponse(BaseModel):
    """One RelationshipObservation support presentation (semantic edge first)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_observation_id: UUID
    relationship_id: UUID
    relationship_type: RelationshipType
    source_entity_id: UUID
    source_entity_type: EntityType | None = None
    source_entity_value: str | None = None
    target_entity_id: UUID
    target_entity_type: EntityType | None = None
    target_entity_value: str | None = None
    observed_at: datetime | None = None


class SupportPresentationResponse(BaseModel):
    """The resolved presentation map keyed by request (indexed by ID)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence: tuple[EvidenceSupportPresentationResponse, ...] = ()
    relationship_observations: tuple[
        RelationshipObservationSupportPresentationResponse, ...
    ] = ()
