# SPDX-License-Identifier: AGPL-3.0-only
"""Public Relationship and RelationshipObservation DTOs.

A Relationship exposes its stable edge identity; an observation exposes the
immutable historical record with the observed/retrieved time distinction
preserved. Observations are never routed through generic history.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.relationships import RelationshipType


class RelationshipResponse(BaseModel):
    """One stable relationship edge visible to an Investigation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    type: RelationshipType


class RelationshipObservationResponse(BaseModel):
    """One immutable historical relationship observation.

    ``observed_at`` is the source observation time when known; ``retrieved_at``
    is ATI's retrieval time and the canonical cursor key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    relationship_id: UUID
    evidence_id: UUID
    investigation_id: UUID | None
    observed_at: datetime | None
    retrieved_at: datetime
    source: str
    confidence: float | None
