# SPDX-License-Identifier: AGPL-3.0-only
"""Public Evidence DTOs.

Responses expose normalized facts and provenance only; the raw provider
payload is never part of the public contract.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType


class EvidenceResponse(BaseModel):
    """One immutable Evidence observation, normalized facts only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    type: EvidenceType
    subject_entity_id: UUID
    subject_type: EntityType
    subject_value: str
    source: str
    source_record_id: str | None
    source_url: str | None
    observed_at: datetime | None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
