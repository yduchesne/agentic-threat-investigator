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
    """One exact admitted EvidenceObservation, normalized facts only (PR 28B).

    ``id`` is the exact EvidenceObservation identity, never the stable
    Evidence ID. The legacy ``subject_*`` field names are retained for wire
    compatibility: they resolve to the observation's first associated Entity
    in deterministic order (or ``None`` when the observation has none). They
    are presentation compatibility only; there is no privileged Evidence
    subject and no role semantics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    type: EvidenceType
    subject_entity_id: UUID | None = None
    subject_type: EntityType | None = None
    subject_value: str | None = None
    source: str
    source_record_id: str | None
    source_url: str | None
    observed_at: datetime | None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
