# SPDX-License-Identifier: AGPL-3.0-only
"""Public timeline DTOs.

Timeline events expose observable workflow actions only; hidden reasoning,
prompts, provider payloads, and LangGraph details are never serialized.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEventType,
)


class TimelineEventResponse(BaseModel):
    """One safe observable workflow event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    type: InvestigationTimelineEventType
    occurred_at: datetime
    provider: str | None
    target_entity_id: UUID | None
    evidence_ids: tuple[UUID, ...]
    entity_ids: tuple[UUID, ...]
    relationship_ids: tuple[UUID, ...]
    error_code: str | None
    pivot_depth: int | None
    reason_code: str | None
    provider_calls_used: int | None
    replans_used: int | None
    entity_count: int | None
