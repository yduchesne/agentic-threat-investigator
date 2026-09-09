# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Analyst-facing investigation workflow timeline events.

The timeline is a distinct, append-only record of safe observable workflow
actions. It is separate from audit events, domain-object history, application
logs, and distributed tracing, and it never carries prose reasoning, raw
provider payloads, secrets, or chain-of-thought.
"""

from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from agentic_threat_investigator.domain.identifiers import SourceId


class InvestigationTimelineEventType(str, Enum):
    """Safe observable workflow actions recorded on an investigation timeline."""

    INVESTIGATION_STARTED = "investigation_started"
    PROVIDER_WORK_STARTED = "provider_work_started"
    PROVIDER_WORK_COMPLETED = "provider_work_completed"
    PROVIDER_WORK_FAILED = "provider_work_failed"
    EVIDENCE_PERSISTED = "evidence_persisted"
    ENTITIES_DISCOVERED = "entities_discovered"


class InvestigationTimelineEvent(BaseModel):
    """One append-only, analyst-facing workflow timeline event.

    Events carry typed identifiers and a stable event type only: no free-form
    reason text, raw payloads, stack traces, prompts, or hidden reasoning.
    Presentation prose, where required later, is derived deterministically
    from the event type and fields.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    investigation_id: UUID
    type: InvestigationTimelineEventType
    occurred_at: datetime
    provider: SourceId | None = None
    target_entity_id: UUID | None = None
    evidence_ids: tuple[UUID, ...] = ()
    entity_ids: tuple[UUID, ...] = ()
    relationship_ids: tuple[UUID, ...] = ()
    error_code: str | None = None

    @field_validator("occurred_at")
    @classmethod
    def validate_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp, normalized to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timeline timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        """Reject blank error codes; codes are stable bounded identifiers."""
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("timeline error_code must not be blank")
        return stripped
