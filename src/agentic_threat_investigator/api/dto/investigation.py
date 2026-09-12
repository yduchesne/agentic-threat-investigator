# SPDX-License-Identifier: AGPL-3.0-only
"""Public Investigation DTOs.

Creation requests are strict, bounded, and rejected on unknown fields.
Responses expose stable public operational state only: orchestration queues,
dispatcher state, research fingerprints, job identities, and LangGraph
metadata are never serialized.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.investigation import InvestigationStatus

MAX_OBJECTIVE_LENGTH = 4000
MAX_INDICATOR_VALUE_LENGTH = 2048


class IndicatorRequest(BaseModel):
    """One raw indicator submitted for canonicalization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: EntityType
    value: str = Field(min_length=1, max_length=MAX_INDICATOR_VALUE_LENGTH)

    @field_validator("value")
    @classmethod
    def value_not_blank(cls, value: str) -> str:
        """Reject blank indicator values."""
        if not value.strip():
            raise ValueError("indicator value must not be blank")
        return value


class CreateInvestigationRequest(BaseModel):
    """Strict create-Investigation request DTO."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    indicators: tuple[IndicatorRequest, ...] = Field(min_length=1)
    objective: str = Field(min_length=1, max_length=MAX_OBJECTIVE_LENGTH)

    @field_validator("objective")
    @classmethod
    def objective_not_blank(cls, value: str) -> str:
        """Reject blank objectives."""
        if not value.strip():
            raise ValueError("objective must not be blank")
        return value


class CreateInvestigationResponse(BaseModel):
    """The authoritative result of an asynchronous creation request."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    status: InvestigationStatus
    created_at: datetime


class InvestigationResponse(BaseModel):
    """Stable public operational state of one Investigation.

    Explicitly excluded: pending pivots/provider work, completed work,
    coordinator counters, traversal metadata, research execution state,
    errors, orchestration/job internals, and LangGraph checkpoints.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    status: InvestigationStatus
    objective: str
    root_entity_ids: tuple[UUID, ...]
    discovered_entity_ids: tuple[UUID, ...]
    evidence_ids: tuple[UUID, ...]
    relationship_ids: tuple[UUID, ...]
    assessment_id: UUID | None
    report_id: UUID | None
    stop_reason: str | None
    created_at: datetime
    started_at: datetime
    completed_at: datetime | None
    version: int
