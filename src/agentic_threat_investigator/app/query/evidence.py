# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence collection query contract and service boundary."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.app.query.models import (
    QueryPage,
    normalize_utc,
    require_ordered_half_open,
)
from agentic_threat_investigator.app.query.pagination import (
    CursorEnvelope,
    filter_fingerprint,
)
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType


class EvidenceListQuery(BaseModel):
    """Bounded Evidence listing filters for one Investigation.

    Canonical order preserves the persisted execution semantics:
    ``retrieved_at DESC, id ASC``. ``retrieved_from``/``retrieved_to`` bound a
    half-open ``[from, to)`` UTC interval. The Investigation scope is
    mandatory; there is no global Evidence browse contract in v0.1.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    source: str | None = None
    subject_entity_id: UUID | None = None
    evidence_type: EvidenceType | None = None
    retrieved_from: datetime | None = None
    retrieved_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator("retrieved_from", "retrieved_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @field_validator("source")
    @classmethod
    def source_not_blank(cls, value: str | None) -> str | None:
        """Reject blank source filters."""
        if value is not None and not value.strip():
            raise ValueError("source filter must not be blank")
        return value

    @model_validator(mode="after")
    def half_open(self) -> "EvidenceListQuery":
        """Require the retrieved-at interval to be well ordered."""
        require_ordered_half_open(
            ((self.retrieved_from, self.retrieved_to, "retrieved_at"),)
        )
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "source": self.source,
                "subject_entity_id": self.subject_entity_id,
                "evidence_type": self.evidence_type,
                "retrieved_from": self.retrieved_from,
                "retrieved_to": self.retrieved_to,
            }
        )


class EvidenceQueryService(ABC):
    """Analyst-facing Evidence read contract (PR 23A)."""

    @abstractmethod
    async def list(self, query: EvidenceListQuery) -> QueryPage[Evidence]:
        """Return one bounded page of immutable Evidence observations.

        Ordering is ``retrieved_at DESC, id ASC``; cursors are bound to the
        exact filter set.
        """


def evidence_sort_values(retrieved_at: datetime, evidence_id: UUID) -> tuple[str, str]:
    """Return canonical cursor sort values for one evidence row."""
    return retrieved_at.astimezone(UTC).isoformat(), str(evidence_id)


def parse_evidence_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("evidence cursor requires retrieved_at and id")
    retrieved_at = datetime.fromisoformat(envelope.sort_values[0])
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ValueError("evidence cursor timestamp must be timezone-aware")
    return retrieved_at.astimezone(UTC), UUID(envelope.sort_values[1])
