# SPDX-License-Identifier: AGPL-3.0-only
"""ResearchResult collection query contract and service boundary.

ResearchResults are immutable, append-only contextual research artifacts.
Their natural query paths are investigation + time and investigation +
subject entity + time.
"""

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
from agentic_threat_investigator.domain.research import ResearchResult


class ResearchResultListQuery(BaseModel):
    """Bounded ResearchResult listing filters for one Investigation.

    Canonical order is ``created_at DESC, id ASC``. ``created_from`` and
    ``created_to`` bound a half-open ``[from, to)`` UTC interval.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    subject_entity_id: UUID | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator("created_from", "created_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @model_validator(mode="after")
    def half_open(self) -> "ResearchResultListQuery":
        """Require the created-at interval to be well ordered."""
        require_ordered_half_open(((self.created_from, self.created_to, "created_at"),))
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "subject_entity_id": self.subject_entity_id,
                "created_from": self.created_from,
                "created_to": self.created_to,
            }
        )


class ResearchResultQueryService(ABC):
    """Analyst-facing ResearchResult read contract (PR 23A)."""

    @abstractmethod
    async def list(self, query: ResearchResultListQuery) -> QueryPage[ResearchResult]:
        """Return one bounded page of immutable research results.

        Ordering is ``created_at DESC, id ASC``; cursors are bound to the
        exact filter set.
        """


def research_result_sort_values(
    created_at: datetime, result_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one research result row."""
    return created_at.astimezone(UTC).isoformat(), str(result_id)


def parse_research_result_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("research result cursor requires created_at and id")
    created_at = datetime.fromisoformat(envelope.sort_values[0])
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("research result cursor timestamp must be timezone-aware")
    return created_at.astimezone(UTC), UUID(envelope.sort_values[1])
