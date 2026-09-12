# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation timeline query contract and service boundary.

The timeline is an append-only, analyst-facing workflow record ordered
chronologically by ``occurred_at`` then the table-wide monotonic
``sequence``. PR 23A exposes a bounded keyset variant preserving that exact
deterministic order.
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
from agentic_threat_investigator.domain.investigation_timeline import (
    InvestigationTimelineEvent,
    InvestigationTimelineEventType,
)


class TimelineListQuery(BaseModel):
    """Bounded timeline event listing for one Investigation.

    Canonical order is the established chronological ``occurred_at ASC,
    sequence ASC``. ``occurred_from``/``occurred_to`` bound a half-open
    ``[from, to)`` UTC interval; the event-type filter is a bounded residual
    filter in v0.1.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    event_type: InvestigationTimelineEventType | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator("occurred_from", "occurred_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @model_validator(mode="after")
    def half_open(self) -> "TimelineListQuery":
        """Require the occurred-at interval to be well ordered."""
        require_ordered_half_open(
            ((self.occurred_from, self.occurred_to, "occurred_at"),)
        )
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "event_type": self.event_type,
                "occurred_from": self.occurred_from,
                "occurred_to": self.occurred_to,
            }
        )


class TimelineQueryService(ABC):
    """Analyst-facing timeline read contract (PR 23A)."""

    @abstractmethod
    async def list(
        self, query: TimelineListQuery
    ) -> QueryPage[InvestigationTimelineEvent]:
        """Return one bounded page of timeline events in chronological order.

        Ordering is ``occurred_at ASC, sequence ASC`` with bound cursors.
        """


def timeline_sort_values(occurred_at: datetime, sequence: int) -> tuple[str, str]:
    """Return canonical cursor sort values for one timeline event row."""
    return occurred_at.astimezone(UTC).isoformat(), str(sequence)


def parse_timeline_cursor(envelope: CursorEnvelope) -> tuple[datetime, int]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("timeline cursor requires occurred_at and sequence")
    occurred_at = datetime.fromisoformat(envelope.sort_values[0])
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("timeline cursor timestamp must be timezone-aware")
    sequence = int(envelope.sort_values[1])
    if sequence < 1:
        raise ValueError("timeline cursor sequence must be positive")
    return occurred_at.astimezone(UTC), sequence
