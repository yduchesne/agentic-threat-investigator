# SPDX-License-Identifier: AGPL-3.0-only
"""Investigation collection query contract and service boundary."""

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
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
)


class InvestigationListQuery(BaseModel):
    """Bounded investigation listing filters with canonical ordering.

    Canonical order is ``created_at DESC, id ASC``. ``created_from`` and
    ``created_to`` bound a half-open ``[from, to)`` UTC interval. Soft-deleted
    investigations are always hidden by normal listing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: InvestigationStatus | None = None
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
    def half_open(self) -> "InvestigationListQuery":
        """Require the created-at interval to be well ordered."""
        require_ordered_half_open(((self.created_from, self.created_to, "created_at"),))
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "status": self.status,
                "created_from": self.created_from,
                "created_to": self.created_to,
            }
        )


class InvestigationQueryService(ABC):
    """Analyst-facing Investigation read contract (PR 23A).

    Execution-oriented write repositories remain the authority for mutation;
    this service owns bounded filtering and keyset pagination only.
    """

    @abstractmethod
    async def list(
        self, query: InvestigationListQuery
    ) -> QueryPage[InvestigationState]:
        """Return one bounded page of visible investigations.

        Rows are ordered newest-first by creation time with a deterministic
        UUID tie-breaker; cursors are bound to the exact filter set.
        """

    @abstractmethod
    async def get(self, investigation_id: UUID) -> InvestigationState | None:
        """Return one visible Investigation by identity, if any.

        Soft-deleted Investigations are hidden; the returned state carries
        the authoritative database-owned version and timestamps.
        """


def investigation_sort_values(
    created_at: datetime, investigation_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one investigation row.

    The timestamp is normalized to UTC ISO-8601; the UUID uses its canonical
    string representation.
    """
    return created_at.astimezone(UTC).isoformat(), str(investigation_id)


def parse_investigation_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope.

    The envelope's ``query_kind`` and filter fingerprint are validated by the
    caller before this parse; here only the canonical sort-value strings are
    decoded into the ordering identity.
    """
    if len(envelope.sort_values) != 2:
        raise ValueError("investigation cursor requires created_at and id")
    created_at = datetime.fromisoformat(envelope.sort_values[0])
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("investigation cursor timestamp must be timezone-aware")
    return created_at.astimezone(UTC), UUID(envelope.sort_values[1])
