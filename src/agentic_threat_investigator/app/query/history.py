# SPDX-License-Identifier: AGPL-3.0-only
"""Generic domain-object history query contracts.

Generic resource-state history lives in ``domain_object_history`` with stable
object identity ``object_type + object_id`` (the original domain object ID);
no ``natural_key`` column exists or is introduced. RelationshipObservation is
deliberately excluded from this table: observation rows are themselves the
historical record and are queried through their own contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any
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
from agentic_threat_investigator.domain.immutable_json import FrozenDict, freeze_mapping


class HistoryOperation(str, Enum):
    """Immutable history operations recorded in ``domain_object_history``."""

    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class DomainObjectHistoryRecord(BaseModel):
    """One immutable generic history row (read model).

    ``state`` and ``diff`` are deeply frozen JSONB snapshots. ``object_id``
    is the original domain object identity; ``version`` is the resource's
    database-allocated revision at that operation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    object_type: str
    object_id: UUID
    version: int
    operation: HistoryOperation
    state: dict[str, Any]
    diff: dict[str, Any]
    actor_id: UUID | None = None
    request_id: UUID | None = None
    investigation_id: UUID | None = None
    occurred_at: datetime

    @field_validator("state", "diff", mode="after")
    @classmethod
    def freeze_state(cls, value: dict[str, Any]) -> FrozenDict:
        """Store JSONB snapshots as deeply immutable objects."""
        return freeze_mapping(value)

    @field_validator("occurred_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        """Require timezone-aware UTC-normalized timestamps."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("history timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("version")
    @classmethod
    def positive_version(cls, value: int) -> int:
        """Require positive resource versions."""
        if value < 1:
            raise ValueError("history version must be positive")
        return value


class DomainHistoryListQuery(BaseModel):
    """Bounded generic history browsing filters.

    Canonical order is ``occurred_at DESC, id ASC`` using the history row's
    own primary key as the stable tie-breaker (the column already exists;
    nothing is invented for pagination). ``object_id`` requires
    ``object_type`` because object IDs are not globally type-unique as a
    domain contract. ``occurred_from``/``occurred_to`` bound a half-open
    ``[from, to)`` UTC interval.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    object_type: str | None = None
    object_id: UUID | None = None
    investigation_id: UUID | None = None
    operation: HistoryOperation | None = None
    occurred_from: datetime | None = None
    occurred_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator("object_type")
    @classmethod
    def object_type_not_blank(cls, value: str | None) -> str | None:
        """Reject blank object-type filters."""
        if value is not None and not value.strip():
            raise ValueError("object_type filter must not be blank")
        return value

    @field_validator("occurred_from", "occurred_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized timestamps."""
        return normalize_utc(value)

    @model_validator(mode="after")
    def object_id_requires_type(self) -> "DomainHistoryListQuery":
        """Require ``object_type`` whenever ``object_id`` is filtered."""
        if self.object_id is not None and self.object_type is None:
            raise ValueError("object_id history filtering requires object_type")
        return self

    @model_validator(mode="after")
    def half_open(self) -> "DomainHistoryListQuery":
        """Require the occurred-at interval to be well ordered."""
        require_ordered_half_open(
            ((self.occurred_from, self.occurred_to, "occurred_at"),)
        )
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "object_type": self.object_type,
                "object_id": self.object_id,
                "investigation_id": self.investigation_id,
                "operation": self.operation,
                "occurred_from": self.occurred_from,
                "occurred_to": self.occurred_to,
            }
        )


class DomainHistoryQueryService(ABC):
    """Analyst-facing generic resource-history read contract (PR 23A)."""

    @abstractmethod
    async def list(
        self, query: DomainHistoryListQuery
    ) -> QueryPage[DomainObjectHistoryRecord]:
        """Return one bounded page of immutable history rows, newest first.

        Ordering is ``occurred_at DESC, id ASC``; cursors are bound to the
        exact filter set.
        """

    @abstractmethod
    async def get_object_version(
        self,
        *,
        object_type: str,
        object_id: UUID,
        version: int,
    ) -> DomainObjectHistoryRecord | None:
        """Return the exact history row for one object version, if any.

        The stable identity is ``object_type + object_id + version``.
        """


def domain_history_sort_values(
    occurred_at: datetime, history_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one history row."""
    return occurred_at.astimezone(UTC).isoformat(), str(history_id)


def parse_domain_history_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("domain history cursor requires occurred_at and id")
    occurred_at = datetime.fromisoformat(envelope.sort_values[0])
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("domain history cursor timestamp must be timezone-aware")
    return occurred_at.astimezone(UTC), UUID(envelope.sort_values[1])


def validate_object_version(object_type: str, version: int) -> None:
    """Reject blank object types and non-positive exact versions.

    Shared by the service boundary and unit tests; exact-version lookups fail
    closed rather than silently scanning.
    """
    if not object_type.strip():
        raise ValueError("object_type must not be blank")
    if version < 1:
        raise ValueError("history version must be positive")


def history_record_from_row(
    row_id: UUID,
    object_type: str,
    object_id: UUID,
    version: int,
    operation: str,
    state: Mapping[str, Any],
    diff: Mapping[str, Any],
    actor_id: UUID | None,
    request_id: UUID | None,
    investigation_id: UUID | None,
    occurred_at: datetime,
) -> DomainObjectHistoryRecord:
    """Build the immutable read model from canonical history row values."""
    return DomainObjectHistoryRecord(
        id=row_id,
        object_type=object_type,
        object_id=object_id,
        version=version,
        operation=HistoryOperation(operation),
        state=freeze_mapping(state),
        diff=freeze_mapping(diff),
        actor_id=actor_id,
        request_id=request_id,
        investigation_id=investigation_id,
        occurred_at=occurred_at,
    )
