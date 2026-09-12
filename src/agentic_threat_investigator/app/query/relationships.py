# SPDX-License-Identifier: AGPL-3.0-only
"""Relationship and RelationshipObservation query contracts.

A Relationship is a stable semantic edge and does not inherently belong to
one Investigation; an Investigation sees Relationships through its
RelationshipObservations. RelationshipObservation is independently queryable
as the immutable historical record and is deliberately never routed through
``domain_object_history``.
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
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipObservation,
    RelationshipType,
)


class RelationshipListQuery(BaseModel):
    """Bounded listing of distinct Relationships visible to one Investigation.

    Visibility derives from RelationshipObservation rows correlated with the
    Investigation; no ``investigation_id`` column is added to the stable
    Relationship resource for API convenience. Canonical order is
    ``relationship.id ASC`` — a stable deterministic identity order for v0.1.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    source_entity_id: UUID | None = None
    target_entity_id: UUID | None = None
    relationship_type: RelationshipType | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "source_entity_id": self.source_entity_id,
                "target_entity_id": self.target_entity_id,
                "relationship_type": self.relationship_type,
            }
        )


class RelationshipObservationListQuery(BaseModel):
    """Historical RelationshipObservation browsing contract.

    At least one of ``investigation_id`` / ``relationship_id`` is required:
    there is no global unscoped observation scan in v0.1. Canonical order is
    ``retrieved_at DESC, id ASC`` because ``retrieved_at`` is mandatory and
    cursor semantics never depend on the nullable ``observed_at`` ordering.
    ``observed_at`` remains an independent half-open date filter.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID | None = None
    relationship_id: UUID | None = None
    source: str | None = None
    retrieved_from: datetime | None = None
    retrieved_to: datetime | None = None
    observed_from: datetime | None = None
    observed_to: datetime | None = None
    limit: int = Field(ge=1)
    cursor: str | None = None

    @field_validator(
        "retrieved_from",
        "retrieved_to",
        "observed_from",
        "observed_to",
    )
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
    def requires_scope(self) -> "RelationshipObservationListQuery":
        """Require an investigation or relationship scope."""
        if self.investigation_id is None and self.relationship_id is None:
            raise ValueError(
                "relationship observation queries require an investigation "
                "or relationship scope"
            )
        return self

    @model_validator(mode="after")
    def half_open(self) -> "RelationshipObservationListQuery":
        """Require both date intervals to be well ordered."""
        require_ordered_half_open(
            (
                (self.retrieved_from, self.retrieved_to, "retrieved_at"),
                (self.observed_from, self.observed_to, "observed_at"),
            )
        )
        return self

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding."""
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "relationship_id": self.relationship_id,
                "source": self.source,
                "retrieved_from": self.retrieved_from,
                "retrieved_to": self.retrieved_to,
                "observed_from": self.observed_from,
                "observed_to": self.observed_to,
            }
        )


class RelationshipQueryService(ABC):
    """Analyst-facing Relationship read contract (PR 23A)."""

    @abstractmethod
    async def list(self, query: RelationshipListQuery) -> QueryPage[Relationship]:
        """Return distinct stable Relationships visible to the Investigation.

        Repeated observations never duplicate an edge; ordering is stable
        ``relationship.id ASC`` with bound cursors.
        """


class RelationshipObservationQueryService(ABC):
    """Analyst-facing RelationshipObservation read contract (PR 23A).

    Observations are the immutable historical record themselves; this service
    queries ``relationship_observation`` directly and never uses
    ``domain_object_history``.
    """

    @abstractmethod
    async def list(
        self, query: RelationshipObservationListQuery
    ) -> QueryPage[RelationshipObservation]:
        """Return one bounded page of immutable observations.

        Ordering is ``retrieved_at DESC, id ASC``; ``observed_at`` ranges
        filter independently and are never cursor keys.
        """


def relationship_observation_sort_values(
    retrieved_at: datetime, observation_id: UUID
) -> tuple[str, str]:
    """Return canonical cursor sort values for one observation row."""
    return retrieved_at.astimezone(UTC).isoformat(), str(observation_id)


def parse_relationship_observation_cursor(
    envelope: CursorEnvelope,
) -> tuple[datetime, UUID]:
    """Parse the typed continuation values from a validated cursor envelope."""
    if len(envelope.sort_values) != 2:
        raise ValueError("relationship observation cursor requires retrieved_at and id")
    retrieved_at = datetime.fromisoformat(envelope.sort_values[0])
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ValueError(
            "relationship observation cursor timestamp must be timezone-aware"
        )
    return retrieved_at.astimezone(UTC), UUID(envelope.sort_values[1])


def relationship_sort_values(relationship_id: UUID) -> tuple[str]:
    """Return the canonical cursor sort value for one relationship row."""
    return (str(relationship_id),)


def parse_relationship_cursor(envelope: CursorEnvelope) -> UUID:
    """Parse the typed continuation identity from a validated cursor envelope."""
    if len(envelope.sort_values) != 1:
        raise ValueError("relationship cursor requires an id")
    return UUID(envelope.sort_values[0])
