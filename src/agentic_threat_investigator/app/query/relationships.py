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
    RelationshipDirection,
    RelationshipObservation,
    RelationshipType,
)


class RelationshipListQuery(BaseModel):
    """Bounded listing of distinct Relationships visible to one Investigation.

    Visibility derives from RelationshipObservation rows correlated with the
    Investigation; no ``investigation_id`` column is added to the stable
    Relationship resource for API convenience. Canonical order is
    ``relationship.id ASC`` — a stable deterministic identity order for v0.1.

    ``entity_id`` selects the one-hop neighborhood of one focal entity: it
    intersects normally with ``source_entity_id``, ``target_entity_id`` and
    ``relationship_type`` (source-or-target OR semantics, never a
    client-side merge across two bounded queries).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    source_entity_id: UUID | None = None
    target_entity_id: UUID | None = None
    entity_id: UUID | None = None
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
                "entity_id": self.entity_id,
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

    Entity-centric filtering (PR 24E) joins the stable Relationship and is
    Investigation-scoped by ``investigation_id``: ``entity_id`` filters by
    the joined edge endpoints, ``direction`` selects the focal side
    (``source``/``target``/``either``), ``counterparty_entity_id`` pins the
    other endpoint, and ``relationship_type`` filters the joined edge's
    type URN. ``direction`` and ``counterparty_entity_id`` require
    ``entity_id``; an entity without an explicit direction behaves as
    ``either``. Relationship type is never copied into observation
    persistence to support the query.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID | None = None
    relationship_id: UUID | None = None
    source: str | None = None
    retrieved_from: datetime | None = None
    retrieved_to: datetime | None = None
    observed_from: datetime | None = None
    observed_to: datetime | None = None
    entity_id: UUID | None = None
    direction: RelationshipDirection | None = None
    relationship_type: RelationshipType | None = None
    counterparty_entity_id: UUID | None = None
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
    def entity_filters_require_entity(self) -> "RelationshipObservationListQuery":
        """Require ``entity_id`` whenever direction/counterparty is used.

        ``direction`` names which side of a focal entity's edges to select;
        ``counterparty_entity_id`` pins the other endpoint. Both are
        meaningless without the focal entity, so they fail closed instead of
        being silently reinterpreted. An entity without a direction is a
        legal query and behaves as ``either`` (documented in
        :meth:`effective_direction`).
        """
        if self.direction is not None and self.entity_id is None:
            raise ValueError("direction filtering requires entity_id")
        if self.counterparty_entity_id is not None and self.entity_id is None:
            raise ValueError("counterparty_entity_id filtering requires entity_id")
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

    def effective_direction(self) -> RelationshipDirection | None:
        """Return the canonical direction applied by the query implementation.

        A focal entity without an explicit direction is the documented
        ``either`` behavior; without an entity no direction applies.
        """
        if self.direction is not None:
            return self.direction
        if self.entity_id is not None:
            return RelationshipDirection.EITHER
        return None

    def fingerprint(self) -> str:
        """Return the canonical SHA-256 of the filter set for cursor binding.

        The effective direction (documented ``either`` fallback) participates
        in the fingerprint so an entity-only query and the equivalent
        explicit-``either`` query share one bounded cursor context, while
        different entities/directions never share one.
        """
        return filter_fingerprint(
            {
                "investigation_id": self.investigation_id,
                "relationship_id": self.relationship_id,
                "source": self.source,
                "retrieved_from": self.retrieved_from,
                "retrieved_to": self.retrieved_to,
                "observed_from": self.observed_from,
                "observed_to": self.observed_to,
                "entity_id": self.entity_id,
                "direction": self.effective_direction(),
                "relationship_type": self.relationship_type,
                "counterparty_entity_id": self.counterparty_entity_id,
            }
        )


class RelationshipObservationItem(BaseModel):
    """One immutable observation with its joined stable Relationship semantics.

    PR 24E read projection (never persisted and never a domain model): the
    immutable ``RelationshipObservation`` fields stay authoritative while
    ``relationship_source_entity_id``, ``relationship_target_entity_id`` and
    ``relationship_type`` are denormalized response fields sourced from the
    joined stable ``Relationship`` row. They are ``None`` only when the join
    could not resolve the edge, which cannot happen through the FK for
    normally written data.
    """

    model_config = ConfigDict(frozen=True)

    id: UUID
    relationship_id: UUID
    evidence_id: UUID
    investigation_id: UUID | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    source: str
    confidence: float | None = None
    relationship_source_entity_id: UUID | None = None
    relationship_target_entity_id: UUID | None = None
    relationship_type: RelationshipType | None = None

    @classmethod
    def from_observation(
        cls,
        observation: RelationshipObservation,
        *,
        relationship_source_entity_id: UUID | None,
        relationship_target_entity_id: UUID | None,
        relationship_type: RelationshipType | None,
    ) -> "RelationshipObservationItem":
        """Build the joined read item from one observation and its edge."""
        return cls(
            id=observation.id,
            relationship_id=observation.relationship_id,
            evidence_id=observation.evidence_id,
            investigation_id=observation.investigation_id,
            observed_at=observation.observed_at,
            retrieved_at=observation.retrieved_at,
            source=observation.source,
            confidence=observation.confidence,
            relationship_source_entity_id=relationship_source_entity_id,
            relationship_target_entity_id=relationship_target_entity_id,
            relationship_type=relationship_type,
        )


class RelationshipQueryService(ABC):
    """Analyst-facing Relationship read contract (PR 23A)."""

    @abstractmethod
    async def list(self, query: RelationshipListQuery) -> QueryPage[Relationship]:
        """Return distinct stable Relationships visible to the Investigation.

        Repeated observations never duplicate an edge; ordering is stable
        ``relationship.id ASC`` with bound cursors.
        """

    @abstractmethod
    async def get(
        self, investigation_id: UUID, relationship_id: UUID
    ) -> Relationship | None:
        """Return one Relationship visible to the Investigation, if any.

        Visibility derives from RelationshipObservation correlation; a
        cross-Investigation lookup returns ``None`` so the HTTP layer maps it
        to a 404 without enumerating resources.
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
    ) -> QueryPage[RelationshipObservationItem]:
        """Return one bounded page of immutable observations.

        Ordering is ``retrieved_at DESC, id ASC``; ``observed_at`` ranges
        filter independently and are never cursor keys. Each item carries
        the joined stable Relationship semantics source entity, target
        entity and relationship type — delivered with the page, never via
        one Relationship GET per observation.
        """

    @abstractmethod
    async def get(
        self,
        investigation_id: UUID,
        observation_id: UUID,
    ) -> RelationshipObservationItem | None:
        """Return one Investigation-scoped immutable observation, if any.

        Exact identity + Investigation scope only: the observation must
        exist and belong to the path Investigation, otherwise ``None``
        (missing and cross-Investigation lookups are indistinguishable
        so the HTTP layer can map both to one scoped 404 without
        enumerating cross-Investigation existence). The item carries the
        same joined stable Relationship semantics as :meth:`list`; it is
        never queried through ``domain_object_history`` and no list scan
        or relationship inference is involved.
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
