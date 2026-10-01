# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Graph read projections and the one-hop neighborhood query contract (PR 31A).

The v0.5 graph-exploration surface is a read projection over ATI's
authoritative relational domain: ``Entity`` is the canonical graph node
identity, ``Relationship`` is the canonical graph edge identity, and
``RelationshipObservation`` is the immutable temporal/evidentiary support
for a Relationship. :class:`GraphNode`, :class:`GraphEdge` and
:class:`GraphResult` are immutable application read models only: they are
never persisted, never introduce graph-local identities, never leak
frontend-library concepts, and never add a graph database.

The one-hop :class:`GraphNeighborhoodQuery` carries an explicit
:class:`GraphScope` (``investigation`` by default vs ``known``), reuses
``RelationshipDirection`` and ``RelationshipType``, supports bounded
server-side filters (connected Entity type, Relationship type,
RelationshipObservation source, half-open ``observed_at`` interval), and
carries an explicit result bound. PostgreSQL retrieval is PR 31B work; this
module owns the application contract only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.app.query.models import normalize_utc
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)


class GraphScope(StrEnum):
    """Exactly two graph scopes: Investigation-supported or broader known.

    ``INVESTIGATION`` (the default) admits a Relationship as visible only
    when at least one supporting RelationshipObservation references an
    EvidenceObservation admitted to the requested Investigation; ``KNOWN``
    retains the Investigation-visible focal Entity but admits globally known
    live Relationships supported by global RelationshipObservations even
    when those observations were never admitted to this Investigation.
    """

    INVESTIGATION = "investigation"
    KNOWN = "known"


class GraphNode(BaseModel):
    """One immutable graph node projection of a canonical Entity.

    ``entity_id`` is the authoritative ``Entity.id`` of a persisted Entity
    (never a graph-local identity) and is therefore mandatory and non-null.
    ``entity_type`` and ``value`` reuse the canonical Entity contract;
    ``display_name`` preserves the optional Entity display name. Persistence
    internals (``version``, ``deleted_at``, ``deleted_by_actor_id``,
    ``content_hash``) and arbitrary attribute blobs are never exposed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: UUID
    entity_type: EntityType
    value: str
    display_name: str | None = None


class GraphEdge(BaseModel):
    """One immutable graph edge projection of a canonical Relationship.

    ``relationship_id``, ``source_entity_id``, ``target_entity_id`` and
    ``relationship_type`` map directly to the authoritative Relationship, so
    repeated RelationshipObservation records never produce duplicate edges.
    ``observation_count`` is the descriptive support count within the
    active scope and surviving source/time filters and is always at least 1.
    ``investigation_observation_count`` counts the same matching observations
    whose exact EvidenceObservation is admitted to the current Investigation;
    it is backend truth and never inferred in the frontend. Invariants:
    ``0 <= investigation_observation_count <= observation_count`` and, in
    Investigation scope, the two counts are equal. ``first_observed_at`` /
    ``last_observed_at`` summarize only non-null
    ``RelationshipObservation.observed_at`` values in the active scope; they
    never mean relationship creation/end/lifetime and ``retrieved_at`` is
    never substituted for a missing ``observed_at``. No aggregate confidence
    or Evidence identity is exposed in PR 31A.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    relationship_id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: RelationshipType
    observation_count: int = Field(ge=1)
    investigation_observation_count: int = Field(ge=0)
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized observation summaries."""
        return normalize_utc(value)

    @model_validator(mode="after")
    def observed_order(self) -> "GraphEdge":
        """Require a well-ordered observed-time summary when both exist."""
        if (
            self.first_observed_at is not None
            and self.last_observed_at is not None
            and self.first_observed_at > self.last_observed_at
        ):
            raise ValueError(
                "graph edge first_observed_at must not be after last_observed_at"
            )
        return self

    @model_validator(mode="after")
    def support_within_total(self) -> "GraphEdge":
        """Require Investigation support never to exceed the filtered total."""
        if self.investigation_observation_count > self.observation_count:
            raise ValueError(
                "graph edge investigation_observation_count must not exceed "
                "observation_count"
            )
        return self


class GraphResult(BaseModel):
    """One atomic bounded topology projection of a one-hop neighborhood.

    ``nodes`` and ``edges`` are closed: every edge endpoint appears in
    ``nodes``, node Entity IDs and edge Relationship IDs are each unique, and
    a self-relationship requires only one node. An isolated focal Entity with
    zero visible edges is valid: not every node must participate in an edge.
    ``truncated`` truthfully reports whether more matching Relationships
    existed than the requested bound could carry; it is intentionally not a
    cursor and carries no layout/rendering state.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    truncated: bool

    @model_validator(mode="after")
    def closed_topology(self) -> "GraphResult":
        """Require identity uniqueness and edge endpoint closure."""
        node_ids: set[UUID] = {node.entity_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("graph node entity IDs must be unique")
        edge_ids: set[UUID] = {edge.relationship_id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("graph edge relationship IDs must be unique")
        for edge in self.edges:
            if edge.source_entity_id not in node_ids:
                raise ValueError("graph edge source entity must be present in nodes")
            if edge.target_entity_id not in node_ids:
                raise ValueError("graph edge target entity must be present in nodes")
        return self


class GraphNeighborhoodQuery(BaseModel):
    """One bounded one-hop neighborhood request with explicit graph context.

    The query is always scoped to one Investigation and one focal Entity.
    ``scope`` selects Investigation-supported topology (the default) or the
    broader Known graph around the Investigation-visible focal Entity;
    omitted scope always means ``INVESTIGATION``. ``direction`` is relative
    to the focal Entity and defaults to ``EITHER`` (reusing
    ``RelationshipDirection``). ``relationship_type`` filters the canonical
    Relationship type; ``entity_type`` filters the connected/counterparty
    Entity type relative to the focal Entity; ``source`` exact-matches
    ``RelationshipObservation.source`` (blank rejected); ``observed_from`` /
    ``observed_to`` bound ``observed_at`` with half-open ``[from, to)``
    semantics and a non-empty window when both are supplied (``retrieved_at``
    is never substituted). ``limit`` bounds the number of returned
    Relationships and is mandatory at the contract level; callers/composition
    layers may later apply configured defaults on top of it. PR 31A adds no
    cursor, depth, multi-hop, path, lifecycle, or datasource semantics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    entity_id: UUID
    scope: GraphScope = GraphScope.INVESTIGATION
    direction: RelationshipDirection = RelationshipDirection.EITHER
    relationship_type: RelationshipType | None = None
    entity_type: EntityType | None = None
    source: str | None = None
    observed_from: datetime | None = None
    observed_to: datetime | None = None
    limit: int = Field(ge=1)

    @field_validator("observed_from", "observed_to")
    @classmethod
    def utc(cls, value: datetime | None) -> datetime | None:
        """Require timezone-aware UTC-normalized observation bounds."""
        return normalize_utc(value)

    @field_validator("source")
    @classmethod
    def source_not_blank(cls, value: str | None) -> str | None:
        """Reject blank source filters."""
        if value is not None and not value.strip():
            raise ValueError("source filter must not be blank")
        return value

    @model_validator(mode="after")
    def interval_ordered(self) -> "GraphNeighborhoodQuery":
        """Require a strictly ordered half-open interval when both bounds exist.

        One-sided intervals are legal; a two-sided interval must form a
        non-empty ``[observed_from, observed_to)`` window, so equal or
        reversed bounds are rejected.
        """
        if (
            self.observed_from is not None
            and self.observed_to is not None
            and self.observed_from >= self.observed_to
        ):
            raise ValueError("graph observed_from must be earlier than observed_to")
        return self


class GraphQueryService(ABC):
    """Application-level one-hop graph read contract (PR 31A).

    Graph exploration belongs to the analyst read path
    (``app/query/*`` + ``infrastructure/persistence/query/*``), never to a
    mutation-style repository. Implementations perform one bounded read,
    materialize a :class:`GraphResult` and never mutate, perform provider
    I/O, or invoke an LLM.
    """

    @abstractmethod
    async def neighborhood(self, query: GraphNeighborhoodQuery) -> GraphResult | None:
        """Return the bounded one-hop neighborhood of the focal Entity.

        Returns the focal Entity as a node whenever it is valid/visible for
        the query (both scopes require the focal Entity to be admitted to the
        Investigation via an exact EvidenceObservation), even when no
        matching Relationships exist (a ``GraphResult`` with zero edges).
        Returns ``None`` when the focal Entity is missing or not visible,
        which is deliberately distinct from an isolated valid focal node.

        Returned edges are distinct canonical Relationships and nodes are
        distinct canonical Entities; every edge endpoint is present in the
        result nodes; direction is relative to the focal Entity; ``KNOWN``
        scope returns global support while ``INVESTIGATION`` scope requires
        Investigation admission; source/time predicates filter observations
        before grouping/bounding; edge Investigation support counts are
        backend truth; the result is bounded by ``query.limit`` Relationships;
        and ``truncated`` truthfully reports whether additional matching
        Relationships existed.
        """
