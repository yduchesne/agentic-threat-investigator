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

The one-hop :class:`GraphNeighborhoodQuery` is Investigation-scoped, reuses
``RelationshipDirection`` and ``RelationshipType``, and carries an explicit
result bound. PostgreSQL retrieval is PR 31B work; this module owns the
application contract only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentic_threat_investigator.app.query.models import normalize_utc
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)


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
    query's Investigation visibility scope and is always at least 1.
    ``first_observed_at`` / ``last_observed_at`` summarize only non-null
    ``RelationshipObservation.observed_at`` values in the query scope; they
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
    """One Investigation-scoped, bounded one-hop neighborhood request.

    The query is always scoped to one Investigation and one focal Entity.
    ``direction`` is relative to the focal Entity and defaults to ``EITHER``
    (reusing ``RelationshipDirection``); ``relationship_type`` is an optional
    filter over the canonical Relationship type. ``limit`` bounds the number
    of returned Relationships and is mandatory at the contract level;
    callers/composition layers may later apply configured defaults on top of
    it. PR 31A adds no cursor, depth, temporal, datasource, counterparty, or
    global-scope semantics.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    entity_id: UUID
    direction: RelationshipDirection = RelationshipDirection.EITHER
    relationship_type: RelationshipType | None = None
    limit: int = Field(ge=1)


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
        the Investigation-scoped query, even when no matching Relationships
        exist (a ``GraphResult`` with zero edges). Returns ``None`` when the
        focal Entity is missing or not visible in the Investigation scope,
        which is deliberately distinct from an isolated valid focal node.

        Returned edges are distinct canonical Relationships and nodes are
        distinct canonical Entities; every edge endpoint is present in the
        result nodes; direction is relative to the focal Entity; the result
        is bounded by ``query.limit`` Relationships; and ``truncated``
        truthfully reports whether additional matching Relationships existed.
        """
