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

PR 31H adds :class:`GraphTraversalQuery`: the same scoped graph context plus
an explicit 1..3 hop depth. It is a bounded, cycle-safe, read-only
server-side walk over already-persisted canonical Relationship topology;
it never invokes providers, never mutates persistence, never invents path
finding (PR 31I) and never replaces one-hop interactive expansion.

PR 31I adds :class:`GraphPathQuery` / :class:`GraphPath` /
:class:`GraphPathResult` and :meth:`GraphQueryService.find_paths`: bounded,
deterministic, cycle-safe simple-path finding between two
Investigation-visible canonical Entities. Paths are read projections that
reuse the canonical :class:`GraphNode` / :class:`GraphEdge` vocabulary and
carry ordered canonical ID references only; no path record is ever
persisted and no second graph model is introduced.
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

GRAPH_TRAVERSAL_MAX_DEPTH = 3
"""Hard server-owned maximum traversal depth (PR 31H).

Depth is hop distance from the focal Entity: ``1`` means exactly the one-hop
neighborhood, ``3`` is the deepest supported walk. The bound is enforced by
the contract and defensively inside the PostgreSQL stored function.
"""

DEFAULT_TRAVERSAL_MAX_DEPTH = 2
"""API default traversal depth when a caller omits ``max_depth`` (PR 31H)."""

GRAPH_PATH_MAX_DEPTH = 6
"""Hard server-owned maximum path depth (PR 31I).

Depth is hop distance from the source Entity: ``1`` means exactly one
Relationship, ``6`` is the deepest supported bounded path. The bound is
enforced by the :class:`GraphPathQuery` contract and defensively inside the
``ati.find_graph_paths`` stored function. It is independent of the PR 31H
traversal depth (1..3): path finding between two explicit Entities is a
different, narrower analytical operation with its own ceilings.
"""

DEFAULT_GRAPH_PATH_MAX_DEPTH = 4
"""API default path depth when a caller omits ``max_depth`` (PR 31I)."""

GRAPH_PATH_MAX_RESULTS = 25
"""Hard server-owned maximum number of returned paths (PR 31I).

The bound limits returned distinct simple paths, never path row work inside
PostgreSQL; the stored function probes ``max_paths + 1`` qualifying paths to
report truthful ``truncated`` state. Like :data:`GRAPH_PATH_MAX_DEPTH`, it is
enforced by the application contract and defensively inside the stored
function; oversized caller values are rejected, never silently clamped.
"""

DEFAULT_GRAPH_PATH_MAX_RESULTS = 10
"""API default returned path count when a caller omits ``max_paths`` (PR 31I)."""


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


class _GraphContextBase(BaseModel):
    """Shared scoped graph-query semantic context (PR 31G filters).

    A narrow internal base shared by the one-hop neighborhood, the PR 31H
    traversal and the PR 31I path query so the Investigation/focal scoping,
    the two-value ``GraphScope``, direction, Relationship/Entity type
    filters, exact ``source`` and half-open ``observed_at`` interval
    validation can never drift between the operations. It deliberately
    carries no result bound: the neighborhood/traversal operations apply a
    Relationship ``limit`` through :class:`_BoundedGraphQueryBase` while the
    path operation applies its own ``max_paths`` ceiling, so no operation
    inherits a bound that is meaningless for it.
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
    def interval_ordered(self) -> "_GraphContextBase":
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


class _BoundedGraphQueryBase(_GraphContextBase):
    """A graph-query context carrying a canonical Relationship result bound.

    ``limit`` bounds distinct canonical Relationships (never raw observation
    rows) and is mandatory at the contract level; callers/composition layers
    apply configured defaults on top of it. Only operations whose result is
    a bounded edge set (neighborhood and traversal) use this base; the path
    operation carries no Relationship page limit.
    """

    limit: int = Field(ge=1)


class GraphNeighborhoodQuery(_BoundedGraphQueryBase):
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


class GraphTraversalQuery(_BoundedGraphQueryBase):
    """One bounded multi-hop traversal request over canonical topology.

    The query inherits the exact PR 31G graph context (Investigation,
    focal Entity, scope, direction, Relationship type, connected Entity
    type, exact observation source, half-open ``observed_at`` interval)
    and adds one explicit ``max_depth`` measured as hop distance from the
    focal Entity: ``1`` equals the one-hop neighborhood, ``2`` and ``3``
    walk deeper canonical Relationships. Depth is hard-bounded by
    :data:`GRAPH_TRAVERSAL_MAX_DEPTH`; the traversal is deterministic,
    cycle-safe (an Entity path can never revisit itself), read-only, and
    bounded by ``limit`` distinct canonical Relationships. Visibility and
    observation filters apply before any recursion, so a traversal can
    never cross a hidden edge.
    """

    max_depth: int

    @field_validator("max_depth")
    @classmethod
    def bounded_depth(cls, value: int) -> int:
        """Reject traversal depths outside the server-owned 1..3 window."""
        if value < 1 or value > GRAPH_TRAVERSAL_MAX_DEPTH:
            raise ValueError(
                f"graph max_depth must be between 1 and {GRAPH_TRAVERSAL_MAX_DEPTH}"
            )
        return value


class GraphPathQuery(_GraphContextBase):
    """One bounded deterministic path request between two Entities.

    The query reuses the exact PR 31G graph context (Investigation, source
    Entity as ``entity_id``, scope, direction, Relationship type, connected
    Entity type, exact observation source, half-open ``observed_at``
    interval) and adds an explicit ``target_entity_id`` endpoint plus two
    path-owned bounds: ``max_depth`` (hop distance from the source Entity,
    1..:data:`GRAPH_PATH_MAX_DEPTH`, default :data:`DEFAULT_GRAPH_PATH_MAX_DEPTH`)
    and ``max_paths`` (1..:data:`GRAPH_PATH_MAX_RESULTS`, default
    :data:`DEFAULT_GRAPH_PATH_MAX_RESULTS`), with oversized values rejected
    rather than clamped. Both endpoints must be valid/live and visible to
    the Investigation through ATI's exact EvidenceObservation admission rule
    in BOTH scopes: ``known`` may broaden eligible intermediate/support
    topology but never permits arbitrary global source/target lookup. The
    query deliberately carries no Relationship ``limit``: the path result is
    bounded by ``max_paths`` simple paths, not by an edge page size.
    """

    target_entity_id: UUID
    max_depth: int
    max_paths: int

    @field_validator("max_depth")
    @classmethod
    def bounded_depth(cls, value: int) -> int:
        """Reject path depths outside the server-owned 1..6 window."""
        if value < 1 or value > GRAPH_PATH_MAX_DEPTH:
            raise ValueError(
                f"graph path max_depth must be between 1 and {GRAPH_PATH_MAX_DEPTH}"
            )
        return value

    @field_validator("max_paths")
    @classmethod
    def bounded_paths(cls, value: int) -> int:
        """Reject path counts outside the server-owned 1..25 window."""
        if value < 1 or value > GRAPH_PATH_MAX_RESULTS:
            raise ValueError(
                f"graph path max_paths must be between 1 and {GRAPH_PATH_MAX_RESULTS}"
            )
        return value


class GraphPath(BaseModel):
    """One ordered, cycle-safe simple path of canonical references.

    The path carries canonical IDs only: ordered Entity IDs connected by the
    ordered Relationship IDs, satisfying ``len(entity_ids) ==
    len(relationship_ids) + 1`` with no repeated Entity and no repeated
    Relationship inside one simple path. The zero-hop source==target path is
    legal (``entity_ids`` of length 1, empty ``relationship_ids``). Paths are
    read projections over already-persisted canonical topology; they are
    never persisted and never create graph-local identities.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_ids: tuple[UUID, ...]
    relationship_ids: tuple[UUID, ...]

    @model_validator(mode="after")
    def valid_simple_path(self) -> "GraphPath":
        """Require a well-formed simple path of canonical references."""
        if not self.entity_ids:
            raise ValueError("graph path must contain at least one entity")
        if len(self.relationship_ids) != len(self.entity_ids) - 1:
            raise ValueError(
                "graph path relationship count must be entity count minus one"
            )
        if len(set(self.entity_ids)) != len(self.entity_ids):
            raise ValueError("graph path entity IDs must be unique")
        if len(set(self.relationship_ids)) != len(self.relationship_ids):
            raise ValueError("graph path relationship IDs must be unique")
        return self


class GraphPathResult(BaseModel):
    """One bounded path-finding projection over canonical graph vocabulary.

    ``nodes`` and ``edges`` reuse the canonical :class:`GraphNode` /
    :class:`GraphEdge` models: each returned canonical Entity/Relationship
    appears exactly once regardless of how many selected paths use it, and
    every edge endpoint exists in ``nodes``. ``paths`` are ordered
    (shortest first, deterministic canonical tie-break) and only reference
    canonical IDs already present in ``nodes``/``edges`` with each
    Relationship connecting its adjacent path Entities. ``truncated`` is
    true exactly when at least one additional qualifying simple path existed
    within ``max_depth`` and the active graph context beyond ``max_paths``;
    it never means a deeper path might exist or that an individual path was
    cut. A no-path outcome yields the two visible endpoint nodes, empty
    edges/paths and ``truncated=false``; endpoint-visibility failure is
    represented by the service returning ``None`` instead of a result.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    paths: tuple[GraphPath, ...]
    truncated: bool

    @model_validator(mode="after")
    def closed_path_topology(self) -> "GraphPathResult":
        """Require identity uniqueness, endpoint closure and valid references."""
        node_ids: set[UUID] = {node.entity_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("graph path result node entity IDs must be unique")
        edge_ids: set[UUID] = {edge.relationship_id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("graph path result edge relationship IDs must be unique")
        for edge in self.edges:
            if edge.source_entity_id not in node_ids:
                raise ValueError(
                    "graph path result edge source entity must be present in nodes"
                )
            if edge.target_entity_id not in node_ids:
                raise ValueError(
                    "graph path result edge target entity must be present in nodes"
                )
        edges_by_id = {edge.relationship_id: edge for edge in self.edges}
        for path in self.paths:
            for entity_id in path.entity_ids:
                if entity_id not in node_ids:
                    raise ValueError(
                        "graph path result path references an entity absent from nodes"
                    )
            for relationship_id in path.relationship_ids:
                if relationship_id not in edge_ids:
                    raise ValueError(
                        "graph path result path references a relationship absent from "
                        "edges"
                    )
            for index, relationship_id in enumerate(path.relationship_ids):
                edge = edges_by_id[relationship_id]
                source = path.entity_ids[index]
                target = path.entity_ids[index + 1]
                if not (
                    (
                        edge.source_entity_id == source
                        and edge.target_entity_id == target
                    )
                    or (
                        edge.source_entity_id == target
                        and edge.target_entity_id == source
                    )
                ):
                    raise ValueError(
                        "graph path relationship does not connect adjacent path "
                        "entities"
                    )
        return self


class GraphQueryService(ABC):
    """Application-level one-hop graph read contract (PR 31A; PR 31H).

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

    @abstractmethod
    async def traverse(self, query: GraphTraversalQuery) -> GraphResult | None:
        """Return the bounded multi-hop traversal of the focal Entity.

        ``None``, an isolated focal node, edge summaries, scope/filter and
        bounces/truncation semantics are exactly those of
        :meth:`neighborhood` for the same graph context. Depth is hop
        distance from the focal Entity and ``1`` is semantically equivalent
        to the one-hop neighborhood for the same context and non-truncating
        limit. Traversal is deterministic, cycle-safe (an Entity path never
        revisits a branch Entity; a self-loop is topology but never
        recurses), bounded by ``query.max_depth`` (1..
        :data:`GRAPH_TRAVERSAL_MAX_DEPTH`) and by ``query.limit`` distinct
        canonical Relationships, and read-only: no provider, LLM,
        Coordinator, persistence or acquisition work occurs. Direction and
        connected Entity type apply at every frontier and PR 31G
        scope/source/time/type filters apply to every traversed Relationship
        before recursion, so traversal can never cross a hidden edge.
        """

    @abstractmethod
    async def find_paths(self, query: GraphPathQuery) -> GraphPathResult | None:
        """Return bounded deterministic simple paths between two Entities.

        Both endpoints must be valid/live Entities visible to the requested
        Investigation through the exact EvidenceObservation admission rule in
        both scopes; ``known`` may broaden eligible intermediate/support
        topology but never permits arbitrary global endpoint lookup.
        ``None`` means either endpoint is missing, soft-deleted, or not
        Investigation-visible (a scoped not-found outcome, never confused
        with a no-path result); ``GraphPathResult(paths=())`` means both
        endpoints are visible but no eligible simple connection exists within
        ``max_depth`` (the result still projects the two visible endpoints);
        ``source == target`` returns exactly one zero-hop path. Path search
        is bounded by ``query.max_depth`` and ``query.max_paths``, order is
        deterministic (ascending hop count, then canonical path signature),
        paths are simple/cycle-safe, ``truncated`` truthfully reports whether
        additional qualifying simple paths existed beyond ``max_paths``, edge
        summaries use PR 31G/31H observation semantics (never path
        multiplicity), and the operation is read-only: no provider, LLM,
        Coordinator, persistence or acquisition work occurs.
        """
