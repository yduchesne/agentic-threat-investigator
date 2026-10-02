# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL graph read adapters via stored functions (PR 31B; PR 31G; PR 31H; PR 31I).

The concrete :class:`PostgresGraphQueryService` implements the PR 31A / PR 31H
/ PR 31I graph read contracts on top of ATI's authoritative relational model.
It never persists graph projections and never introduces a graph database:
canonical ``Entity`` rows project to ``GraphNode`` items, canonical
``Relationship`` rows project to ``GraphEdge`` items (one edge per
Relationship, aggregated inside PostgreSQL before materialization).

PR 31I consolidates the graph read boundary: after PR 31H the multi-hop
traversal already lived exclusively inside the versioned ``ati.traverse_graph``
stored function while the one-hop ``neighborhood`` still constructed direct
SQLAlchemy SELECT/JOIN/EXISTS/GROUP BY SQL. This module now routes every
graph read through versioned stored functions:

    neighborhood() -> ati.traverse_graph(... , max_depth = 1)
    traverse()     -> ati.traverse_graph(... , max_depth = 1..3)
    find_paths()   -> ati.find_graph_paths(...)

The adapter contains no production graph SELECT / join / CTE / filter /
aggregation / endpoint-lookup SQL: ``text(...)`` appears only to invoke the
stored functions, and the shared ``_map_graph_result_rows`` /
``_map_path_result_rows`` helpers map returned rows to canonical application
models. Every filter/scope/visibility/cycle/aggregation/bounding decision is
stored-function-owned; binding parameters and mapping rows is all the Python
does.

One-hop semantics are unchanged by the migration: for the same graph context
and a non-truncating bound, ``neighborhood(query)`` is exactly the depth-1
``traverse`` call, with the same focal visibility rule (both scopes require
the focal Entity to be admitted via an exact EvidenceObservation), the same
edge summaries and the same truncation behavior. ``None`` means the stored
function returned no rows (missing/soft-deleted/not-visible focal Entity); a
visible isolated focal Entity is a one-node ``GraphResult``.

Path finding (PR 31I) is bounded, deterministic and cycle-safe. Both
endpoints must be valid/live and Investigation-visible through the exact
admission rule in both scopes (Known scope may broaden intermediate/support
topology only). A single ``ati.find_graph_paths`` invocation returns an
explicit metadata row (``endpoints_visible``, ``truncated``) plus canonical
node/edge/path rows, so "endpoint invalid" (maps to ``None``) is
distinguishable from "both endpoints visible but no eligible path" (an empty
``GraphPathResult.paths``) without a second SQL query.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Row, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.query.graph import (
    GraphEdge,
    GraphNeighborhoodQuery,
    GraphNode,
    GraphPath,
    GraphPathQuery,
    GraphPathResult,
    GraphQueryService,
    GraphResult,
    GraphScope,
    GraphTraversalQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)


class PostgresGraphQueryService(GraphQueryService):
    """Stored-function-invocation/mapping boundary for every graph read.

    ``neighborhood`` and ``traverse`` share one ``ati.traverse_graph``
    invocation (depth 1 vs the requested depth) and one canonical row mapper;
    ``find_paths`` invokes ``ati.find_graph_paths`` exactly once and maps its
    metadata + canonical node/edge/path rows. No graph SELECT, JOIN, CTE,
    filter, aggregation, endpoint lookup or recursion exists in Python.
    """

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the short-lived read session and the configured limits."""
        self._session = session
        self._limits = limits

    async def neighborhood(self, query: GraphNeighborhoodQuery) -> GraphResult | None:
        """Return the bounded one-hop neighborhood via the stored function.

        The read is exactly the PR 31H depth-1 traversal: the same validated
        context is bound to ``ati.traverse_graph`` with ``max_depth = 1`` and
        the returned canonical node/edge rows are mapped by the shared
        mapper. ``None`` means the focal Entity is missing, soft-deleted, or
        not visible to the Investigation (in both scopes); a visible isolated
        focal Entity yields a one-node result even when every filter removes
        all edges. This is a behavior-preserving persistence-boundary
        migration of the legacy direct-SQL one-hop read: same focal rule,
        same scope/source/time/type filtering, same edge summaries, same
        deterministic ordering and same limit + 1 truncation probe.
        """
        limit = self._limits.validate_limit(query.limit)
        rows = await self._invoke_traverse_graph(
            investigation_id=query.investigation_id,
            entity_id=query.entity_id,
            max_depth=1,
            scope=query.scope,
            direction=query.direction,
            relationship_type=query.relationship_type,
            entity_type=query.entity_type,
            source=query.source,
            observed_from=query.observed_from,
            observed_to=query.observed_to,
            limit=limit,
        )
        return self._map_graph_result_rows(rows)

    async def traverse(self, query: GraphTraversalQuery) -> GraphResult | None:
        """Return the bounded multi-hop traversal via the stored function.

        This adapter is a thin persistence boundary: it validates the bound
        through :class:`QueryLimits`, invokes the PR 31H stored function
        ``ati.traverse_graph`` with the exact validated parameters and maps
        its canonical node/edge rows into one :class:`GraphResult`. It
        contains no traversal SELECT, recursive CTE, join, filter,
        aggregation, endpoint lookup, or other graph SQL; every PR 31H SQL
        query lives inside the stored function. ``None`` means the stored
        function returned no rows because the focal Entity is missing,
        soft-deleted, or not visible to the Investigation (both scopes).
        """
        limit = self._limits.validate_limit(query.limit)
        rows = await self._invoke_traverse_graph(
            investigation_id=query.investigation_id,
            entity_id=query.entity_id,
            max_depth=query.max_depth,
            scope=query.scope,
            direction=query.direction,
            relationship_type=query.relationship_type,
            entity_type=query.entity_type,
            source=query.source,
            observed_from=query.observed_from,
            observed_to=query.observed_to,
            limit=limit,
        )
        return self._map_graph_result_rows(rows)

    async def find_paths(self, query: GraphPathQuery) -> GraphPathResult | None:
        """Return bounded deterministic simple paths via the stored function.

        Binds the validated PR 31I parameters and invokes
        ``ati.find_graph_paths`` exactly once; there is no second SQL query
        for endpoint lookup, edge summaries, or path reconstruction. The
        stored function's explicit metadata row distinguishes the two empty
        outcomes: ``endpoints_visible = false`` maps to ``None`` (either
        endpoint is missing, soft-deleted, or not Investigation-visible), and
        ``endpoints_visible = true`` with no path rows maps to an empty
        successful :class:`GraphPathResult` whose nodes still project the two
        visible endpoints. Every returned path is validated to start at the
        source Entity and end at the target Entity (stored-function contract);
        a violation is an internal invariant failure and fails closed.
        """
        rows = (
            await self._session.execute(
                text(
                    "SELECT * FROM ati.find_graph_paths("
                    ":investigation_id, :source_entity_id, :target_entity_id, "
                    ":max_depth, :max_paths, :scope, :direction, "
                    ":relationship_type, :entity_type, :source, :observed_from, "
                    ":observed_to)"
                ),
                {
                    "investigation_id": query.investigation_id,
                    "source_entity_id": query.entity_id,
                    "target_entity_id": query.target_entity_id,
                    "max_depth": query.max_depth,
                    "max_paths": query.max_paths,
                    "scope": query.scope.value,
                    "direction": query.direction.value,
                    "relationship_type": (
                        query.relationship_type.value
                        if query.relationship_type is not None
                        else None
                    ),
                    "entity_type": (
                        query.entity_type.value
                        if query.entity_type is not None
                        else None
                    ),
                    "source": query.source,
                    "observed_from": query.observed_from,
                    "observed_to": query.observed_to,
                },
            )
        ).all()
        if not rows:
            return None
        return self._map_path_result_rows(query, rows)

    async def _invoke_traverse_graph(
        self,
        *,
        investigation_id: UUID,
        entity_id: UUID,
        max_depth: int,
        scope: GraphScope,
        direction: RelationshipDirection,
        relationship_type: RelationshipType | None,
        entity_type: EntityType | None,
        source: str | None,
        observed_from: datetime | None,
        observed_to: datetime | None,
        limit: int,
    ) -> Sequence[Row[Any]]:
        """Invoke the traversal stored function and return its raw rows."""
        return (
            await self._session.execute(
                text(
                    "SELECT * FROM ati.traverse_graph("
                    ":investigation_id, :entity_id, :max_depth, :scope, "
                    ":direction, :relationship_type, :entity_type, :source, "
                    ":observed_from, :observed_to, :limit)"
                ),
                {
                    "investigation_id": investigation_id,
                    "entity_id": entity_id,
                    "max_depth": max_depth,
                    "scope": scope.value,
                    "direction": direction.value,
                    "relationship_type": (
                        relationship_type.value
                        if relationship_type is not None
                        else None
                    ),
                    "entity_type": (
                        entity_type.value if entity_type is not None else None
                    ),
                    "source": source,
                    "observed_from": observed_from,
                    "observed_to": observed_to,
                    "limit": limit,
                },
            )
        ).all()

    @staticmethod
    def _map_graph_result_rows(rows: Sequence[Row[Any]]) -> GraphResult | None:
        """Map stored-function node/edge rows to one bounded GraphResult.

        ``None`` when the stored function returned no rows (invisible focal).
        ``truncated`` is propagated from every returned row (the stored
        function reports ONE truthful value on all rows); an unknown row kind
        is an internal invariant violation and fails closed.
        """
        if not rows:
            return None
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        truncated = False
        for row in rows:
            if row.kind == "node":
                nodes.append(
                    GraphNode(
                        entity_id=row.node_entity_id,
                        entity_type=EntityType(row.node_entity_type),
                        value=row.node_canonical_value,
                        display_name=row.node_display_name,
                    )
                )
                truncated = row.truncated
            elif row.kind == "edge":
                edges.append(
                    GraphEdge(
                        relationship_id=row.edge_relationship_id,
                        source_entity_id=row.edge_source_entity_id,
                        target_entity_id=row.edge_target_entity_id,
                        relationship_type=RelationshipType(
                            row.edge_relationship_type_urn
                        ),
                        observation_count=row.edge_observation_count,
                        investigation_observation_count=(
                            row.edge_investigation_observation_count
                        ),
                        first_observed_at=row.edge_first_observed_at,
                        last_observed_at=row.edge_last_observed_at,
                    )
                )
                truncated = row.truncated
            else:  # pragma: no cover - stored-function contract invariant
                raise AssertionError(
                    f"graph stored function returned an unknown row kind: {row.kind!r}"
                )
        return GraphResult(nodes=tuple(nodes), edges=tuple(edges), truncated=truncated)

    @staticmethod
    def _map_path_result_rows(
        query: GraphPathQuery, rows: Sequence[Row[Any]]
    ) -> GraphPathResult | None:
        """Map one stored-function path result into a canonical GraphPathResult.

        The metadata row is authoritative: ``endpoints_visible = false`` maps
        to ``None``; otherwise node/edge/path rows map to canonical models
        and the result is validated for closure and shared endpoints. Unknown
        row kinds or a missing metadata row are internal invariant violations
        and fail closed.
        """
        endpoints_visible = False
        truncated = False
        meta_seen = False
        nodes: list[GraphNode] = []
        edges: list[GraphEdge] = []
        paths: list[GraphPath] = []
        for row in rows:
            if row.kind == "meta":
                meta_seen = True
                endpoints_visible = row.endpoints_visible
                truncated = row.truncated
            elif row.kind == "node":
                nodes.append(
                    GraphNode(
                        entity_id=row.node_entity_id,
                        entity_type=EntityType(row.node_entity_type),
                        value=row.node_canonical_value,
                        display_name=row.node_display_name,
                    )
                )
            elif row.kind == "edge":
                edges.append(
                    GraphEdge(
                        relationship_id=row.edge_relationship_id,
                        source_entity_id=row.edge_source_entity_id,
                        target_entity_id=row.edge_target_entity_id,
                        relationship_type=RelationshipType(
                            row.edge_relationship_type_urn
                        ),
                        observation_count=row.edge_observation_count,
                        investigation_observation_count=(
                            row.edge_investigation_observation_count
                        ),
                        first_observed_at=row.edge_first_observed_at,
                        last_observed_at=row.edge_last_observed_at,
                    )
                )
            elif row.kind == "path":
                paths.append(
                    GraphPath(
                        entity_ids=tuple(row.path_entity_ids),
                        relationship_ids=tuple(row.path_relationship_ids),
                    )
                )
            else:  # pragma: no cover - stored-function contract invariant
                raise AssertionError(
                    f"path stored function returned an unknown row kind: {row.kind!r}"
                )
        if not meta_seen:  # pragma: no cover - stored-function contract invariant
            raise AssertionError("path stored function returned no metadata row")
        if not endpoints_visible:
            return None
        result = GraphPathResult(
            nodes=tuple(nodes),
            edges=tuple(edges),
            paths=tuple(paths),
            truncated=truncated,
        )
        # Service-construction invariant: every path shares the requested
        # endpoints (stored-function contract); fail closed on violation.
        for path in result.paths:
            if (
                not path.entity_ids
                or path.entity_ids[0] != query.entity_id
                or path.entity_ids[-1] != query.target_entity_id
            ):
                raise AssertionError(
                    "path stored function returned a path not anchored at the "
                    "requested endpoints"
                )
        return result
