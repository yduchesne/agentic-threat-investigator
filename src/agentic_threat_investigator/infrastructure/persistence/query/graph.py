# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL one-hop graph neighborhood reads (PR 31B).

The concrete :class:`PostgresGraphQueryService` implements the PR 31A graph
read contract on top of ATI's authoritative relational model. It never
persists graph projections and never introduces a graph database: canonical
``Entity`` rows project to ``GraphNode`` items, canonical ``Relationship``
rows project to ``GraphEdge`` items (one edge per Relationship, aggregated
before materialization), and only ``RelationshipObservation`` rows whose
exact ``EvidenceObservation`` is admitted to the requested Investigation
through ``InvestigationEvidence`` contribute to edge visibility and to the
``observation_count`` / first/last observed summaries.

Focal Entity visibility follows the same exact-admission rule through the
``EvidenceObservationEntity`` association: the Entity exists, is not
soft-deleted, and at least one associated EvidenceObservation is admitted to
the requested Investigation. Missing or not-visible focal Entities return
``None``; a visible isolated focal Entity returns a one-node
``GraphResult``.

The read path follows the established analyst-facing SQLAlchemy query-service
architecture (no stored read functions). Bounds use the server-owned
``QueryLimits`` ceiling and the ``limit + 1`` truncation probe ordered by
``relationship.id ASC``; endpoint Entities are loaded in one bulk query (no
N+1 reads).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import Row, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select

from agentic_threat_investigator.app.query.graph import (
    GraphEdge,
    GraphNeighborhoodQuery,
    GraphNode,
    GraphQueryService,
    GraphResult,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)

from ..postgresql.models import (
    EntityRow,
    EvidenceObservationEntityRow,
    InvestigationEvidenceRow,
    RelationshipObservationRow,
    RelationshipRow,
)


def _graph_node_from_row(row: EntityRow) -> GraphNode:
    """Map one live canonical Entity row to a GraphNode projection.

    Only the PR 31A projection fields are exposed: identity, canonical type
    and value, and the optional display name. Persistence internals
    (``version``, ``deleted_at``, ``content_hash``, ``attributes``) never
    leak into the graph projection.
    """
    return GraphNode(
        entity_id=row.id,
        entity_type=EntityType(row.entity_type),
        value=row.canonical_value,
        display_name=row.display_name,
    )


class PostgresGraphQueryService(GraphQueryService):
    """One bounded Investigation-scoped one-hop graph neighbor read."""

    def __init__(self, session: AsyncSession, limits: QueryLimits) -> None:
        """Bind the short-lived read session and the configured limits."""
        self._session = session
        self._limits = limits

    async def neighborhood(self, query: GraphNeighborhoodQuery) -> GraphResult | None:
        """Return the bounded one-hop neighborhood of the focal Entity.

        The read has three bounded SQL steps in one short-lived session:
        the focal visibility probe, the grouped canonical Relationship
        selection with Investigation-scoped observation summaries, and one
        bulk endpoint Entity projection. ``None`` means the focal Entity is
        missing, soft-deleted, or not visible to the Investigation; a
        visible isolated focal Entity yields a one-node unfiltered result.
        """
        limit = self._limits.validate_limit(query.limit)

        focal_row = (
            await self._session.execute(
                select(EntityRow).where(
                    EntityRow.id == query.entity_id,
                    EntityRow.deleted_at.is_(None),
                    select(EvidenceObservationEntityRow.evidence_observation_id)
                    .join(
                        InvestigationEvidenceRow,
                        InvestigationEvidenceRow.evidence_observation_id
                        == EvidenceObservationEntityRow.evidence_observation_id,
                    )
                    .where(
                        EvidenceObservationEntityRow.entity_id == EntityRow.id,
                        InvestigationEvidenceRow.investigation_id
                        == query.investigation_id,
                    )
                    .exists(),
                )
            )
        ).scalar_one_or_none()
        if focal_row is None:
            return None
        focal_node = _graph_node_from_row(focal_row)

        rows = (await self._session.execute(self._edge_statement(query, limit))).all()
        selected_rows = rows[:limit]
        truncated = len(rows) > limit
        if not selected_rows:
            return GraphResult(nodes=(focal_node,), edges=(), truncated=False)

        edges = tuple(
            GraphEdge(
                relationship_id=row.relationship_id,
                source_entity_id=row.source_entity_id,
                target_entity_id=row.target_entity_id,
                relationship_type=RelationshipType(row.relationship_type_urn),
                observation_count=row.observation_count,
                first_observed_at=row.first_observed_at,
                last_observed_at=row.last_observed_at,
            )
            for row in selected_rows
        )
        nodes = await self._endpoint_nodes(focal_node, selected_rows)
        return GraphResult(nodes=nodes, edges=edges, truncated=truncated)

    def _edge_statement(self, query: GraphNeighborhoodQuery, limit: int) -> Select[Any]:
        """Build the grouped, bounded canonical Relationship edge selection.

        One row per live canonical Relationship whose endpoint Entities are
        live and whose InvestigationEvidence-admitted observations survive
        the direction/type filters; observation summaries are computed over
        exactly those admitted observations. The ``limit + 1`` probe bounds
        canonical Relationships (never raw observation rows) in
        ``relationship.id ASC`` order.
        """
        source_entity = aliased(EntityRow)
        target_entity = aliased(EntityRow)
        stmt = (
            select(
                RelationshipRow.id.label("relationship_id"),
                RelationshipRow.source_entity_id,
                RelationshipRow.target_entity_id,
                RelationshipRow.relationship_type_urn,
                func.count(RelationshipObservationRow.id).label("observation_count"),
                func.min(RelationshipObservationRow.observed_at).label(
                    "first_observed_at"
                ),
                func.max(RelationshipObservationRow.observed_at).label(
                    "last_observed_at"
                ),
            )
            .join(
                RelationshipObservationRow,
                RelationshipObservationRow.relationship_id == RelationshipRow.id,
            )
            .join(
                InvestigationEvidenceRow,
                InvestigationEvidenceRow.evidence_observation_id
                == RelationshipObservationRow.evidence_observation_id,
            )
            .join(source_entity, source_entity.id == RelationshipRow.source_entity_id)
            .join(target_entity, target_entity.id == RelationshipRow.target_entity_id)
            .where(
                InvestigationEvidenceRow.investigation_id == query.investigation_id,
                RelationshipRow.deleted_at.is_(None),
                source_entity.deleted_at.is_(None),
                target_entity.deleted_at.is_(None),
            )
            .group_by(
                RelationshipRow.id,
                RelationshipRow.source_entity_id,
                RelationshipRow.target_entity_id,
                RelationshipRow.relationship_type_urn,
            )
            .order_by(RelationshipRow.id.asc())
            .limit(limit + 1)
        )
        if query.direction is RelationshipDirection.SOURCE:
            stmt = stmt.where(RelationshipRow.source_entity_id == query.entity_id)
        elif query.direction is RelationshipDirection.TARGET:
            stmt = stmt.where(RelationshipRow.target_entity_id == query.entity_id)
        else:
            stmt = stmt.where(
                or_(
                    RelationshipRow.source_entity_id == query.entity_id,
                    RelationshipRow.target_entity_id == query.entity_id,
                )
            )
        if query.relationship_type is not None:
            stmt = stmt.where(
                RelationshipRow.relationship_type_urn == query.relationship_type.value
            )
        return stmt

    async def _endpoint_nodes(
        self, focal_node: GraphNode, selected_rows: Sequence[Row[Any]]
    ) -> tuple[GraphNode, ...]:
        """Load and order every endpoint Entity of the selected edges.

        The focal node comes first; the remaining live endpoint Entities are
        loaded in one bounded query and ordered by Entity ID. A soft-deleted
        endpoint would have been filtered before selection, so a selected
        edge whose endpoint cannot be mapped indicates data/query
        inconsistency and fails closed deterministically.
        """
        non_focal_ids: set[UUID] = set()
        for row in selected_rows:
            if row.source_entity_id != focal_node.entity_id:
                non_focal_ids.add(row.source_entity_id)
            if row.target_entity_id != focal_node.entity_id:
                non_focal_ids.add(row.target_entity_id)
        if not non_focal_ids:
            return (focal_node,)

        rows = (
            (
                await self._session.execute(
                    select(EntityRow).where(
                        EntityRow.id.in_(non_focal_ids),
                        EntityRow.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        nodes_by_id = {row.id: _graph_node_from_row(row) for row in rows}
        missing = non_focal_ids - nodes_by_id.keys()
        if missing:  # pragma: no cover - FK/soft-delete invariant complement
            raise AssertionError(
                "graph edge endpoint entity row is missing for endpoint(s): "
                + ", ".join(sorted(str(entity_id) for entity_id in missing))
            )
        return (focal_node,) + tuple(
            nodes_by_id[entity_id] for entity_id in sorted(non_focal_ids)
        )
