# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31A graph read-contract unit tests (G31A matrix).

These tests validate the application graph contract only: immutable read
projections, identity closure, temporal rules, the bounded query model, and
the ``GraphResult | None`` service semantics. No database is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.graph import (
    GraphEdge,
    GraphNeighborhoodQuery,
    GraphNode,
    GraphQueryService,
    GraphResult,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)

_ENTITY_VALUE = "example.com"


def _node(
    entity_id: UUID | None = None,
    *,
    entity_type: EntityType = EntityType.DOMAIN,
    value: str = _ENTITY_VALUE,
) -> GraphNode:
    """Build one valid GraphNode projection for contract tests."""
    return GraphNode(
        entity_id=entity_id or uuid4(),
        entity_type=entity_type,
        value=value,
        display_name="Example",
    )


def _edge(
    relationship_id: UUID | None = None,
    *,
    source_entity_id: UUID,
    target_entity_id: UUID,
    relationship_type: RelationshipType = RelationshipType.RESOLVES_TO,
    observation_count: int = 1,
    first_observed_at: datetime | None = None,
    last_observed_at: datetime | None = None,
) -> GraphEdge:
    """Build one valid GraphEdge projection for contract tests."""
    return GraphEdge(
        relationship_id=relationship_id or uuid4(),
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        relationship_type=relationship_type,
        observation_count=observation_count,
        first_observed_at=first_observed_at,
        last_observed_at=last_observed_at,
    )


class _FixedGraphQueryService(GraphQueryService):
    """Tiny contract double returning a fixed result and recording queries."""

    def __init__(self, result: GraphResult | None) -> None:
        self._result = result
        self.queries: list[GraphNeighborhoodQuery] = []

    async def neighborhood(self, query: GraphNeighborhoodQuery) -> GraphResult | None:
        self.queries.append(query)
        return self._result


# --- GraphNode (G31A-M01..M03) -------------------------------------------------


def test_m01_valid_graph_node_accepted() -> None:
    """A valid immutable GraphNode projection is accepted."""
    node = _node()
    assert node.entity_type == EntityType.DOMAIN
    assert node.value == _ENTITY_VALUE
    assert node.display_name == "Example"
    with pytest.raises(ValidationError):
        node.display_name = "mutated"  # frozen models reject assignment


def test_m02_graph_node_requires_entity_id() -> None:
    """A GraphNode without an entity ID is rejected."""
    with pytest.raises(ValidationError):
        GraphNode(entity_type=EntityType.DOMAIN, value=_ENTITY_VALUE)  # type: ignore[call-arg]


def test_m03_unknown_graph_node_field_rejected() -> None:
    """extra='forbid' keeps rendering vocabulary out of the contract."""
    with pytest.raises(ValidationError):
        GraphNode(
            entity_id=uuid4(),
            entity_type=EntityType.DOMAIN,
            value=_ENTITY_VALUE,
            position={"x": 1, "y": 2},  # type: ignore[call-arg]  # rendering state must never enter
        )


# --- GraphEdge (G31A-E01..E07) -------------------------------------------------


def test_e01_valid_edge_with_single_observation_accepted() -> None:
    """A valid edge with observation count 1 is accepted."""
    edge = _edge(source_entity_id=uuid4(), target_entity_id=uuid4())
    assert edge.observation_count == 1
    assert edge.first_observed_at is None
    assert edge.last_observed_at is None


def test_e02_zero_observation_count_rejected() -> None:
    """An Investigation-visible Relationship needs >= 1 qualifying observation."""
    with pytest.raises(ValidationError):
        _edge(source_entity_id=uuid4(), target_entity_id=uuid4(), observation_count=0)


def test_e03_naive_first_observed_rejected() -> None:
    """A naive first observed summary is rejected."""
    with pytest.raises(ValidationError):
        _edge(
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            first_observed_at=datetime(2026, 1, 1),
        )


def test_e04_naive_last_observed_rejected() -> None:
    """A naive last observed summary is rejected."""
    with pytest.raises(ValidationError):
        _edge(
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            last_observed_at=datetime(2026, 1, 1),
        )


def test_e05_first_after_last_rejected() -> None:
    """first_observed_at must not be after last_observed_at."""
    with pytest.raises(ValidationError):
        _edge(
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            first_observed_at=datetime(2026, 3, 1, tzinfo=UTC),
            last_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_e06_both_observed_summaries_null_accepted() -> None:
    """Null summaries are valid when no observation carries observed_at."""
    edge = _edge(
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        first_observed_at=None,
        last_observed_at=None,
    )
    assert edge.first_observed_at is None
    assert edge.last_observed_at is None


def test_e07_unknown_graph_edge_field_rejected() -> None:
    """Unapproved edge metadata such as an aggregate confidence is rejected."""
    with pytest.raises(ValidationError):
        GraphEdge(
            relationship_id=uuid4(),
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            relationship_type=RelationshipType.RESOLVES_TO,
            observation_count=1,
            confidence=0.9,  # type: ignore[call-arg]  # no aggregation semantics are approved in PR 31A
        )


# --- GraphResult (G31A-R01..R09) -----------------------------------------------


def test_r01_isolated_focal_node_accepted() -> None:
    """A focal node with zero visible edges is a valid isolated result."""
    focal = _node()
    result = GraphResult(nodes=(focal,), edges=(), truncated=False)
    assert result.nodes == (focal,)
    assert result.edges == ()
    assert result.truncated is False


def test_r02_closed_topology_accepted() -> None:
    """Distinct nodes with every edge endpoint present are accepted."""
    source = _node()
    target = _node()
    edge = _edge(source_entity_id=source.entity_id, target_entity_id=target.entity_id)
    result = GraphResult(nodes=(source, target), edges=(edge,), truncated=False)
    assert len(result.nodes) == 2
    assert len(result.edges) == 1


def test_r03_duplicate_node_id_rejected() -> None:
    """Identical entity IDs must not be duplicated in nodes."""
    entity_id = uuid4()
    with pytest.raises(ValidationError, match="entity IDs must be unique"):
        GraphResult(
            nodes=(_node(entity_id), _node(entity_id)),
            edges=(),
            truncated=False,
        )


def test_r04_duplicate_relationship_id_rejected() -> None:
    """Identical relationship IDs must not be duplicated in edges."""
    source = _node()
    target = _node()
    relationship_id = uuid4()
    with pytest.raises(ValidationError, match="relationship IDs must be unique"):
        GraphResult(
            nodes=(source, target),
            edges=(
                _edge(
                    relationship_id,
                    source_entity_id=source.entity_id,
                    target_entity_id=target.entity_id,
                ),
                _edge(
                    relationship_id,
                    source_entity_id=source.entity_id,
                    target_entity_id=target.entity_id,
                ),
            ),
            truncated=False,
        )


def test_r05_missing_source_endpoint_rejected() -> None:
    """An edge whose source entity is absent from nodes is rejected."""
    target = _node()
    with pytest.raises(ValidationError, match="source entity must be present"):
        GraphResult(
            nodes=(target,),
            edges=(
                _edge(
                    source_entity_id=uuid4(),
                    target_entity_id=target.entity_id,
                ),
            ),
            truncated=False,
        )


def test_r06_missing_target_endpoint_rejected() -> None:
    """An edge whose target entity is absent from nodes is rejected."""
    source = _node()
    with pytest.raises(ValidationError, match="target entity must be present"):
        GraphResult(
            nodes=(source,),
            edges=(
                _edge(
                    source_entity_id=source.entity_id,
                    target_entity_id=uuid4(),
                ),
            ),
            truncated=False,
        )


def test_r07_self_edge_requires_one_node_only() -> None:
    """A self-relationship renders exactly one node and one edge."""
    focal = _node()
    edge = _edge(source_entity_id=focal.entity_id, target_entity_id=focal.entity_id)
    result = GraphResult(nodes=(focal,), edges=(edge,), truncated=False)
    assert len(result.nodes) == 1
    assert len(result.edges) == 1


def test_r08_truncated_false_accepted() -> None:
    """truncated=False signals a complete bounded result."""
    focal = _node()
    result = GraphResult(nodes=(focal,), edges=(), truncated=False)
    assert result.truncated is False


def test_r09_truncated_true_accepted() -> None:
    """truncated=True is an explicit completeness boundary signal."""
    source = _node()
    target = _node()
    edge = _edge(source_entity_id=source.entity_id, target_entity_id=target.entity_id)
    result = GraphResult(nodes=(source, target), edges=(edge,), truncated=True)
    assert result.truncated is True


# --- GraphNeighborhoodQuery (G31A-Q01..Q07) -----------------------------------


def test_q01_query_defaults_to_either() -> None:
    """The default direction is RelationshipDirection.EITHER."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(), entity_id=uuid4(), limit=10
    )
    assert query.direction is RelationshipDirection.EITHER


def test_q02_source_direction_accepted() -> None:
    """SOURCE selects edges outgoing from the focal Entity."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        direction=RelationshipDirection.SOURCE,
        limit=10,
    )
    assert query.direction is RelationshipDirection.SOURCE


def test_q03_target_direction_accepted() -> None:
    """TARGET selects edges incoming to the focal Entity."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        direction=RelationshipDirection.TARGET,
        limit=10,
    )
    assert query.direction is RelationshipDirection.TARGET


def test_q04_relationship_type_filter_accepted() -> None:
    """An optional RelationshipType filter is accepted."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        relationship_type=RelationshipType.RESOLVES_TO,
        limit=10,
    )
    assert query.relationship_type is RelationshipType.RESOLVES_TO


def test_q05_limit_one_accepted() -> None:
    """A bound of one matching Relationship is valid."""
    query = GraphNeighborhoodQuery(investigation_id=uuid4(), entity_id=uuid4(), limit=1)
    assert query.limit == 1


def test_q06_limit_zero_rejected() -> None:
    """A non-positive bound is rejected."""
    with pytest.raises(ValidationError):
        GraphNeighborhoodQuery(investigation_id=uuid4(), entity_id=uuid4(), limit=0)


def test_q07_unknown_query_field_rejected() -> None:
    """Cursor/depth/path vocabulary must not enter the query contract."""
    with pytest.raises(ValidationError):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            limit=10,
            depth=2,  # type: ignore[call-arg]  # traversal belongs to PR 31H/31I
        )


# --- GraphQueryService (G31A-S01..S03) -----------------------------------------


def test_s01_test_double_implements_contract() -> None:
    """A concrete double satisfies the GraphQueryService ABC."""
    service = _FixedGraphQueryService(None)
    assert isinstance(service, GraphQueryService)


@pytest.mark.asyncio
async def test_s02_isolated_focal_node_distinct_from_missing() -> None:
    """An isolated focal-node graph is distinct from a missing focal Entity."""
    focal = _node()
    isolated = GraphResult(nodes=(focal,), edges=(), truncated=False)
    service = _FixedGraphQueryService(isolated)
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=focal.entity_id,
        limit=10,
        direction=RelationshipDirection.TARGET,
    )
    result = await service.neighborhood(query)
    assert result is not None
    assert result.nodes == (focal,)
    assert result.edges == ()
    assert result.truncated is False
    assert service.queries == [query]


@pytest.mark.asyncio
async def test_s03_none_represents_missing_focal_entity() -> None:
    """None expresses a missing or not-visible focal Entity."""
    service = _FixedGraphQueryService(None)
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(), entity_id=uuid4(), limit=10
    )
    result = await service.neighborhood(query)
    assert result is None
    assert service.queries == [query]
