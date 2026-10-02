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
    GraphPathQuery,
    GraphPathResult,
    GraphQueryService,
    GraphResult,
    GraphScope,
    GraphTraversalQuery,
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
    investigation_observation_count: int | None = None,
    first_observed_at: datetime | None = None,
    last_observed_at: datetime | None = None,
) -> GraphEdge:
    """Build one valid GraphEdge projection for contract tests.

    ``investigation_observation_count`` defaults to ``observation_count``
    (the Investigation-scope invariant) unless an explicit value is given.
    """
    return GraphEdge(
        relationship_id=relationship_id or uuid4(),
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        relationship_type=relationship_type,
        observation_count=observation_count,
        investigation_observation_count=(
            observation_count
            if investigation_observation_count is None
            else investigation_observation_count
        ),
        first_observed_at=first_observed_at,
        last_observed_at=last_observed_at,
    )


class _FixedGraphQueryService(GraphQueryService):
    """Tiny contract double returning a fixed result and recording queries."""

    def __init__(self, result: GraphResult | None) -> None:
        self._result = result
        self.queries: list[GraphNeighborhoodQuery] = []
        self.traversals: list[GraphTraversalQuery] = []
        self.path_queries: list[GraphPathQuery] = []

    async def neighborhood(self, query: GraphNeighborhoodQuery) -> GraphResult | None:
        self.queries.append(query)
        return self._result

    async def traverse(self, query: GraphTraversalQuery) -> GraphResult | None:
        self.traversals.append(query)
        return self._result

    async def find_paths(self, query: GraphPathQuery) -> GraphPathResult | None:
        """Return None; the PR 31I contract double records the path query."""
        self.path_queries.append(query)
        return None


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


# --- GraphEdge Investigation support count (GQ11, G31G-E) -----------------------


def test_e08_zero_investigation_support_count_accepted() -> None:
    """A known-scope edge may carry zero Investigation support."""
    edge = _edge(
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        observation_count=3,
        investigation_observation_count=0,
    )
    assert edge.investigation_observation_count == 0


def test_e09_support_count_equal_to_total_accepted() -> None:
    """Investigation scope requires equal counts (accepted by the contract)."""
    edge = _edge(
        source_entity_id=uuid4(),
        target_entity_id=uuid4(),
        observation_count=2,
        investigation_observation_count=2,
    )
    assert edge.observation_count == edge.investigation_observation_count


def test_gq11_investigation_support_exceeding_total_rejected() -> None:
    """An edge whose Investigation support count exceeds its total is rejected."""
    with pytest.raises(ValidationError, match="must not exceed"):
        _edge(
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            observation_count=1,
            investigation_observation_count=2,
        )


def test_gq11_negative_support_count_rejected() -> None:
    """A negative Investigation support count is rejected."""
    with pytest.raises(ValidationError):
        _edge(
            source_entity_id=uuid4(),
            target_entity_id=uuid4(),
            observation_count=1,
            investigation_observation_count=-1,
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


# --- GraphNeighborhoodQuery scope/filters (GQ01..GQ10, GQ12) -------------------


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


def test_gq01_omitted_scope_defaults_to_investigation() -> None:
    """Omitting scope keeps current-main Investigation behavior."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(), entity_id=uuid4(), limit=10
    )
    assert query.scope is GraphScope.INVESTIGATION


def test_gq02_known_scope_accepted() -> None:
    """The broader Known graph scope is an explicit accepted value."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        scope=GraphScope.KNOWN,
        limit=10,
    )
    assert query.scope is GraphScope.KNOWN


def test_gq03_invalid_scope_rejected() -> None:
    """A scope value outside the two-value vocabulary is rejected."""
    with pytest.raises(ValidationError):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            scope="global",  # type: ignore[arg-type]  # third scope must not exist
            limit=10,
        )


def test_gq04_blank_source_rejected() -> None:
    """A blank source filter is rejected."""
    with pytest.raises(ValidationError, match="must not be blank"):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            source="   ",
            limit=10,
        )


def test_gq05_one_sided_from_accepted() -> None:
    """A one-sided lower observation bound is legal."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        limit=10,
    )
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to is None


def test_gq06_one_sided_to_accepted() -> None:
    """A one-sided upper observation bound is legal."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        observed_to=datetime(2026, 2, 1, tzinfo=UTC),
        limit=10,
    )
    assert query.observed_to == datetime(2026, 2, 1, tzinfo=UTC)
    assert query.observed_from is None


def test_gq07_valid_interval_accepted() -> None:
    """A strictly ordered two-sided interval is accepted."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        observed_to=datetime(2026, 2, 1, tzinfo=UTC),
        limit=10,
    )
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to == datetime(2026, 2, 1, tzinfo=UTC)


def test_gq08_equal_interval_rejected() -> None:
    """An empty (equal-bounds) interval is rejected."""
    with pytest.raises(ValidationError, match="earlier than"):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            observed_from=datetime(2026, 1, 1, tzinfo=UTC),
            observed_to=datetime(2026, 1, 1, tzinfo=UTC),
            limit=10,
        )


def test_gq09_reversed_interval_rejected() -> None:
    """A reversed two-sided interval is rejected."""
    with pytest.raises(ValidationError, match="earlier than"):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            observed_from=datetime(2026, 3, 1, tzinfo=UTC),
            observed_to=datetime(2026, 1, 1, tzinfo=UTC),
            limit=10,
        )


def test_gq10_naive_observed_bound_rejected() -> None:
    """Naive timestamps keep the existing UTC contract: rejected."""
    with pytest.raises(ValidationError):
        GraphNeighborhoodQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            observed_from=datetime(2026, 1, 1),
            limit=10,
        )


def test_gq12_canonical_entity_type_accepted() -> None:
    """A canonical EntityType filter is accepted on the query."""
    query = GraphNeighborhoodQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        entity_type=EntityType.IP_ADDRESS,
        limit=10,
    )
    assert query.entity_type is EntityType.IP_ADDRESS


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


# --- GraphTraversalQuery (PR 31H H-U01..H-U12) --------------------------------


def _traversal(
    *,
    max_depth: int = 2,
    limit: int = 10,
    scope: GraphScope = GraphScope.INVESTIGATION,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> GraphTraversalQuery:
    """Build one valid bounded traversal query for contract tests."""
    return GraphTraversalQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        max_depth=max_depth,
        limit=limit,
        scope=scope,
        source=source,
        observed_from=observed_from,
        observed_to=observed_to,
    )


def test_hu01_depth_one_accepted() -> None:
    """Depth 1 is the one-hop-equivalent traversal floor."""
    query = _traversal(max_depth=1)
    assert query.max_depth == 1


def test_hu02_depth_two_accepted() -> None:
    """Depth 2 is an accepted bounded walk."""
    query = _traversal(max_depth=2)
    assert query.max_depth == 2


def test_hu03_depth_three_accepted() -> None:
    """Depth 3 is the maximum accepted walk."""
    query = _traversal(max_depth=3)
    assert query.max_depth == 3


def test_hu04_depth_zero_rejected() -> None:
    """Depth 0 (focal only) is rejected: depth is hop distance."""
    with pytest.raises(ValidationError, match="max_depth"):
        _traversal(max_depth=0)


def test_hu05_depth_four_rejected() -> None:
    """Depth 4 exceeds the hard server-owned traversal bound."""
    with pytest.raises(ValidationError, match="max_depth"):
        _traversal(max_depth=4)


def test_hu06_default_scope_is_investigation() -> None:
    """Omitted scope keeps the PR 31G Investigation default."""
    assert _traversal().scope is GraphScope.INVESTIGATION


def test_hu07_blank_source_rejected() -> None:
    """A blank exact source filter is rejected like the neighborhood."""
    with pytest.raises(ValidationError, match="must not be blank"):
        _traversal(source="   ")


def test_hu08_naive_observed_bound_rejected() -> None:
    """A timezone-less observed bound is rejected like the neighborhood."""
    with pytest.raises(ValidationError):
        _traversal(observed_from=datetime(2026, 1, 1))


def test_hu09_one_sided_interval_accepted() -> None:
    """A one-sided observed bound is legal."""
    query = _traversal(
        observed_from=datetime(2026, 1, 1, tzinfo=UTC),
        observed_to=None,
    )
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to is None


def test_hu10_invalid_interval_same_rule_as_neighborhood() -> None:
    """Equal/reversed two-sided intervals fail exactly like the neighborhood."""
    with pytest.raises(ValidationError, match="earlier than"):
        _traversal(
            observed_from=datetime(2026, 2, 1, tzinfo=UTC),
            observed_to=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_hu11_duplicate_identity_result_rejected() -> None:
    """A traversal result reuses the canonical GraphResult identity rules."""
    entity_id = uuid4()
    with pytest.raises(ValidationError, match="entity IDs must be unique"):
        GraphResult(
            nodes=(_node(entity_id), _node(entity_id)), edges=(), truncated=False
        )
    relationship_id = uuid4()
    source = _node()
    target = _node()
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


def test_hu12_endpoint_closure_enforced() -> None:
    """A traversal result reuses the canonical GraphResult closure rule."""
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


# --- GraphQueryService.traverse (PR 31H H-U13..H-U14) ---------------------------


def test_hu13_service_double_implements_neighborhood_and_traverse() -> None:
    """The contract double satisfies the extended service ABC."""
    service = _FixedGraphQueryService(None)
    assert isinstance(service, GraphQueryService)


@pytest.mark.asyncio
async def test_hu14_isolated_focal_distinct_from_missing() -> None:
    """A visible isolated focal traversal is distinct from ``None``."""
    focal = _node()
    isolated = GraphResult(nodes=(focal,), edges=(), truncated=False)
    service = _FixedGraphQueryService(isolated)
    query = _traversal(max_depth=3, limit=5)
    result = await service.traverse(query)
    assert result is not None
    assert result.nodes == (focal,)
    assert result.edges == ()
    assert result.truncated is False
    assert service.traversals == [query]
    assert service.queries == []


@pytest.mark.asyncio
async def test_hu14b_missing_focal_traverse_returns_none() -> None:
    """``None`` expresses a missing or not-visible traversal focal."""
    service = _FixedGraphQueryService(None)
    query = _traversal()
    result = await service.traverse(query)
    assert result is None
    assert service.traversals == [query]
