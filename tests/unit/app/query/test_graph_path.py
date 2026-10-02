# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31I application path contract tests (P-U01..P-U20).

Pure model/query contract tests: server-owned path bounds, the
``GraphPathQuery`` reuse of the PR 31G context (blank source rejection and
half-open interval validation inherited from the shared base), and the
``GraphPath`` / ``GraphPathResult`` structural validators (zero-hop legality,
entity/relationship arity, simple-path uniqueness, result closure and edge
adjacency). No database, API or frontend work is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.query.graph import (
    DEFAULT_GRAPH_PATH_MAX_DEPTH,
    DEFAULT_GRAPH_PATH_MAX_RESULTS,
    GRAPH_PATH_MAX_DEPTH,
    GRAPH_PATH_MAX_RESULTS,
    GraphEdge,
    GraphNode,
    GraphPath,
    GraphPathQuery,
    GraphPathResult,
    GraphScope,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType


def _path_query(
    *,
    max_depth: int = DEFAULT_GRAPH_PATH_MAX_DEPTH,
    max_paths: int = DEFAULT_GRAPH_PATH_MAX_RESULTS,
    scope: GraphScope = GraphScope.INVESTIGATION,
    source: str | None = None,
    observed_from: datetime | None = None,
    observed_to: datetime | None = None,
) -> GraphPathQuery:
    """Build one valid bounded path query for contract tests."""
    return GraphPathQuery(
        investigation_id=uuid4(),
        entity_id=uuid4(),
        target_entity_id=uuid4(),
        max_depth=max_depth,
        max_paths=max_paths,
        scope=scope,
        source=source,
        observed_from=observed_from,
        observed_to=observed_to,
    )


def _node(entity_id: UUID | None = None) -> GraphNode:
    """Build one canonical node projection for contract tests."""
    return GraphNode(
        entity_id=entity_id or uuid4(),
        entity_type=EntityType.DOMAIN,
        value="example.com",
    )


def _edge(
    *,
    source_entity_id: UUID,
    target_entity_id: UUID,
    relationship_id: UUID | None = None,
) -> GraphEdge:
    """Build one canonical edge projection for contract tests."""
    return GraphEdge(
        relationship_id=relationship_id or uuid4(),
        source_entity_id=source_entity_id,
        target_entity_id=target_entity_id,
        relationship_type=RelationshipType.RESOLVES_TO,
        observation_count=1,
        investigation_observation_count=1,
    )


def _zero_hop_path(entity_id: UUID) -> GraphPath:
    """Build the legal zero-hop source==target path."""
    return GraphPath(entity_ids=(entity_id,), relationship_ids=())


def _source_target_path(
    source: UUID,
    target: UUID,
    *,
    edge_id: UUID | None = None,
) -> GraphPath:
    """Build one legal one-hop path between two Entities."""
    return GraphPath(
        entity_ids=(source, target),
        relationship_ids=(edge_id or uuid4(),),
    )


def _path_result(
    *,
    nodes: tuple[GraphNode, ...],
    edges: tuple[GraphEdge, ...],
    paths: tuple[GraphPath, ...] = (),
    truncated: bool = False,
) -> GraphPathResult:
    """Build one path result with valid defaults for the given topology."""
    return GraphPathResult(nodes=nodes, edges=edges, paths=paths, truncated=truncated)


# --- GraphPathQuery bounds (P-U01..P-U12) --------------------------------------


def test_pu01_depth_one_accepted() -> None:
    """P-U01: depth 1 is the one-edge path floor."""
    query = _path_query(max_depth=1)
    assert query.max_depth == 1


def test_pu02_depth_maximum_accepted() -> None:
    """P-U02: the hard maximum depth 6 is accepted."""
    query = _path_query(max_depth=GRAPH_PATH_MAX_DEPTH)
    assert query.max_depth == GRAPH_PATH_MAX_DEPTH


def test_pu03_depth_zero_rejected() -> None:
    """P-U03: depth 0 is rejected: depth is hop distance."""
    with pytest.raises(ValidationError, match="max_depth"):
        _path_query(max_depth=0)


def test_pu04_depth_above_maximum_rejected() -> None:
    """P-U04: depth 7 exceeds the hard server-owned bound."""
    with pytest.raises(ValidationError, match="max_depth"):
        _path_query(max_depth=GRAPH_PATH_MAX_DEPTH + 1)


def test_pu05_max_paths_one_accepted() -> None:
    """P-U05: max_paths 1 is accepted."""
    query = _path_query(max_paths=1)
    assert query.max_paths == 1


def test_pu06_max_paths_maximum_accepted() -> None:
    """P-U06: the hard maximum result count 25 is accepted."""
    query = _path_query(max_paths=GRAPH_PATH_MAX_RESULTS)
    assert query.max_paths == GRAPH_PATH_MAX_RESULTS


def test_pu07_max_paths_zero_rejected() -> None:
    """P-U07: max_paths 0 is rejected."""
    with pytest.raises(ValidationError, match="max_paths"):
        _path_query(max_paths=0)


def test_pu08_max_paths_above_maximum_rejected() -> None:
    """P-U08: max_paths 26 exceeds the hard server-owned bound."""
    with pytest.raises(ValidationError, match="max_paths"):
        _path_query(max_paths=GRAPH_PATH_MAX_RESULTS + 1)


def test_pu09_blank_source_rejected() -> None:
    """P-U09: the inherited PR 31G blank-source rule applies to paths."""
    with pytest.raises(ValidationError, match="must not be blank"):
        _path_query(source="   ")


def test_pu10_equal_observed_bounds_rejected() -> None:
    """P-U10: equal observed bounds form an empty half-open interval."""
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError, match="observed_from"):
        _path_query(observed_from=moment, observed_to=moment)


def test_pu11_reversed_observed_bounds_rejected() -> None:
    """P-U11: reversed observed bounds are rejected."""
    with pytest.raises(ValidationError, match="observed_from"):
        _path_query(
            observed_from=datetime(2026, 2, 1, tzinfo=UTC),
            observed_to=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_pu12_one_sided_observed_bounds_accepted() -> None:
    """P-U12: one-sided observed bounds are legal."""
    query = _path_query(observed_to=datetime(2026, 1, 1, tzinfo=UTC))
    assert query.observed_to == datetime(2026, 1, 1, tzinfo=UTC)


def test_pu12b_no_relationship_limit_field() -> None:
    """A path query must not carry a meaningless Relationship ``limit``."""
    with pytest.raises(ValidationError):
        GraphPathQuery(
            investigation_id=uuid4(),
            entity_id=uuid4(),
            target_entity_id=uuid4(),
            max_depth=4,
            max_paths=10,
            limit=10,  # type: ignore[call-arg]
        )


def test_pu12c_defaults_match_server_owned_ceiling_contract() -> None:
    """Defaults are within the hard ceilings and oversized values are capped."""
    query = _path_query()
    assert query.max_depth == DEFAULT_GRAPH_PATH_MAX_DEPTH
    assert query.max_paths == DEFAULT_GRAPH_PATH_MAX_RESULTS
    assert DEFAULT_GRAPH_PATH_MAX_DEPTH <= GRAPH_PATH_MAX_DEPTH
    assert DEFAULT_GRAPH_PATH_MAX_RESULTS <= GRAPH_PATH_MAX_RESULTS


# --- GraphPath (P-U13..P-U16) --------------------------------------------------


def test_pu13_zero_hop_path_accepted() -> None:
    """P-U13: the zero-hop source==target path is legal."""
    entity_id = uuid4()
    path = _zero_hop_path(entity_id)
    assert path.entity_ids == (entity_id,)
    assert path.relationship_ids == ()


def test_pu14_arity_mismatch_rejected() -> None:
    """P-U14: entity count must be relationship count plus one."""
    source, target = uuid4(), uuid4()
    with pytest.raises(ValidationError, match="relationship count"):
        GraphPath(entity_ids=(source, target), relationship_ids=())


def test_pu15_duplicate_entity_in_simple_path_rejected() -> None:
    """P-U15: a simple path never repeats an Entity."""
    middle = uuid4()
    with pytest.raises(ValidationError, match="unique"):
        GraphPath(
            entity_ids=(uuid4(), middle, middle),
            relationship_ids=(uuid4(), uuid4()),
        )


def test_pu16_duplicate_relationship_in_path_rejected() -> None:
    """P-U16: a simple path never repeats a Relationship."""
    repeated = uuid4()
    with pytest.raises(ValidationError, match="unique"):
        GraphPath(
            entity_ids=(uuid4(), uuid4(), uuid4()),
            relationship_ids=(repeated, repeated),
        )


def test_pu16b_empty_entity_path_rejected() -> None:
    """A path must contain at least one Entity."""
    with pytest.raises(ValidationError, match="at least one entity"):
        GraphPath(entity_ids=(), relationship_ids=())


# --- GraphPathResult (P-U17..P-U20 + closure/adjacency) ------------------------


def test_pu17_path_references_missing_result_node_rejected() -> None:
    """P-U17: every path Entity ID must exist in the result nodes."""
    source, target = uuid4(), uuid4()
    edge = _edge(source_entity_id=source, target_entity_id=target)
    missing = uuid4()
    with pytest.raises(ValidationError, match="absent from nodes"):
        _path_result(
            nodes=(_node(source), _node(target)),
            edges=(edge,),
            paths=(
                GraphPath(
                    entity_ids=(source, missing),
                    relationship_ids=(edge.relationship_id,),
                ),
            ),
        )


def test_pu18_path_references_missing_result_edge_rejected() -> None:
    """P-U18: every path Relationship ID must exist in the result edges."""
    source, target = uuid4(), uuid4()
    path = _source_target_path(source, target)
    with pytest.raises(ValidationError, match="absent from edges"):
        _path_result(
            nodes=(_node(source), _node(target)),
            edges=(),
            paths=(path,),
        )


def test_pu19_duplicate_canonical_node_rejected() -> None:
    """P-U19: nodes deduplicate by canonical Entity ID."""
    entity_id = uuid4()
    with pytest.raises(ValidationError, match="unique"):
        _path_result(nodes=(_node(entity_id), _node(entity_id)), edges=())


def test_pu20_duplicate_canonical_edge_rejected() -> None:
    """P-U20: edges deduplicate by canonical Relationship ID."""
    shared = uuid4()
    source, target = uuid4(), uuid4()
    with pytest.raises(ValidationError, match="unique"):
        _path_result(
            nodes=(_node(source), _node(target)),
            edges=(
                _edge(
                    source_entity_id=source,
                    target_entity_id=target,
                    relationship_id=shared,
                ),
                _edge(
                    source_entity_id=target,
                    target_entity_id=source,
                    relationship_id=shared,
                ),
            ),
        )


def test_pu20b_edge_endpoint_missing_from_nodes_rejected() -> None:
    """Every edge endpoint must exist in the result nodes."""
    source, target, stray = uuid4(), uuid4(), uuid4()
    with pytest.raises(ValidationError, match="present in nodes"):
        _path_result(
            nodes=(_node(source), _node(target)),
            edges=(_edge(source_entity_id=source, target_entity_id=stray),),
        )


def test_pu20c_edge_not_connecting_adjacent_path_entities_rejected() -> None:
    """P-U20c: a path Relationship must connect its adjacent path Entities."""
    source, middle, target = uuid4(), uuid4(), uuid4()
    unconnected = _edge(source_entity_id=source, target_entity_id=middle)
    # The path claims source->middle via an edge that actually connects
    # source->middle — build a mismatched adjacency instead.
    edge = _edge(source_entity_id=source, target_entity_id=target)
    path = GraphPath(
        entity_ids=(source, middle),
        relationship_ids=(edge.relationship_id,),
    )
    with pytest.raises(ValidationError, match="connect adjacent"):
        _path_result(
            nodes=(_node(source), _node(middle), _node(target)),
            edges=(edge, unconnected),
            paths=(path,),
        )


def test_pu20d_valid_result_with_multiple_paths_accepted() -> None:
    """A closed multi-path result with shared topology is accepted."""
    source, middle_a, middle_b, target = uuid4(), uuid4(), uuid4(), uuid4()
    edge_a = _edge(source_entity_id=source, target_entity_id=middle_a)
    edge_b = _edge(source_entity_id=middle_a, target_entity_id=target)
    edge_c = _edge(source_entity_id=source, target_entity_id=middle_b)
    edge_d = _edge(source_entity_id=middle_b, target_entity_id=target)
    result = _path_result(
        nodes=(_node(source), _node(middle_a), _node(middle_b), _node(target)),
        edges=(edge_a, edge_b, edge_c, edge_d),
        paths=(
            GraphPath(
                entity_ids=(source, middle_a, target),
                relationship_ids=(edge_a.relationship_id, edge_b.relationship_id),
            ),
            GraphPath(
                entity_ids=(source, middle_b, target),
                relationship_ids=(edge_c.relationship_id, edge_d.relationship_id),
            ),
        ),
    )
    assert len(result.paths) == 2
    assert result.truncated is False


def test_pu21_query_rejects_extra_fields() -> None:
    """extra='forbid' keeps path-only vocabulary out of sibling queries."""
    with pytest.raises(ValidationError):
        GraphPathQuery(  # type: ignore[call-arg]
            investigation_id=uuid4(),
            entity_id=uuid4(),
            target_entity_id=uuid4(),
            max_depth=4,
            max_paths=10,
            limit=10,
        )
