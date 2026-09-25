# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31C graph DTO validation and mapping unit tests (G31C-D01..D06).

The public graph DTOs are explicit frozen allowlists; the mappers copy the
PR 31A application read models field-for-field without sorting,
de-duplication, filtering, calculations, or cursor/page metadata.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.api.dto.graph import (
    GraphEdgeResponse,
    GraphNeighborhoodResponse,
    GraphNodeResponse,
)
from agentic_threat_investigator.api.mappers import (
    to_graph_edge_response,
    to_graph_neighborhood_response,
    to_graph_node_response,
)
from agentic_threat_investigator.app.query.graph import (
    GraphEdge,
    GraphNode,
    GraphResult,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType

FOCAL_ID = UUID("22222222-2222-4222-8222-222222222222")
NEIGHBOR_ID = UUID("33333333-3333-4333-8333-333333333333")
EDGE_ID = UUID("44444444-4444-4444-8444-444444444444")


def _node(
    *,
    entity_id: UUID = FOCAL_ID,
    entity_type: EntityType = EntityType.DOMAIN,
    value: str = "example.com",
    display_name: str | None = "Example",
) -> GraphNode:
    """Build one deterministic focal graph node."""
    return GraphNode(
        entity_id=entity_id,
        entity_type=entity_type,
        value=value,
        display_name=display_name,
    )


def _edge(
    *,
    first: datetime | None = datetime(2026, 1, 1, tzinfo=UTC),
    last: datetime | None = datetime(2026, 1, 3, tzinfo=UTC),
) -> GraphEdge:
    """Build one deterministic graph edge."""
    return GraphEdge(
        relationship_id=EDGE_ID,
        source_entity_id=FOCAL_ID,
        target_entity_id=NEIGHBOR_ID,
        relationship_type=RelationshipType.RESOLVES_TO,
        observation_count=3,
        first_observed_at=first,
        last_observed_at=last,
    )


def test_g31c_d01_graph_node_mapping_is_exact() -> None:
    """GraphNode maps to the public DTO field-for-field."""
    node = _node(display_name=None)
    response = to_graph_node_response(node)
    assert isinstance(response, GraphNodeResponse)
    assert response.entity_id == FOCAL_ID
    assert response.entity_type is EntityType.DOMAIN
    assert response.value == "example.com"
    assert response.display_name is None
    payload = response.model_dump()
    assert set(payload) == {"entity_id", "entity_type", "value", "display_name"}


def test_g31c_d02_graph_edge_mapping_is_exact() -> None:
    """GraphEdge maps topology/type/count/times exactly."""
    response = to_graph_edge_response(_edge())
    assert isinstance(response, GraphEdgeResponse)
    assert response.relationship_id == EDGE_ID
    assert response.source_entity_id == FOCAL_ID
    assert response.target_entity_id == NEIGHBOR_ID
    assert response.relationship_type is RelationshipType.RESOLVES_TO
    assert response.observation_count == 3
    assert response.first_observed_at == datetime(2026, 1, 1, tzinfo=UTC)
    assert response.last_observed_at == datetime(2026, 1, 3, tzinfo=UTC)
    payload = response.model_dump()
    assert set(payload) == {
        "relationship_id",
        "source_entity_id",
        "target_entity_id",
        "relationship_type",
        "observation_count",
        "first_observed_at",
        "last_observed_at",
    }


def test_g31c_d03_null_observed_times_remain_null() -> None:
    """Null summary times never get substituted during mapping."""
    response = to_graph_edge_response(_edge(first=None, last=None))
    assert response.first_observed_at is None
    assert response.last_observed_at is None
    assert response.observation_count == 3


def test_g31c_d04_graph_result_mapping_preserves_order_and_truncation() -> None:
    """GraphResult mapping preserves service ordering and truncated truth."""
    result = GraphResult(
        nodes=(_node(), _node(entity_id=NEIGHBOR_ID, display_name=None)),
        edges=(_edge(),),
        truncated=True,
    )
    response = to_graph_neighborhood_response(result)
    assert isinstance(response, GraphNeighborhoodResponse)
    assert [node.entity_id for node in response.nodes] == [FOCAL_ID, NEIGHBOR_ID]
    assert [edge.relationship_id for edge in response.edges] == [EDGE_ID]
    assert response.truncated is True
    assert set(response.model_dump()) == {"nodes", "edges", "truncated"}
    assert "next_cursor" not in response.model_dump()


def test_g31c_d05_unknown_dto_field_is_rejected() -> None:
    """Unknown fields never enter the public graph DTOs."""
    with pytest.raises(ValidationError):
        GraphNodeResponse(  # type: ignore[call-arg]
            entity_id=FOCAL_ID,
            entity_type=EntityType.DOMAIN,
            value="example.com",
            position={"x": 1},
        )
    with pytest.raises(ValidationError):
        GraphEdgeResponse(  # type: ignore[call-arg]
            relationship_id=EDGE_ID,
            source_entity_id=FOCAL_ID,
            target_entity_id=NEIGHBOR_ID,
            relationship_type=RelationshipType.RESOLVES_TO,
            observation_count=3,
            confidence=0.9,
        )
    with pytest.raises(ValidationError):
        GraphNeighborhoodResponse(  # type: ignore[call-arg]
            nodes=(),
            edges=(),
            truncated=False,
            next_cursor=None,
        )


def test_g31c_d06_dto_mutation_is_rejected() -> None:
    """Graph response DTOs are immutable after construction."""
    response = GraphNodeResponse(
        entity_id=FOCAL_ID,
        entity_type=EntityType.DOMAIN,
        value="example.com",
    )
    with pytest.raises(ValidationError):
        response.value = "mutated"

    edge = GraphEdgeResponse(
        relationship_id=EDGE_ID,
        source_entity_id=FOCAL_ID,
        target_entity_id=NEIGHBOR_ID,
        relationship_type=RelationshipType.RESOLVES_TO,
        observation_count=1,
    )
    with pytest.raises(ValidationError):
        edge.observation_count = 99


def test_g31c_d07_mapper_never_reorders_or_duplicates() -> None:
    """Mapping is a pure projection: input order/identity counts are kept."""
    node = _node(
        entity_id=uuid4(), entity_type=EntityType.IP_ADDRESS, value="192.0.2.1"
    )
    counterparty = _node(entity_id=uuid4(), entity_type=EntityType.ASN, value="AS13335")
    result = GraphResult(
        nodes=(node, counterparty),
        edges=(),
        truncated=False,
    )
    response = to_graph_neighborhood_response(result)
    assert [item.entity_id for item in response.nodes] == [
        node.entity_id,
        counterparty.entity_id,
    ]
    assert len(response.nodes) == 2
    assert len({item.entity_id for item in response.nodes}) == 2
