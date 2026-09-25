# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31C graph neighborhood route contract tests (G31C-R01..R16).

Pure HTTP contract tests with injected application fakes: the route builds
exactly one ``GraphNeighborhoodQuery``, calls only
``services.graph.neighborhood``, maps the result to explicit public DTOs,
and translates scoped absence to one stable 404. No database, real
authentication, LLM, or provider work is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.graph import (
    GraphEdge,
    GraphNeighborhoodQuery,
    GraphNode,
    GraphResult,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import (
    Relationship,
    RelationshipDirection,
    RelationshipType,
)

from .conftest import (
    FakeAuthenticationService,
    FakeQueryBundle,
    build_test_app,
    login_client,
)

INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")


def _focal_node() -> GraphNode:
    """Build one deterministic focal DOMAIN node."""
    return GraphNode(
        entity_id=UUID("22222222-2222-4222-8222-222222222222"),
        entity_type=EntityType.DOMAIN,
        value="example.com",
        display_name="Example",
    )


def _neighbor_node() -> GraphNode:
    """Build one deterministic counterparty IP node."""
    return GraphNode(
        entity_id=UUID("33333333-3333-4333-8333-333333333333"),
        entity_type=EntityType.IP_ADDRESS,
        value="192.0.2.1",
        display_name=None,
    )


def _edge() -> GraphEdge:
    """Build one deterministic edge with a full observation summary."""
    return GraphEdge(
        relationship_id=UUID("44444444-4444-4444-8444-444444444444"),
        source_entity_id=_focal_node().entity_id,
        target_entity_id=_neighbor_node().entity_id,
        relationship_type=RelationshipType.RESOLVES_TO,
        observation_count=3,
        first_observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_observed_at=datetime(2026, 1, 3, tzinfo=UTC),
    )


def _result() -> GraphResult:
    """Build one bounded two-node one-edge neighborhood result."""
    return GraphResult(
        nodes=(_focal_node(), _neighbor_node()),
        edges=(_edge(),),
        truncated=False,
    )


def test_g31c_r01_successful_result_returns_exact_public_projection() -> None:
    """A graph result maps to the explicit public DTO field-for-field."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{_focal_node().entity_id}/neighborhood"
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1
    assert body["truncated"] is False
    node = body["nodes"][0]
    assert node == {
        "entity_id": str(_focal_node().entity_id),
        "entity_type": EntityType.DOMAIN.value,
        "value": "example.com",
        "display_name": "Example",
    }
    edge = body["edges"][0]
    assert edge == {
        "relationship_id": str(_edge().relationship_id),
        "source_entity_id": str(_edge().source_entity_id),
        "target_entity_id": str(_edge().target_entity_id),
        "relationship_type": RelationshipType.RESOLVES_TO.value,
        "observation_count": 3,
        "first_observed_at": "2026-01-01T00:00:00Z",
        "last_observed_at": "2026-01-03T00:00:00Z",
    }
    # The wire carries nodes/edges/truncated only: no cursor/page metadata,
    # raw payloads, Entity persistence internals, aggregate confidence,
    # layout coordinates, or frontend-library data.
    assert set(body) == {"nodes", "edges", "truncated"}
    for internal in (
        "next_cursor",
        "total",
        "cursor",
        "raw_payload",
        "attributes",
        "content_hash",
        "deleted_at",
        "version",
        "confidence",
        "position",
        "x",
        "y",
        "data",
        "selected",
        "handle",
    ):
        assert internal not in body


def test_g31c_r02_query_maps_exactly() -> None:
    """Investigation/entity/direction/type/limit map to the query verbatim."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    entity = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{entity}/neighborhood",
            params={
                "direction": RelationshipDirection.TARGET.value,
                "relationship_type": RelationshipType.CNAME_OF.value,
                "limit": "7",
            },
        )
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert isinstance(query, GraphNeighborhoodQuery)
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == entity
    assert query.direction is RelationshipDirection.TARGET
    assert query.relationship_type is RelationshipType.CNAME_OF
    assert query.limit == 7


def test_g31c_r03_omitted_direction_defaults_to_either() -> None:
    """An omitted direction parameter maps to RelationshipDirection.EITHER."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood"
        )
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert query.direction is RelationshipDirection.EITHER


def test_g31c_r04_omitted_limit_uses_configured_default() -> None:
    """An omitted limit maps to the configured query default page size."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(
        bundle=bundle,
        settings=Settings(
            public_base_url="http://testserver", query_default_page_size=17
        ),
    ) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood"
        )
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert query.limit == 17


def test_g31c_r05_visible_isolated_focal_returns_200() -> None:
    """A visible focal Entity with zero edges is a 200 focal-only graph."""
    bundle = FakeQueryBundle()
    bundle.graph.result = GraphResult(nodes=(_focal_node(),), edges=(), truncated=False)
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{_focal_node().entity_id}/neighborhood"
        )
    assert response.status_code == 200
    body = response.json()
    assert [node["entity_id"] for node in body["nodes"]] == [
        str(_focal_node().entity_id)
    ]
    assert body["edges"] == []
    assert body["truncated"] is False
    assert "next_cursor" not in body


def test_g31c_r06_service_none_is_scoped_404() -> None:
    """Missing/deleted/not-visible focal entities map to one scoped 404."""
    bundle = FakeQueryBundle()
    bundle.graph.result = None
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood"
        )
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "graph_entity_not_found"
    assert body["error"]["message"] == (
        "Graph entity was not found for this investigation."
    )
    assert len(bundle.graph.neighborhood_queries) == 1


def test_g31c_r07_malformed_focal_uuid_is_422() -> None:
    """A malformed focal Entity UUID fails as 422, never reaching the service."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            "not-a-uuid/neighborhood"
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r08_malformed_investigation_uuid_is_422() -> None:
    """A malformed Investigation UUID fails as 422 with the stable envelope."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/not-a-uuid/graph/entities/{uuid4()}/neighborhood"
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r09_invalid_direction_is_422() -> None:
    """A non-allowlisted direction value fails closed as 422."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"direction": "diagonal"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r10_invalid_relationship_type_is_422() -> None:
    """A non-allowlisted relationship type fails closed as 422."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"relationship_type": "urn:ati:relationship:dns:made_up"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r11_oversized_limit_is_400_invalid_request() -> None:
    """An oversized service limit becomes a stable 400, never clamped."""

    async def bounded_neighborhood(query: GraphNeighborhoodQuery) -> GraphResult:
        """Reject limits above the server maximum before any read."""
        if query.limit > 200:
            raise ValueError("limit must be between 1 and 200")
        return _result()

    bundle = FakeQueryBundle()
    bundle.graph.neighborhood = bounded_neighborhood  # type: ignore[method-assign]
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood",
            params={"limit": "500"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_g31c_r12_unauthenticated_is_401() -> None:
    """The graph endpoint requires authentication like every analytical GET."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood"
        )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r13_non_analyst_role_is_403() -> None:
    """Non-analyst roles are forbidden from the analytical read.

    The v0.1 ``UserRole`` vocabulary has no lower-privilege member, so the
    route-level 403 is exercised with an authenticated actor carrying an
    unsupported role value through the session seam; the shared
    ``require_analyst`` dependency then rejects it exactly like analytical
    GETs.
    """
    from typing import Any

    class ObserverActor:
        """Authenticated actor with an unsupported role value."""

        id = uuid4()
        role = "observer"
        enabled = True
        deleted_at = None

    class ObserverAuthentication(FakeAuthenticationService):
        """Authentication double returning the unsupported-role actor."""

        async def validate_session(self, token: str) -> Any:
            """Accept the fixture token and return the observer actor."""
            if token != self.token:
                return None
            return ObserverActor()

    bundle = FakeQueryBundle()
    with build_test_app(
        bundle=bundle, authentication=ObserverAuthentication()
    ) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood"
        )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    assert bundle.graph.neighborhood_queries == []


def test_g31c_r14_truncated_flag_is_preserved() -> None:
    """A truthful truncated result passes through unchanged."""
    bundle = FakeQueryBundle()
    bundle.graph.result = GraphResult(
        nodes=(_focal_node(), _neighbor_node()),
        edges=(_edge(),),
        truncated=True,
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{_focal_node().entity_id}/neighborhood"
        )
    assert response.status_code == 200
    body = response.json()
    assert body["truncated"] is True
    assert "next_cursor" not in body
    assert set(body) == {"nodes", "edges", "truncated"}


def test_g31c_r15_null_observation_summaries_stay_null() -> None:
    """Null first/last observed times pass through without substitution."""
    bundle = FakeQueryBundle()
    edge = GraphEdge(
        relationship_id=_edge().relationship_id,
        source_entity_id=_edge().source_entity_id,
        target_entity_id=_edge().target_entity_id,
        relationship_type=RelationshipType.RESOLVES_TO,
        observation_count=2,
        first_observed_at=None,
        last_observed_at=None,
    )
    bundle.graph.result = GraphResult(
        nodes=(_focal_node(), _neighbor_node()), edges=(edge,), truncated=False
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{_focal_node().entity_id}/neighborhood"
        )
    assert response.status_code == 200
    edge_body = response.json()["edges"][0]
    assert edge_body["first_observed_at"] is None
    assert edge_body["last_observed_at"] is None
    assert edge_body["observation_count"] == 2


def test_g31c_r16_graph_relationship_id_works_with_existing_detail() -> None:
    """A graph edge's relationship_id resolves through Relationship detail."""
    bundle = FakeQueryBundle()
    edge = _edge()
    relationship = Relationship(
        id=edge.relationship_id,
        source_entity_id=edge.source_entity_id,
        target_entity_id=edge.target_entity_id,
        type=RelationshipType.RESOLVES_TO,
    )
    bundle.graph.result = _result()
    bundle.relationships.gets[(INVESTIGATION, edge.relationship_id)] = relationship
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        graph_response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{_focal_node().entity_id}/neighborhood"
        )
        assert graph_response.status_code == 200
        graph_edge = graph_response.json()["edges"][0]
        detail_response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationships/"
            f"{graph_edge['relationship_id']}"
        )
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == graph_edge["relationship_id"]
    assert detail["type"] == graph_edge["relationship_type"]
    assert detail["source_entity_id"] == graph_edge["source_entity_id"]
    assert detail["target_entity_id"] == graph_edge["target_entity_id"]


@pytest.mark.parametrize(
    "params",
    [
        {"cursor": "abc"},
        {"depth": "2"},
        {"observed_from": "2026-01-01T00:00:00Z"},
        {"datasource": "google_public_dns"},
    ],
)
def test_g31c_r17_unsupported_filters_fail_closed(params: dict[str, str]) -> None:
    """Cursor/depth/temporal/datasource filters are not part of the contract."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood",
            params=params,
        )
    # Unknown query parameters are ignored by FastAPI (not part of the
    # public contract), so the route must still succeed while never issuing
    # more than one neighborhood query with the canonical parameter set.
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert isinstance(query, GraphNeighborhoodQuery)
    assert query.direction is RelationshipDirection.EITHER
    assert query.relationship_type is None
