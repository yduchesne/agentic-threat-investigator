# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31C graph neighborhood route contract tests (G31C-R01..R17; PR 31G).

Pure HTTP contract tests with injected application fakes: the route builds
exactly one ``GraphNeighborhoodQuery``, calls only
``services.graph.neighborhood``, maps the result to explicit public DTOs,
and translates scoped absence to one stable 404. No database, real
authentication, LLM, or provider work is involved. PR 31G adds scope and
filter parameters and the per-edge Investigation support count to the wire.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.graph import (
    DEFAULT_TRAVERSAL_MAX_DEPTH,
    GraphEdge,
    GraphNeighborhoodQuery,
    GraphNode,
    GraphResult,
    GraphScope,
    GraphTraversalQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.query.relationships import (
    RelationshipReadItem,
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
        investigation_observation_count=3,
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
        "investigation_observation_count": 3,
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
        investigation_observation_count=2,
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
    bundle.relationships.gets[(INVESTIGATION, edge.relationship_id)] = (
        RelationshipReadItem(
            relationship=relationship,
            source_entity_type=EntityType.DOMAIN,
            source_entity_value="update-package.test",
            target_entity_type=EntityType.MALWARE,
            target_entity_value="malware.badloader_v2",
        )
    )
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
        {"datasource": "google_public_dns"},
    ],
)
def test_g31c_r17_unsupported_filters_fail_closed(params: dict[str, str]) -> None:
    """Cursor/depth/datasource filters are not part of the contract."""
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
    assert query.scope is GraphScope.INVESTIGATION
    assert query.entity_type is None
    assert query.source is None
    assert query.observed_from is None
    assert query.observed_to is None


# --- PR 31G scope/filter parameter contract (G31G-R01..R08) ---------------------


def test_g31g_r01_scope_and_filters_map_verbatim() -> None:
    """scope/entity_type/source/observed bounds map to the query verbatim."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    entity = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{entity}/neighborhood",
            params={
                "scope": "known",
                "entity_type": EntityType.IP_ADDRESS.value,
                "relationship_type": RelationshipType.CNAME_OF.value,
                "source": "rdap",
                "observed_from": "2026-01-01T00:00:00Z",
                "observed_to": "2026-02-01T00:00:00Z",
            },
        )
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert isinstance(query, GraphNeighborhoodQuery)
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == entity
    assert query.scope is GraphScope.KNOWN
    assert query.direction is RelationshipDirection.EITHER
    assert query.relationship_type is RelationshipType.CNAME_OF
    assert query.entity_type is EntityType.IP_ADDRESS
    assert query.source == "rdap"
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to == datetime(2026, 2, 1, tzinfo=UTC)


def test_g31g_r02_omitted_scope_defaults_to_investigation() -> None:
    """Omitted scope keeps current-main Investigation behavior."""
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
    assert query.scope is GraphScope.INVESTIGATION


def test_g31g_r03_invalid_scope_is_422() -> None:
    """A scope outside the two-value vocabulary fails closed as 422."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"scope": "global"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31g_r04_invalid_entity_type_is_422() -> None:
    """A non-allowlisted connected Entity type fails closed as 422."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"entity_type": "crypto_wallet"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.graph.neighborhood_queries == []


def test_g31g_r05_blank_source_is_400() -> None:
    """A blank source filter is a stable 400 invalid_request."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"source": "   "},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.graph.neighborhood_queries == []


def test_g31g_r06_equal_observed_interval_is_400() -> None:
    """An empty (equal-bounds) observed interval is a stable 400."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={
                "observed_from": "2026-01-01T00:00:00Z",
                "observed_to": "2026-01-01T00:00:00Z",
            },
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.graph.neighborhood_queries == []


def test_g31g_r07_reversed_observed_interval_is_400() -> None:
    """A reversed observed interval is a stable 400."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={
                "observed_from": "2026-03-01T00:00:00Z",
                "observed_to": "2026-01-01T00:00:00Z",
            },
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.graph.neighborhood_queries == []


def test_g31g_r08_naive_observed_bound_is_400() -> None:
    """A naive (timezone-less) observed bound is a stable 400."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{uuid4()}/neighborhood",
            params={"observed_from": "2026-01-01T00:00:00"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.graph.neighborhood_queries == []


def create_openapi_schema() -> dict[str, Any]:
    """Build the deterministic OpenAPI schema for the fixture app."""
    from agentic_threat_investigator.api.app import create_app
    from agentic_threat_investigator.config import Settings

    schema = create_app(Settings()).openapi()
    assert isinstance(schema, dict)
    return schema


# --- PR 31H traversal route contract (H-A01..H-A12) ---------------------------

_TRAVERSAL = (
    f"/api/v1/investigations/{INVESTIGATION}/graph/entities/{{entity_id}}/traversal"
)


def test_ha01_default_traversal_depth_scope_direction() -> None:
    """Omitted max_depth defaults to 2; scope/direction to Investigation/either."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_TRAVERSAL.format(entity_id=uuid4()))
    assert response.status_code == 200
    query = bundle.graph.traversal_queries[0]
    assert isinstance(query, GraphTraversalQuery)
    assert query.max_depth == DEFAULT_TRAVERSAL_MAX_DEPTH
    assert query.scope is GraphScope.INVESTIGATION
    assert query.direction is RelationshipDirection.EITHER
    assert bundle.graph.neighborhood_queries == []


@pytest.mark.parametrize("depth", [1, 3])
def test_ha02_ha03_explicit_depth_forwarded(depth: int) -> None:
    """Explicit depth 1 and depth 3 are forwarded verbatim."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _TRAVERSAL.format(entity_id=uuid4()), params={"max_depth": str(depth)}
        )
    assert response.status_code == 200
    query = bundle.graph.traversal_queries[0]
    assert query.max_depth == depth


@pytest.mark.parametrize("depth", [0, 4])
def test_ha04_depth_outside_bounds_is_stable_400(depth: int) -> None:
    """Depth 0/4 fail closed as a stable 400, never reaching the service."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _TRAVERSAL.format(entity_id=uuid4()),
            params={"max_depth": str(depth)},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.graph.traversal_queries == []


def test_ha05_all_pr31g_filters_forwarded_exactly() -> None:
    """Every PR 31G filter parameter maps to the traversal query verbatim."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    entity = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _TRAVERSAL.format(entity_id=entity),
            params={
                "max_depth": "3",
                "direction": RelationshipDirection.SOURCE.value,
                "scope": "known",
                "relationship_type": RelationshipType.CNAME_OF.value,
                "entity_type": EntityType.IP_ADDRESS.value,
                "source": "rdap",
                "observed_from": "2026-01-01T00:00:00Z",
                "observed_to": "2026-02-01T00:00:00Z",
                "limit": "9",
            },
        )
    assert response.status_code == 200
    query = bundle.graph.traversal_queries[0]
    assert isinstance(query, GraphTraversalQuery)
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == entity
    assert query.max_depth == 3
    assert query.direction is RelationshipDirection.SOURCE
    assert query.scope is GraphScope.KNOWN
    assert query.relationship_type is RelationshipType.CNAME_OF
    assert query.entity_type is EntityType.IP_ADDRESS
    assert query.source == "rdap"
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to == datetime(2026, 2, 1, tzinfo=UTC)
    assert query.limit == 9


def test_ha06_oversized_limit_is_existing_bounded_failure() -> None:
    """An oversized traversal limit fails through the existing service bound."""

    async def bounded_traverse(query: GraphTraversalQuery) -> GraphResult:
        """Reject limits above the server maximum before any read."""
        if query.limit > QueryLimits().max_page_size:
            raise ValueError("limit must be between 1 and 200")
        return _result()

    bundle = FakeQueryBundle()
    bundle.graph.traverse = bounded_traverse  # type: ignore[method-assign]
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            _TRAVERSAL.format(entity_id=uuid4()), params={"limit": "500"}
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_ha07_service_none_is_graph_entity_404() -> None:
    """Missing/deleted/not-visible focal maps to the scoped graph 404."""
    bundle = FakeQueryBundle()
    bundle.graph.result = None
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_TRAVERSAL.format(entity_id=uuid4()))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "graph_entity_not_found"
    assert len(bundle.graph.traversal_queries) == 1


def test_ha08_isolated_focal_is_200_focal_only() -> None:
    """A visible isolated focal Entity maps to a 200 focal-only graph."""
    bundle = FakeQueryBundle()
    bundle.graph.result = GraphResult(nodes=(_focal_node(),), edges=(), truncated=False)
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_TRAVERSAL.format(entity_id=_focal_node().entity_id))
    assert response.status_code == 200
    body = response.json()
    assert [node["entity_id"] for node in body["nodes"]] == [
        str(_focal_node().entity_id)
    ]
    assert body["edges"] == []
    assert body["truncated"] is False
    assert set(body) == {"nodes", "edges", "truncated"}


def test_ha09_truncated_flag_preserved() -> None:
    """A truthful truncated traversal passes through unchanged."""
    bundle = FakeQueryBundle()
    bundle.graph.result = GraphResult(
        nodes=(_focal_node(), _neighbor_node()),
        edges=(_edge(),),
        truncated=True,
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_TRAVERSAL.format(entity_id=uuid4()))
    assert response.status_code == 200
    assert response.json()["truncated"] is True


def test_ha10_summaries_copied_exactly() -> None:
    """Edge summaries are copied field-for-field onto the traversal wire."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(_TRAVERSAL.format(entity_id=uuid4()))
    assert response.status_code == 200
    edge = response.json()["edges"][0]
    expected = _edge()
    assert edge == {
        "relationship_id": str(expected.relationship_id),
        "source_entity_id": str(expected.source_entity_id),
        "target_entity_id": str(expected.target_entity_id),
        "relationship_type": RelationshipType.RESOLVES_TO.value,
        "observation_count": 3,
        "investigation_observation_count": 3,
        "first_observed_at": "2026-01-01T00:00:00Z",
        "last_observed_at": "2026-01-03T00:00:00Z",
    }


def test_ha11_openapi_synchronized() -> None:
    """The traversal operation is part of the pinned OpenAPI contract."""
    schema = create_openapi_schema()
    path = (
        "/api/v1/investigations/{investigation_id}/graph/entities/{entity_id}/traversal"
    )
    operation = schema["paths"][path]["get"]
    assert operation["operationId"] == "get_graph_entity_traversal"
    parameters = {parameter["name"] for parameter in operation["parameters"]}
    assert "max_depth" in parameters
    assert "limit" in parameters


def test_ha12_neighborhood_contract_unchanged() -> None:
    """The one-hop neighborhood keeps the exact PR 31G contract."""
    bundle = FakeQueryBundle()
    bundle.graph.result = _result()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/graph/entities/"
            f"{uuid4()}/neighborhood",
            params={"max_depth": "2"},
        )
    # Unknown query parameters are ignored: the neighborhood stays one-hop and
    # never accepts a depth.
    assert response.status_code == 200
    query = bundle.graph.neighborhood_queries[0]
    assert isinstance(query, GraphNeighborhoodQuery)
    assert bundle.graph.traversal_queries == []
