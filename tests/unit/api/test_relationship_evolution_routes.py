# SPDX-License-Identifier: AGPL-3.0-only
"""PR 24E relationship route contract tests.

Pure HTTP contract tests with injected application fakes: the new
entity-centric RelationshipObservation filters map exactly to the PR 23A
query DTO (server-side), unsupported combinations fail with the stable
public envelope, and the joined Relationship semantics appear in the public
observation DTO without any invented endpoint. Also covers the one-hop
Relationship ``entity_id`` neighborhood filter used by the graph.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.app.query.relationships import (
    RelationshipObservationItem,
)
from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)

from .conftest import FakeQueryBundle, build_test_app, login_client

INVESTIGATION = UUID("11111111-1111-1111-1111-111111111111")


def _observation_item() -> RelationshipObservationItem:
    """Build one joined observation item fixture."""
    return RelationshipObservationItem(
        id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        relationship_id=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        evidence_id=UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        investigation_id=INVESTIGATION,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        retrieved_at=datetime(2026, 1, 2, tzinfo=UTC),
        source="urn:ati:source:google_public_dns",
        confidence=0.9,
        relationship_source_entity_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        relationship_target_entity_id=UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        relationship_type=RelationshipType.RESOLVES_TO,
    )


def test_entity_filter_maps_to_query_dto() -> None:
    """A valid entity UUID reaches the observation query as the focal entity."""
    bundle = FakeQueryBundle()
    entity = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"entity_id": str(entity)},
        )
    assert response.status_code == 200
    query = bundle.relationship_observations.queries[0]
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == entity
    assert query.direction is None
    assert query.effective_direction() is RelationshipDirection.EITHER


def test_direction_and_counterparty_map_onto_entity() -> None:
    """Direction, counterparty and relationship type map exactly."""
    bundle = FakeQueryBundle()
    entity = uuid4()
    counterparty = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={
                "entity_id": str(entity),
                "direction": "source",
                "counterparty_entity_id": str(counterparty),
                "relationship_type": RelationshipType.RESOLVES_TO.value,
            },
        )
    assert response.status_code == 200
    query = bundle.relationship_observations.queries[0]
    assert query.entity_id == entity
    assert query.direction is RelationshipDirection.SOURCE
    assert query.counterparty_entity_id == counterparty
    assert query.relationship_type is RelationshipType.RESOLVES_TO


def test_all_filters_combined_map_exactly() -> None:
    """Old and new filters compose by intersection on one query DTO."""
    bundle = FakeQueryBundle()
    entity = uuid4()
    counterparty = uuid4()
    relationship_id = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={
                "relationship_id": str(relationship_id),
                "source": "urn:ati:source:google_public_dns",
                "retrieved_from": "2026-01-01T00:00:00Z",
                "retrieved_to": "2026-02-01T00:00:00Z",
                "observed_from": "2026-01-01T00:00:00Z",
                "observed_to": "2026-01-15T00:00:00Z",
                "entity_id": str(entity),
                "direction": "either",
                "counterparty_entity_id": str(counterparty),
                "relationship_type": RelationshipType.CNAME_OF.value,
            },
        )
    assert response.status_code == 200
    query = bundle.relationship_observations.queries[0]
    assert query.relationship_id == relationship_id
    assert query.source == "urn:ati:source:google_public_dns"
    assert query.retrieved_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.retrieved_to == datetime(2026, 2, 1, tzinfo=UTC)
    assert query.observed_from == datetime(2026, 1, 1, tzinfo=UTC)
    assert query.observed_to == datetime(2026, 1, 15, tzinfo=UTC)
    assert query.entity_id == entity
    assert query.direction is RelationshipDirection.EITHER
    assert query.counterparty_entity_id == counterparty
    assert query.relationship_type is RelationshipType.CNAME_OF


def test_invalid_entity_uuid_fails_closed() -> None:
    """A malformed entity UUID is a 422 validation error, never a query."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"entity_id": "not-a-uuid"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.relationship_observations.queries == []


def test_invalid_direction_fails_closed() -> None:
    """A non-allowlisted direction value is a 422 validation error."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"entity_id": str(uuid4()), "direction": "diagonal"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.relationship_observations.queries == []


def test_direction_without_entity_fails_closed() -> None:
    """direction without entity_id is rejected with the stable 400 style."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"direction": "source"},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.relationship_observations.queries == []


def test_counterparty_without_entity_fails_closed() -> None:
    """counterparty_entity_id without entity_id is rejected, never ignored."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"counterparty_entity_id": str(uuid4())},
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert bundle.relationship_observations.queries == []


def test_unknown_relationship_type_fails_closed() -> None:
    """A non-allowlisted relationship type is a 422 validation error."""
    bundle = FakeQueryBundle()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations",
            params={"relationship_type": "urn:ati:relationship:dns:made_up"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert bundle.relationship_observations.queries == []


def test_observation_response_exposes_joined_relationship_semantics() -> None:
    """The public observation DTO carries the joined edge fields (no N+1)."""
    bundle = FakeQueryBundle()
    bundle.relationship_observations.page = QueryPage(
        items=(_observation_item(),), next_cursor=None
    )
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationship-observations"
        )
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["relationship_source_entity_id"] == str(
        _observation_item().relationship_source_entity_id
    )
    assert item["relationship_target_entity_id"] == str(
        _observation_item().relationship_target_entity_id
    )
    assert item["relationship_type"] == RelationshipType.RESOLVES_TO.value
    assert item["observed_at"] == "2026-01-01T00:00:00Z"
    assert item["retrieved_at"] == "2026-01-02T00:00:00Z"
    # No hidden operational fields leak through the joined projection.
    assert "version" not in item
    assert "deleted_at" not in item


def test_relationship_neighborhood_entity_filter_maps() -> None:
    """The one-hop Relationship entity_id filter reaches the Relationships DTO."""
    bundle = FakeQueryBundle()
    entity = uuid4()
    with build_test_app(bundle=bundle) as client:
        login_client(client)
        response = client.get(
            f"/api/v1/investigations/{INVESTIGATION}/relationships",
            params={"entity_id": str(entity)},
        )
    assert response.status_code == 200
    query = bundle.relationships.queries[0]
    assert query.investigation_id == INVESTIGATION
    assert query.entity_id == entity
    assert query.source_entity_id is None
    assert query.target_entity_id is None
