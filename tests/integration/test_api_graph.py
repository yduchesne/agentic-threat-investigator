# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31C PostgreSQL-backed API graph vertical slice (G31C-I01..I10).

Every test exercises the real FastAPI application, real authentication,
request-scoped ``PostgresQueryServices``, the PostgreSQL graph query, and the
public DTO mapper over real ``/api/v1`` HTTP:

``HTTP -> graph route -> QueryServices -> PostgresGraphQueryService
     -> PostgreSQL -> GraphResult -> mapper -> public DTO``

GraphQueryService is never faked here; the shared synthetic seeding helpers
provide the durable graph state.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from agentic_threat_investigator.domain.relationships import (
    RelationshipDirection,
    RelationshipType,
)
from tests.integration.api_helpers import api_client, api_settings, seed_user
from tests.support.query_fixtures import (
    FIXED_TIME,
    seed_entity,
    seed_evidence_observation,
    seed_investigation,
    seed_observation,
    seed_relationship,
)


def _neighborhood_url(investigation_id: Any, entity_id: Any) -> str:
    """Return the canonical graph neighborhood URL for the two identities."""
    return (
        f"/api/v1/investigations/{investigation_id}/graph/entities/{entity_id}"
        "/neighborhood"
    )


def _login(client: Any) -> None:
    """Authenticate the seeded analyst with the fixture credentials."""
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "alice",
            "password": "correct horse battery staple",
        },
    )
    assert login.status_code == 200


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i01_visible_focal_with_admitted_edge_returns_200(
    session_factory: Any,
) -> None:
    """A visible focal Entity with an admitted edge returns both nodes + edge."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        for _ in range(2):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(_neighborhood_url(investigation_id, focal))

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"nodes", "edges", "truncated"}
    assert body["truncated"] is False
    node_ids = {node["entity_id"] for node in body["nodes"]}
    assert node_ids == {str(edge.source_entity_id), str(edge.target_entity_id)}
    assert len(body["edges"]) == 1
    edge_body = body["edges"][0]
    assert edge_body["relationship_id"] == str(edge.id)
    assert edge_body["source_entity_id"] == str(focal)
    assert edge_body["target_entity_id"] == str(target)
    assert edge_body["relationship_type"] == RelationshipType.RESOLVES_TO.value
    assert edge_body["observation_count"] == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i02_source_direction_returns_outgoing_only(
    session_factory: Any,
) -> None:
    """direction=source selects only outgoing edges through the real query."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        outgoing_target = await seed_entity(uow, value="192.0.2.1")
        incoming_source = await seed_entity(uow, value="other.example.net")
        for source, target in ((focal, outgoing_target), (incoming_source, focal)):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            edge = await seed_relationship(
                uow, source_entity_id=source, target_entity_id=target
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(
            _neighborhood_url(investigation_id, focal),
            params={"direction": RelationshipDirection.SOURCE.value},
        )

    assert response.status_code == 200
    body = response.json()
    assert len(body["edges"]) == 1
    assert body["edges"][0]["source_entity_id"] == str(focal)
    assert body["edges"][0]["target_entity_id"] == str(outgoing_target)
    node_ids = {node["entity_id"] for node in body["nodes"]}
    assert str(incoming_source) not in node_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i03_target_direction_returns_incoming_only(
    session_factory: Any,
) -> None:
    """direction=target selects only incoming edges through the real query."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        outgoing_target = await seed_entity(uow, value="192.0.2.1")
        incoming_source = await seed_entity(uow, value="other.example.net")
        for source, target in ((focal, outgoing_target), (incoming_source, focal)):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            edge = await seed_relationship(
                uow, source_entity_id=source, target_entity_id=target
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(
            _neighborhood_url(investigation_id, focal),
            params={"direction": RelationshipDirection.TARGET.value},
        )

    assert response.status_code == 200
    body = response.json()
    assert len(body["edges"]) == 1
    assert body["edges"][0]["source_entity_id"] == str(incoming_source)
    assert body["edges"][0]["target_entity_id"] == str(focal)
    node_ids = {node["entity_id"] for node in body["nodes"]}
    assert str(outgoing_target) not in node_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i04_relationship_type_filter_returns_matching_edges(
    session_factory: Any,
) -> None:
    """relationship_type narrows the real query to the canonical URN only."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target_a = await seed_entity(uow, value="192.0.2.1")
        target_b = await seed_entity(uow, value="192.0.2.2")
        edge_a = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target_a
        )
        edge_b = await seed_relationship(
            uow,
            source_entity_id=focal,
            target_entity_id=target_b,
            relationship_type=RelationshipType.CNAME_OF,
        )
        for edge in (edge_a, edge_b):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(
            _neighborhood_url(investigation_id, focal),
            params={"relationship_type": RelationshipType.CNAME_OF.value},
        )

    assert response.status_code == 200
    body = response.json()
    assert [edge["relationship_id"] for edge in body["edges"]] == [str(edge_b.id)]
    node_ids = {node["entity_id"] for node in body["nodes"]}
    assert str(target_a) not in node_ids
    assert str(target_b) in node_ids


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i05_cross_investigation_focal_is_scoped_404(
    session_factory: Any,
) -> None:
    """A focal visible in Investigation B under A maps to the scoped 404."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_b, entity_id=focal
        )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(_neighborhood_url(investigation_a, focal))

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "graph_entity_not_found"
    assert "example.com" not in response.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i06_visible_isolated_focal_returns_200_focal_only(
    session_factory: Any,
) -> None:
    """A visible focal Entity with no edges is a 200 focal-only graph."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(_neighborhood_url(investigation_id, focal))

    assert response.status_code == 200
    body = response.json()
    assert [node["entity_id"] for node in body["nodes"]] == [str(focal)]
    assert body["edges"] == []
    assert body["truncated"] is False
    assert body["nodes"][0]["value"] == "example.com"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i07_multiple_observations_aggregate_to_one_edge(
    session_factory: Any,
) -> None:
    """Repeated admitted observations yield one edge with exact summaries."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        first = FIXED_TIME
        last = FIXED_TIME + timedelta(days=2)
        for observed_at in (first, None, last):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
                observed_at=observed_at,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(_neighborhood_url(investigation_id, focal))

    assert response.status_code == 200
    edge_body = response.json()["edges"][0]
    assert edge_body["observation_count"] == 3
    assert edge_body["first_observed_at"] == "2026-01-01T00:00:00Z"
    assert edge_body["last_observed_at"] == "2026-01-03T00:00:00Z"
    assert len(response.json()["edges"]) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i08_relationship_id_resolves_through_existing_detail(
    session_factory: Any,
) -> None:
    """The graph edge's relationship_id works with the Relationship detail."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow,
            source_entity_id=focal,
            target_entity_id=target,
            relationship_type=RelationshipType.REGISTERED_TO,
        )
        evidence = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=focal
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence,
        )

    with api_client(api_settings()) as client:
        _login(client)
        graph_response = client.get(_neighborhood_url(investigation_id, focal))
        assert graph_response.status_code == 200
        graph_edge = graph_response.json()["edges"][0]
        detail_response = client.get(
            f"/api/v1/investigations/{investigation_id}/relationships/"
            f"{graph_edge['relationship_id']}"
        )

    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == graph_edge["relationship_id"]
    assert detail["type"] == RelationshipType.REGISTERED_TO.value
    assert detail["source_entity_id"] == str(focal)
    assert detail["target_entity_id"] == str(target)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i09_relationship_id_filters_observation_list(
    session_factory: Any,
) -> None:
    """The graph relationship_id retrieves supporting observations."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        target = await seed_entity(uow, value="192.0.2.1")
        edge = await seed_relationship(
            uow, source_entity_id=focal, target_entity_id=target
        )
        for _ in range(2):
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        graph_response = client.get(_neighborhood_url(investigation_id, focal))
        assert graph_response.status_code == 200
        graph_edge = graph_response.json()["edges"][0]
        observations = client.get(
            f"/api/v1/investigations/{investigation_id}/relationship-observations",
            params={"relationship_id": graph_edge["relationship_id"]},
        )

    assert observations.status_code == 200
    items = observations.json()["items"]
    assert len(items) == 2
    assert all(
        item["relationship_id"] == graph_edge["relationship_id"] for item in items
    )
    assert items[0]["relationship_source_entity_id"] == str(focal)
    assert items[0]["relationship_type"] == RelationshipType.RESOLVES_TO.value


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i10_small_limit_returns_truncated_without_cursor(
    session_factory: Any,
) -> None:
    """A small limit with extra edges returns truncated=true and no cursor."""
    await seed_user(session_factory)
    from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
        PostgresUnitOfWork,
    )

    async with PostgresUnitOfWork(session_factory) as uow:
        investigation_id = await seed_investigation(uow)
        focal = await seed_entity(uow, value="example.com")
        for index in range(2):
            target = await seed_entity(uow, value=f"192.0.2.{index + 1}")
            edge = await seed_relationship(
                uow, source_entity_id=focal, target_entity_id=target
            )
            evidence = await seed_evidence_observation(
                uow, investigation_id=investigation_id, entity_id=focal
            )
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                relationship=edge,
                evidence_observation_id=evidence,
            )

    with api_client(api_settings()) as client:
        _login(client)
        response = client.get(
            _neighborhood_url(investigation_id, focal), params={"limit": "1"}
        )

    assert response.status_code == 200
    body = response.json()
    assert len(body["edges"]) == 1
    assert body["truncated"] is True
    assert set(body) == {"nodes", "edges", "truncated"}
    assert "next_cursor" not in body
    assert "cursor" not in body
