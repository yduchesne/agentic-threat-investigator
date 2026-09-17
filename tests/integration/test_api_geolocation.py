# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25A vertical slice: real PostgreSQL + FastAPI geolocation projection.

Proves the canonical delivered read path end to end: persisted Entity +
persisted ``GEOLOCATION`` LegacyEvidence -> ``PostgresInvestigationGeolocationQueryService``
-> ``QueryServiceBundle`` -> FastAPI route -> public JSON DTO. No MMDB
lookup or provider execution occurs anywhere: LegacyEvidence is seeded through the
normal repositories exactly as the DB-IP producer path would persist it.
A second slice proves strict Investigation isolation through the HTTP
boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.legacy_evidence import EntityRef, LegacyEvidence
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    seed_user,
)
from tests.support.query_fixtures import (
    evidence_factory,
    seed_entity,
    seed_investigation,
)

PROVIDER = "urn:ati:source:dbip_city_lite"
FIXED = datetime(2026, 1, 1, tzinfo=UTC)
PASSWORD = "correct horse battery staple"


def _geolocation_evidence(
    investigation_id: UUID, entity_id: UUID, *, facts: dict[str, object] | None = None
) -> LegacyEvidence:
    """Build one persisted GEOLOCATION LegacyEvidence observation."""
    return LegacyEvidence(
        investigation_id=investigation_id,
        type=EvidenceType.GEOLOCATION,
        subject=EntityRef(
            id=entity_id, type=EntityType.IP_ADDRESS, value="203.0.113.10"
        ),
        source=PROVIDER,
        observed_at=None,
        retrieved_at=FIXED,
        facts=facts
        or {
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6062,
            "longitude": -122.3321,
            "provider": PROVIDER,
            "precision": "city",
        },
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v01_canonical_read_projection_slice(
    uow_factory: Any, session_factory: Any
) -> None:
    """A persisted IP + GEOLOCATION LegacyEvidence reaches the public JSON DTO."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        record = await uow.evidence.insert(
            _geolocation_evidence(investigation_id, entity_id)
        )
        # A raw-payload-bearing non-geolocation LegacyEvidence must never enter the
        # projection or the response.
        await uow.evidence.insert(
            evidence_factory(investigation_id, entity_id).model_copy(
                update={
                    "raw_payload": {"http_response": {"body": "secret"}},
                }
            )
        )
        assert record.id is not None
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": PASSWORD},
        )
        response = client.get(f"/api/v1/investigations/{investigation_id}/geolocations")

    assert response.status_code == 200
    body = response.json()
    assert body["truncated"] is False
    assert len(body["items"]) == 1
    (item,) = body["items"]
    assert item["evidence_id"] == str(record.id)
    assert item["entity_id"] == str(entity_id)
    assert item["ip_address"] == "203.0.113.10"
    assert item["country_code"] == "US"
    assert item["region"] == "Washington"
    assert item["city"] == "Seattle"
    assert item["latitude"] == 47.6062
    assert item["longitude"] == -122.3321
    assert item["precision"] == "city"
    assert item["provider"] == PROVIDER
    assert item["observed_at"] is None
    assert item["retrieved_at"]
    for forbidden in ("facts", "raw_payload", "source_record_id", "mmdb"):
        assert forbidden not in response.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_v02_http_investigation_isolation(
    uow_factory: Any, session_factory: Any
) -> None:
    """Each Investigation's HTTP projection is strictly scope-isolated."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        shared = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        evidence_a = await uow.evidence.insert(
            _geolocation_evidence(
                investigation_a,
                shared,
                facts={
                    "country_code": "CA",
                    "city": "Vancouver",
                    "provider": PROVIDER,
                    "precision": "city",
                },
            )
        )
        evidence_b = await uow.evidence.insert(
            _geolocation_evidence(
                investigation_b,
                shared,
                facts={
                    "country_code": "DE",
                    "city": "Berlin",
                    "provider": PROVIDER,
                    "precision": "city",
                },
            )
        )
        assert evidence_a.id is not None and evidence_b.id is not None
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": PASSWORD},
        )
        response_a = client.get(
            f"/api/v1/investigations/{investigation_a}/geolocations"
        )
        response_b = client.get(
            f"/api/v1/investigations/{investigation_b}/geolocations"
        )

    assert response_a.status_code == response_b.status_code == 200
    (item_a,) = response_a.json()["items"]
    (item_b,) = response_b.json()["items"]
    assert item_a["evidence_id"] == str(evidence_a.id)
    assert item_b["evidence_id"] == str(evidence_b.id)
    assert item_a["city"] == "Vancouver"
    assert item_b["city"] == "Berlin"
    assert item_a["entity_id"] == item_b["entity_id"] == str(shared)
