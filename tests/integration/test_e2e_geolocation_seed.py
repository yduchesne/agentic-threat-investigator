# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25C seeder real-PostgreSQL integration proof.

Drives the harness-only seeder against the isolated integration database
through the normal ``PostgresUnitOfWork`` seam, then reads the result
through the real ``PostgresInvestigationGeolocationQueryService`` and the
real authenticated FastAPI ``/geolocations`` endpoint. Behavioral
assertions never query tables directly: the service/API are the read path
an analyst actually uses.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest

from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.geolocation import (
    PostgresInvestigationGeolocationQueryService,
)
from tests.e2e_support.seed_geolocation import (
    PROVIDER,
    apply_seed,
    derive_entity_id,
    derive_evidence_id,
)
from tests.integration.api_helpers import api_client, api_settings, seed_user
from tests.support.query_fixtures import seed_investigation

PASSWORD = "correct horse battery staple"


def _service(uow: PostgresUnitOfWork) -> PostgresInvestigationGeolocationQueryService:
    """Build the real query service over the current session."""
    assert uow.session is not None
    return PostgresInvestigationGeolocationQueryService(uow.session, max_items=100)


def _seed_factory(uow_factory: Any, investigation_id: UUID, scenario: str) -> Any:
    """Run the seeder through fresh Postgres UoWs of the integration session."""
    return apply_seed(uow_factory, investigation_id, scenario)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg01_single_mappable_read_through_service(
    uow_factory: Any,
) -> None:
    """Seeded single mappable data reaches the PR 25A query service."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(uow_factory, investigation_id, "single_mappable")
    assert len(report.created_evidence_ids) == 1

    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(investigation_id)

    assert result.truncated is False
    assert len(result.items) == 1
    item = result.items[0]
    assert item.entity_id == derive_entity_id("203.0.113.10")
    assert item.evidence_id == derive_evidence_id(
        investigation_id, "single_mappable", 0, "203.0.113.10"
    )
    assert item.ip_address == "203.0.113.10"
    assert item.latitude == 47.6062 and item.longitude == -122.3321
    assert item.precision.value == "city"
    assert item.provider == PROVIDER
    assert item.country_code == "US" and item.city == "Seattle"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg02_multi_ioc_distinct_identity_and_order(
    uow_factory: Any,
) -> None:
    """Multiple seeded IPs project as distinct items in canonical order."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(uow_factory, investigation_id, "multi_ioc")
    assert len(report.created_evidence_ids) == 2

    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(investigation_id)

    assert [item.ip_address for item in result.items] == [
        "203.0.113.10",
        "203.0.113.20",
    ]
    assert len({item.entity_id for item in result.items}) == 2
    assert len({item.evidence_id for item in result.items}) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg03_same_coordinate_items_remain_distinct(
    uow_factory: Any,
) -> None:
    """Same-coordinate seeded IPs remain distinct Entity/Evidence rows."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(uow_factory, investigation_id, "same_location")
    assert len(report.created_evidence_ids) == 2

    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 2
    first, second = result.items
    assert first.latitude == second.latitude == 47.6062
    assert first.longitude == second.longitude == -122.3321
    assert first.entity_id != second.entity_id
    assert first.evidence_id != second.evidence_id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg04_coordinate_less_context_retained(uow_factory: Any) -> None:
    """Seeded coordinate-less context remains an actionable read item."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(uow_factory, investigation_id, "non_mappable")
    assert len(report.created_evidence_ids) == 1

    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    item = result.items[0]
    assert item.ip_address == "192.0.2.40"
    assert item.latitude is None and item.longitude is None
    assert item.precision.value == "region"
    assert item.country_code == "US" and item.region == "Oregon"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg05_repeat_invocation_bounded_idempotent(uow_factory: Any) -> None:
    """Re-seeding the same Investigation reuses rows without duplicates."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    first = await _seed_factory(uow_factory, investigation_id, "multi_ioc")
    second = await _seed_factory(uow_factory, investigation_id, "multi_ioc")

    assert len(first.created_evidence_ids) == 2
    assert second.created_evidence_ids == ()
    assert tuple(sorted(second.reused_evidence_ids)) == tuple(
        sorted(first.created_evidence_ids)
    )

    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 2
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg06_cross_investigation_isolation(uow_factory: Any) -> None:
    """Investigation A's seeded rows are never visible in Investigation B."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
    await _seed_factory(uow_factory, investigation_a, "single_mappable")

    async with uow_factory() as uow:
        result_a = await _service(uow).list_for_investigation(investigation_a)
        result_b = await _service(uow).list_for_investigation(investigation_b)

    assert len(result_a.items) == 1
    assert result_b.items == ()
    assert result_b.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sg07_real_http_endpoint_reads_seeded_rows(
    uow_factory: Any, session_factory: Any
) -> None:
    """Authenticated real ``/geolocations`` returns the seeded projection."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(uow_factory, investigation_id, "single_mappable")
    assert len(report.created_evidence_ids) == 1
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
    assert item["evidence_id"] == str(
        derive_evidence_id(investigation_id, "single_mappable", 0, "203.0.113.10")
    )
    assert item["entity_id"] == str(derive_entity_id("203.0.113.10"))
    assert item["ip_address"] == "203.0.113.10"
    assert item["precision"] == "city"
    assert item["provider"] == PROVIDER
    assert item["latitude"] == 47.6062 and item["longitude"] == -122.3321
    for forbidden in ("facts", "raw_payload", "source_record_id"):
        assert forbidden not in response.text
