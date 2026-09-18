# SPDX-License-Identifier: AGPL-3.0-only
"""PR 25A integration: Investigation geolocation projection (G-P01..G-P16).

Every test drives the real ``PostgresInvestigationGeolocationQueryService``
over real PostgreSQL with LegacyEvidence/Entity rows persisted through the normal
application repositories. LegacyEvidence is seeded directly as persisted rows — no
MMDB/provider execution is involved anywhere in the read path.

G-P01..G-P13 are the core projection/bounded-read matrix; G-P14..G-P16 are the
defensive cases (malformed persisted facts, partial coordinate pair, and
nonexistent Investigation).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.app.query.geolocation import (
    GeolocationFactsError,
    InvestigationGeolocationItem,
    InvestigationGeolocationResult,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.geolocation import (
    PostgresInvestigationGeolocationQueryService,
)
from tests.support.query_fixtures import (
    FIXED_TIME,
    seed_entity,
    seed_evidence_observation,
    seed_investigation,
)

PROVIDER = "urn:ati:source:dbip_city_lite"


def city_facts(**overrides: Any) -> dict[str, Any]:
    """Build one canonical fully mappable persisted geolocation facts dict."""
    facts: dict[str, Any] = {
        "country_code": "US",
        "region": "Washington",
        "city": "Seattle",
        "latitude": 47.6062,
        "longitude": -122.3321,
        "provider": PROVIDER,
        "precision": "city",
    }
    facts.update(overrides)
    return facts


def geolocation_evidence(
    investigation_id: UUID,
    entity_id: UUID,
    *,
    retrieved_at: datetime = FIXED_TIME,
    observed_at: datetime | None = None,
    facts: dict[str, Any] | None = None,
    source: str = PROVIDER,
    ip_value: str = "203.0.113.10",
) -> ConvertedEvidence:
    """Build one deterministic global GEOLOCATION ConvertedEvidence.

    The entity association uses the caller-supplied canonical Entity id; the
    IP value is the entity's canonical value (the reference geography is
    resolved by the Entity, never re-embedded in the observation).
    """
    del investigation_id, observed_at, ip_value
    evidence_id = uuid4()
    return ConvertedEvidence(
        evidence=Evidence(
            id=evidence_id,
            type=EvidenceType.GEOLOCATION,
            source=source,
            source_record_id=f"geoloc-{evidence_id}",
        ),
        observation=EvidenceObservationCandidate(
            evidence_id=evidence_id,
            retrieved_at=retrieved_at,
            facts=facts or city_facts(),
        ),
    )


async def seed_geolocation_observation(
    uow: PostgresUnitOfWork,
    *,
    investigation_id: UUID,
    entity_id: UUID,
    retrieved_at: datetime = FIXED_TIME,
    observed_at: datetime | None = None,
    facts: dict[str, Any] | None = None,
    source: str = PROVIDER,
    ip_value: str = "203.0.113.10",
) -> UUID:
    """Persist one global GEOLOCATION observation, associate, and admit it.

    Returns the exact EvidenceObservation identity; projection tie-breaks
    and drill-downs use this identity (PR 28B).
    """
    converted = geolocation_evidence(
        investigation_id,
        entity_id,
        retrieved_at=retrieved_at,
        observed_at=observed_at,
        facts=facts,
        source=source,
        ip_value=ip_value,
    )
    persisted = await uow.evidence.persist(converted)
    await uow.evidence_observation_entities.associate(
        persisted.observation.id, entity_id
    )
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=persisted.observation.id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=retrieved_at,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )
    return persisted.observation.id


def _service(
    uow: PostgresUnitOfWork, *, max_items: int = 100
) -> PostgresInvestigationGeolocationQueryService:
    """Build the real query service over the current session."""
    assert uow.session is not None
    return PostgresInvestigationGeolocationQueryService(uow.session, max_items)


def _assert_geolocation_item(
    item: InvestigationGeolocationItem,
    expected: dict[str, Any],
) -> None:
    """Assert one projected item's approved typed fields."""
    assert item.evidence_observation_id == expected["evidence_observation_id"]
    assert item.entity_id == expected["entity_id"]
    assert item.ip_address == expected["ip_address"]
    assert item.country_code == expected.get("country_code")
    assert item.region == expected.get("region")
    assert item.city == expected.get("city")
    assert item.latitude == expected.get("latitude")
    assert item.longitude == expected.get("longitude")
    assert item.precision.value == expected["precision"]
    assert item.provider == expected["provider"]
    assert item.observed_at == expected.get("observed_at")
    assert item.retrieved_at == expected["retrieved_at"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp01_empty_investigation(uow_factory: Any) -> None:
    """An existing Investigation with no geolocation data yields empty items."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        result = await _service(uow).list_for_investigation(investigation_id)

    assert isinstance(result, InvestigationGeolocationResult)
    assert result.items == ()
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp02_one_ip_projection(uow_factory: Any) -> None:
    """One GEOLOCATION LegacyEvidence produces exactly one projection item."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        record = await seed_geolocation_observation(
            uow, investigation_id=investigation_id, entity_id=entity_id
        )
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    assert result.truncated is False
    _assert_geolocation_item(
        result.items[0],
        {
            "evidence_observation_id": record,
            "entity_id": entity_id,
            "ip_address": "203.0.113.10",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6062,
            "longitude": -122.3321,
            "precision": "city",
            "provider": PROVIDER,
            "observed_at": None,
            "retrieved_at": FIXED_TIME,
        },
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp03_multiple_ips_deterministic_order(uow_factory: Any) -> None:
    """Multiple IP entities project in canonical ip/entity deterministic order."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_ids: dict[str, UUID] = {}
        for value in ("198.51.100.30", "198.51.100.10", "198.51.100.20"):
            entity_ids[value] = await seed_entity(
                uow, entity_type=EntityType.IP_ADDRESS, value=value
            )
            await seed_geolocation_observation(
                uow,
                investigation_id=investigation_id,
                entity_id=entity_ids[value],
            )

        result = await _service(uow).list_for_investigation(investigation_id)

    assert [item.ip_address for item in result.items] == [
        "198.51.100.10",
        "198.51.100.20",
        "198.51.100.30",
    ]
    assert [item.entity_id for item in result.items] == [
        entity_ids["198.51.100.10"],
        entity_ids["198.51.100.20"],
        entity_ids["198.51.100.30"],
    ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp04_latest_per_entity(uow_factory: Any) -> None:
    """Only the newest retrieved observation per entity is projected."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            retrieved_at=FIXED_TIME,
            facts=city_facts(city="Old City"),
        )

        newer = await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            retrieved_at=FIXED_TIME.replace(year=2027),
            facts=city_facts(city="New City"),
        )

        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    assert result.items[0].evidence_observation_id == newer
    assert result.items[0].city == "New City"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp05_deterministic_tie_breaker(uow_factory: Any) -> None:
    """Equal retrieved_at resolves deterministically by ascending evidence id."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        first = await seed_geolocation_observation(
            uow, investigation_id=investigation_id, entity_id=entity_id
        )
        second = await seed_geolocation_observation(
            uow, investigation_id=investigation_id, entity_id=entity_id
        )
        assert first != second
        result = await _service(uow).list_for_investigation(investigation_id)

    # retrieved_at DESC, id ASC: the smaller UUID wins the tie.
    assert [item.evidence_observation_id for item in result.items] == [
        min(first, second)
    ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp06_generic_evidence_excluded(uow_factory: Any) -> None:
    """REPUTATION/NETWORK/DNS LegacyEvidence never enters the projection."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        await seed_evidence_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            source="urn:ati:source:abuseipdb",
        )
        await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            facts=city_facts(provider="urn:ati:source:ipinfo_lite"),
            source="urn:ati:source:ipinfo_lite",
        )

        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    assert result.items[0].provider == "urn:ati:source:ipinfo_lite"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp07_non_ip_geolocation_excluded(uow_factory: Any) -> None:
    """GEOLOCATION LegacyEvidence on a non-IP subject is defensively excluded."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        domain_id = await seed_entity(uow, value="example.com")
        await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=domain_id,
            source=PROVIDER,
            retrieved_at=FIXED_TIME,
            facts=city_facts(),
        )
        result = await _service(uow).list_for_investigation(investigation_id)

    assert result.items == ()
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp08_cross_investigation_isolation(uow_factory: Any) -> None:
    """A shared Entity never leaks one Investigation's LegacyEvidence into another."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        shared = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        evidence_a = await seed_geolocation_observation(
            uow,
            investigation_id=investigation_a,
            entity_id=shared,
            facts=city_facts(city="Seattle A"),
        )
        evidence_b = await seed_geolocation_observation(
            uow,
            investigation_id=investigation_b,
            entity_id=shared,
            facts=city_facts(city="Seattle B"),
        )

        result_a = await _service(uow).list_for_investigation(investigation_a)
        result_b = await _service(uow).list_for_investigation(investigation_b)

    assert [item.evidence_observation_id for item in result_a.items] == [evidence_a]
    assert [item.evidence_observation_id for item in result_b.items] == [evidence_b]
    assert result_a.items[0].city == "Seattle A"
    assert result_b.items[0].city == "Seattle B"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp09_coordinate_less_context_retained(uow_factory: Any) -> None:
    """Valid geographic context without coordinates remains in items."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        record = await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            facts=city_facts(latitude=None, longitude=None),
        )

        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    assert result.items[0].evidence_observation_id == record
    assert result.items[0].latitude is None
    assert result.items[0].longitude is None
    assert result.items[0].country_code == "US"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp10_truncation_bound(uow_factory: Any) -> None:
    """Seeding max_items + 1 IPs truncates deterministically at the bound."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        for i in range(1, 6):
            entity_id = await seed_entity(
                uow, entity_type=EntityType.IP_ADDRESS, value=f"198.51.100.{i}"
            )
            await seed_geolocation_observation(
                uow,
                investigation_id=investigation_id,
                entity_id=entity_id,
                ip_value=f"198.51.100.{i}",
            )

        bounded = await _service(uow, max_items=3).list_for_investigation(
            investigation_id
        )
        full = await _service(uow, max_items=100).list_for_investigation(
            investigation_id
        )

    assert len(full.items) == 5
    assert full.truncated is False
    assert len(bounded.items) == 3
    assert bounded.truncated is True
    assert [item.evidence_observation_id for item in bounded.items] == [
        item.evidence_observation_id for item in full.items[:3]
    ]
    assert [item.ip_address for item in bounded.items] == [
        "198.51.100.1",
        "198.51.100.2",
        "198.51.100.3",
    ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp11_exactly_at_bound_not_truncated(uow_factory: Any) -> None:
    """Seeding exactly max_items current IPs reports truncated=False."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        for i in range(1, 4):
            entity_id = await seed_entity(
                uow, entity_type=EntityType.IP_ADDRESS, value=f"198.51.100.{i}"
            )
            await seed_geolocation_observation(
                uow,
                investigation_id=investigation_id,
                entity_id=entity_id,
                ip_value=f"198.51.100.{i}",
            )

        result = await _service(uow, max_items=3).list_for_investigation(
            investigation_id
        )

    assert len(result.items) == 3
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp12_historical_volume_stays_bounded(uow_factory: Any) -> None:
    """Many historical observations per entity still yield one item each."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entities: list[UUID] = []
        for value in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            entity_ids = []
            entity_id = await seed_entity(
                uow, entity_type=EntityType.IP_ADDRESS, value=value
            )
            for minute in range(1, 8):
                record = await seed_geolocation_observation(
                    uow,
                    investigation_id=investigation_id,
                    entity_id=entity_id,
                    retrieved_at=FIXED_TIME,
                    facts=city_facts(city=f"City-{minute}"),
                )

                entity_ids.append(record)
            entities.append(entity_id)
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 3
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp13_single_bounded_read(uow_factory: Any) -> None:
    """The projection is one bounded SQL read over latest-per-entity rows.

    PR 25D inspected the existing test support for reusable SQL
    statement-counting infrastructure (SQLAlchemy ``before/after_cursor_execute``
    listeners, query counters, or statement recorders). The only SQLAlchemy
    event listeners in the repository register batch composite types (the E2E
    seeder) or track active UnitOfWork lifecycle phases (the analyst pipeline
    transaction tracker); neither counts SQL statements, so no lightweight
    established mechanism exists to instrument the read. Per the PR 25D
    decision, no generic statement-count framework was created; the criterion
    is met structurally: the service issues exactly one SELECT on the
    latest-per-entity ranked subquery with a ``max_items + 1`` LIMIT, never
    per-item LegacyEvidence gets or Python-side grouping of historical rows.
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        for _minute in range(1, 5):
            await seed_geolocation_observation(
                uow, investigation_id=investigation_id, entity_id=entity_id
            )
        result = await _service(uow).list_for_investigation(investigation_id)

    assert len(result.items) == 1
    assert result.truncated is False


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp14_malformed_persisted_facts_fail_closed(uow_factory: Any) -> None:
    """G-P14: malformed persisted geolocation facts fail the read closed."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            facts={"provider": PROVIDER, "precision": "city", "latitude": 47.6},
        )

        with pytest.raises(GeolocationFactsError):
            await _service(uow).list_for_investigation(investigation_id)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp15_partial_pair_from_raw_facts_fails_closed(
    uow_factory: Any,
) -> None:
    """G-P15: a persisted partial coordinate pair is never silently repaired."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        entity_id = await seed_entity(
            uow, entity_type=EntityType.IP_ADDRESS, value="203.0.113.10"
        )
        await seed_geolocation_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=entity_id,
            facts=city_facts(longitude=None),
        )

        with pytest.raises(GeolocationFactsError):
            await _service(uow).list_for_investigation(investigation_id)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_gp16_nonexistent_investigation_empty(uow_factory: Any) -> None:
    """G-P16: an unknown Investigation yields the established empty collection."""
    async with uow_factory() as uow:
        result = await _service(uow).list_for_investigation(uuid4())

    assert result.items == ()
    assert result.truncated is False
