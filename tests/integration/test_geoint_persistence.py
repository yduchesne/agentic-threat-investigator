# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26A/26A-2 GEOINT persistence matrices on real PostgreSQL.

PR 26A matrix (G26A-P01..P34): published foundation — canonical Location
identity, immutable EntityLocationObservation provenance, database-maintained
EntityLocation current state with deterministic reconciliation, initial
pending GeoResolution work — through the versioned SQL API v0021 with typed
SQLSTATE mapping and thin repositories.

PR 26A-2 corrective matrix (G26A2-P01..P05): proves on real PostgreSQL that
``ati.entity_location.version`` is consistently database-sequence allocated
(``ati.entity_location_version_seq``) on creation and every actual
current-state mutation — never arithmetic ``target.version + 1`` — with
sequence gaps valid, no-op history leaving the persisted version unchanged,
and rollback preserving the prior persisted version.
"""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.persistence.repositories import (
    EntityLocationObservationDuplicateError,
    GeoEntityNotFoundError,
    GeoEvidenceNotFoundError,
    GeoEvidenceSubjectMismatchError,
    GeoEvidenceTypeError,
    GeoInvalidInputError,
    GeoLocationNotFoundError,
    LocationIdentityConflictError,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
)
from agentic_threat_investigator.domain.geoint import (
    EntityLocationObservation,
    GeoResolution,
    GeoResolutionStatus,
    Location,
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)

pytestmark = pytest.mark.integration

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def location_factory(
    *,
    location_type: LocationType = LocationType.COUNTRY,
    name: str = "United States",
    canonical_name: str = "United States",
    country_code: str = "US",
    admin1_code: str | None = None,
    admin2_code: str | None = None,
    parent_location_id: UUID | None = None,
    id: UUID | None = None,
) -> Location:
    """Build a deterministic valid Location fixture."""
    return Location(
        id=id,
        type=location_type,
        name=name,
        canonical_name=canonical_name,
        country_code=country_code,
        admin1_code=admin1_code,
        admin2_code=admin2_code,
        parent_location_id=parent_location_id,
    )


async def seed_geolocation_evidence(
    uow: PostgresUnitOfWork,
) -> tuple[UUID, UUID, UUID, UUID]:
    """Create one investigation, an IP Entity, and GEOLOCATION LegacyEvidence.

    Returns (investigation_id, ip_entity_id, domain_entity_id, evidence_id).
    The domain Entity exists for the LegacyEvidence-subject-mismatch tests.
    """
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    ip_entity = await uow.entities.upsert(
        Entity(type=EntityType.IP_ADDRESS, value="203.0.113.7")
    )
    domain_entity = await uow.entities.upsert(
        Entity(type=EntityType.DOMAIN, value="example.com")
    )
    assert ip_entity.id is not None and domain_entity.id is not None
    evidence_id = uuid4()
    persisted = await uow.evidence.persist(
        ConvertedEvidence(
            evidence=Evidence(
                id=evidence_id,
                type=EvidenceType.GEOLOCATION,
                source="urn:ati:source:dbip",
                source_record_id=f"gp-{evidence_id}",
            ),
            observation=EvidenceObservationCandidate(
                evidence_id=evidence_id,
                retrieved_at=_RETRIEVED_AT,
                facts={"country_code": "US", "city": "Example City"},
            ),
        )
    )
    await uow.evidence_observation_entities.associate(
        persisted.observation.id, ip_entity.id
    )
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=persisted.observation.id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=_RETRIEVED_AT,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )
    return investigation_id, ip_entity.id, domain_entity.id, persisted.observation.id


def observation_factory(
    *,
    id: UUID | None = None,
    entity_id: UUID,
    location_id: UUID,
    evidence_observation_id: UUID,
    precision: LocationPrecision = LocationPrecision.COUNTRY,
    retrieved_at: datetime = _RETRIEVED_AT,
    observed_at: datetime | None = None,
    resolution_method: str = "test_method",
) -> EntityLocationObservation:
    """Build a deterministic immutable observation fixture."""
    return EntityLocationObservation(
        id=id or uuid4(),
        entity_id=entity_id,
        location_id=location_id,
        evidence_observation_id=evidence_observation_id,
        precision=precision,
        observed_at=observed_at,
        retrieved_at=retrieved_at,
        resolved_at=retrieved_at,
        resolution_method=resolution_method,
    )


async def table_count(uow: PostgresUnitOfWork, table: str) -> int:
    """Count every row of one application table in the active UoW."""
    assert uow.session is not None
    result = await uow.session.execute(text(f"SELECT count(*) FROM ati.{table}"))
    return int(result.scalar_one())


# --------------------------------------------------------------------------
# Location matrix (G26A-P01..P08)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gp01_country_location_round_trips(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P01 a country Location persists and round-trips authoritatively."""
    async with uow_factory() as uow:
        country = location_factory()
        persisted = await uow.locations.upsert(country)
        assert persisted.id is not None
        assert persisted.version is not None
        assert persisted.created_at is not None and persisted.updated_at is not None
        assert persisted.type is LocationType.COUNTRY
        assert persisted.country_code == "US"
        assert persisted.parent_location_id is None
        fetched = await uow.locations.get_by_id(persisted.id)
        assert fetched == persisted


@pytest.mark.asyncio
async def test_gp02_administrative_area_parent_and_admin1_enforced(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P02 an administrative-area Location requires parent + admin1."""
    async with uow_factory() as uow:
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        area = await uow.locations.upsert(
            location_factory(
                location_type=LocationType.ADMINISTRATIVE_AREA,
                name="California",
                canonical_name="California",
                admin1_code="CA",
                parent_location_id=country.id,
            )
        )
        assert area.id is not None and area.admin1_code == "CA"
        assert area.parent_location_id == country.id
        # The shape constraint is also enforced database-side for direct SQL.
        assert uow.session is not None
        with pytest.raises(IntegrityError):
            await uow.session.execute(
                text("""
                    INSERT INTO ati.location (
                        location_type, name, canonical_name, country_code,
                        version)
                    VALUES ('administrative_area', 'Broken', 'Broken', 'US', 1)
                """)
            )


@pytest.mark.asyncio
async def test_gp03_city_parent_and_admin1_enforced(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P03 a city Location requires parent + admin1; admin2 stays optional."""
    async with uow_factory() as uow:
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        area = await uow.locations.upsert(
            location_factory(
                location_type=LocationType.ADMINISTRATIVE_AREA,
                name="California",
                canonical_name="California",
                admin1_code="CA",
                parent_location_id=country.id,
            )
        )
        assert area.id is not None
        city = await uow.locations.upsert(
            location_factory(
                location_type=LocationType.CITY,
                name="San Francisco",
                canonical_name="San Francisco",
                admin1_code="CA",
                admin2_code="075",
                parent_location_id=area.id,
            )
        )
        assert city.id is not None
        assert city.admin2_code == "075"
        city_without_admin2 = await uow.locations.upsert(
            location_factory(
                location_type=LocationType.CITY,
                name="Oakland",
                canonical_name="Oakland",
                admin1_code="CA",
                parent_location_id=area.id,
            )
        )
        assert city_without_admin2.id is not None
        assert city_without_admin2.admin2_code is None


@pytest.mark.asyncio
async def test_gp04_same_canonical_identity_reuses_without_version_churn(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P04 the same canonical identity reuses one Location, no version churn."""
    async with uow_factory() as uow:
        first = await uow.locations.upsert(location_factory())
        second = await uow.locations.upsert(location_factory())
        assert first.id == second.id
        assert first.version == second.version
        assert await table_count(uow, "location") == 1


@pytest.mark.asyncio
async def test_gp05_concurrent_same_identity_upsert_yields_one_row(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P05 concurrent same-identity upserts produce one canonical row."""

    async def _upsert() -> Location:
        """Upsert the canonical Location in an independent committed UoW."""
        async with uow_factory() as uow:
            return await uow.locations.upsert(location_factory())

    created_a, created_b = await asyncio.gather(_upsert(), _upsert())
    assert created_a.id == created_b.id
    assert created_a.id is not None
    async with uow_factory() as uow:
        assert await table_count(uow, "location") == 1


@pytest.mark.asyncio
async def test_gp06_incompatible_duplicate_canonical_state_fails_atomically(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P06 incompatible state for one canonical identity fails atomically."""
    async with uow_factory() as uow:
        await uow.locations.upsert(location_factory())
    async with uow_factory() as uow:
        with pytest.raises(LocationIdentityConflictError):
            await uow.locations.upsert(
                location_factory(name="USA", canonical_name="United States")
            )
    async with uow_factory() as uow:
        # No second row and no version churn on the existing row.
        assert await table_count(uow, "location") == 1
        current = await uow.locations.get_by_identity(
            location_type="country",
            country_code="US",
            admin1_code=None,
            admin2_code=None,
            canonical_name="United States",
        )
        assert current is not None and current.name == "United States"


@pytest.mark.asyncio
async def test_gp07_invalid_shape_rejected_database_side(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P07 invalid type/country/code shape is rejected database-side."""
    invalid_insert = """
        INSERT INTO ati.location (
            location_type, name, canonical_name, country_code, version)
        VALUES (:location_type, 'Broken', 'Broken', :country_code, 1)
    """
    async with uow_factory() as uow:
        assert uow.session is not None
        with pytest.raises(IntegrityError):
            await uow.session.execute(
                text(invalid_insert),
                {"location_type": "continent", "country_code": "US"},
            )
    async with uow_factory() as uow:
        assert uow.session is not None
        with pytest.raises(IntegrityError):
            await uow.session.execute(
                text(invalid_insert),
                {"location_type": "country", "country_code": "US1"},
            )
    # The stored function surfaces the same rejection as a typed state even
    # when model validation is bypassed with model_construct.
    async with uow_factory() as uow:
        with pytest.raises(GeoInvalidInputError):
            await uow.locations.upsert(
                Location.model_construct(
                    type=LocationType.COUNTRY,
                    name="Broken",
                    canonical_name="Broken",
                    country_code="US1",
                )
            )


@pytest.mark.asyncio
async def test_gp08_postgis_enabled_only_for_reference_location_state(
    integration_engine: AsyncEngine,
) -> None:
    """G26A-P08/G26B-P03 PostGIS spatial state is bounded to ati.location.

    PR 26A pinned this test to a non-spatial GEOINT foundation; PR 26B
    intentionally adds PostGIS and the ``geometry``/``centroid`` reference
    state on ``ati.location`` only. EntityLocation,
    EntityLocationObservation, and GeoResolution remain spatial-free, no
    PostGIS ``geography`` column exists anywhere, and no latitude/longitude
    columns exist on the GEOINT tables (those live in GEOLOCATION LegacyEvidence
    facts, not GEOINT persistence).
    """
    async with integration_engine.connect() as connection:
        extensions = {
            row[0]
            for row in await connection.execute(
                text("""
                    SELECT e.extname FROM pg_extension e
                    JOIN pg_namespace n ON n.oid = e.extnamespace
                    WHERE n.nspname = 'ati'
                """)
            )
        }
        columns = {
            row[0]
            for row in await connection.execute(
                text("""
                    SELECT column_name FROM information_schema.columns
                    WHERE table_schema = 'ati'
                      AND table_name IN ('location', 'entity_location',
                                         'entity_location_observation',
                                         'geo_resolution')
                """)
            )
        }
    assert "postgis" in extensions
    assert {"geometry", "centroid"} <= columns
    assert not {"geography", "latitude", "longitude"} & columns


# --------------------------------------------------------------------------
# Observation / current-state matrix (G26A-P09..P22)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gp09_first_observation_creates_entity_location_atomically(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P09 the first observation appends one row and creates current state."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        observation = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
        )
        persisted = await uow.entity_location_observations.append(observation)
        assert persisted.version is not None
        assert await table_count(uow, "entity_location_observation") == 1
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.location_id == country.id
        assert current.latest_observation_id == observation.id
        assert current.first_observed_at == _RETRIEVED_AT
        assert current.last_observed_at == _RETRIEVED_AT
        assert current.version is not None


@pytest.mark.asyncio
async def test_gp10_observation_stores_exact_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P10 an observation stores exact Entity/Location/LegacyEvidence/timing."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        observed_at = _RETRIEVED_AT - timedelta(days=1)
        observation = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            precision=LocationPrecision.COUNTRY,
            observed_at=observed_at,
        )
        persisted = await uow.entity_location_observations.append(observation)
        fetched = await uow.entity_location_observations.get_by_id(observation.id)
        assert fetched is not None
        assert fetched.entity_id == entity_id
        assert fetched.location_id == country.id
        assert fetched.evidence_observation_id == evidence_id
        assert fetched.precision is LocationPrecision.COUNTRY
        assert fetched.observed_at == observed_at
        assert fetched.retrieved_at == _RETRIEVED_AT
        assert fetched.resolved_at == _RETRIEVED_AT
        assert fetched.resolution_method == "test_method"
        assert fetched.version == persisted.version


@pytest.mark.asyncio
async def test_gp11_observation_requires_geolocation_evidence(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P11 non-GEOLOCATION LegacyEvidence cannot back an observation."""
    async with uow_factory() as uow:
        investigation_id = uuid4()
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[uuid4()],
                objective="Assess the indicator.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        )
        domain = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.org")
        )
        assert domain.id is not None
        dns_evidence_id = uuid4()
        dns_evidence_out = await uow.evidence.persist(
            ConvertedEvidence(
                evidence=Evidence(
                    id=dns_evidence_id,
                    type=EvidenceType.DNS,
                    source="urn:ati:source:google_public_dns",
                    source_record_id=f"dns_evidence-{dns_evidence_id}",
                ),
                observation=EvidenceObservationCandidate(
                    evidence_id=dns_evidence_id,
                    retrieved_at=_RETRIEVED_AT,
                ),
            )
        )
        assert dns_evidence_out.observation.id is not None
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        with pytest.raises(GeoEvidenceTypeError):
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=domain.id,
                    location_id=country.id,
                    evidence_observation_id=dns_evidence_out.observation.id,
                )
            )


@pytest.mark.asyncio
async def test_gp12_evidence_subject_mismatch_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P12 LegacyEvidence subject must equal the observation Entity."""
    async with uow_factory() as uow:
        _, entity_id, domain_entity_id, evidence_id = await seed_geolocation_evidence(
            uow
        )
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        assert entity_id != domain_entity_id
    async with uow_factory() as uow:
        with pytest.raises(GeoEvidenceSubjectMismatchError):
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=domain_entity_id,
                    location_id=country.id,
                    evidence_observation_id=evidence_id,
                )
            )


@pytest.mark.asyncio
async def test_gp13_missing_entity_location_evidence_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P13 missing Entity/Location/LegacyEvidence references fail closed."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
    async with uow_factory() as uow:
        with pytest.raises(GeoEntityNotFoundError):
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=uuid4(),
                    location_id=country.id,
                    evidence_observation_id=evidence_id,
                )
            )
    async with uow_factory() as uow:
        with pytest.raises(GeoLocationNotFoundError):
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=entity_id,
                    location_id=uuid4(),
                    evidence_observation_id=evidence_id,
                )
            )
    async with uow_factory() as uow:
        with pytest.raises(GeoEvidenceNotFoundError):
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=entity_id,
                    location_id=country.id,
                    evidence_observation_id=uuid4(),
                )
            )


@pytest.mark.asyncio
async def test_gp14_duplicate_observation_rejected_without_current_state_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P14 a duplicate observation UUID is rejected without state mutation."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        observation = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
        )
        await uow.entity_location_observations.append(observation)
        current_before = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current_before is not None
    async with uow_factory() as uow:
        with pytest.raises(EntityLocationObservationDuplicateError):
            await uow.entity_location_observations.append(observation)
    async with uow_factory() as uow:
        current_after = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current_after == current_before
        assert await table_count(uow, "entity_location_observation") == 1


@pytest.mark.asyncio
async def test_gp15_later_observation_updates_current_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P15 a later observation advances current Location/observation."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        first = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT,
        )
        await uow.entity_location_observations.append(first)
        later = observation_factory(
            entity_id=entity_id,
            location_id=other.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=2),
        )
        await uow.entity_location_observations.append(later)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.location_id == other.id
        assert current.latest_observation_id == later.id
        assert current.last_observed_at == _RETRIEVED_AT + timedelta(days=2)
        assert current.first_observed_at == _RETRIEVED_AT


@pytest.mark.asyncio
async def test_gp16_older_observation_does_not_rewind_current_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P16 an older historical observation appends without rewinding."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        later = observation_factory(
            entity_id=entity_id,
            location_id=other.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=2),
        )
        await uow.entity_location_observations.append(later)
        older = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT,
            observed_at=_RETRIEVED_AT - timedelta(days=5),
        )
        await uow.entity_location_observations.append(older)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        # Current state still reflects the later observation.
        assert current.location_id == other.id
        assert current.latest_observation_id == later.id
        assert current.last_observed_at == _RETRIEVED_AT + timedelta(days=2)
        # Both observations are preserved as history.
        assert await table_count(uow, "entity_location_observation") == 2


@pytest.mark.asyncio
async def test_gp17_equal_effective_timestamps_use_uuid_tie_break(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P17 equal effective timestamps resolve by observation UUID ascending."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        lower_id, higher_id = uuid4(), uuid4()
        if lower_id > higher_id:
            lower_id, higher_id = higher_id, lower_id
        await uow.entity_location_observations.append(
            observation_factory(
                id=lower_id,
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=_RETRIEVED_AT,
            )
        )
        await uow.entity_location_observations.append(
            observation_factory(
                id=higher_id,
                entity_id=entity_id,
                location_id=other.id,
                evidence_observation_id=evidence_id,
                retrieved_at=_RETRIEVED_AT,
            )
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.latest_observation_id == higher_id
        assert current.location_id == other.id


@pytest.mark.asyncio
async def test_gp18_first_observed_time_remains_earliest_across_out_of_order(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P18 first_observed_at stays the earliest across out-of-order appends."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        earliest = _RETRIEVED_AT - timedelta(days=10)
        middle = _RETRIEVED_AT - timedelta(days=3)
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=middle,
            )
        )
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=earliest,
            )
        )
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=_RETRIEVED_AT,
            )
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.first_observed_at == earliest
        assert current.last_observed_at == _RETRIEVED_AT


@pytest.mark.asyncio
async def test_gp19_last_observed_reflects_deterministic_latest(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P19 last-observed/current association reflects the latest observation."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        newer = observation_factory(
            entity_id=entity_id,
            location_id=other.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=7),
        )
        await uow.entity_location_observations.append(newer)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.last_observed_at == _RETRIEVED_AT + timedelta(days=7)
        assert current.location_id == other.id
        assert current.latest_observation_id == newer.id
        assert current.precision is LocationPrecision.COUNTRY


@pytest.mark.asyncio
async def test_gp20_observation_produces_no_domain_object_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P20 appending an observation creates no domain_object_history row."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
            )
        )
        assert uow.session is not None
        history = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = 'entity_location_observation'"
            )
        )
        assert int(history) == 0


@pytest.mark.asyncio
async def test_gp21_rollback_leaves_no_observation_or_partial_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P21 a rollback leaves neither observation nor partial state."""
    uow = uow_factory()
    async with uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
            )
        )
        await uow.rollback()
    async with uow_factory() as uow:
        assert await table_count(uow, "entity_location_observation") == 0
        assert await uow.entity_locations.get_by_entity_id(entity_id) is None


@pytest.mark.asyncio
async def test_gp22_entity_location_has_no_public_mutation_path(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P22 current EntityLocation cannot be mutated through the repository."""
    async with uow_factory() as uow:
        repository = uow.entity_locations
        assert not hasattr(repository, "update")
        assert not hasattr(repository, "set_location")
        assert not hasattr(repository, "delete")
        # The only public operation is the bounded read.
        assert not await uow.entity_locations.get_by_entity_id(uuid4())


# --------------------------------------------------------------------------
# GeoResolution matrix (G26A-P23..P30)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gp23_geolocation_evidence_creates_pending_work(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P23 valid GEOLOCATION LegacyEvidence creates PENDING work with exact state."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        resolution = await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
        assert resolution.id is not None
        assert resolution.status is GeoResolutionStatus.PENDING
        assert resolution.attempt_count == 0
        assert resolution.claimed_by is None
        assert resolution.lease_expires_at is None
        assert resolution.next_attempt_at is None
        assert resolution.resolved_location_id is None
        assert resolution.last_error_code is None
        assert resolution.version is not None
        fetched = await uow.geo_resolutions.get_by_id(resolution.id)
        assert fetched == resolution


@pytest.mark.asyncio
async def test_gp24_duplicate_pair_is_idempotent_single_row(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P24 a duplicate Entity/LegacyEvidence pair reuses one pending row."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        first = await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
        second = await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
        assert first.id == second.id
        assert first.version == second.version
        assert await table_count(uow, "geo_resolution") == 1


@pytest.mark.asyncio
async def test_gp25_concurrent_duplicate_creation_creates_one_row(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P25 concurrent duplicate creation yields one work row."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)

    async def _create() -> GeoResolution:
        """Create pending work in an independent committed UoW."""
        async with uow_factory() as uow:
            return await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
                )
            )

    created_a, created_b = await asyncio.gather(_create(), _create())
    assert created_a.id == created_b.id
    assert created_a.status is GeoResolutionStatus.PENDING
    async with uow_factory() as uow:
        assert await table_count(uow, "geo_resolution") == 1


@pytest.mark.asyncio
async def test_gp26_non_geolocation_evidence_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P26 non-GEOLOCATION LegacyEvidence cannot create resolution work."""
    async with uow_factory() as uow:
        investigation_id = uuid4()
        await uow.investigations.create(
            InvestigationState(
                investigation_id=investigation_id,
                status=InvestigationStatus.RUNNING,
                trigger_type=InvestigationTriggerType.MANUAL,
                root_entity_ids=[uuid4()],
                objective="Assess the indicator.",
                budget=default_investigation_budget(),
                started_at=_RETRIEVED_AT,
            )
        )
        domain = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value="example.net")
        )
        assert domain.id is not None
        dns_evidence_id = uuid4()
        dns_evidence_out = await uow.evidence.persist(
            ConvertedEvidence(
                evidence=Evidence(
                    id=dns_evidence_id,
                    type=EvidenceType.DNS,
                    source="urn:ati:source:google_public_dns",
                    source_record_id=f"dns_evidence-{dns_evidence_id}",
                ),
                observation=EvidenceObservationCandidate(
                    evidence_id=dns_evidence_id,
                    retrieved_at=_RETRIEVED_AT,
                ),
            )
        )
        assert dns_evidence_out.observation.id is not None
        with pytest.raises(GeoEvidenceTypeError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(),
                    entity_id=domain.id,
                    evidence_observation_id=dns_evidence_out.observation.id,
                )
            )


@pytest.mark.asyncio
async def test_gp27_resolution_evidence_subject_mismatch_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P27 resolution LegacyEvidence subject mismatch is rejected."""
    async with uow_factory() as uow:
        _, entity_id, domain_entity_id, evidence_id = await seed_geolocation_evidence(
            uow
        )
        with pytest.raises(GeoEvidenceSubjectMismatchError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(),
                    entity_id=domain_entity_id,
                    evidence_observation_id=evidence_id,
                )
            )


@pytest.mark.asyncio
async def test_gp28_missing_or_invisible_entity_evidence_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P28 missing/invisible Entity or LegacyEvidence is rejected."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
    async with uow_factory() as uow:
        with pytest.raises(GeoEntityNotFoundError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(), entity_id=uuid4(), evidence_observation_id=evidence_id
                )
            )
    async with uow_factory() as uow:
        with pytest.raises(GeoEvidenceNotFoundError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(), entity_id=entity_id, evidence_observation_id=uuid4()
                )
            )
    # A soft-deleted Entity is invisible to the resolution path.
    async with uow_factory() as uow:
        deleted = await uow.entities.soft_delete(entity_id)
        assert deleted.deleted_at is not None
    async with uow_factory() as uow:
        with pytest.raises(GeoEntityNotFoundError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
                )
            )


@pytest.mark.asyncio
async def test_gp29_lifecycle_api_lives_on_the_single_repository(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P29 (PR 26C) lifecycle API lives on the one GeoResolution repository.

    PR 26A shipped no claim/lease/completion surface and this test asserted
    its absence; PR 26C extends the same repository and SQL API v0024 with
    the bounded lifecycle (no second queue repository/table was created). The
    assertion now pins the complete v0024 function surface.
    """
    async with uow_factory() as uow:
        repository = uow.geo_resolutions
        assert not hasattr(repository, "renew_lease")
        assert not hasattr(repository, "retry")
        assert uow.session is not None
        routines = {
            row[0]
            for row in await uow.session.execute(
                text(
                    "SELECT routine_name FROM information_schema.routines "
                    "WHERE routine_schema = 'ati'"
                )
            )
        }
        geo_routines = {name for name in routines if "geo_resolution" in name}
        assert geo_routines == {
            "create_geo_resolution",
            "claim_geo_resolutions",
            "complete_geo_resolution_resolved",
            "complete_geo_resolution_unresolvable",
            "record_geo_resolution_failure",
        }


@pytest.mark.asyncio
async def test_gp30_no_second_queue_table(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P30 GeoResolution is not duplicated into a second queue table."""
    async with uow_factory() as uow:
        assert uow.session is not None
        tables = {
            row[0]
            for row in await uow.session.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'ati'"
                )
            )
        }
        assert "geo_resolution" in tables
        assert not {"geo_resolution_queue", "geo_resolution_work"} & tables


# --------------------------------------------------------------------------
# UnitOfWork / transaction matrix (G26A-P31..P34)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gp31_geoint_repositories_participate_in_normal_uow(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P31 GEOINT repositories share the normal UnitOfWork transaction."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        observation = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
        )
        await uow.entity_location_observations.append(observation)
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
        # Everything is visible inside the same open transaction.
        assert await table_count(uow, "location") == 1
        assert await table_count(uow, "entity_location_observation") == 1
        assert await table_count(uow, "geo_resolution") == 1


@pytest.mark.asyncio
async def test_gp32_exception_rolls_back_all_geoint_mutations(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P32 an exception rolls back all GEOINT mutations in the UoW."""
    uow = uow_factory()
    with pytest.raises(RuntimeError):
        async with uow:
            _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
            country = await uow.locations.upsert(location_factory())
            assert country.id is not None
            await uow.entity_location_observations.append(
                observation_factory(
                    entity_id=entity_id,
                    location_id=country.id,
                    evidence_observation_id=evidence_id,
                )
            )
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
                )
            )
            raise RuntimeError("injected failure")
    async with uow_factory() as uow:
        assert await table_count(uow, "location") == 0
        assert await table_count(uow, "entity_location_observation") == 0
        assert await table_count(uow, "geo_resolution") == 0


@pytest.mark.asyncio
async def test_gp33_repositories_never_commit_independently(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P33 repository methods do not commit; only the UoW owns commit."""
    uow = uow_factory()
    async with uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
            )
        )
        # Discard the transaction without committing: nothing may persist.
        await uow.rollback()
    async with uow_factory() as uow:
        assert await table_count(uow, "location") == 0
        assert await table_count(uow, "entity_location_observation") == 0


@pytest.mark.asyncio
async def test_gp34_database_assigned_versions_returned_authoritatively(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A-P34 database-assigned versions are returned authoritatively."""
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None and country.version is not None
        observation = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
        )
        persisted_observation = await uow.entity_location_observations.append(
            observation
        )
        assert persisted_observation.version is not None
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        before = current.version
        resolution = await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(), entity_id=entity_id, evidence_observation_id=evidence_id
            )
        )
        assert resolution.version is not None
        # A second observation advances only the reconciled current state.
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=_RETRIEVED_AT + timedelta(days=1),
            )
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        assert before is not None
        assert current.version > before


# --------------------------------------------------------------------------
# PR 26A-2 corrective matrix (G26A2-P01..P05)
# --------------------------------------------------------------------------
#
# PR 26A-2 makes ``ati.entity_location.version`` consistently
# database-sequence allocated (``ati.entity_location_version_seq``) on every
# actual current-state mutation. EntityLocation versions are monotonic
# database-issued change tokens, not contiguous ``+1`` revision counters;
# sequence gaps are valid. G26A2-P01..P05 prove sequence provenance on real
# PostgreSQL; G26A-P34 was corrected to stop assuming row-local contiguity.


@pytest.mark.asyncio
async def test_g26a2_p01_initial_version_is_sequence_issued(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A2-P01 the initial EntityLocation version is sequence-issued.

    Creates first observation/current state and proves the persisted version
    equals exactly the value ``ati.entity_location_version_seq`` would issue
    next — without assuming the sequence starts at 1. The sequence state is
    read immediately before the append, so any earlier sequence consumption
    in the shared test session is accounted for.
    """
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        assert uow.session is not None
        is_called, last_value = (
            await uow.session.execute(
                text(
                    "SELECT is_called, last_value FROM ati.entity_location_version_seq"
                )
            )
        ).one()
        expected = int(last_value) + 1 if is_called else 1
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
            )
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        assert current.version == expected


@pytest.mark.asyncio
async def test_g26a2_p02_later_current_mutation_proves_sequence_provenance(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A2-P02 a later-current mutation follows the sequence, not +1.

    Creates current state, deliberately advances ``ati.entity_location_version_seq``
    with a direct test-only ``nextval`` (forcing a gap), then appends a
    deterministically later observation. The persisted version must come from
    the sequence — strictly beyond the forced gap — and therefore cannot be
    ``before + 1``. This is the primary regression test and must fail on
    pre-fix main for exactly that reason.
    """
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        first = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
        )
        await uow.entity_location_observations.append(first)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        before = current.version
        # Force exactly one gap with a direct test-only nextval. The sequence
        # (not the row) is now one value ahead of the persisted version.
        assert uow.session is not None
        gap = int(
            (
                await uow.session.execute(
                    text("SELECT nextval('ati.entity_location_version_seq')")
                )
            ).scalar_one()
        )
        assert gap == before + 1
        # Append a deterministically later observation: an actual
        # current-state mutation.
        later = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=1),
        )
        await uow.entity_location_observations.append(later)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        after = current.version
        assert after > before
        # The version is sequence-issued: it lies beyond the forced gap, so
        # arithmetic `target.version + 1` allocation would have produced
        # `after == gap` on a gap-free sequence and `after == before + 1` here.
        assert after != before + 1
        assert after > gap
        assert current.latest_observation_id == later.id
        assert current.last_observed_at == _RETRIEVED_AT + timedelta(days=1)


@pytest.mark.asyncio
async def test_g26a2_p03_earliest_time_only_mutation_gets_new_token(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A2-P03 an earliest-time-only mutation receives a new sequence token.

    Appends an older observation that extends ``first_observed_at`` without
    winning latest-current ordering: the current Location/precision/latest
    observation and ``last_observed_at`` stay put, ``first_observed_at``
    moves earlier, and the persisted version changes with a sequence-issued
    value beyond a forced gap (no contiguous ``+1`` assumption).
    """
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        later = observation_factory(
            entity_id=entity_id,
            location_id=other.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=2),
        )
        await uow.entity_location_observations.append(later)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        before = current.version
        assert uow.session is not None
        gap = int(
            (
                await uow.session.execute(
                    text("SELECT nextval('ati.entity_location_version_seq')")
                )
            ).scalar_one()
        )
        assert gap == before + 1
        older = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            observed_at=_RETRIEVED_AT - timedelta(days=5),
        )
        await uow.entity_location_observations.append(older)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        # Earliest time moved earlier; latest-current state is untouched.
        assert current.first_observed_at == _RETRIEVED_AT - timedelta(days=5)
        assert current.location_id == other.id
        assert current.precision is LocationPrecision.COUNTRY
        assert current.latest_observation_id == later.id
        assert current.last_observed_at == _RETRIEVED_AT + timedelta(days=2)
        # The earliest-time-only mutation is a real current-state mutation and
        # receives a new sequence-issued token beyond the forced gap.
        assert current.version > before
        assert current.version != gap
        assert current.version > gap


@pytest.mark.asyncio
async def test_g26a2_p04_true_historical_noop_leaves_version_unchanged(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A2-P04 a true historical no-op leaves the persisted version unchanged.

    Appends an observation that neither wins latest ordering nor extends
    earliest time. The observation persists as history, current fields remain
    unchanged, and the persisted EntityLocation version is exactly unchanged
    — the sequence itself may still have consumed a value, which is valid.
    """
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        other = await uow.locations.upsert(
            location_factory(name="Canada", canonical_name="Canada", country_code="CA")
        )
        assert other.id is not None
        # Establish the current-state window: latest at T+2d on 'other',
        # earliest at T on 'country'.
        later = observation_factory(
            entity_id=entity_id,
            location_id=other.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=2),
        )
        await uow.entity_location_observations.append(later)
        earliest = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT,
        )
        await uow.entity_location_observations.append(earliest)
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        before = current.version
        first, last, latest, location, precision = (
            current.first_observed_at,
            current.last_observed_at,
            current.latest_observation_id,
            current.location_id,
            current.precision,
        )
        # An observation strictly inside the window neither wins latest
        # ordering nor extends earliest time: a true current-state no-op.
        middle = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT + timedelta(days=1),
        )
        await uow.entity_location_observations.append(middle)
        # The observation itself persists as immutable history.
        fetched = await uow.entity_location_observations.get_by_id(middle.id)
        assert fetched is not None and fetched.version is not None
        assert await table_count(uow, "entity_location_observation") == 3
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None
        assert current.first_observed_at == first
        assert current.last_observed_at == last
        assert current.latest_observation_id == latest
        assert current.location_id == location
        assert current.precision is precision
        # No current-state mutation: the persisted version is exactly unchanged.
        assert current.version == before


@pytest.mark.asyncio
async def test_g26a2_p05_rollback_preserves_prior_persisted_version(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26A2-P05 rollback preserves the prior persisted EntityLocation version.

    Commits baseline current state, performs a current-state-changing append
    in a second UoW and forces rollback, then asserts in a new UoW that the
    pre-transaction EntityLocation state and version remain. A consumed
    sequence value is acceptable.
    """
    async with uow_factory() as uow:
        _, entity_id, _, evidence_id = await seed_geolocation_evidence(uow)
        country = await uow.locations.upsert(location_factory())
        assert country.id is not None
        first = observation_factory(
            entity_id=entity_id,
            location_id=country.id,
            evidence_observation_id=evidence_id,
            retrieved_at=_RETRIEVED_AT,
        )
        await uow.entity_location_observations.append(first)
    async with uow_factory() as uow:
        baseline = await uow.entity_locations.get_by_entity_id(entity_id)
        assert baseline is not None and baseline.version is not None
        before = baseline.version
    # A current-state-changing append is rolled back (explicit rollback, so
    # the UoW exit does not commit it).
    uow = uow_factory()
    async with uow:
        await uow.entity_location_observations.append(
            observation_factory(
                entity_id=entity_id,
                location_id=country.id,
                evidence_observation_id=evidence_id,
                retrieved_at=_RETRIEVED_AT + timedelta(days=1),
            )
        )
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        # The mutation is visible inside the open transaction...
        assert current.version > before
        await uow.rollback()
    # ...and the rollback leaves the pre-transaction state/version intact.
    async with uow_factory() as uow:
        current = await uow.entity_locations.get_by_entity_id(entity_id)
        assert current is not None and current.version is not None
        assert current.version == before
        assert current.latest_observation_id == baseline.latest_observation_id
        assert current.location_id == baseline.location_id
        assert current.first_observed_at == baseline.first_observed_at
        assert current.last_observed_at == baseline.last_observed_at
        assert await table_count(uow, "entity_location_observation") == 1
