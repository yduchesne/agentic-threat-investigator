# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26D Investigation-scoped GEOINT query/API matrices on real PostgreSQL.

G26D-P01..P32 matrix: exact-LegacyEvidence scope isolation, Investigation-relative
current/history under the exact PR 26A currentness ordering, Location
reverse lookups with deterministic keyset pagination, purpose-built
containment (boundary-inclusive ``ST_Covers`` over SRID-4326 geometry),
bounded summaries, EXPLAIN-based index-eligibility proof, the canonical
vertical slice (production resolution -> query -> API -> LegacyEvidence
drill-down), and read-only guarantees.

Seeding uses two Investigations sharing Entities/Locations backed by
different LegacyEvidence so every scope assertion holds against the real
database. Timestamps are controlled deterministically through the normal
repositories (``observed_at``/``retrieved_at`` are stamped by the seeding
helpers; no sleeps).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4, uuid5

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    CANONICAL_GEOGRAPHY_METHOD,
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointLocationObservationListQuery,
    GeointObservationQuery,
    GeointQueryService,
    GeointSummaryQuery,
)
from agentic_threat_investigator.app.query.models import QueryLimits
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
    CanonicalLocationResolution,
    EntityLocationObservation,
    GeographicClaim,
    GeoResolution,
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
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.query.geoint import (
    PostgresGeointQueryService,
)
from tests.integration.api_helpers import api_client, api_settings, seed_user

pytestmark = pytest.mark.integration

FIXED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
FIXED_ID = UUID("aaaaaaaa-0000-4000-8000-000000000000")

# Simplified but internally consistent reference geography. The coarse
# rectangles are chosen so the containment matrix is exact: US covers
# WA/Seattle/TX/Dallas but is strictly below Canada's southern boundary
# (lat 49), BC starts at lat 49, and Boundary Town sits exactly on the WA
# polygon corner (-125 45) so boundary-inclusive ST_Covers includes it.
US_GEOMETRY = "SRID=4326;POLYGON((-126 24,-66 24,-66 49,-126 49,-126 24))"
WA_GEOMETRY = "SRID=4326;POLYGON((-125 45,-116 45,-116 48.9,-125 48.9,-125 45))"
SEATTLE_POINT = "SRID=4326;POINT(-122.3321 47.6062)"
TX_GEOMETRY = (
    "SRID=4326;POLYGON((-106.6 25.8,-93.5 25.8,-93.5 36.5,-106.6 36.5,-106.6 25.8))"
)
DALLAS_POINT = "SRID=4326;POINT(-96.7969 32.7767)"
CA_GEOMETRY = "SRID=4326;POLYGON((-141 49,-52 49,-52 84,-141 84,-141 49))"
BC_GEOMETRY = "SRID=4326;POLYGON((-139 49,-120 49,-120 60,-139 60,-139 49))"
VANCOUVER_POINT = "SRID=4326;POINT(-123.1207 49.5)"
BOUNDARY_TOWN_POINT = "SRID=4326;POINT(-125 45)"


def geography_location(
    location_type: LocationType,
    name: str,
    country_code: str,
    *,
    admin1_code: str | None = None,
    parent_location_id: UUID | None = None,
    geometry: str | None = None,
    id: UUID | None = None,
) -> Location:
    """Build one canonical reference Location with spatial state."""
    return Location(
        id=id,
        type=location_type,
        name=name,
        canonical_name=name,
        country_code=country_code,
        admin1_code=admin1_code,
        parent_location_id=parent_location_id,
        geometry=geometry,
        centroid=None,
    )


def geographic_location_id(name: str) -> UUID:
    """Return the deterministic canonical Location identity used by seeding."""
    return uuid5(UUID("7d5f0f2e-6f2f-4a3e-9c3a-26d7c8d1f001"), name)


class Geography:
    """Persisted canonical geography identities, keyed by canonical name."""

    def __init__(self, ids: dict[str, UUID]) -> None:
        """Bind the canonical identities."""
        self.ids = ids

    def __getitem__(self, name: str) -> UUID:
        """Return one canonical Location identity."""
        return self.ids[name]

    def __contains__(self, name: str) -> bool:
        """Return whether one canonical Location was seeded."""
        return name in self.ids


async def seed_geography(uow: UnitOfWork) -> Geography:
    """Seed the country/admin/city corpus with geometry via the reference API."""
    definitions = [
        geography_location(
            LocationType.COUNTRY,
            "United States",
            "US",
            geometry=US_GEOMETRY,
            id=geographic_location_id("United States"),
        ),
        geography_location(
            LocationType.ADMINISTRATIVE_AREA,
            "Washington",
            "US",
            admin1_code="WA",
            parent_location_id=geographic_location_id("United States"),
            geometry=WA_GEOMETRY,
            id=geographic_location_id("Washington"),
        ),
        geography_location(
            LocationType.CITY,
            "Seattle",
            "US",
            admin1_code="WA",
            parent_location_id=geographic_location_id("Washington"),
            geometry=SEATTLE_POINT,
            id=geographic_location_id("Seattle"),
        ),
        geography_location(
            LocationType.ADMINISTRATIVE_AREA,
            "Texas",
            "US",
            admin1_code="TX",
            parent_location_id=geographic_location_id("United States"),
            geometry=TX_GEOMETRY,
            id=geographic_location_id("Texas"),
        ),
        geography_location(
            LocationType.CITY,
            "Dallas",
            "US",
            admin1_code="TX",
            parent_location_id=geographic_location_id("Texas"),
            geometry=DALLAS_POINT,
            id=geographic_location_id("Dallas"),
        ),
        geography_location(
            LocationType.COUNTRY,
            "Canada",
            "CA",
            geometry=CA_GEOMETRY,
            id=geographic_location_id("Canada"),
        ),
        geography_location(
            LocationType.ADMINISTRATIVE_AREA,
            "British Columbia",
            "CA",
            admin1_code="BC",
            parent_location_id=geographic_location_id("Canada"),
            geometry=BC_GEOMETRY,
            id=geographic_location_id("British Columbia"),
        ),
        geography_location(
            LocationType.CITY,
            "Vancouver",
            "CA",
            admin1_code="BC",
            parent_location_id=geographic_location_id("British Columbia"),
            geometry=VANCOUVER_POINT,
            id=geographic_location_id("Vancouver"),
        ),
        geography_location(
            LocationType.CITY,
            "Boundary Town",
            "US",
            admin1_code="WA",
            parent_location_id=geographic_location_id("Washington"),
            geometry=BOUNDARY_TOWN_POINT,
            id=geographic_location_id("Boundary Town"),
        ),
        # A canonical city without any spatial state (NULL geometry).
        geography_location(
            LocationType.CITY,
            "Auburn",
            "US",
            admin1_code="WA",
            parent_location_id=geographic_location_id("Washington"),
            id=geographic_location_id("Auburn"),
        ),
    ]
    ids: dict[str, UUID] = {}
    for location in definitions:
        result = await uow.locations.upsert_reference(location)
        assert result.location.id is not None
        ids[result.location.canonical_name] = result.location.id
    return Geography(ids)


async def seed_investigation(uow: UnitOfWork, *, wanted_id: UUID | None = None) -> UUID:
    """Create one running Investigation and return its identity."""
    investigation_id = wanted_id or uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the indicator.",
            budget=default_investigation_budget(),
            started_at=FIXED,
        )
    )
    return investigation_id


async def seed_entity(
    uow: UnitOfWork,
    *,
    value: str = "203.0.113.10",
    entity_type: EntityType = EntityType.IP_ADDRESS,
) -> UUID:
    """Create one canonical Entity and return its identity."""
    entity = await uow.entities.upsert(Entity(type=entity_type, value=value))
    assert entity.id is not None
    return entity.id


class ObservationSeed:
    """Persisted identities of one seeded scoped observation."""

    def __init__(
        self, entity_id: UUID, evidence_id: UUID, observation_id: UUID
    ) -> None:
        """Bind the exact persisted identities."""
        self.entity_id = entity_id
        self.evidence_id = evidence_id
        self.observation_id = observation_id


async def seed_observation(
    uow: UnitOfWork,
    *,
    investigation_id: UUID,
    location_id: UUID,
    entity_value: str = "203.0.113.10",
    precision: LocationPrecision = LocationPrecision.COUNTRY,
    retrieved_at: datetime = FIXED,
    observed_at: datetime | None = None,
    facts: dict[str, object] | None = None,
    observation_id: UUID | None = None,
) -> ObservationSeed:
    """Create, persist, and observe one Entity at one Location in scope.

    Writes through the normal repositories exactly like the production
    resolution path: canonical Entity, global GEOLOCATION ConvertedEvidence,
    exact admission/association, then the versioned GEOINT append.
    """
    entity_id = await seed_entity(uow, value=entity_value)
    evidence_id = observation_id if observation_id is not None else uuid4()
    stable = Evidence(
        id=evidence_id,
        type=EvidenceType.GEOLOCATION,
        source="urn:ati:source:test",
        source_record_id=f"geo-{evidence_id}",
    )
    persisted_evidence = await uow.evidence.persist(
        ConvertedEvidence(
            evidence=stable,
            observation=EvidenceObservationCandidate(
                evidence_id=stable.id,
                observed_at=observed_at,
                retrieved_at=retrieved_at,
                facts=facts
                or {
                    "country_code": "US",
                    "provider": "urn:ati:source:test",
                    "precision": {
                        LocationPrecision.COUNTRY: "country",
                        LocationPrecision.ADMINISTRATIVE_AREA: "region",
                        LocationPrecision.CITY: "city",
                    }[precision],
                },
            ),
        ),
        observation_id=evidence_id,
    )
    await uow.evidence_observation_entities.associate(
        persisted_evidence.observation.id, entity_id
    )
    await uow.investigation_evidence.admit(
        InvestigationEvidence(
            investigation_id=investigation_id,
            evidence_observation_id=persisted_evidence.observation.id,
            inclusion_reason=InvestigationEvidenceReason.INITIAL,
            added_at=retrieved_at,
            added_by=InvestigationEvidenceActor.SYSTEM,
        )
    )
    persisted = await uow.entity_location_observations.append(
        EntityLocationObservation(
            id=evidence_id,
            entity_id=entity_id,
            location_id=location_id,
            evidence_observation_id=evidence_id,
            precision=precision,
            observed_at=observed_at,
            retrieved_at=retrieved_at,
            resolved_at=retrieved_at,
            resolution_method=CANONICAL_GEOGRAPHY_METHOD,
        )
    )
    return ObservationSeed(entity_id, evidence_id, persisted.id)


async def seed_geolocation_for_investigation(
    uow: UnitOfWork,
    investigation_id: UUID,
    entity_id: UUID,
    entity_value: str,
    *,
    retrieved_at: datetime = FIXED,
    observed_at: datetime | None = None,
    facts: dict[str, object] | None = None,
) -> UUID:
    """Persist one admitted global GEOLOCATION observation for an entity."""
    identity = uuid4()
    stable = Evidence(
        id=identity,
        type=EvidenceType.GEOLOCATION,
        source="urn:ati:source:test",
        source_record_id=f"geo-{identity}",
    )
    persisted = await uow.evidence.persist(
        ConvertedEvidence(
            evidence=stable,
            observation=EvidenceObservationCandidate(
                evidence_id=stable.id,
                observed_at=observed_at,
                retrieved_at=retrieved_at,
                facts=facts
                or {
                    "country_code": "US",
                    "provider": "urn:ati:source:test",
                    "precision": "country",
                },
            ),
        ),
        observation_id=identity,
    )
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
    del entity_value
    return persisted.observation.id


async def make_query_service(
    session_factory: async_sessionmaker[Any],
    *,
    summary_top_locations: int = 10,
) -> GeointQueryService:
    """Build one real PostgresGeointQueryService over a fresh read session."""
    session = session_factory()
    return PostgresGeointQueryService(
        session,
        QueryLimits(default_page_size=50, max_page_size=200),
        summary_top_locations=summary_top_locations,
    )


async def close_query_service(service: GeointQueryService) -> None:
    """Close the read session bound to one query service."""
    assert isinstance(service, PostgresGeointQueryService)
    await service._session.close()


async def table_count(session_factory: async_sessionmaker[Any], table: str) -> int:
    """Count every row of one application table."""
    async with session_factory() as session:
        result = await session.execute(text(f"SELECT count(*) FROM ati.{table}"))
        return int(result.scalar_one())


# ---------------------------------------------------------------------------
# Scope (G26D-P01..P06)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p01_observation_evidence_in_scope_visible(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P01 an observation backed by I1 LegacyEvidence is visible under I1."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await seed_geography(uow)
        seed = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geographic_location_id("United States"),
        )
    service = await make_query_service(session_factory)
    try:
        entity = await service.get_entity(
            GeointEntityQuery(
                investigation_id=investigation_id, entity_id=seed.entity_id
            )
        )
        assert entity is not None
        assert entity.current_observation.observation_id == seed.observation_id
        assert entity.current_observation.evidence_observation_id == seed.evidence_id
        detail = await service.get_observation(
            GeointObservationQuery(
                investigation_id=investigation_id,
                observation_id=seed.observation_id,
            )
        )
        assert detail is not None
        assert detail.observation.evidence_observation_id == seed.evidence_id
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p02_same_observation_invisible_under_other_investigation(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P02 the same observation is invisible under a second Investigation."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        await seed_geography(uow)
        seed = await seed_observation(
            uow,
            investigation_id=investigation_a,
            location_id=geographic_location_id("United States"),
        )
    service = await make_query_service(session_factory)
    try:
        assert (
            await service.get_observation(
                GeointObservationQuery(
                    investigation_id=investigation_a,
                    observation_id=seed.observation_id,
                )
            )
            is not None
        )
        assert (
            await service.get_observation(
                GeointObservationQuery(
                    investigation_id=investigation_b,
                    observation_id=seed.observation_id,
                )
            )
            is None
        )
        history = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_b,
                entity_id=seed.entity_id,
                limit=50,
                cursor=None,
            )
        )
        assert history.items == ()
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p03_entity_in_both_sees_own_history(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P03 a shared Entity sees only its own Investigation history."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seed_a = await seed_observation(
            uow,
            investigation_id=investigation_a,
            location_id=geography["United States"],
            entity_value="203.0.113.17",
        )
        seed_b = await seed_observation(
            uow,
            investigation_id=investigation_b,
            location_id=geography["Canada"],
            entity_value="203.0.113.17",
            retrieved_at=FIXED + timedelta(days=1),
        )
        assert seed_a.entity_id == seed_b.entity_id
    service = await make_query_service(session_factory)
    try:
        current_a = await service.get_entity(
            GeointEntityQuery(
                investigation_id=investigation_a, entity_id=seed_a.entity_id
            )
        )
        current_b = await service.get_entity(
            GeointEntityQuery(
                investigation_id=investigation_b, entity_id=seed_b.entity_id
            )
        )
        assert current_a is not None and current_b is not None
        assert (
            current_a.current_observation.location.location_id
            == geography["United States"]
        )
        assert current_b.current_observation.location.location_id == geography["Canada"]
        history_a = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_a,
                entity_id=seed_a.entity_id,
                limit=50,
            )
        )
        assert [item.observation_id for item in history_a.items] == [
            seed_a.observation_id
        ]
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p04_global_current_does_not_leak(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P04 a newer I2 observation never advances I1's current context."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seed_a = await seed_observation(
            uow,
            investigation_id=investigation_a,
            location_id=geography["United States"],
            entity_value="203.0.113.23",
        )
        await seed_observation(
            uow,
            investigation_id=investigation_b,
            location_id=geography["Canada"],
            entity_value="203.0.113.23",
            retrieved_at=FIXED + timedelta(days=30),
        )
    service = await make_query_service(session_factory)
    try:
        current_a = await service.get_entity(
            GeointEntityQuery(
                investigation_id=investigation_a, entity_id=seed_a.entity_id
            )
        )
        assert current_a is not None
        # I1 current remains the I1-backed US observation even though the
        # global materialized EntityLocation was advanced by I2 to Canada.
        assert current_a.current_observation.observation_id == seed_a.observation_id
        assert (
            current_a.current_observation.location.location_id
            == geography["United States"]
        )
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p05_global_location_unused_in_scope_is_empty(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P05 a Location used only by I2 is empty under I1."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_observation(
            uow,
            investigation_id=investigation_b,
            location_id=geography["Seattle"],
            entity_value="203.0.113.31",
        )
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_a,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        observations = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_a,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        assert entities.items == ()
        assert observations.items == ()
        assert entities.containment_applied is False
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p06_cross_scope_observation_detail_not_found(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P06 a cross-scope observation detail fails closed with None."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seed = await seed_observation(
            uow,
            investigation_id=investigation_a,
            location_id=geography["United States"],
        )
    service = await make_query_service(session_factory)
    try:
        assert (
            await service.get_observation(
                GeointObservationQuery(
                    investigation_id=investigation_b,
                    observation_id=seed.observation_id,
                )
            )
            is None
        )
    finally:
        await close_query_service(service)


# ---------------------------------------------------------------------------
# Current/history semantics (G26D-P07..P12)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p07_single_scoped_observation_is_current(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P07 with one scoped observation that observation is current."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seed = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
        )
    service = await make_query_service(session_factory)
    try:
        current = await service.get_entity(
            GeointEntityQuery(
                investigation_id=investigation_id, entity_id=seed.entity_id
            )
        )
        assert current is not None
        assert current.current_observation.observation_id == seed.observation_id
        assert current.current_observation.precision is LocationPrecision.COUNTRY
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p08_two_scoped_use_pr26a_ordering(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P08 two scoped observations follow the PR 26A ordering."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.41")
        earlier = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.41",
            retrieved_at=FIXED,
        )
        later = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Washington"],
            entity_value="203.0.113.41",
            retrieved_at=FIXED + timedelta(days=1),
        )
        assert earlier.entity_id == later.entity_id == entity_id
    service = await make_query_service(session_factory)
    try:
        current = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )
        assert current is not None
        assert current.current_observation.observation_id == later.observation_id
        assert (
            current.current_observation.location.location_id == geography["Washington"]
        )
        history = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=50
            )
        )
        assert [item.observation_id for item in history.items] == [
            later.observation_id,
            earlier.observation_id,
        ]
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p09_equal_effective_time_uses_uuid_tie_break(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P09 equal effective times resolve by observation UUID descending."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.43")
        lower_id, higher_id = uuid4(), uuid4()
        if higher_id < lower_id:
            lower_id, higher_id = higher_id, lower_id
        lower = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.43",
            retrieved_at=FIXED,
            observation_id=lower_id,
        )
        higher = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Washington"],
            entity_value="203.0.113.43",
            retrieved_at=FIXED,
            observation_id=higher_id,
        )
        assert lower.entity_id == higher.entity_id == entity_id
    service = await make_query_service(session_factory)
    try:
        current = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )
        assert current is not None
        assert current.current_observation.observation_id == higher_id
        history = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=50
            )
        )
        assert [item.observation_id for item in history.items] == [
            higher_id,
            lower_id,
        ]
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p10_earlier_observation_retained_in_history(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P10 an earlier historical observation is retained, never rewound."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.47")
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Washington"],
            entity_value="203.0.113.47",
            retrieved_at=FIXED + timedelta(days=2),
        )
        older = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.47",
            retrieved_at=FIXED,
        )
    service = await make_query_service(session_factory)
    try:
        history = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=50
            )
        )
        assert len(history.items) == 2
        assert older.observation_id in {item.observation_id for item in history.items}
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p11_null_observed_at_uses_retrieved_at(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P11 NULL observed_at falls back to retrieved_at for currentness."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.53")
        # A states an explicit observed_at older than B's retrieved_at, but
        # B has no observed_at: B's effective time is its retrieved_at.
        a = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.53",
            observed_at=FIXED - timedelta(days=3),
            retrieved_at=FIXED,
        )
        b = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Washington"],
            entity_value="203.0.113.53",
            observed_at=None,
            retrieved_at=FIXED + timedelta(days=1),
        )
        assert a.entity_id == b.entity_id == entity_id
    service = await make_query_service(session_factory)
    try:
        current = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )
        assert current is not None
        assert current.current_observation.observation_id == b.observation_id
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p12_global_and_scoped_latest_differ(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P12 the scoped latest can differ from the global latest."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.59")
        scoped_latest = await seed_observation(
            uow,
            investigation_id=investigation_a,
            location_id=geography["Seattle"],
            entity_value="203.0.113.59",
            retrieved_at=FIXED + timedelta(days=1),
        )
        global_latest = await seed_observation(
            uow,
            investigation_id=investigation_b,
            location_id=geography["Vancouver"],
            entity_value="203.0.113.59",
            retrieved_at=FIXED + timedelta(days=2),
        )
        assert scoped_latest.entity_id == global_latest.entity_id == entity_id
    service = await make_query_service(session_factory)
    try:
        current_a = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_a, entity_id=entity_id)
        )
        assert current_a is not None
        # The global/current materialized EntityLocation points at the I2
        # Vancouver observation; I1's current is its own scoped Seattle one.
        assert (
            current_a.current_observation.observation_id == scoped_latest.observation_id
        )
        assert (
            current_a.current_observation.location.location_id == geography["Seattle"]
        )
    finally:
        await close_query_service(service)


# ---------------------------------------------------------------------------
# Location reverse lookup and pagination (G26D-P13..P18)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p13_exact_location_entities_distinct_scoped(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P13 exact Location entities returns distinct scoped Entities."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        for value in ("203.0.113.61", "203.0.113.62", "203.0.113.63"):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                entity_value=value,
                precision=LocationPrecision.CITY,
            )
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        assert entities.items
        assert len(entities.items) == 3
        # Deterministic entity ordering: entity_type, canonical_value, id.
        values = [item.entity_value for item in entities.items]
        assert values == sorted(values)
        assert all(
            item.current_observation.location.location_id == geography["Seattle"]
            for item in entities.items
        )
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p14_repeated_observation_same_entity_once(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P14 repeated observations of one Entity still list the Entity once."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        entity_id = await seed_entity(uow, value="203.0.113.67")
        for offset in (0, 1, 2):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                entity_value="203.0.113.67",
                precision=LocationPrecision.CITY,
                retrieved_at=FIXED + timedelta(days=offset),
            )
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        assert [item.entity_id for item in entities.items] == [entity_id]
        latest = entities.items[0].current_observation
        assert latest.location.location_id == geography["Seattle"]
        observations = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        assert len(observations.items) == 3
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p15_location_observation_list_all_qualifying(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P15 the observation list returns every qualifying observation."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        for value, offset in (("203.0.113.71", 0), ("203.0.113.73", 1)):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                entity_value=value,
                precision=LocationPrecision.ADMINISTRATIVE_AREA,
                retrieved_at=FIXED + timedelta(days=offset),
            )
    service = await make_query_service(session_factory)
    try:
        observations = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                limit=50,
            )
        )
        assert len(observations.items) == 2
        # Newest effective time first (PR 26A ordering).
        assert observations.items[0].retrieved_at >= observations.items[1].retrieved_at
        assert all(
            item.location.location_id == geography["Washington"]
            for item in observations.items
        )
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p16_pagination_static_set_no_gaps_or_duplicates(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P16 paging a static set yields no gaps or duplicates."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        for offset in (0, 1, 2, 3, 4):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["United States"],
                entity_value="203.0.113.79",
                retrieved_at=FIXED + timedelta(days=offset),
            )
    service = await make_query_service(session_factory)
    try:
        cursor: str | None = None
        seen: list[UUID] = []
        while True:
            page = await service.list_entity_observations(
                GeointEntityObservationListQuery(
                    investigation_id=investigation_id,
                    entity_id=await _observation_entity(session_factory),
                    limit=2,
                    cursor=cursor,
                )
            )
            for item in page.items:
                assert item.observation_id not in seen
                seen.append(item.observation_id)
            cursor = page.next_cursor
            if cursor is None:
                break
        assert len(seen) == 5
    finally:
        await close_query_service(service)


async def _observation_entity(
    session_factory: async_sessionmaker[Any],
) -> UUID:
    """Return the single seeded observation Entity for pagination tests."""
    async with session_factory() as session:
        result = await session.execute(
            text("SELECT entity_id FROM ati.entity_location_observation LIMIT 1")
        )
        value = result.scalar_one()
        assert isinstance(value, UUID)
        return value


@pytest.mark.asyncio
async def test_p17_second_page_exact_continuation(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P17 the second page continues the first page exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seeds: list[ObservationSeed] = []
        for offset in (0, 1, 2, 3, 4):
            seeds.append(
                await seed_observation(
                    uow,
                    investigation_id=investigation_id,
                    location_id=geography["United States"],
                    entity_value="203.0.113.83",
                    retrieved_at=FIXED + timedelta(days=offset),
                )
            )
        entity_id = seeds[0].entity_id
    service = await make_query_service(session_factory)
    # Newest-first: offsets 4,3,2,1,0.
    expected_order = [seeds[i].observation_id for i in (4, 3, 2, 1, 0)]
    try:
        first = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=2
            )
        )
        assert [item.observation_id for item in first.items] == expected_order[:2]
        assert first.next_cursor is not None
        second = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id,
                entity_id=entity_id,
                limit=2,
                cursor=first.next_cursor,
            )
        )
        assert [item.observation_id for item in second.items] == expected_order[2:4]
        assert second.next_cursor is not None
        # The full independent fetch matches the paged continuation exactly.
        full = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=50
            )
        )
        assert [item.observation_id for item in full.items] == expected_order
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p18_terminal_page_cursor_null(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P18 the terminal page carries a NULL continuation cursor."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.89",
        )
    service = await make_query_service(session_factory)
    try:
        page = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["United States"],
                limit=10,
            )
        )
        assert len(page.items) == 1
        assert page.next_cursor is None
    finally:
        await close_query_service(service)


# ---------------------------------------------------------------------------
# Containment (G26D-P19..P26)
# ---------------------------------------------------------------------------


async def _seed_us_observations(
    uow: UnitOfWork, investigation_id: UUID, geography: Geography
) -> None:
    """Seed observations at US, WA, Seattle, TX, and Dallas in one scope."""
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        location_id=geography["United States"],
        entity_value="203.0.113.101",
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        location_id=geography["Washington"],
        entity_value="203.0.113.102",
        precision=LocationPrecision.ADMINISTRATIVE_AREA,
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        location_id=geography["Seattle"],
        entity_value="203.0.113.103",
        precision=LocationPrecision.CITY,
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        location_id=geography["Texas"],
        entity_value="203.0.113.104",
        precision=LocationPrecision.ADMINISTRATIVE_AREA,
    )
    await seed_observation(
        uow,
        investigation_id=investigation_id,
        location_id=geography["Dallas"],
        entity_value="203.0.113.105",
        precision=LocationPrecision.CITY,
    )


@pytest.mark.asyncio
async def test_p19_wa_exact_is_exact_only(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P19 exact WA selection returns only the WA observation."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                limit=50,
            )
        )
        observations = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                limit=50,
            )
        )
        assert [item.entity_value for item in entities.items] == ["203.0.113.102"]
        assert len(observations.items) == 1
        assert entities.containment_applied is False
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p20_wa_contained_includes_seattle(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P20 WA contained selects WA plus the Seattle children in scope."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                include_contained=True,
                limit=50,
            )
        )
        observations = await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                include_contained=True,
                limit=50,
            )
        )
        seen = {item.entity_value for item in entities.items}
        assert seen == {"203.0.113.102", "203.0.113.103"}
        assert entities.containment_applied is True
        assert observations.containment_applied is True
        observed_locations = {
            (item.location.location_id, item.location.location_type)
            for item in observations.items
        }
        assert (geography["Washington"], LocationType.ADMINISTRATIVE_AREA) in (
            observed_locations
        )
        assert (geography["Seattle"], LocationType.CITY) in observed_locations
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p21_us_contained_includes_all_us_children(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P21 US contained selects US/WA/Seattle/TX/Dallas in scope."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["United States"],
                include_contained=True,
                limit=50,
            )
        )
        values = {item.entity_value for item in entities.items}
        assert values == {
            "203.0.113.101",
            "203.0.113.102",
            "203.0.113.103",
            "203.0.113.104",
            "203.0.113.105",
        }
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p22_us_contained_excludes_canada(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P22 US containment never leaks Canada into the scope."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Vancouver"],
            entity_value="203.0.113.106",
            precision=LocationPrecision.CITY,
        )
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["United States"],
                include_contained=True,
                limit=50,
            )
        )
        values = {item.entity_value for item in entities.items}
        assert "203.0.113.106" not in values
        assert {
            item.current_observation.location.country_code for item in entities.items
        } == {"US"}
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p23_boundary_point_included_by_st_covers(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P23 a canonical point on the boundary is included by ST_Covers."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Boundary Town"],
            entity_value="203.0.113.107",
            precision=LocationPrecision.CITY,
        )
    service = await make_query_service(session_factory)
    try:
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                include_contained=True,
                limit=50,
            )
        )
        assert [item.entity_value for item in entities.items] == ["203.0.113.107"]
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p24_null_selected_geometry_is_exact_with_flag(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P24 a NULL selected geometry degrades to exact-only with a flag."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Auburn"],
            entity_value="203.0.113.109",
            precision=LocationPrecision.CITY,
        )
    service = await make_query_service(session_factory)
    try:
        contained = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Auburn"],
                include_contained=True,
                limit=50,
            )
        )
        exact = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Auburn"],
                limit=50,
            )
        )
        assert [item.entity_value for item in contained.items] == ["203.0.113.109"]
        assert [item.entity_value for item in exact.items] == ["203.0.113.109"]
        assert contained.containment_applied is False  # honest, never guessed
        assert exact.containment_applied is False
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p25_city_contained_is_exact_no_radius(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P25 a city Point with contained=true stays exact; no radius."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    service = await make_query_service(session_factory)
    try:
        contained = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                include_contained=True,
                limit=50,
            )
        )
        exact = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                limit=50,
            )
        )
        assert [item.entity_value for item in contained.items] == ["203.0.113.103"]
        assert [item.entity_value for item in exact.items] == ["203.0.113.103"]
        assert contained.containment_applied is False
        assert exact.containment_applied is False
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p26_query_never_mutates_hierarchy(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P26 GEOINT reads never create hierarchy or Relationship records."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    locations_before = await table_count(session_factory, "location")
    relationships_before = await table_count(session_factory, "relationship")
    observations_before = await table_count(
        session_factory, "entity_location_observation"
    )
    service = await make_query_service(session_factory)
    try:
        await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=geography["United States"],
                include_contained=True,
                limit=50,
            )
        )
        await service.list_location_observations(
            GeointLocationObservationListQuery(
                investigation_id=investigation_id,
                location_id=geography["United States"],
                include_contained=True,
                limit=50,
            )
        )
        await service.summary(GeointSummaryQuery(investigation_id=investigation_id))
    finally:
        await close_query_service(service)
    assert await table_count(session_factory, "location") == locations_before
    assert await table_count(session_factory, "relationship") == relationships_before
    assert (
        await table_count(session_factory, "entity_location_observation")
        == observations_before
    )


# ---------------------------------------------------------------------------
# Summary (G26D-P27..P32)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p27_summary_no_observations_is_zero(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P27 an Investigation with no observations summarizes as zero."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        await seed_geography(uow)
    service = await make_query_service(session_factory)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.observation_count == 0
        assert summary.entity_count_with_location == 0
        assert summary.location_count == 0
        assert summary.country_count == 0
        assert summary.administrative_area_count == 0
        assert summary.city_count == 0
        assert summary.precision_counts.country == 0
        assert summary.precision_counts.administrative_area == 0
        assert summary.precision_counts.city == 0
        assert summary.top_locations == ()
        assert summary.truncated is False
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p28_summary_exact_observation_count(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P28 the summary observation count is exact, history included."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_entity(uow, value="203.0.113.113")
        for offset in range(3):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["Washington"],
                entity_value="203.0.113.113",
                precision=LocationPrecision.ADMINISTRATIVE_AREA,
                retrieved_at=FIXED + timedelta(days=offset),
            )
    service = await make_query_service(session_factory)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.observation_count == 3
        assert summary.entity_count_with_location == 1
        assert summary.location_count == 1
        assert summary.administrative_area_count == 1
        assert summary.precision_counts.administrative_area == 3
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p29_summary_distinct_scoped_entities(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P29 the summary entity count is distinct scoped Entities."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        for value in ("203.0.113.121", "203.0.113.122"):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography["Seattle"],
                entity_value=value,
                precision=LocationPrecision.CITY,
            )
    service = await make_query_service(session_factory)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.entity_count_with_location == 2
        assert summary.observation_count == 2
        assert summary.city_count == 1
        assert summary.precision_counts.city == 2
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p30_summary_precision_vocabulary_counts(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P30 precision counts follow the approved vocabulary exactly."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
            entity_value="203.0.113.127",
            precision=LocationPrecision.COUNTRY,
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Washington"],
            entity_value="203.0.113.128",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Seattle"],
            entity_value="203.0.113.129",
            precision=LocationPrecision.CITY,
        )
    service = await make_query_service(session_factory)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.precision_counts.country == 1
        assert summary.precision_counts.administrative_area == 1
        assert summary.precision_counts.city == 1
        assert summary.country_count == 1
        assert summary.administrative_area_count == 1
        assert summary.city_count == 1
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p31_summary_top_tie_break_deterministic(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P31 equal top groups order by canonical name and Location UUID."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        # One entity per location: both groups tie at scoped_entity_count 1.
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Dallas"],
            entity_value="203.0.113.131",
            precision=LocationPrecision.CITY,
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Seattle"],
            entity_value="203.0.113.132",
            precision=LocationPrecision.CITY,
        )
        await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["Texas"],
            entity_value="203.0.113.133",
            precision=LocationPrecision.ADMINISTRATIVE_AREA,
        )
    service = await make_query_service(session_factory)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        names = [top.location.canonical_name for top in summary.top_locations]
        assert names == ["Dallas", "Seattle", "Texas"]
        assert all(top.scoped_entity_count == 1 for top in summary.top_locations)
    finally:
        await close_query_service(service)


@pytest.mark.asyncio
async def test_p32_summary_active_groups_bounded_and_truncated(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """G26D-P32 exceeding the top-location bound is bounded and flagged."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        for name, offset in (
            ("United States", 0),
            ("Washington", 1),
            ("Seattle", 2),
            ("Texas", 3),
            ("Dallas", 4),
        ):
            await seed_observation(
                uow,
                investigation_id=investigation_id,
                location_id=geography[name],
                entity_value=f"203.0.113.{140 + offset}",
                precision=LocationPrecision.COUNTRY,
                retrieved_at=FIXED + timedelta(days=offset),
            )
    service = await make_query_service(session_factory, summary_top_locations=2)
    try:
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert len(summary.top_locations) == 2
        assert summary.truncated is True
        # The bounded top groups remain the deterministic leaders.
        names = [top.location.canonical_name for top in summary.top_locations]
        assert names == ["Dallas", "Seattle"]
    finally:
        await close_query_service(service)


# ---------------------------------------------------------------------------
# Query-plan tests (index eligibility)
# ---------------------------------------------------------------------------


def _index_names(node: object, found: set[str]) -> None:
    """Collect every index name present in an EXPLAIN plan tree."""
    if isinstance(node, Mapping):
        name = node.get("Index Name")
        if isinstance(name, str):
            found.add(name)
        for value in node.values():
            _index_names(value, found)
    elif isinstance(node, list):
        for item in node:
            _index_names(item, found)


def _node_types(node: object, found: set[str]) -> None:
    """Collect every node type present in an EXPLAIN plan tree."""
    if isinstance(node, Mapping):
        node_type = node.get("Node Type")
        if isinstance(node_type, str):
            found.add(node_type)
        for value in node.values():
            _node_types(value, found)
    elif isinstance(node, list):
        for item in node:
            _node_types(item, found)


async def _plan(
    session_factory: async_sessionmaker[Any],
    statement: str,
    params: Mapping[str, object],
) -> tuple[set[str], set[str]]:
    """Return (index names, node types) for one representative statement."""
    async with session_factory() as session:
        await session.execute(text("SET LOCAL enable_seqscan = off"))
        result = await session.execute(
            text("EXPLAIN (FORMAT JSON) " + statement), dict(params)
        )
        payload = result.scalar_one()
    indexes: set[str] = set()
    node_types: set[str] = set()
    _index_names(payload, indexes)
    _node_types(payload, node_types)
    return indexes, node_types


def _observation_entity_history_statement(
    entity_id: UUID, investigation_id: UUID
) -> str:
    """Return the exact production Entity-history statement shape."""
    return f"""
        SELECT ob.id FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        WHERE ob.entity_id = '{entity_id}'
          AND ie.investigation_id = '{investigation_id}'
        ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
        LIMIT 10

    """


def _observation_scope_join_statement(investigation_id: UUID) -> str:
    """Return the exact production scope-join grouping statement shape."""
    return f"""
        SELECT count(*) FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        WHERE ie.investigation_id = '{investigation_id}'

    """


def _location_reverse_statement(location_id: UUID, investigation_id: UUID) -> str:
    """Return the exact production Location-observation statement shape."""
    return f"""
        SELECT ob.id FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        WHERE ob.location_id = '{location_id}'
          AND ie.investigation_id = '{investigation_id}'
        ORDER BY COALESCE(ob.observed_at, ob.retrieved_at) DESC, ob.id DESC
        LIMIT 10

    """


def _containment_statement(location_id: UUID, investigation_id: UUID) -> str:
    """Return the exact production containment statement shape."""
    return f"""
        SELECT ob.id FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        WHERE ob.location_id IN (
                SELECT l.id FROM ati.location l, ati.location sel
                WHERE sel.id = '{location_id}'
                  AND (l.id = sel.id OR (l.geometry && sel.geometry
                       AND ST_Covers(sel.geometry, l.geometry))))
          AND ie.investigation_id = '{investigation_id}'
        LIMIT 10

    """


def _summary_counts_statement(investigation_id: UUID) -> str:
    """Return the exact production summary-counts statement shape."""
    return f"""
        SELECT count(*), count(DISTINCT ob.entity_id), count(DISTINCT ob.location_id)
        FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        JOIN ati.location loc ON loc.id = ob.location_id
        WHERE ie.investigation_id = '{investigation_id}'

    """


def _summary_top_locations_statement(investigation_id: UUID) -> str:
    """Return the exact production summary top-Locations statement shape."""
    return f"""
        SELECT loc.id, count(DISTINCT ob.entity_id) AS scoped_entity_count
        FROM ati.entity_location_observation ob
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = ob.evidence_observation_id
        JOIN ati.location loc ON loc.id = ob.location_id
        WHERE ie.investigation_id = '{investigation_id}'
        GROUP BY loc.id, loc.location_type, loc.canonical_name, loc.country_code,
                 loc.admin1_code, loc.admin2_code, loc.parent_location_id,
                 ST_Y(loc.centroid), ST_X(loc.centroid)
        ORDER BY scoped_entity_count DESC, loc.canonical_name ASC, loc.id ASC
        LIMIT 10

    """


def _latest_per_entity_statement(location_id: UUID, investigation_id: UUID) -> str:
    """Return the exact production Location-Entity statement shape."""
    return f"""
        SELECT * FROM (
          SELECT DISTINCT ON (ob.entity_id)
            ob.id, ob.entity_id, ent.entity_type, ent.canonical_value
          FROM ati.entity_location_observation ob
          JOIN ati.investigation_evidence ie
            ON ie.evidence_observation_id = ob.evidence_observation_id
          JOIN ati.entity ent ON ent.id = ob.entity_id
          WHERE ob.location_id = '{location_id}'
            AND ie.investigation_id = '{investigation_id}'
          ORDER BY ob.entity_id, COALESCE(ob.observed_at, ob.retrieved_at) DESC,
                   ob.id DESC
        ) latest
        ORDER BY latest.entity_type, latest.canonical_value, latest.entity_id
        LIMIT 10
    """


@pytest.mark.asyncio
async def test_explain_entity_history_uses_entity_index(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """Entity history stays index-eligible on the existing entity index."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        seed = await seed_observation(
            uow,
            investigation_id=investigation_id,
            location_id=geography["United States"],
        )
    indexes, _node_types = await _plan(
        session_factory,
        _observation_entity_history_statement(seed.entity_id, investigation_id),
        {},
    )
    assert "entity_location_observation_entity_retrieved_idx" in indexes


@pytest.mark.asyncio
async def test_explain_scope_join_and_reverse_use_observation_indexes(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """Scope joins and Location lookups never scan the observation table."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    observation_indexes = {
        "entity_location_observation_evidence_idx",
        "entity_location_observation_location_idx",
        "entity_location_observation_entity_retrieved_idx",
    }
    scope_indexes, scope_nodes = await _plan(
        session_factory,
        _observation_scope_join_statement(investigation_id),
        {},
    )
    assert scope_indexes & observation_indexes
    assert "Seq Scan" not in scope_nodes

    reverse_indexes, reverse_nodes = await _plan(
        session_factory,
        _location_reverse_statement(geography["Seattle"], investigation_id),
        {},
    )
    assert reverse_indexes & observation_indexes
    assert "Seq Scan" not in reverse_nodes

    latest_indexes, latest_nodes = await _plan(
        session_factory,
        _latest_per_entity_statement(geography["Seattle"], investigation_id),
        {},
    )
    assert latest_indexes & observation_indexes
    assert "Seq Scan" not in latest_nodes


@pytest.mark.asyncio
async def test_explain_containment_uses_gist_and_observation_indexes(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """Containment stays bounded through the GiST and observation indexes."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    indexes, node_types = await _plan(
        session_factory,
        _containment_statement(geography["United States"], investigation_id),
        {},
    )
    assert "location_geometry_gist_idx" in indexes
    assert indexes & {
        "entity_location_observation_evidence_idx",
        "entity_location_observation_location_idx",
    }
    assert "Seq Scan" not in node_types


@pytest.mark.asyncio
async def test_explain_summary_stays_bounded_and_index_eligible(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """QP06: summary counts/top-Locations never Cartesian and stay indexable.

    The summary is the PR 26D bounded aggregate over exact LegacyEvidence scope;
    with seq scans disabled the grouped top-Locations query must still use
    the observation indexes (no accidental Cartesian explosion) and the SQL
    itself carries the documented GROUP BY/LIMIT bounds.
    """
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_id, geography)
    observation_indexes = {
        "entity_location_observation_evidence_idx",
        "entity_location_observation_location_idx",
        "entity_location_observation_entity_retrieved_idx",
    }
    counts_indexes, counts_nodes = await _plan(
        session_factory, _summary_counts_statement(investigation_id), {}
    )
    assert counts_indexes & observation_indexes
    assert "Seq Scan" not in counts_nodes

    top_indexes, top_nodes = await _plan(
        session_factory, _summary_top_locations_statement(investigation_id), {}
    )
    assert top_indexes & observation_indexes
    assert "Seq Scan" not in top_nodes
    # The delivered SQL bounds the grouped aggregate: no unbounded Universe.
    statement = _summary_top_locations_statement(investigation_id)
    assert "GROUP BY" in statement and "LIMIT" in statement


# ---------------------------------------------------------------------------
# API vertical slice (G26D-A03..A15 on the real stack)
# ---------------------------------------------------------------------------

PASSWORD = "correct horse battery staple"


@pytest.mark.asyncio
async def test_vs_api_vertical_slice(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """I1 sees only I1 observations; LegacyEvidence drill-down stays exact.

    The production FastAPI application runs over the real PostgreSQL with
    the real per-request ``PostgresQueryServices``; only authentication is a
    seeded real local user.
    """
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        await _seed_us_observations(uow, investigation_a, geography)
        seed_b = await seed_observation(
            uow,
            investigation_id=investigation_b,
            location_id=geography["Canada"],
            entity_value="203.0.113.150",
        )
    await seed_user(session_factory)

    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": PASSWORD},
        )
        summary = client.get(f"/api/v1/investigations/{investigation_a}/geoint/summary")
        assert summary.status_code == 200
        body = summary.json()
        assert body["observation_count"] == 5
        assert body["entity_count_with_location"] == 5
        assert body["truncated"] is False
        assert {top["location"]["canonical_name"] for top in body["top_locations"]} == {
            "Dallas",
            "Seattle",
            "Texas",
            "United States",
            "Washington",
        }
        assert body["precision_counts"] == {
            "country": 1,
            "administrative_area": 2,
            "city": 2,
        }

        history = client.get(
            f"/api/v1/investigations/{investigation_a}/geoint/entities/"
            f"{seed_b.entity_id}/observations?limit=50"
        )
        assert history.status_code == 200
        # The I2-backed shared Entity has no I1 history.
        assert history.json()["items"] == []

        location_entities = client.get(
            f"/api/v1/investigations/{investigation_a}/geoint/locations/"
            f"{geography['United States']}/entities?include_contained=true"
        )
        assert location_entities.status_code == 200
        contained = location_entities.json()
        assert contained["containment_applied"] is True
        assert {item["entity_value"] for item in contained["items"]} == {
            "203.0.113.101",
            "203.0.113.102",
            "203.0.113.103",
            "203.0.113.104",
            "203.0.113.105",
        }

        observations = client.get(
            f"/api/v1/investigations/{investigation_a}/geoint/locations/"
            f"{geography['Seattle']}/observations?include_contained=true"
        )
        assert observations.status_code == 200
        (item,) = observations.json()["items"]
        assert item["location"]["canonical_name"] == "Seattle"
        assert str(item["evidence_id"])  # exact provenance present

        observation_detail = client.get(
            f"/api/v1/investigations/{investigation_a}/geoint/observations/"
            f"{item['observation_id']}"
        )
        assert observation_detail.status_code == 200
        detail = observation_detail.json()
        assert detail["observation"]["evidence_id"] == item["evidence_id"]

        # Exact LegacyEvidence drill-down through the existing LegacyEvidence endpoint.
        evidence = client.get(
            f"/api/v1/investigations/{investigation_a}/evidence/{item['evidence_id']}"
        )
        assert evidence.status_code == 200
        assert evidence.json()["id"] == item["evidence_id"]

        # Cross-scope observation detail is a 404, never a leak.
        cross = client.get(
            f"/api/v1/investigations/{investigation_b}/geoint/observations/"
            f"{item['observation_id']}"
        )
        assert cross.status_code == 404
        assert cross.json()["error"]["code"] == "geoint_observation_not_found"

        # PR 25 geolocation projection still serves unchanged.
        legacy = client.get(f"/api/v1/investigations/{investigation_a}/geolocations")
        assert legacy.status_code == 200
        assert list(legacy.json()) == ["items", "truncated"]

        # An unknown/not-visible Investigation yields the established empty
        # collections (PR 23C convention), never a 404 or a leak.
        unknown = UUID("99999999-9999-4999-8999-999999999999")
        unknown_summary = client.get(f"/api/v1/investigations/{unknown}/geoint/summary")
        assert unknown_summary.status_code == 200
        assert unknown_summary.json()["observation_count"] == 0
        unknown_entities = client.get(
            f"/api/v1/investigations/{unknown}/geoint/locations/"
            f"{geography['Seattle']}/entities"
        )
        assert unknown_entities.status_code == 200
        assert unknown_entities.json()["items"] == []

    # Reads mutate nothing.
    assert await table_count(session_factory, "entity_location_observation") == 6


# ---------------------------------------------------------------------------
# Canonical vertical slice (production resolution -> query -> API)
# ---------------------------------------------------------------------------


class _SessionBoundResolver(LocationResolver):
    """LocationResolver adapter with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[Any]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _worker_instance(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> GeoResolutionWorker:
    """Compose one production-style worker with the real resolver."""
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=_SessionBoundResolver(session_factory),
        config=GeoResolutionWorkerConfig(
            enabled=True,
            worker_id="worker-26d",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        ),
    )


@pytest.mark.asyncio
async def test_vs_canonical_resolution_to_query_to_api(
    uow_factory: Callable[[], UnitOfWork],
    session_factory: async_sessionmaker[Any],
) -> None:
    """Real PR 26C resolution -> query -> API -> LegacyEvidence end to end."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        geography = await seed_geography(uow)
        # I1 GEOLOCATION LegacyEvidence resolves canonically to Seattle.
        entity_id = await seed_entity(uow, value="203.0.113.200")
        evidence_a = await seed_geolocation_for_investigation(
            uow,
            investigation_a,
            entity_id,
            "203.0.113.200",
            retrieved_at=FIXED,
            facts={
                "country_code": "US",
                "region": "Washington",
                "city": "Seattle",
                "precision": "city",
            },
        )
        resolution_a = await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(),
                entity_id=entity_id,
                evidence_observation_id=evidence_a,
            )
        )
        assert resolution_a.id is not None
        # I2 resolves the same Entity to Vancouver with a newer timestamp.
        evidence_b = await seed_geolocation_for_investigation(
            uow,
            investigation_b,
            entity_id,
            "203.0.113.200",
            retrieved_at=FIXED + timedelta(days=1),
            facts={
                "country_code": "CA",
                "region": "British Columbia",
                "city": "Vancouver",
                "precision": "city",
            },
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=uuid4(),
                entity_id=entity_id,
                evidence_observation_id=evidence_b,
            )
        )

    worker = _worker_instance(uow_factory, session_factory)
    completed = await worker.run_once()
    assert completed == 2

    async with uow_factory() as uow:
        observation_rows = await uow.entity_location_observations.list_for_entity(
            entity_id, limit=1000
        )
    assert len(observation_rows) == 2

    service = await make_query_service(session_factory)
    try:
        # I1 current is its own scoped Seattle observation.
        current_a = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_a, entity_id=entity_id)
        )
        assert current_a is not None
        assert current_a.current_observation.location.canonical_name == "Seattle"
        assert current_a.current_observation.evidence_observation_id == evidence_a
        known_observation_id = current_a.current_observation.observation_id

        # I1 cannot retrieve the I2 observation detail.
        observation_b = [
            row for row in observation_rows if row.evidence_observation_id == evidence_b
        ]
        assert len(observation_b) == 1
        cross = await service.get_observation(
            GeointObservationQuery(
                investigation_id=investigation_a, observation_id=observation_b[0].id
            )
        )
        assert cross is None

        # Containment: I1 contains Seattle from the country boundary.
        contained = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_a,
                location_id=geography["United States"],
                include_contained=True,
                limit=50,
            )
        )
        assert [item.entity_value for item in contained.items] == ["203.0.113.200"]
        assert contained.containment_applied is True
    finally:
        await close_query_service(service)

    await seed_user(session_factory)
    with api_client(api_settings()) as client:
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": PASSWORD},
        )
        entity_response = client.get(
            f"/api/v1/investigations/{investigation_a}/geoint/entities/{entity_id}"
        )
        assert entity_response.status_code == 200
        body = entity_response.json()
        assert body["current_observation"]["location"]["canonical_name"] == "Seattle"
        assert body["current_observation"]["evidence_id"] == str(evidence_a)
        assert body["current_observation"]["precision"] == "city"

        # Exact LegacyEvidence endpoint accepts the exact evidence_id from the API.
        evidence_response = client.get(
            f"/api/v1/investigations/{investigation_a}/evidence/{evidence_a}"
        )
        assert evidence_response.status_code == 200

        # Pagination of the resolved history is deterministic and complete.
        history_pages: list[str] = []
        cursor: str | None = None
        while True:
            params: dict[str, object] = {"limit": 1}
            if cursor is not None:
                params["cursor"] = cursor
            page = client.get(
                f"/api/v1/investigations/{investigation_a}/geoint/entities/"
                f"{entity_id}/observations",
                params=params,
            )
            assert page.status_code == 200
            payload = page.json()
            history_pages.extend(item["observation_id"] for item in payload["items"])
            cursor = payload["next_cursor"]
            if cursor is None:
                break
        assert history_pages == [str(known_observation_id)]

    # The read path mutated nothing beyond the resolution work.
    async with uow_factory() as uow:
        total = await table_count(session_factory, "entity_location_observation")
        assert total == 2
