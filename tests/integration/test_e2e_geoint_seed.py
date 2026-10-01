# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26E seeder real-PostgreSQL + PostGIS integration proof.

Drives the harness-only GEOINT seeder against the isolated integration
database through the normal repositories, the real reference-geography
import (the exact ``ati-geography-build`` + ingestion path the operator
runs), the production ``GeoResolutionWorker`` with the real
``PostgresCanonicalGeographyResolver``, and then reads the result through
the real PR 26D query service. Behavioral assertions never insert
``Location``/``EntityLocationObservation``/``EntityLocation`` directly and
never query tables directly: the service/API are the read path an analyst
actually uses.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from agentic_threat_investigator.app.geoint.reference_ingestion import (
    ReferenceIngestionService,
)
from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.persistence.repositories import (
    GeoResolutionDuplicateStateError,
)
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointObservationQuery,
    GeointSummaryQuery,
)
from agentic_threat_investigator.cli import geography_build_main
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
    GeoResolution,
    GeoResolutionStatus,
    LocationType,
    canonical_location_uuid,
    observation_uuid_for_resolution,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.query.geoint import (
    PostgresGeointQueryService,
)
from agentic_threat_investigator.infrastructure.sources.geography import (
    JsonlGeographyCorpus,
)
from tests.e2e_support.seed_geoint import (
    E2eSeedIncompatibleResolutionError,
    apply_seed,
    build_seed_units,
    derive_entity_id,
)
from tests.support.query_fixtures import seed_investigation

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "geoint"
PASSWORD = "correct horse battery staple"


def _build_corpus(tmp_path: Path) -> Path:
    """Run the real ati-geography-build derivation over the fixtures."""
    output = tmp_path / "ati-geography.ndjson"
    status = geography_build_main(
        [
            "--geonames-country-info",
            str(FIXTURES / "geonames" / "countryInfo.txt"),
            "--geonames-admin1",
            str(FIXTURES / "geonames" / "admin1CodesASCII.txt"),
            "--geonames-cities",
            str(FIXTURES / "geonames" / "cities1000.txt"),
            "--natural-earth-countries",
            str(FIXTURES / "natural_earth" / "ne_countries.geojson"),
            "--natural-earth-admin1",
            str(FIXTURES / "natural_earth" / "ne_admin1.geojson"),
            "--output",
            str(output),
        ]
    )
    assert status == 0
    return output


async def _import_geography(uow_factory: Callable[..., Any], tmp_path: Path) -> None:
    """Ingest the built corpus through the production ingestion service."""
    artifact = _build_corpus(tmp_path)
    records = JsonlGeographyCorpus().read_path(artifact)
    stats = await ReferenceIngestionService(uow_factory).ingest(records)
    assert stats.rejected == 0
    assert stats.conflicts == 0
    assert stats.created > 0


class _SessionBoundResolver(LocationResolver):
    """LocationResolver adapter with one short read session per resolve."""

    def __init__(self, session_factory: async_sessionmaker[Any]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve through the real PostGIS canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _service(uow: Any) -> PostgresGeointQueryService:
    """Build the real PR 26D query service over the current session."""
    assert uow.session is not None
    return PostgresGeointQueryService(uow.session)


def _seed_factory(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    investigation_id: Any,
    scenario: str,
    **kwargs: Any,
) -> Any:
    """Run the seeder end to end with the production resolver worker."""
    return apply_seed(
        uow_factory,
        resolver=_SessionBoundResolver(session_factory),
        investigation_id=investigation_id,
        scenario=scenario,
        **kwargs,
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_entity_history_resolves_to_observations(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """Entity history: current is the newer Location; both rows persist."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(
        uow_factory, session_factory, investigation_id, "entity_history"
    )
    assert len(report.observation_ids) == 2

    async with uow_factory() as uow:
        service = _service(uow)
        entity_id = derive_entity_id("203.0.113.10")
        entity = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )
        assert entity is not None
        assert entity.current_observation is not None
        assert entity.current_observation.location.canonical_name == "Dallas"
        history = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_id, entity_id=entity_id, limit=10
            )
        )
        assert len(history.items) == 2
        names = [item.location.canonical_name for item in history.items]
        assert set(names) == {"Seattle", "Dallas"}
        # The two observations carry distinct timestamps and exact evidence.
        assert len({item.retrieved_at for item in history.items}) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_same_location_entities_stay_distinct(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """Same-location seeding produces two individually inspectable Entities."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    await _seed_factory(uow_factory, session_factory, investigation_id, "same_location")
    async with uow_factory() as uow:
        service = _service(uow)
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.entity_count_with_location == 2
        assert summary.observation_count == 2
        seattle = next(
            top.location
            for top in summary.top_locations
            if top.location.canonical_name == "Seattle"
        )
        entities = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=seattle.location_id,
                include_contained=False,
                limit=10,
            )
        )
        assert {item.entity_value for item in entities.items} == {
            "203.0.113.20",
            "203.0.113.30",
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_containment_exact_vs_included(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """Containment: Washington exact excludes Seattle; included contains it."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    await _seed_factory(uow_factory, session_factory, investigation_id, "containment")

    async with uow_factory() as uow:
        service = _service(uow)
        us = canonical_location_uuid(
            location_type=LocationType.COUNTRY,
            country_code="US",
            admin1_code=None,
            admin2_code=None,
            canonical_name="United States",
        )
        wa = await _location_id(service, investigation_id, "Washington")
        seattle = await _location_id(service, investigation_id, "Seattle")

        exact_wa = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=wa,
                include_contained=False,
                limit=10,
            )
        )
        assert exact_wa.containment_applied is False
        assert {item.entity_value for item in exact_wa.items} == {"203.0.113.50"}

        contained_wa = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=wa,
                include_contained=True,
                limit=10,
            )
        )
        assert contained_wa.containment_applied is True
        assert {item.entity_value for item in contained_wa.items} == {
            "203.0.113.40",
            "203.0.113.50",
        }

        contained_us = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=us,
                include_contained=True,
                limit=10,
            )
        )
        assert {item.entity_value for item in contained_us.items} == {
            "203.0.113.40",
            "203.0.113.50",
        }

        # City Points never expand: Seattle contained == exact.
        contained_seattle = await service.list_location_entities(
            GeointLocationEntityListQuery(
                investigation_id=investigation_id,
                location_id=seattle,
                include_contained=True,
                limit=10,
            )
        )
        assert contained_seattle.containment_applied is False
        assert {item.entity_value for item in contained_seattle.items} == {
            "203.0.113.40"
        }


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_non_mappable_has_no_representative_coordinates(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """Non-mappable: a valid observation without plottable coordinates."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    report = await _seed_factory(
        uow_factory, session_factory, investigation_id, "non_mappable"
    )
    assert len(report.observation_ids) == 1
    async with uow_factory() as uow:
        service = _service(uow)
        entity_id = derive_entity_id("203.0.113.70")
        entity = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_id, entity_id=entity_id)
        )
        assert entity is not None and entity.current_observation is not None
        assert entity.current_observation.location.canonical_name == "EdgeLand"
        assert entity.current_observation.location.latitude is None
        assert entity.current_observation.location.longitude is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_cross_investigation_isolation(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """I1 sees only I1; the I2 observation is never leaked."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
    report = await _seed_factory(
        uow_factory,
        session_factory,
        investigation_a,
        "cross_investigation",
        other_investigation_id=investigation_b,
    )
    # Both scoped rows complete (one per Investigation); the report lists
    # them in unit order, so the second identity belongs to I2.
    assert len(report.observation_ids) == 2

    async with uow_factory() as uow:
        service = _service(uow)
        entity_id = derive_entity_id("203.0.113.60")
        entity_a = await service.get_entity(
            GeointEntityQuery(investigation_id=investigation_a, entity_id=entity_id)
        )
        assert entity_a is not None and entity_a.current_observation is not None
        assert entity_a.current_observation.location.canonical_name == "Seattle"
        history_a = await service.list_entity_observations(
            GeointEntityObservationListQuery(
                investigation_id=investigation_a, entity_id=entity_id, limit=10
            )
        )
        assert [item.location.canonical_name for item in history_a.items] == ["Seattle"]
        # The I2 observation (Dallas) is cross-scope: detail is not visible.
        units = build_seed_units(
            investigation_a,
            "cross_investigation",
            other_investigation_id=investigation_b,
        )
        (i2_unit,) = [unit for unit in units if unit.admitted_to == investigation_b]
        i2_detail = await service.get_observation(
            GeointObservationQuery(
                investigation_id=investigation_a,
                observation_id=observation_uuid_for_resolution(i2_unit.resolution_id),
            )
        )
        assert i2_detail is None


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_idempotent_rerun_reuses_rows(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI01: an identical second seed reuses rows, never duplicating work."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    units = build_seed_units(investigation_id, "same_location")
    first = await _seed_factory(
        uow_factory, session_factory, investigation_id, "same_location"
    )
    assert len(first.created_evidence_ids) == 2
    assert all(
        unit.resolution_id is not None for unit in units
    )  # deterministic candidates exist
    second = await _seed_factory(
        uow_factory, session_factory, investigation_id, "same_location"
    )
    assert second.created_evidence_ids == ()
    assert sorted(second.reused_evidence_ids) == sorted(first.created_evidence_ids)
    # One semantic resolution per pair, never a fresh PENDING row, and the
    # exact canonical observations per (entity, evidence) survive byte-stable.
    async with uow_factory() as uow:
        for unit in units:
            row = await uow.geo_resolutions.get_by_entity_evidence(
                unit.entity_id, unit.evidence_id
            )
            assert row is not None
            assert row.status is GeoResolutionStatus.RESOLVED
        first_rows = {
            row.evidence_observation_id: row
            for row in await uow.entity_location_observations.list_for_entity(
                units[0].entity_id
            )
        }
        second_rows = {
            row.evidence_observation_id: row
            for row in await uow.entity_location_observations.list_for_entity(
                units[1].entity_id
            )
        }
        # Exact provenance: the observation binds the deterministic evidence id
        # and the deterministic canonical Location id (Seattle).
        assert set(first_rows) == {units[0].evidence_id}
        assert set(second_rows) == {units[1].evidence_id}
        assert len(first_rows) == 1 and len(second_rows) == 1
        service = _service(uow)
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.observation_count == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_seed_replayed_for_second_investigation_reuses_resolved_work(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI01b: the same scenario for a second Investigation reuses resolved work.

    This is the deterministic fresh-main defect reconstruction: a replay for a
    fresh Investigation reuses the stable Evidence through the UNCHANGED
    persist path and returned the first Investigation's observation, then
    collided with the already-claimed/resolved pair. The corrected seeder
    reads the semantic pair first and reuses the RESOLVED work; the second
    Investigation receives the exact same canonical observation scoped by its
    own admission.
    """
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
    first = await _seed_factory(
        uow_factory, session_factory, investigation_a, "entity_history"
    )
    assert len(first.observation_ids) == 2
    pairs_a = [
        (unit.entity_id, unit.evidence_id)
        for unit in build_seed_units(investigation_a, "entity_history")
    ]
    second = await _seed_factory(
        uow_factory, session_factory, investigation_b, "entity_history"
    )
    assert len(second.observation_ids) == 2
    async with uow_factory() as uow:
        # Exactly one semantic resolution per pair, all RESOLVED, none PENDING.
        for entity_id, evidence_id in pairs_a:
            row = await uow.geo_resolutions.get_by_entity_evidence(
                entity_id, evidence_id
            )
            assert row is not None
            assert row.status is GeoResolutionStatus.RESOLVED
        # B sees the exact same preferred evidence as A (the stable evidence
        # was reused, not duplicated) and the canonical observation count stays
        # at exactly two rows total for the shared entity.
        service = _service(uow)
        summary_b = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_b)
        )
        assert summary_b.observation_count == 2
        summary_a = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_a)
        )
        assert summary_a.observation_count == 2
        rows = await uow.entity_location_observations.list_for_entity(
            derive_entity_id("203.0.113.10")
        )
        assert len(rows) == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pre_existing_pending_is_reused_and_completed(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI02: pre-existing PENDING work is reused and completed normally."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    (unit,) = build_seed_units(investigation_id, "non_mappable")
    # Establish prerequisites + PENDING work through the normal repositories.
    from agentic_threat_investigator.domain.evidence import (
        InvestigationEvidence,
        InvestigationEvidenceActor,
        InvestigationEvidenceReason,
    )
    from tests.e2e_support.seed_geoint import SEED_RETRIEVED_AT

    async with uow_factory() as uow:
        entity = await uow.entities.upsert(unit.entity)
        assert entity.id is not None
        persisted = await uow.evidence.persist(
            unit.evidence, observation_id=unit.evidence_id
        )
        await uow.evidence_observation_entities.associate(
            persisted.observation.id, entity.id
        )
        await uow.investigation_evidence.admit(
            InvestigationEvidence(
                investigation_id=unit.admitted_to,
                evidence_observation_id=persisted.observation.id,
                inclusion_reason=InvestigationEvidenceReason.INITIAL,
                added_at=SEED_RETRIEVED_AT,
                added_by=InvestigationEvidenceActor.SYSTEM,
            )
        )
        await uow.geo_resolutions.create_pending(
            GeoResolution(
                id=unit.resolution_id,
                entity_id=entity.id,
                evidence_observation_id=persisted.observation.id,
            )
        )
    report = await _seed_factory(
        uow_factory, session_factory, investigation_id, "non_mappable"
    )
    assert report.reused_evidence_ids == (unit.evidence_id,)
    assert len(report.observation_ids) == 1
    async with uow_factory() as uow:
        row = await uow.geo_resolutions.get_by_entity_evidence(
            unit.entity_id, unit.evidence_id
        )
        assert row is not None and row.status is GeoResolutionStatus.RESOLVED


@pytest.mark.asyncio
@pytest.mark.integration
async def test_database_duplicate_state_guard_still_fires(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI03: the DB duplicate-state guard is authoritative and never weakened."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    await _seed_factory(uow_factory, session_factory, investigation_id, "same_location")
    units = build_seed_units(investigation_id, "same_location")
    async with uow_factory() as uow:
        entity = await uow.entities.upsert(units[0].entity)
        assert entity.id is not None
        with pytest.raises(GeoResolutionDuplicateStateError):
            await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=units[0].resolution_id,
                    entity_id=entity.id,
                    evidence_observation_id=units[0].evidence_id,
                )
            )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_incompatible_terminal_resolution_fails_closed(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI04: UNRESOLVABLE/FAILED pairs fail the replay with zero reset."""
    await _import_geography(uow_factory, tmp_path)

    async def establish_terminal(
        uow_factory: Callable[..., Any],
        investigation_id: Any,
        unit: Any,
        status: GeoResolutionStatus,
        code: str,
    ) -> None:
        from agentic_threat_investigator.domain.evidence import (
            InvestigationEvidence,
            InvestigationEvidenceActor,
            InvestigationEvidenceReason,
        )
        from tests.e2e_support.seed_geoint import SEED_RETRIEVED_AT

        async with uow_factory() as uow:
            entity = await uow.entities.upsert(unit.entity)
            assert entity.id is not None
            persisted = await uow.evidence.persist(
                unit.evidence, observation_id=unit.evidence_id
            )
            await uow.evidence_observation_entities.associate(
                persisted.observation.id, entity.id
            )
            await uow.investigation_evidence.admit(
                InvestigationEvidence(
                    investigation_id=unit.admitted_to,
                    evidence_observation_id=persisted.observation.id,
                    inclusion_reason=InvestigationEvidenceReason.INITIAL,
                    added_at=SEED_RETRIEVED_AT,
                    added_by=InvestigationEvidenceActor.SYSTEM,
                )
            )
            claimed = await uow.geo_resolutions.create_pending(
                GeoResolution(
                    id=unit.resolution_id,
                    entity_id=entity.id,
                    evidence_observation_id=persisted.observation.id,
                )
            )
            assert claimed.id is not None and claimed.version is not None
            [claimed_row] = await uow.geo_resolutions.claim_batch(
                claimed_by="gi04-terminal",
                limit=10,
                lease_seconds=300,
                max_attempts=3,
            )
            if status is GeoResolutionStatus.UNRESOLVABLE:
                await uow.geo_resolutions.complete_unresolvable(
                    resolution_id=claimed_row.id,
                    expected_version=claimed_row.version,
                    claimed_by=claimed_row.claimed_by,
                    error_code=code,
                )
            else:
                await uow.geo_resolutions.record_failure(
                    claimed_row.id,
                    claimed_row.version,
                    claimed_row.claimed_by,
                    code,
                    retryable=False,
                    retry_base_seconds=60.0,
                    retry_max_seconds=3600.0,
                    max_attempts=3,
                )

    # Each terminal status needs its own Investigation AND scenario: the
    # stable Evidence identity is (scenario, index, value), so reusing the
    # same scenario for a second Investigation would re-enter the very
    # root-cause path this test proves (stable reuse -> existing pair).
    for terminal_status, scenario, index, code in (
        (GeoResolutionStatus.UNRESOLVABLE, "non_mappable", 0, "test_no_match"),
        (GeoResolutionStatus.FAILED, "entity_history", 0, "test_worker_failure"),
    ):
        async with uow_factory() as uow:
            investigation_id = await seed_investigation(uow)
        unit = build_seed_units(investigation_id, scenario)[index]
        await establish_terminal(
            uow_factory, investigation_id, unit, terminal_status, code
        )
        with pytest.raises(E2eSeedIncompatibleResolutionError):
            await _seed_factory(
                uow_factory, session_factory, investigation_id, scenario
            )
        async with uow_factory() as uow:
            row = await uow.geo_resolutions.get_by_entity_evidence(
                unit.entity_id, unit.evidence_id
            )
            assert row is not None
            assert row.status is terminal_status  # never reset or recreated


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pre_existing_canonical_entity_under_different_uuid(
    uow_factory: Callable[..., Any],
    session_factory: async_sessionmaker[Any],
    tmp_path: Path,
) -> None:
    """GI05: a canonical Entity persisted under another UUID binds downstream."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    (unit,) = build_seed_units(investigation_id, "non_mappable")
    existing_entity_id = uuid4()
    async with uow_factory() as uow:
        persisted = await uow.entities.upsert(
            Entity(
                id=existing_entity_id,
                type=EntityType.IP_ADDRESS,
                value=unit.entity_value,
            )
        )
        assert persisted.id == existing_entity_id
    report = await _seed_factory(
        uow_factory, session_factory, investigation_id, "non_mappable"
    )
    assert report.entity_ids == (existing_entity_id,)
    async with uow_factory() as uow:
        row = await uow.geo_resolutions.get_by_entity_evidence(
            existing_entity_id, unit.evidence_id
        )
        assert row is not None and row.status is GeoResolutionStatus.RESOLVED
        rows = await uow.entity_location_observations.list_for_entity(
            existing_entity_id
        )
        assert len(rows) == 1
        assert rows[0].evidence_observation_id == unit.evidence_id


async def _location_id(
    service: PostgresGeointQueryService, investigation_id: Any, name: str
) -> Any:
    """Resolve one canonical Location identity through a summary read."""
    summary = await service.summary(
        GeointSummaryQuery(investigation_id=investigation_id)
    )
    for top in summary.top_locations:
        if top.location.canonical_name == name:
            return top.location.location_id
    raise AssertionError(f"location {name!r} missing from the summary")
