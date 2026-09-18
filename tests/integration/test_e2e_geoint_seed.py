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

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from agentic_threat_investigator.app.geoint.reference_ingestion import (
    ReferenceIngestionService,
)
from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.query.geoint import (
    GeointEntityObservationListQuery,
    GeointEntityQuery,
    GeointLocationEntityListQuery,
    GeointObservationQuery,
    GeointSummaryQuery,
)
from agentic_threat_investigator.cli import geography_build_main
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
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
    """A second invocation reuses rows and creates no duplicates."""
    await _import_geography(uow_factory, tmp_path)
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    first = await _seed_factory(
        uow_factory, session_factory, investigation_id, "same_location"
    )
    assert len(first.created_evidence_ids) == 2
    second = await _seed_factory(
        uow_factory, session_factory, investigation_id, "same_location"
    )
    assert second.created_evidence_ids == ()
    assert sorted(second.reused_evidence_ids) == sorted(first.created_evidence_ids)
    async with uow_factory() as uow:
        service = _service(uow)
        summary = await service.summary(
            GeointSummaryQuery(investigation_id=investigation_id)
        )
        assert summary.observation_count == 2


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
