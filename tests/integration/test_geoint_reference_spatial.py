# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B canonical geography/PostGIS matrices on real PostgreSQL + PostGIS.

G26B-P matrix: PostGIS runtime/schema/round-trip/validation/index proofs.
G26B-I matrix: deterministic reference ingestion semantics.
G26B-R matrix: bounded claim -> canonical Location resolution semantics.

All tests run against the isolated PostGIS-enabled PostgreSQL container; a
fixture corpus (``tests/fixtures/geoint``) exercises the production corpus
parser and reference ingestion path. No PostGIS behavior is mocked.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.geoint.reference_ingestion import (
    ReferenceIngestionService,
    ReferenceIngestionStatistics,
)
from agentic_threat_investigator.app.persistence.repositories import (
    InvalidReferenceGeometryError,
    InvalidReferenceHierarchyError,
    LocationReferenceOutcome,
)
from agentic_threat_investigator.domain.geo_reference import (
    GeographicReferenceRecord,
    ReferenceParent,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    CanonicalLocationResolutionStatus,
    GeographicClaim,
    Location,
    LocationPrecision,
    LocationType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.sources.geography import (
    JsonlGeographyCorpus,
)

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "geoint"
WA_GEOMETRY = "SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))"
REFRESHED_WA_GEOMETRY = "SRID=4326;POLYGON((-125 46,-117 46,-117 49,-125 49,-125 46))"


def corpus(*, include_edge: bool = True) -> list[GeographicReferenceRecord]:
    """Return the checked-in reference corpus records."""
    paths = [FIXTURES / "corpus_small.jsonl"]
    if include_edge:
        paths.append(FIXTURES / "corpus_synthetic_edge.jsonl")
    return JsonlGeographyCorpus().read_paths(paths)


def country_claim(country: str = "US", **kwargs: object) -> GeographicClaim:
    """Build one bounded country-precision claim."""
    defaults: dict[str, object] = {
        "country_code": country,
        "precision": LocationPrecision.COUNTRY,
    }
    defaults.update(kwargs)
    return GeographicClaim.model_validate(defaults)


def admin_claim(
    country: str, *, admin: str | None = None, code: str | None = None, **kwargs: object
) -> GeographicClaim:
    """Build one bounded administrative-area claim."""
    defaults: dict[str, object] = {
        "country_code": country,
        "administrative_area": admin,
        "administrative_area_code": code,
        "precision": LocationPrecision.ADMINISTRATIVE_AREA,
    }
    defaults.update(kwargs)
    return GeographicClaim.model_validate(defaults)


def city_claim(
    country: str,
    city: str,
    *,
    admin: str | None = None,
    code: str | None = None,
    **kwargs: object,
) -> GeographicClaim:
    """Build one bounded city claim."""
    defaults: dict[str, object] = {
        "country_code": country,
        "administrative_area": admin,
        "administrative_area_code": code,
        "city": city,
        "precision": LocationPrecision.CITY,
    }
    defaults.update(kwargs)
    return GeographicClaim.model_validate(defaults)


async def ingest_all(
    uow_factory: Callable[[], PostgresUnitOfWork],
    records: list[GeographicReferenceRecord],
) -> ReferenceIngestionStatistics:
    """Ingest one corpus batch through the production service."""
    return await ReferenceIngestionService(uow_factory).ingest(records)


async def resolver(uow: PostgresUnitOfWork) -> PostgresCanonicalGeographyResolver:
    """Build the PostGIS resolver over the active UoW session."""
    assert uow.session is not None
    return PostgresCanonicalGeographyResolver(uow.session)


async def location_count(uow: PostgresUnitOfWork) -> int:
    """Count every canonical Location row in the active UoW."""
    assert uow.session is not None
    return int(
        (
            await uow.session.execute(text("SELECT count(*) FROM ati.location"))
        ).scalar_one()
    )


# --------------------------------------------------------------------------
# G26B-P: PostGIS runtime and spatial Location schema
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p01_postgis_available_after_migration(
    integration_engine: AsyncEngine,
) -> None:
    """G26B-P01 the PostGIS extension is installed in the ati schema."""
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
    assert "postgis" in extensions


@pytest.mark.asyncio
async def test_p02_pgvector_and_postgis_coexist(
    integration_engine: AsyncEngine,
) -> None:
    """G26B-P02 pgvector and PostGIS are simultaneously available."""
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
        vector_count = await connection.scalar(
            text("SELECT count(*) FROM ati.document_chunk")
        )
    assert {"postgis", "vector"} <= extensions
    assert vector_count is not None  # the vector column remains queryable


@pytest.mark.asyncio
async def test_p03_location_geometry_is_srid4326_geometry_not_geography(
    integration_engine: AsyncEngine,
) -> None:
    """G26B-P03 ati.location.geometry is SRID-4326 geometry, never geography."""
    async with integration_engine.connect() as connection:
        columns = {
            row[0]: row[1]
            for row in await connection.execute(
                text("""
                    SELECT column_name, udt_name FROM information_schema.columns
                    WHERE table_schema = 'ati' AND table_name = 'location'
                      AND column_name IN ('geometry', 'centroid')
                """)
            )
        }
        geometry_meta = {
            (row[0], row[1], row[2])
            for row in await connection.execute(
                text("""
                    SELECT f_geometry_column, type, srid FROM geometry_columns
                    WHERE f_table_schema = 'ati' AND f_table_name = 'location'
                """)
            )
        }
    assert columns == {"geometry": "geometry", "centroid": "geometry"}
    assert ("geometry", "GEOMETRY", 4326) in geometry_meta
    assert ("centroid", "POINT", 4326) in geometry_meta
    assert not any("geography" in column for column in columns)


@pytest.mark.asyncio
async def test_p04_centroid_column_has_point_4326_type(
    integration_engine: AsyncEngine,
) -> None:
    """G26B-P04 the centroid column is Point/4326 geometry."""
    async with integration_engine.connect() as connection:
        centroid = await connection.scalar(
            text("""
                SELECT type || '/' || srid FROM geometry_columns
                WHERE f_table_schema = 'ati' AND f_table_name = 'location'
                  AND f_geometry_column = 'centroid'
            """)
        )
    assert centroid == "POINT/4326"


@pytest.mark.asyncio
async def test_p05_country_polygon_persists_and_round_trips(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P05 a country polygon persists and round-trips as EWKT text."""
    async with uow_factory() as uow:
        written = await uow.locations.upsert_reference(
            Location(
                type=LocationType.COUNTRY,
                name="Polygonia",
                canonical_name="Polygonia",
                country_code="PP",
                geometry="SRID=4326;POLYGON((-125 45,-116 45,-116 49.5,-125 49.5,-125 45))",
            )
        )
        assert written.outcome is LocationReferenceOutcome.CREATED
        assert written.location.id is not None
        assert written.location.geometry == WA_GEOMETRY
        fetched = await uow.locations.get_by_id(written.location.id)
        assert fetched is not None and fetched.geometry == WA_GEOMETRY
        # A polygonal country also received a derived on-surface representative
        # point (ST_PointOnSurface), documented as such, never ST_Centroid.
        assert fetched.centroid is not None and fetched.centroid.startswith(
            "SRID=4326;POINT"
        )


@pytest.mark.asyncio
async def test_p07_city_point_persists_and_round_trips(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P07 a city point persists in both spatial columns (canonical point)."""
    async with uow_factory() as uow:
        await ingest_all(uow_factory, corpus(include_edge=False))
        seattle = await uow.locations.get_by_identity(
            location_type="city",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Seattle",
        )
        assert seattle is not None
        assert seattle.geometry == "SRID=4326;POINT(-122.3321 47.6062)"
        assert seattle.centroid == seattle.geometry


@pytest.mark.asyncio
async def test_p13_null_geometry_remains_valid(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P13 coordinate-less reference state keeps NULL spatial fields."""
    async with uow_factory() as uow:
        await ingest_all(uow_factory, corpus(include_edge=False))
        auburn = await uow.locations.get_by_identity(
            location_type="city",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Auburn",
        )
        assert auburn is not None
        assert auburn.geometry is None and auburn.centroid is None


@pytest.mark.asyncio
async def test_p14_gist_geometry_index_exists(integration_engine: AsyncEngine) -> None:
    """G26B-P14 the justified GiST index on non-null geometry exists."""
    async with integration_engine.connect() as connection:
        definition = await connection.scalar(
            text("""
                SELECT indexdef FROM pg_indexes
                WHERE schemaname = 'ati' AND tablename = 'location'
                  AND indexname = 'location_geometry_gist_idx'
            """)
        )
    assert definition is not None
    assert "gist" in definition and "geometry" in definition


@pytest.mark.asyncio
async def test_p15_containment_query_is_gist_index_eligible(
    uow_factory: Callable[[], PostgresUnitOfWork],
    integration_engine: AsyncEngine,
) -> None:
    """G26B-P15 the containment candidate query is spatial-index eligible.

    A generated corpus large enough that the planner prefers the GiST index
    over a sequential scan; eligibility is asserted via EXPLAIN (not exact
    cost values).
    """
    async with uow_factory() as uow:
        assert uow.session is not None
        await uow.session.execute(
            text("""
                DO $$
                DECLARE i integer; v_parent uuid; v_x integer;
                BEGIN
                  INSERT INTO ati.location (
                    id, location_type, name, canonical_name, country_code,
                    parent_location_id, version)
                  VALUES (
                    'cccccccc-0000-4000-8000-000000000001', 'country',
                    'Generated', 'Generated', 'GG', NULL, 1);
                  SELECT id INTO v_parent FROM ati.location
                    WHERE id = 'cccccccc-0000-4000-8000-000000000001';
                  FOR i IN 1..1200 LOOP
                    v_x := -90 + (i % 180);
                    INSERT INTO ati.location (
                      id, location_type, name, canonical_name, country_code,
                      admin1_code, parent_location_id, geometry, centroid,
                      version)
                    VALUES (
                      gen_random_uuid(), 'administrative_area',
                      format('GenArea%s', i), format('GenArea%s', i), 'GG',
                      format('G%s', i), v_parent,
                      ST_GeomFromText(format(
                        'POLYGON((%s %s,%s %s,%s %s,%s %s,%s %s))',
                        v_x, -90, v_x + 1, -90, v_x + 1, -89,
                        v_x, -89, v_x, -90),
                        4326),
                      ST_PointOnSurface(ST_GeomFromText(format(
                        'POLYGON((%s %s,%s %s,%s %s,%s %s,%s %s))',
                        v_x, -90, v_x + 1, -90, v_x + 1, -89,
                        v_x, -89, v_x, -90), 4326)),
                      i + 1)
                    ON CONFLICT DO NOTHING;
                  END LOOP;
                END
                $$;
            """)
        )
        await uow.commit()
    async with integration_engine.connect() as connection:
        # Fresh statistics so the planner's selectivity estimates are real;
        # eligibility is then proven via EXPLAIN (never exact cost values).
        await connection.execute(text("ANALYZE ati.location"))
        plan = await connection.scalar(
            text("""
                EXPLAIN SELECT l.id FROM ati.location l
                WHERE l.location_type = 'administrative_area'
                  AND l.country_code = 'GG'
                  AND l.geometry && ST_SetSRID(ST_Point(0.5, -89.5), 4326)
                  AND ST_Covers(
                      l.geometry, ST_SetSRID(ST_Point(0.5, -89.5), 4326))
            """)
        )
    assert plan is not None and isinstance(plan, str)
    assert "location_geometry_gist_idx" in plan


@pytest.mark.asyncio
async def test_p08_invalid_srid_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P08 a non-4326 declared SRID is rejected fail-closed."""
    async with uow_factory() as uow:
        with pytest.raises(InvalidReferenceGeometryError, match="4326"):
            await uow.locations.upsert_reference(
                Location(
                    type=LocationType.COUNTRY,
                    name="X",
                    canonical_name="X",
                    country_code="US",
                    geometry="SRID=3857;POINT(0 0)",
                )
            )


async def _location_count(uow_factory: Callable[[], PostgresUnitOfWork]) -> int:
    """Return the persisted canonical Location count in its own transaction."""
    async with uow_factory() as uow:
        return await location_count(uow)


@pytest.mark.asyncio
async def test_p09_empty_geometry_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P09 empty geometries are rejected."""
    async with uow_factory() as uow:
        with pytest.raises(InvalidReferenceGeometryError):
            await uow.locations.upsert_reference(
                Location(
                    type=LocationType.COUNTRY,
                    name="X",
                    canonical_name="X",
                    country_code="US",
                    geometry="SRID=4326;POLYGON EMPTY",
                )
            )


@pytest.mark.asyncio
async def test_p10_invalid_polygon_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P10 an invalid (self-intersecting) polygon is rejected."""
    async with uow_factory() as uow:
        with pytest.raises(InvalidReferenceGeometryError, match="valid"):
            await uow.locations.upsert_reference(
                Location(
                    type=LocationType.COUNTRY,
                    name="X",
                    canonical_name="X",
                    country_code="US",
                    geometry="SRID=4326;POLYGON((0 0,2 2,0 2,2 0,0 0))",
                )
            )


@pytest.mark.asyncio
async def test_p11_city_polygon_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P11 a polygon supplied as city geometry is rejected."""
    await ingest_all(uow_factory, corpus(include_edge=False))
    async with uow_factory() as uow:
        washington = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        assert washington is not None and washington.id is not None
        with pytest.raises(InvalidReferenceGeometryError, match="point"):
            await uow.locations.upsert_reference(
                Location(
                    type=LocationType.CITY,
                    name="X",
                    canonical_name="X",
                    country_code="US",
                    admin1_code="WA",
                    parent_location_id=washington.id,
                    geometry="SRID=4326;POLYGON((0 0,1 0,1 1,0 1,0 0))",
                )
            )


@pytest.mark.asyncio
async def test_p12_country_point_geometry_rejected(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-P12 a Point supplied as country/admin geometry is rejected."""
    async with uow_factory() as uow:
        with pytest.raises(InvalidReferenceGeometryError, match="polygonal"):
            await uow.locations.upsert_reference(
                Location(
                    type=LocationType.COUNTRY,
                    name="X",
                    canonical_name="X",
                    country_code="US",
                    geometry="SRID=4326;POINT(1 1)",
                )
            )


# --------------------------------------------------------------------------
# G26B-I: canonical reference ingestion
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_i01_country_admin_city_parent_before_child_import(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I01 country -> admin -> city hierarchy imports parent-first."""
    records = corpus()
    stats = await ingest_all(uow_factory, records)
    assert stats.created == len(records)
    async with uow_factory() as uow:
        united_states = await uow.locations.get_by_identity(
            location_type="country",
            country_code="US",
            admin1_code=None,
            admin2_code=None,
            canonical_name="United States",
        )
        washington = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        seattle = await uow.locations.get_by_identity(
            location_type="city",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Seattle",
        )
        assert united_states is not None and washington is not None
        assert seattle is not None
        assert washington.parent_location_id == united_states.id
        assert seattle.parent_location_id == washington.id


@pytest.mark.asyncio
async def test_i02_second_identical_import_is_noop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I02 re-importing the same corpus is a true no-op."""
    records = corpus()
    first = await ingest_all(uow_factory, records)
    second = await ingest_all(uow_factory, records)
    assert first.created == len(records)
    assert second.unchanged == len(records)
    assert second.created == 0 and second.enriched == 0
    async with uow_factory() as uow:
        assert await location_count(uow) == len(records)


@pytest.mark.asyncio
async def test_i03_deterministic_ids_across_clean_databases(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I03 canonical UUIDv5 ids repeat identically after truncation."""
    records = corpus()
    await ingest_all(uow_factory, records)
    first_ids = await _canonical_ids(uow_factory, records)
    async with uow_factory() as uow:
        assert uow.session is not None
        await uow.session.execute(text("TRUNCATE ati.location CASCADE"))
    await ingest_all(uow_factory, records)
    second_ids = await _canonical_ids(uow_factory, records)
    assert first_ids == second_ids


async def _canonical_ids(
    uow_factory: Callable[[], PostgresUnitOfWork],
    records: list[GeographicReferenceRecord],
) -> dict[tuple[str, str, str, str, str], UUID]:
    """Return identity -> row id for every imported record."""
    async with uow_factory() as uow:
        result: dict[tuple[str, str, str, str, str], UUID] = {}
        for record in records:
            located = await uow.locations.get_by_identity(
                location_type=record.location_type.value,
                country_code=record.country_code,
                admin1_code=record.admin1_code,
                admin2_code=record.admin2_code,
                canonical_name=record.canonical_name,
            )
            assert located is not None and located.id is not None
            result[
                (
                    record.location_type.value,
                    record.country_code,
                    record.admin1_code or "",
                    record.admin2_code or "",
                    record.canonical_name,
                )
            ] = located.id
    return result


@pytest.mark.asyncio
async def test_i04_existing_pr26a_location_is_enriched_not_duplicated(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I04 a PR 26A Location is enriched rather than duplicated."""
    async with uow_factory() as uow:
        # PR 26A path: create the Washington admin without spatial state.
        united_states = await uow.locations.upsert(
            Location(
                type=LocationType.COUNTRY,
                name="United States",
                canonical_name="United States",
                country_code="US",
            )
        )
        assert united_states.id is not None
        legacy = await uow.locations.upsert(
            Location(
                type=LocationType.ADMINISTRATIVE_AREA,
                name="Washington",
                canonical_name="Washington",
                country_code="US",
                admin1_code="WA",
                parent_location_id=united_states.id,
            )
        )
        assert legacy.id is not None
        legacy_version = legacy.version
    await ingest_all(
        uow_factory,
        [record for record in corpus(include_edge=False) if record.admin1_code == "WA"],
    )
    async with uow_factory() as uow:
        enriched = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        assert enriched is not None
        # Same canonical row: identifier is unchanged, geometry was filled,
        # and a new sequence version was allocated by the enrichment.
        assert enriched.id == legacy.id
        assert enriched.geometry == WA_GEOMETRY
        assert legacy_version is not None and enriched.version is not None
        assert enriched.version > legacy_version
        # Exactly one canonical row for the identity: enrichment never created
        # a duplicate Washington.
        assert uow.session is not None
        washington_count = await uow.session.scalar(
            text(
                "SELECT count(*) FROM ati.location "
                "WHERE location_type = 'administrative_area' "
                "AND country_code = 'US' AND admin1_code = 'WA'"
            )
        )
        assert washington_count == 1


@pytest.mark.asyncio
async def test_i05_geometry_refresh_allocates_new_version(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I05 a geometry refresh mutates the same row with a new version."""
    records = corpus(include_edge=False)
    await ingest_all(uow_factory, records)
    refreshed: list[GeographicReferenceRecord] = []
    for record in records:
        if (
            record.admin1_code == "WA"
            and record.location_type is LocationType.ADMINISTRATIVE_AREA
        ):
            refreshed.append(
                record.model_copy(update={"geometry": REFRESHED_WA_GEOMETRY})
            )
        else:
            refreshed.append(record)
    stats = await ingest_all(uow_factory, refreshed)
    assert stats.enriched == 1 and stats.unchanged == len(records) - 1
    async with uow_factory() as uow:
        washington = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        assert washington is not None and washington.geometry == REFRESHED_WA_GEOMETRY
        assert washington.centroid is not None  # derived on-surface point


@pytest.mark.asyncio
async def test_i06_second_refresh_is_noop(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I06 a repeated refresh run is a no-op without version churn."""
    records = corpus(include_edge=False)
    refreshed: list[GeographicReferenceRecord] = []
    for record in records:
        if (
            record.admin1_code == "WA"
            and record.location_type is LocationType.ADMINISTRATIVE_AREA
        ):
            refreshed.append(
                record.model_copy(update={"geometry": REFRESHED_WA_GEOMETRY})
            )
        else:
            refreshed.append(record)
    await ingest_all(uow_factory, refreshed)
    async with uow_factory() as uow:
        before = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        assert before is not None and before.version is not None
    second = await ingest_all(uow_factory, refreshed)
    assert second.unchanged == len(refreshed) and second.enriched == 0
    async with uow_factory() as uow:
        after = await uow.locations.get_by_identity(
            location_type="administrative_area",
            country_code="US",
            admin1_code="WA",
            admin2_code=None,
            canonical_name="Washington",
        )
        assert after is not None and after.version == before.version


@pytest.mark.asyncio
async def test_i07_incompatible_hierarchy_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I07 a child without an available parent fails closed."""
    records = corpus(include_edge=False)
    broken = records[0].model_copy(
        update={
            "location_type": LocationType.CITY,
            "name": "Orphan",
            "canonical_name": "Orphan",
            "admin1_code": "WA",
            "parent": ReferenceParent(
                location_type=LocationType.ADMINISTRATIVE_AREA,
                country_code="US",
                admin1_code="OR",
                canonical_name="Oregon",
            ),
        }
    )
    with pytest.raises(InvalidReferenceHierarchyError, match="parent"):
        await ingest_all(uow_factory, [broken])
    assert await _location_count(uow_factory) == 0


@pytest.mark.asyncio
async def test_i08_malformed_source_geometry_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I08 malformed source geometry fails closed with no partial state."""
    records = corpus(include_edge=False)
    assert len(records) == 11
    records[10] = records[10].model_copy(update={"geometry": "SRID=3857;POINT(0 0)"})
    with pytest.raises(InvalidReferenceGeometryError, match="4326"):
        await ingest_all(uow_factory, records)
    assert await _location_count(uow_factory) == 0


@pytest.mark.asyncio
async def test_i08b_invalid_polygon_rolls_back_whole_batch(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I11 transaction rollback leaves no partial child hierarchy.

    The offending geometry is syntactically valid EWKT (passes Python
    canonicalization) but geometrically invalid, so PostgreSQL rejects it
    during the last write; the single ingestion transaction rolls back every
    already-written parent and child.
    """
    records = corpus(include_edge=False)
    records[3] = records[3].model_copy(
        update={"geometry": "SRID=4326;POLYGON((0 0,2 2,0 2,2 0,0 0))"}
    )
    with pytest.raises(InvalidReferenceGeometryError, match="valid"):
        await ingest_all(uow_factory, records)
    assert await _location_count(uow_factory) == 0


@pytest.mark.asyncio
async def test_i09_aliases_do_not_create_duplicate_canonical_rows(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I09 normalized aliases collapse onto one canonical row."""
    records = corpus(include_edge=False)
    duplicate = records[5].model_copy(
        update={"name": "  Seattle ", "canonical_name": "Seattle"}
    )
    with_duplicate = records + [duplicate]
    stats = await ingest_all(uow_factory, with_duplicate)
    assert stats.created == len(records)
    assert stats.unchanged == 1  # the alias collapsed onto the existing row
    async with uow_factory() as uow:
        assert await location_count(uow) == len(records)


@pytest.mark.asyncio
async def test_i10_input_order_does_not_change_canonical_state(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I10 corpus input order never changes canonical IDs/hierarchy."""
    records = corpus()
    await ingest_all(uow_factory, records)
    first_ids = await _canonical_ids(uow_factory, records)
    async with uow_factory() as uow:
        assert uow.session is not None
        await uow.session.execute(text("TRUNCATE ati.location CASCADE"))
    await ingest_all(uow_factory, list(reversed(records)))
    second_ids = await _canonical_ids(uow_factory, records)
    assert first_ids == second_ids


@pytest.mark.asyncio
async def test_i12_concurrent_identical_reference_upserts_converge(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-I12 concurrent identical reference upserts converge on one row."""
    async with uow_factory() as uow:
        outcomes = [
            result.outcome
            for result in await asyncio.gather(
                *[
                    uow.locations.upsert_reference(
                        Location(
                            type=LocationType.COUNTRY,
                            name="Concurrentia",
                            canonical_name="Concurrentia",
                            country_code="CC",
                        )
                    )
                    for _ in range(8)
                ]
            )
        ]
        count = await location_count(uow)
    assert count == 1
    assert outcomes.count(LocationReferenceOutcome.CREATED) == 1
    assert outcomes.count(LocationReferenceOutcome.UNCHANGED) == 7


# --------------------------------------------------------------------------
# G26B-R: deterministic claim -> canonical Location resolution
# --------------------------------------------------------------------------


async def _resolve(
    uow_factory: Callable[[], PostgresUnitOfWork],
    claim: GeographicClaim,
) -> CanonicalLocationResolution:
    """Resolve one claim through the real PostGIS resolver."""
    async with uow_factory() as uow:
        return await (await resolver(uow)).resolve(claim)


async def _canonical_name(
    result: CanonicalLocationResolution,
) -> str | None:
    """Return the selected canonical name of a resolution, if any."""
    return result.location.canonical_name if result.location is not None else None


async def _seed(uow_factory: Callable[[], PostgresUnitOfWork]) -> None:
    """Ingest both fixture corpora once for the resolution matrix."""
    await ingest_all(uow_factory, corpus())


@pytest.mark.asyncio
async def test_r01_country_code_resolves_country(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R01 a country code resolves the canonical country."""
    await _seed(uow_factory)
    result = await _resolve(uow_factory, country_claim("US"))
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert await _canonical_name(result) == "United States"
    assert result.location is not None and result.location.type is LocationType.COUNTRY


@pytest.mark.asyncio
async def test_r02_country_and_admin_code_resolves_area(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R02 country + admin code resolves the administrative area."""
    await _seed(uow_factory)
    result = await _resolve(uow_factory, admin_claim("US", code="WA"))
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert await _canonical_name(result) == "Washington"
    assert result.location is not None and result.location.admin1_code == "WA"


@pytest.mark.asyncio
async def test_r03_country_admin_city_resolves_city(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R03 country + admin + city resolves the canonical city."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory, city_claim("US", "Seattle", admin="Washington")
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert await _canonical_name(result) == "Seattle"
    assert result.location is not None and result.location.type is LocationType.CITY


@pytest.mark.asyncio
async def test_r04_country_only_claim_with_coordinates_stays_country_precision(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R04 coordinates never upgrade a country claim to city precision."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory,
        country_claim("US", latitude=47.6062, longitude=-122.3321),
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert await _canonical_name(result) == "United States"
    assert result.location is not None and result.location.type is LocationType.COUNTRY


@pytest.mark.asyncio
async def test_r05_admin_claim_with_city_coordinates_stays_admin_precision(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R05 a coordinate inside a city never upgrades admin precision."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory,
        admin_claim("US", admin="Washington", latitude=47.6062, longitude=-122.3321),
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert await _canonical_name(result) == "Washington"
    assert (
        result.location is not None
        and result.location.type is LocationType.ADMINISTRATIVE_AREA
    )


@pytest.mark.asyncio
async def test_r06_city_claim_uses_coordinates_only_to_disambiguate(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R06 coordinates disambiguate duplicate city names deterministically."""
    await _seed(uow_factory)
    # Springfield in WA and TX; the coordinate lies inside the WA polygon.
    result = await _resolve(
        uow_factory,
        city_claim("US", "Springfield", latitude=47.4, longitude=-123.2),
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert result.reason_code == "containment_disambiguation"
    assert result.location is not None and result.location.admin1_code == "WA"


@pytest.mark.asyncio
async def test_r07_unknown_country_is_unresolvable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R07 an unknown country is an explicit unresolvable outcome."""
    await _seed(uow_factory)
    result = await _resolve(uow_factory, country_claim("XX"))
    assert result.status is CanonicalLocationResolutionStatus.UNRESOLVABLE
    assert result.reason_code == "unknown_country"


@pytest.mark.asyncio
async def test_r08_unknown_city_in_known_admin_is_unresolvable(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R08 an unknown city inside a known admin is unresolvable."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory, city_claim("US", "Nowhere", admin="Washington")
    )
    assert result.status is CanonicalLocationResolutionStatus.UNRESOLVABLE
    assert result.reason_code == "unknown_city"


@pytest.mark.asyncio
async def test_r09_duplicate_city_without_parent_context_is_ambiguous(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R09 duplicate city names without a discriminator are ambiguous."""
    await _seed(uow_factory)
    result = await _resolve(uow_factory, city_claim("ZZ", "Springfield"))
    assert result.status is CanonicalLocationResolutionStatus.AMBIGUOUS
    assert result.reason_code == "multiple_candidates"
    assert len(result.candidates) == 2 and result.location is None


@pytest.mark.asyncio
async def test_r10_semantic_admin_discriminator_resolves_duplicate_city(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R10 the semantic admin discriminator resolves a duplicate city."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory, city_claim("ZZ", "Springfield", admin="Beta District")
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert result.location is not None and result.location.admin1_code == "BETA"


@pytest.mark.asyncio
async def test_r11_boundary_inclusive_containment_is_explicit_and_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R11 containment is boundary-inclusive (ST_Covers), never ST_Contains.

    The point (-10, 0) lies exactly on the Alpha polygon's eastern/western
    boundary line (longitude -10, inside Beta? no: lon -10 < 0 is outside
    Beta). Boundary-inclusive coverage resolves it; ST_Contains semantics
    would have rejected the boundary point and returned ambiguity.
    """
    await _seed(uow_factory)
    async with uow_factory() as uow:
        assert uow.session is not None
        covers = await uow.session.scalar(
            text("""
                SELECT ST_Covers(
                    geometry, ST_SetSRID(ST_Point(-10.0, 0.0), 4326))
                FROM ati.location
                WHERE admin1_code = 'ALPHA' AND location_type = 'administrative_area'
            """)
        )
        contains = await uow.session.scalar(
            text("""
                SELECT ST_Contains(
                    geometry, ST_SetSRID(ST_Point(-10.0, 0.0), 4326))
                FROM ati.location
                WHERE admin1_code = 'ALPHA' AND location_type = 'administrative_area'
            """)
        )
    assert covers is True  # boundary-inclusive
    assert contains is False  # mathematical interior is exclusive
    result = await _resolve(
        uow_factory,
        city_claim("ZZ", "Springfield", latitude=0.0, longitude=-10.0),
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert result.location is not None and result.location.admin1_code == "ALPHA"


@pytest.mark.asyncio
async def test_r12_competing_boundary_coverage_returns_ambiguity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R12 a coordinate covered by competing polygons is ambiguous."""
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory,
        city_claim("ZZ", "Springfield", latitude=5.0, longitude=5.0),
    )
    assert result.status is CanonicalLocationResolutionStatus.AMBIGUOUS
    assert result.reason_code == "competing_boundary_coverage"
    assert {candidate.location.admin1_code for candidate in result.candidates} == {
        "ALPHA",
        "BETA",
    }


@pytest.mark.asyncio
async def test_r13_coordinate_less_semantic_claim_resolves_normally(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R13 a coordinate-less valid claim resolves through semantics."""
    await _seed(uow_factory)
    result = await _resolve(uow_factory, city_claim("US", "Auburn", admin="Washington"))
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert result.location is not None and result.location.geometry is None


@pytest.mark.asyncio
async def test_r14_no_nearest_city_inference(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R14 proximity never manufactures a city claim or precision."""
    await _seed(uow_factory)
    # A precise coordinate near Seattle resolves to the country only.
    country = await _resolve(
        uow_factory, country_claim("US", latitude=47.6062, longitude=-122.3321)
    )
    assert (
        country.location is not None and country.location.type is LocationType.COUNTRY
    )
    # An admin claim with the same coordinates remains an admin area.
    admin = await _resolve(
        uow_factory,
        admin_claim("US", admin="Washington", latitude=47.6062, longitude=-122.3321),
    )
    assert (
        admin.location is not None
        and admin.location.type is LocationType.ADMINISTRATIVE_AREA
    )
    # A coords-only claim has no semantic context to narrow.
    bare = await _resolve(
        uow_factory,
        GeographicClaim(
            latitude=47.6, longitude=-122.3, precision=LocationPrecision.COUNTRY
        ),
    )
    assert bare.status is CanonicalLocationResolutionStatus.UNRESOLVABLE
    assert bare.reason_code == "missing_semantic_context"


@pytest.mark.asyncio
async def test_r15_candidate_ordering_is_deterministic(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R15 ambiguous candidates are returned in deterministic order."""
    await _seed(uow_factory)
    first = await _resolve(uow_factory, city_claim("ZZ", "Springfield"))
    second = await _resolve(uow_factory, city_claim("ZZ", "Springfield"))
    assert first.status is CanonicalLocationResolutionStatus.AMBIGUOUS
    assert [c.location.id for c in first.candidates] == [
        c.location.id for c in second.candidates
    ]
    assert [c.location.admin1_code for c in first.candidates] == ["ALPHA", "BETA"]


@pytest.mark.asyncio
async def test_r16_hierarchy_and_spatial_containment_can_disagree(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R16 containment disagreement never rewrites canonical hierarchy.

    A Seattle claim whose coordinates sit inside British Columbia (per BC's
    polygon) still resolves Seattle under Washington: exact semantic naming
    beats approximate coordinates, and neither hierarchy nor geometry is
    silently rewritten.
    """
    await _seed(uow_factory)
    result = await _resolve(
        uow_factory,
        city_claim("US", "Seattle", latitude=55.0, longitude=-120.0),
    )
    assert result.status is CanonicalLocationResolutionStatus.RESOLVED
    assert result.location is not None
    assert result.location.canonical_name == "Seattle"
    parent_id = result.location.parent_location_id
    location_id = result.location.id
    assert parent_id is not None and location_id is not None
    async with uow_factory() as uow:
        washington = await uow.locations.get_by_id(parent_id)
        seattle_parent = await uow.locations.get_by_id(location_id)
        assert washington is not None and washington.canonical_name == "Washington"
        assert (
            seattle_parent is not None
            and seattle_parent.parent_location_id == washington.id
        )


@pytest.mark.asyncio
async def test_r17_resolution_performs_no_mutation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R17 resolution never mutates any persisted state."""
    await _seed(uow_factory)
    async with uow_factory() as uow:
        assert uow.session is not None
        before_locations = await location_count(uow)
        before_versions = list(
            (
                await uow.session.execute(
                    text("SELECT id, version FROM ati.location ORDER BY id")
                )
            ).all()
        )
        await (await resolver(uow)).resolve(
            city_claim("US", "Seattle", admin="Washington")
        )
        await (await resolver(uow)).resolve(
            city_claim("ZZ", "Springfield", latitude=5.0, longitude=5.0)
        )
        await (await resolver(uow)).resolve(country_claim("XX"))
        after_locations = await location_count(uow)
        after_versions = list(
            (
                await uow.session.execute(
                    text("SELECT id, version FROM ati.location ORDER BY id")
                )
            ).all()
        )
    assert before_locations == after_locations
    assert before_versions == after_versions


@pytest.mark.asyncio
async def test_r18_no_resolution_path_mutates_geo_resolution(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """G26B-R18 resolution never creates GeoResolution work (PR 26C scope)."""
    await _seed(uow_factory)
    async with uow_factory() as uow:
        assert uow.session is not None
        await (await resolver(uow)).resolve(
            city_claim("US", "Seattle", admin="Washington")
        )
        count = int(
            (
                await uow.session.execute(
                    text("SELECT count(*) FROM ati.geo_resolution")
                )
            ).scalar_one()
        )
    assert count == 0
