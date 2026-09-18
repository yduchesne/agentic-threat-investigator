# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B-2 operational completion proof: source -> corpus -> import -> PostGIS.

Exercises the documented operator workflow end to end on real PostgreSQL +
PostGIS:

1. ``ati-geography-build`` derives the ATI Geography Corpus NDJSON from the
   synthetic real-format GeoNames/Natural Earth fixtures;
2. the production corpus parser reads the artifact;
3. ``ReferenceIngestionService`` (the same path ``ati-geography-import``
   executes) ingests it atomically;
4. United States -> Washington -> Seattle is created with deterministic
   canonical UUIDv5 identities, correct parent hierarchy, polygon geometry
   for country/admin boundaries, a city point, correct SRID/geometry types,
   and a second import is a true no-op with no version churn.

No PostGIS behavior is mocked.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from agentic_threat_investigator.app.geoint.reference_ingestion import (
    ReferenceIngestionService,
)
from agentic_threat_investigator.cli import geography_build_main
from agentic_threat_investigator.domain.geoint import (
    LocationType,
    canonical_location_uuid,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.sources.geography import (
    JsonlGeographyCorpus,
)

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "geoint"
GEONAMES = FIXTURES / "geonames"
NATURAL_EARTH = FIXTURES / "natural_earth"

US_ID = canonical_location_uuid(
    location_type=LocationType.COUNTRY,
    country_code="US",
    admin1_code=None,
    admin2_code=None,
    canonical_name="United States",
)
WA_ID = canonical_location_uuid(
    location_type=LocationType.ADMINISTRATIVE_AREA,
    country_code="US",
    admin1_code="WA",
    admin2_code=None,
    canonical_name="Washington",
)
SEATTLE_ID = canonical_location_uuid(
    location_type=LocationType.CITY,
    country_code="US",
    admin1_code="WA",
    admin2_code=None,
    canonical_name="Seattle",
)
WA_GEOMETRY = "SRID=4326;POLYGON((-125 45, -116 45, -116 49.5, -125 49.5, -125 45))"
CORPUS_RECORD_COUNT = 14


def _build_corpus(tmp_path: Path) -> Path:
    """Run the installed ati-geography-build CLI over the fixtures."""
    output = tmp_path / "ati-geography.ndjson"
    status = geography_build_main(
        [
            "--geonames-country-info",
            str(GEONAMES / "countryInfo.txt"),
            "--geonames-admin1",
            str(GEONAMES / "admin1CodesASCII.txt"),
            "--geonames-cities",
            str(GEONAMES / "cities1000.txt"),
            "--natural-earth-countries",
            str(NATURAL_EARTH / "ne_countries.geojson"),
            "--natural-earth-admin1",
            str(NATURAL_EARTH / "ne_admin1.geojson"),
            "--output",
            str(output),
        ]
    )
    assert status == 0
    return output


async def _location_rows(engine: AsyncEngine) -> list[dict[str, object]]:
    """Return every location row as a lightweight mapping for assertions."""
    async with engine.connect() as connection:
        return [
            dict(row._mapping)
            for row in await connection.execute(
                text(
                    """
                    SELECT id, location_type, canonical_name, country_code,
                           admin1_code, parent_location_id, geometry, centroid, version
                    FROM ati.location ORDER BY canonical_name
                    """
                )
            )
        ]


async def _ingest(
    uow_factory: Callable[[], PostgresUnitOfWork], artifact: Path
) -> None:
    """Ingest one built corpus artifact through the production service."""
    records = JsonlGeographyCorpus().read_path(artifact)
    stats = await ReferenceIngestionService(uow_factory).ingest(records)
    assert stats.rejected == 0
    assert stats.conflicts == 0


@pytest.mark.asyncio
async def test_e2e_build_import_geography_corpus(
    tmp_path: Path,
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PR 26B-2 US -> Washington -> Seattle imports with geometry and IDs."""
    artifact = _build_corpus(tmp_path)
    assert artifact.read_text(encoding="utf-8").startswith("# ATI Geography Corpus v1")

    await _ingest(uow_factory, artifact)

    rows = await _location_rows(integration_engine)
    by_name = {row["canonical_name"]: row for row in rows}

    # Deterministic canonical identities.
    assert by_name["United States"]["id"] == US_ID
    assert by_name["Washington"]["id"] == WA_ID
    assert by_name["Seattle"]["id"] == SEATTLE_ID

    # Correct parent-before-child hierarchy.
    assert by_name["United States"]["parent_location_id"] is None
    assert by_name["Washington"]["parent_location_id"] == US_ID
    assert by_name["Seattle"]["parent_location_id"] == WA_ID

    # Geometry: country MultiPolygon, admin Polygon, city point.
    assert by_name["United States"]["geometry"] is not None
    assert by_name["Washington"]["geometry"] is not None
    assert by_name["Seattle"]["centroid"] is not None

    async with integration_engine.connect() as connection:
        geometry_types = {
            row[0]: row[1]
            for row in await connection.execute(
                text(
                    """
                    SELECT id, ST_GeometryType(geometry)
                    FROM ati.location WHERE id IN (:us, :wa, :seattle)
                    """
                ),
                {"us": US_ID, "wa": WA_ID, "seattle": SEATTLE_ID},
            )
        }
        assert geometry_types == {
            US_ID: "ST_MultiPolygon",
            WA_ID: "ST_Polygon",
            SEATTLE_ID: "ST_Point",
        }

        srids = {
            row[0]: row[1]
            for row in await connection.execute(
                text(
                    """
                    SELECT id, ST_SRID(geometry) FROM ati.location
                    WHERE id IN (:us, :wa, :seattle)
                    """
                ),
                {"us": US_ID, "wa": WA_ID, "seattle": SEATTLE_ID},
            )
        }
        assert srids == {US_ID: 4326, WA_ID: 4326, SEATTLE_ID: 4326}

        wa_text = await connection.scalar(
            text("SELECT ST_AsEWKT(geometry) FROM ati.location WHERE id = :id"),
            {"id": WA_ID},
        )
        expected_wa_text = await connection.scalar(
            text("SELECT ST_AsEWKT(ST_GeomFromEWKT(:wkt))"), {"wkt": WA_GEOMETRY}
        )
        assert wa_text == expected_wa_text

        seattle_text = await connection.scalar(
            text("SELECT ST_AsEWKT(geometry) FROM ati.location WHERE id = :id"),
            {"id": SEATTLE_ID},
        )
        assert seattle_text == "SRID=4326;POINT(-122.33207 47.60621)"

    # The full corpus was ingested (countries + admins + cities).
    assert len(rows) == CORPUS_RECORD_COUNT


@pytest.mark.asyncio
async def test_e2e_second_import_is_idempotent_no_version_churn(
    tmp_path: Path,
    integration_engine: AsyncEngine,
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """PR 26B-2 a repeated import is a true no-op with no version churn."""
    artifact = _build_corpus(tmp_path)
    records = JsonlGeographyCorpus().read_path(artifact)
    first = await ReferenceIngestionService(uow_factory).ingest(records)
    assert first.created == CORPUS_RECORD_COUNT and first.unchanged == 0

    before = {
        row["id"]: row["version"] for row in await _location_rows(integration_engine)
    }
    second = await ReferenceIngestionService(uow_factory).ingest(records)
    assert second.unchanged == CORPUS_RECORD_COUNT
    assert second.created == 0
    assert second.enriched == 0
    after = {
        row["id"]: row["version"] for row in await _location_rows(integration_engine)
    }
    assert after == before


@pytest.mark.asyncio
async def test_e2e_geography_import_cli_entrypoint(
    tmp_path: Path,
    integration_engine: AsyncEngine,
) -> None:
    """PR 26B-2 the installed importer ingests a built corpus atomically.

    Runs the actual installed ``ati-geography-import`` console script in a
    subprocess against the isolated database: the first import creates every
    record with the deterministic canonical identities and hierarchy, and a
    second import is a true no-op with no version churn.
    """
    artifact = _build_corpus(tmp_path)
    env = dict(os.environ)
    url = os.environ["DATABASE_URL"]
    # The installed importer uses the production engine, whose connections
    # must carry the ati schema search path exactly like the migration env
    # (see migrations/env.py); the integration DSN supplies it explicitly.
    if "search_path" not in url:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}options=-csearch_path=ati,public"
    env["ATI_DATABASE_URL"] = url
    env["ATI_CONFIG_PROFILE"] = "default"
    script = _installed_script("ati-geography-import")

    first = subprocess.run(
        [str(script), str(artifact)],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert first.returncode == 0, first.stderr
    rows = await _location_rows(integration_engine)
    by_name = {row["canonical_name"]: row for row in rows}
    assert by_name["United States"]["id"] == US_ID
    assert by_name["Washington"]["parent_location_id"] == US_ID
    assert by_name["Seattle"]["parent_location_id"] == WA_ID
    assert by_name["Seattle"]["geometry"] is not None
    assert len(rows) == CORPUS_RECORD_COUNT
    before = _id_version_map(rows)

    second = subprocess.run(
        [str(script), str(artifact)],
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert second.returncode == 0, second.stderr
    after = _id_version_map(await _location_rows(integration_engine))
    assert after == before


@pytest.mark.asyncio
async def test_e2e_geography_import_rejects_noncorpus_input(
    tmp_path: Path,
    integration_engine: AsyncEngine,
) -> None:
    """PR 26B-2 the installed importer fails closed on malformed input."""
    bad = tmp_path / "bad.ndjson"
    bad.write_text('{"location_type": "city"}\n', encoding="utf-8")
    env = dict(os.environ)
    env["ATI_DATABASE_URL"] = os.environ["DATABASE_URL"]
    env["ATI_CONFIG_PROFILE"] = "default"
    script = _installed_script("ati-geography-import")
    run = subprocess.run(
        [str(script), str(bad)], env=env, capture_output=True, text=True, timeout=180
    )
    assert run.returncode != 0
    rows = await _location_rows(integration_engine)
    assert rows == []  # the failing batch committed nothing


def _id_version_map(rows: list[dict[str, object]]) -> dict[object, object]:
    """Return the id -> version map used for the no-churn assertion."""
    return {row["id"]: row["version"] for row in rows}


def _installed_script(name: str) -> Path:
    """Return the installed console-script stub (proving packaging)."""
    script = Path(sys.prefix) / "bin" / name
    assert script.exists(), f"installed script {script} is missing"
    return script
