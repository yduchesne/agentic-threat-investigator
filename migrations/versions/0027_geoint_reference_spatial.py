# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 26B canonical reference/spatial persistence (SQL API v0023).

PostGIS becomes part of the v0.1 runtime through this migration: the
supported PostgreSQL 18 image now ships both pgvector and PostGIS
(``docker/postgres/Dockerfile``), and the migration establishes the extension
through ordinary Alembic execution so it also works against an
already-existing ATI database whose server has PostGIS installed.

Schema changes on ``ati.location`` only:

- ``geometry geometry(Geometry, 4326)``: optional reference geometry
  (polygonal for country/admin, Point for cities); SRID 4326 ``geometry``,
  never PostGIS ``geography``;
- ``centroid geometry(Point, 4326)``: on-surface representative point
  (``ST_PointOnSurface`` derivation is owned by the write function, which is
  documented as an on-surface representative point, never a mathematical
  ``ST_Centroid``);
- GiST index on non-null ``geometry`` justified by the containment/
  intersection candidate path;
- b-tree ``(location_type, country_code, canonical_name)`` index justified by
  the deterministic claim-resolution narrowing path.

Existing PR 26A rows are not rewritten; they remain valid with
``geometry = NULL`` and ``centroid = NULL``. Spatial validity is enforced by
the versioned write function (the sole mutation path): CHECK constraints
cannot call PostGIS functions, which are not immutable.

No EntityLocationObservation, EntityLocation, or GeoResolution object is
touched. SQL API v0021/v0022 remain immutable.
"""

from pathlib import Path

from alembic import op

revision = "0027_geoint_reference_spatial"
down_revision = "0026_geoint_version_allocation"


def upgrade() -> None:
    """Enable PostGIS; add spatial Location state, indexes, and SQL API v0023."""
    op.execute("CREATE EXTENSION IF NOT EXISTS postgis")
    op.execute(
        """
        ALTER TABLE ati.location
          ADD COLUMN geometry geometry(Geometry, 4326),
          ADD COLUMN centroid geometry(Point, 4326)
        """
    )
    # Containment/intersection candidate selection (PR 26B resolution path).
    op.execute(
        "CREATE INDEX IF NOT EXISTS location_geometry_gist_idx "
        "ON ati.location USING gist (geometry) WHERE geometry IS NOT NULL"
    )
    # Deterministic claim narrowing (country -> admin -> city name lookups).
    op.execute(
        "CREATE INDEX IF NOT EXISTS location_resolution_name_idx "
        "ON ati.location (location_type, country_code, canonical_name)"
    )
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0023/geoint_reference_spatial.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove only the PR 26B spatial objects in dependency-safe order.

    PostGIS is removed only when PR 26B introduced it (the extension
    resides in the ``ati`` schema) and after every PR 26B object that
    depends on it has been dropped. ``CASCADE`` is never used on
    ``DROP EXTENSION``: an unexpected dependent object fails the downgrade
    clearly instead of deleting unrelated extension-dependent objects.
    """
    op.execute("DROP INDEX IF EXISTS ati.location_resolution_name_idx")
    op.execute("DROP INDEX IF EXISTS ati.location_geometry_gist_idx")
    op.execute("ALTER TABLE ati.location DROP COLUMN IF EXISTS centroid")
    op.execute("ALTER TABLE ati.location DROP COLUMN IF EXISTS geometry")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.upsert_reference_location("
        "uuid, text, text, text, text, text, text, uuid, text, text)"
    )
    op.execute("DROP FUNCTION IF EXISTS ati.reference_geometry_parse(text, text)")
    op.execute("DROP FUNCTION IF EXISTS ati.reference_centroid_parse(text)")
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_extension e
            JOIN pg_namespace n ON n.oid = e.extnamespace
            WHERE e.extname = 'postgis' AND n.nspname = 'ati'
          ) THEN
            EXECUTE 'DROP EXTENSION postgis';
          END IF;
        END
        $$;
        """
    )