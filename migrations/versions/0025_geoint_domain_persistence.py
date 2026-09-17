# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 26A GEOINT domain persistence (SQL API v0021).

Creates the non-spatial GEOINT foundation: the canonical ``ati.location``
reference table, the immutable ``ati.entity_location_observation`` history
table, the database-maintained ``ati.entity_location`` current-state table,
and the operational ``ati.geo_resolution`` work table, plus their version
sequences and the versioned stored functions ``ati.upsert_location``,
``ati.append_entity_location_observation``, and
``ati.create_geo_resolution``.

No PostGIS extension, geometry, or spatial semantics are introduced. No
existing table or data is rewritten.
"""

from pathlib import Path

from alembic import op

revision = "0025_geoint_domain_persistence"
down_revision = "0024_api_async_foundation"


def upgrade() -> None:
    """Install the v0021 GEOINT persistence SQL API."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0021/geoint_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove only the PR 26A GEOINT objects in dependency-safe order."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.upsert_location(uuid, text, text, text, text, text, text, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_entity_location_observation("
        "uuid, uuid, uuid, uuid, text, timestamptz, timestamptz, timestamptz, text)"
    )
    op.execute("DROP FUNCTION IF EXISTS ati.create_geo_resolution(uuid, uuid, uuid)")
    op.execute("DROP TABLE IF EXISTS ati.entity_location")
    op.execute("DROP TABLE IF EXISTS ati.entity_location_observation")
    op.execute("DROP TABLE IF EXISTS ati.geo_resolution")
    op.execute("DROP TABLE IF EXISTS ati.location")
    op.execute("DROP SEQUENCE IF EXISTS ati.location_version_seq")
    op.execute("DROP SEQUENCE IF EXISTS ati.entity_location_observation_version_seq")
    op.execute("DROP SEQUENCE IF EXISTS ati.entity_location_version_seq")
    op.execute("DROP SEQUENCE IF EXISTS ati.geo_resolution_version_seq")
