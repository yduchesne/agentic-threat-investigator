# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0022: EntityLocation version-allocation consistency.

PR 26A-2 corrects one PR 26A persistence inconsistency: PR 26A created
``ati.entity_location_version_seq`` and used it for initial
``ati.entity_location`` creation, but the v0021 reconciliation path advanced
changed current rows with ``version = target.version + 1``. SQL API v0022
makes the sequence the sole allocator for every materialized-state mutation:
both the initial insert and every actual ``DO UPDATE`` now take their version
from ``nextval('ati.entity_location_version_seq')``.

Versions are monotonic database-issued change tokens, not contiguous ``+1``
revision counters; sequence gaps caused by rollback, contention, or
PostgreSQL evaluation are valid. A historical observation that does not
mutate current state leaves the persisted version unchanged (the mutation
predicate is unchanged from v0021).

The schema is untouched: no table, sequence, constraint, or index changes.
Existing EntityLocation versions are database-owned historical tokens and
are deliberately not rewritten. ``ati.upsert_location`` and
``ati.create_geo_resolution`` are unchanged and remain owned by SQL API
v0021.
"""

from pathlib import Path

from alembic import op

revision = "0026_geoint_version_allocation"
down_revision = "0025_geoint_domain_persistence"


def upgrade() -> None:
    """Install the v0022 EntityLocation version-allocation function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0022/geoint_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the v0021 function semantics.

    Only the stored-function definitions of the archived v0021 file are
    reinstalled (from the first ``CREATE OR REPLACE FUNCTION`` marker
    onward); the tables, sequences, and constraints are owned by migration
    0025 and are untouched by this migration.
    """
    v0021 = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0021/geoint_persistence.sql")
        .read_text()
    )
    op.execute(v0021[v0021.index("CREATE OR REPLACE FUNCTION") :])