# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 21B corrected provider-work selection persistence.

PR 21B moves the ``investigated_entity_ids`` transition from pivot
authorization to provider-work selection: an entity becomes investigated only
when its provider work is actually selected for execution. The SQL API v0013
function (installed by migration 0016) owns ``investigated_entity_ids`` only
on AUTHORIZE_PIVOT; SQL API v0015 replaces it so the SELECT_PROVIDER_WORK
transition may append the selected work item's entity exactly once, in the
same transition that records ``best_investigated_depth``. Coordinate state
still lives in the existing JSONB ``operational_state``/``budget`` columns,
so no schema change is required: this migration only replaces the stored
function (CREATE OR REPLACE, same signature).
"""

from pathlib import Path

from alembic import op

revision = "0018_coordinator_selection"
down_revision = "0017_timeline_coordinator_events"


def upgrade() -> None:
    """Replace the coordinator transition function with the corrected one."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0015/coordinator_selection_investigated.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the original SQL API v0013 coordinator transition function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0013/coordinator_transition.sql")
        .read_text()
    )
