# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 21 durable coordinator transition writes.

Coordinator state lives in the existing JSONB ``operational_state`` and
``budget`` columns, so no schema change is required: this migration only
installs the stored function that writes coordinator transitions (pivots,
queued provider work, research markers, traversal metadata, analyzed-evidence
/disposition state, stop reason, budget, status) under the canonical
lock/version/history discipline and defensively revalidates budget counters
and the status lifecycle.
"""

from pathlib import Path

from alembic import op

revision = "0016_coordinator_transition"
down_revision = "0015_llm_accounting"


def upgrade() -> None:
    """Install the coordinator transition write function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0013/coordinator_transition.sql")
        .read_text()
    )


def downgrade() -> None:
    """Drop the coordinator transition write functions."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.update_investigation_coordinator_state("
        "uuid, text, text, jsonb, jsonb, boolean, uuid, uuid, bigint)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.set_investigation_analysis_result("
        "uuid, uuid, jsonb, text, uuid, uuid, bigint)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.jsonb_array_starts_with(jsonb, jsonb)"
    )