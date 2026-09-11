# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 20B durable Investigation LLM-budget accounting.

The Investigation budget lives in the existing JSONB ``budget`` column, so no
schema change is required: this migration only installs the stored function
that writes budget documents under the canonical lock/version/history
discipline and defensively revalidates the counters.
"""

from pathlib import Path

from alembic import op

revision = "0015_llm_accounting"
down_revision = "0014_assessment_persistence"


def upgrade() -> None:
    """Install the budget write function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0012/llm_accounting.sql")
        .read_text()
    )


def downgrade() -> None:
    """Drop the budget write function; the JSONB column stays."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.update_investigation_budget("
        "uuid, jsonb, uuid, uuid, bigint)"
    )
