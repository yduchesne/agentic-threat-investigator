# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install the PR 19B investigation timeline table."""

from pathlib import Path

from alembic import op

revision = "0013_investigation_timeline"
down_revision = "0012_pr18c_graph_integrity"


def upgrade() -> None:
    """Install the append-only investigation timeline event table."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0010/investigation_timeline.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the investigation timeline event table and its sequence."""
    op.execute("DROP TABLE IF EXISTS ati.investigation_timeline_event")
    op.execute("DROP SEQUENCE IF EXISTS ati.investigation_timeline_event_seq")
