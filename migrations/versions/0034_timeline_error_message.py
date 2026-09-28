# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0029: bounded Timeline failure diagnostic (PR 31F-2).

Adds one nullable ``error_message`` text column to the append-only
``ati.investigation_timeline_event`` table with a length-bounded CHECK
constraint matching the domain maximum (4096 characters). The diagnostic is
sanitized at the application boundary before persistence; the database bound
is defense-in-depth only. Existing rows remain valid with ``NULL``, no
backfill is performed, and the append-only/chronological/index semantics are
unchanged — the column is never filtered or ordered on.

The downgrade drops only the new column and its constraint; no historical
migration file is edited.
"""

from pathlib import Path

from alembic import op

revision = "0034_timeline_error_message"
down_revision = "0033_datasource_log_published"


def upgrade() -> None:
    """Add the nullable bounded diagnostic column and its CHECK constraint."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0029/timeline_error_message.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove only the PR 31F-2 column and constraint."""
    op.execute(
        """
        ALTER TABLE ati.investigation_timeline_event
          DROP CONSTRAINT investigation_timeline_event_error_message_check;
        ALTER TABLE ati.investigation_timeline_event
          DROP COLUMN error_message;
        """
    )
