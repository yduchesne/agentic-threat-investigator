# SPDX-License-Identifier: AGPL-3.0-only
"""Install v0008 of the relationship write functions."""

from pathlib import Path

from alembic import op

revision = "0011_relationship_persistence"
down_revision = "0010_investigation_remediation"


def upgrade() -> None:
    """Install the v0008 relationship/observation write functions."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0008/relationship_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the v0008 functions; PR 18C has no prior relationship function."""
    op.execute("DROP FUNCTION IF EXISTS ati.append_relationship_observation")
    op.execute("DROP FUNCTION IF EXISTS ati.upsert_relationship")
