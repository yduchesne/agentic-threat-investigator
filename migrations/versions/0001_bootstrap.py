# SPDX-License-Identifier: AGPL-3.0-only
"""Initial ATI schema namespace."""

from alembic import op

revision = "0001_bootstrap"
down_revision = None


def upgrade() -> None:
    """Create the namespace needed by the version table and later objects."""
    op.execute("CREATE SCHEMA IF NOT EXISTS ati")


def downgrade() -> None:
    """Remove the initial namespace."""
    op.execute("DROP SCHEMA IF EXISTS ati CASCADE")
