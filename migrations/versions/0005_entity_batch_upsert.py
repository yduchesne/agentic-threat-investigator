# SPDX-License-Identifier: AGPL-3.0-only
"""Install the canonical composite-array entity batch upsert function."""
from pathlib import Path

from alembic import op

revision = "0005_entity_batch_upsert"
down_revision = "0004_audit"


def upgrade() -> None:
    """Create the versioned entity batch input type and function."""
    op.execute(
        Path(__file__).parents[1].joinpath("sql/ati/v0002/entity_batch.sql").read_text()
    )


def downgrade() -> None:
    """Remove only the objects introduced by this migration."""
    op.execute("DROP FUNCTION IF EXISTS ati.upsert_entities(ati.entity_batch_item[])")
    op.execute("DROP TYPE IF EXISTS ati.entity_batch_item")
