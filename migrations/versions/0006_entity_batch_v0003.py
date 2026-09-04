# SPDX-License-Identifier: AGPL-3.0-only
"""Install v0003 of the entity batch upsert function."""

from pathlib import Path

from alembic import op

revision = "0006_entity_batch_v0003"
down_revision = "0005_entity_batch_upsert"

_V0002_FUNCTION_MARKER = "CREATE OR REPLACE FUNCTION"


def upgrade() -> None:
    """Replace the batch function with the v0003 outcome/duplicate/race contract."""
    op.execute(
        Path(__file__).parents[1].joinpath("sql/ati/v0003/entity_batch.sql").read_text()
    )


def downgrade() -> None:
    """Restore the v0002 function semantics.

    The ``ati.entity_batch_item`` composite type is owned by 0005 and is not
    touched by this migration, so only the function definition of the archived
    v0002 file is reinstalled.
    """
    v0002 = (
        Path(__file__).parents[1].joinpath("sql/ati/v0002/entity_batch.sql").read_text()
    )
    op.execute(v0002[v0002.index(_V0002_FUNCTION_MARKER) :])
