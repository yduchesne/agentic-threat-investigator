# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0032: operational datasource checkpoint (PR 33E).

Adds the durable per-datasource incremental-retrieval checkpoint used by the
TAXII 2.1 collection acquirer: one row per ``(datasource_id,
checkpoint_kind)`` plus two stored functions. ``ati.get_datasource_checkpoint``
reads one row; ``ati.advance_datasource_checkpoint`` compares-and-advances
with the execution's loaded expectation under a transaction-scoped advisory
lock, rejecting stale expectations with a typed SQLSTATE and treating an
advance to the current value as an idempotent no-op. The Python repository
only binds validated parameters, invokes the functions, and maps returned
rows; no checkpoint SQL exists outside the stored functions.

The downgrade drops the functions and the whole table: checkpoint state is
datasource operational state, never immutable Evidence, so removal cannot
destroy audit/history records.
"""

from pathlib import Path

from alembic import op

revision = "0037_datasource_checkpoint"
down_revision = "0036_graph_path_finding"


def upgrade() -> None:
    """Install the checkpoint table and both stored functions."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0032/datasource_checkpoint.sql")
        .read_text()
    )


def downgrade() -> None:
    """Drop the checkpoint functions and table, and nothing else."""
    op.execute(
        """
        DROP FUNCTION ati.get_datasource_checkpoint(
          p_datasource_id text,
          p_checkpoint_kind text
        );
        DROP FUNCTION ati.advance_datasource_checkpoint(
          p_datasource_id text,
          p_checkpoint_kind text,
          p_expected_value text,
          p_new_value text,
          p_updated_at timestamptz
        );
        DROP TABLE ati.datasource_checkpoint;
        """
    )
