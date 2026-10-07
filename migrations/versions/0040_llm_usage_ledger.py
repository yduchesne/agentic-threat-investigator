# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0035: durable append-only LLM usage accounting (PR 38-9).

Adds ``ati.llm_usage`` (one append-only row per actual model attempt with
authoritative usage) plus the ``ati.append_llm_usage`` stored function, which
owns all row invariants and invocation-identity idempotency. The Python
repository only binds validated parameters and maps the returned row; no
usage SQL exists outside the stored function.

The downgrade drops the function and the whole table: usage accounting is
operational observability state, never immutable Evidence, so removal cannot
destroy audit/history records.
"""

from pathlib import Path

from alembic import op

revision = "0040_llm_usage_ledger"
down_revision = "0039_final_report"


def upgrade() -> None:
    """Install the LLM usage table and append function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0035/llm_usage_ledger.sql")
        .read_text()
    )


def downgrade() -> None:
    """Drop the append function and usage table, and nothing else."""
    op.execute(
        """
        DROP FUNCTION IF EXISTS ati.append_llm_usage(
          uuid, text, text, uuid, text, text, bigint, bigint, bigint, bigint,
          bigint, numeric, numeric, numeric, numeric, numeric, text, text,
          text, timestamptz);
        DROP TABLE IF EXISTS ati.llm_usage;
        """
    )
