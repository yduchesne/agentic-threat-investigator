# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 23C asynchronous API persistence.

Creates the minimal durable investigation job table (with its atomic claim
and completion SQL API), the actor-scoped API idempotency table, and their
supporting indexes. No existing data is rewritten and no shipped SQL version
is edited.
"""

from pathlib import Path

from alembic import op

revision = "0024_api_async_foundation"
down_revision = "0023_investigation_report"


def upgrade() -> None:
    """Install the v0020 API async persistence SQL API."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0020/api_async.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the API async persistence API, tables, and functions."""
    op.execute("DROP FUNCTION IF EXISTS ati.create_investigation_job(uuid, timestamptz)")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.claim_next_investigation_job(timestamptz)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.complete_investigation_job("
        "uuid, text, timestamptz, text)"
    )
    op.execute("DROP TABLE IF EXISTS ati.investigation_job")
    op.execute("DROP TABLE IF EXISTS ati.api_idempotency")