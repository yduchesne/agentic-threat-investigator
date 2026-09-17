# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 27B append-only datasource execution log (SQL API v0025).

Fresh-main analysis confirmed ATI had no datasource execution/log model, so
PR 27B adds the smallest durable append-only operational log
(``ati.datasource_log``) rather than a separate durable
``datasource_execution`` table. One acquisition execution receives a fresh
application UUID ``execution_id``; every event carries the same
``execution_id`` and ``datasource_id``.

SQL API v0025 installs:

- ``ati.datasource_log``: bounded operational columns only (no source body,
  decoded object, Evidence body, credential, or raw exception text);
- CHECK constraints pinning the datasource-instance identity grammar, the
  closed seven-value event vocabulary, non-negative stage-local counts, the
  bounded error-code grammar, and the error-code/FAILED binding;
- partial unique indexes enforcing at most one STARTED and at most one
  terminal event per execution, plus the deterministic per-execution
  correlation/order index;
- ``ati.append_datasource_log_event``: the sole normal mutation path, which
  serializes lifecycle validation per execution through a deterministic
  transaction-scoped advisory lock and rejects first-event-not-STARTED,
  duplicate STARTED, datasource mismatch, and append-after-terminal with
  typed ``U27B*`` SQLSTATEs.

No existing source records, ingestion checkpoints, Evidence, or other rows
are rewritten and no backfill is performed: executions before PR 27B were
not logged under this contract. The downgrade drops only the PR 27B table,
indexes, constraints, and function in dependency-safe order.
"""

from pathlib import Path

from alembic import op

revision = "0030_datasource_log"
down_revision = "0029_geoint_read_indexes"


def upgrade() -> None:
    """Install the PR 27B datasource log table and append function."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0025/datasource_log.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove only the PR 27B datasource log objects.

    The identity column, constraints, and indexes drop with the table; only
    the versioned append function must be dropped explicitly.
    """
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_datasource_log_event("
        "uuid, text, text, timestamptz, bigint, bigint, text)"
    )
    op.execute("DROP TABLE IF EXISTS ati.datasource_log")
