# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0028: non-terminal PUBLISHED datasource-log stage (PR 28F-2).

PR 28F-2 adds the producer-side publication stage of the v0.2 Global
Evidence pipeline to the PR 27B datasource lifecycle. SQL API v0025 closed
the ``ati.datasource_log`` event vocabulary at seven values, so this
migration opens exactly one additional **non-terminal** stage, ``published``,
without editing any shipped SQL:

- ``datasource_log_event_type_check`` is replaced by the identical
  constraint extended with ``'published'`` (non-terminal; the terminal set
  remains exactly ``COMPLETED``/``FAILED``/``CANCELLED``);
- ``ati.append_datasource_log_event`` is re-defined with the identical
  signature, U27B* SQLSTATE mapping, advisory-lock serialization, and
  STARTED-first/STARTED-unique/datasource-identity/at-most-one-terminal/
  no-append-after-terminal invariants preserved.

``PUBLISHED.item_count`` is the stage-local count of ``EvidenceMessage``
values accepted by the execution's one ordered ``EvidencePublisher.publish``
call; zero is a valid count. ``PUBLISHED`` never carries an ``error_code``
(the error-code/FAILED binding is unchanged). No authoritative row is
rewritten and no backfill is performed: executions before PR 28F-2 simply
have no ``PUBLISHED`` stage, which the lifecycle already permits for
non-terminal stages.

The downgrade restores the exact PR 27B seven-value constraint and the
v0025 function body; the table, indexes, and remaining constraints are owned
by migration 0030 and are untouched.
"""

from pathlib import Path

from alembic import op

revision = "0033_datasource_log_published"
down_revision = "0032_evidence_batch_persistence"


def upgrade() -> None:
    """Open the non-terminal PUBLISHED datasource-log stage."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0028/datasource_log_published.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the exact PR 27B seven-value event vocabulary.

    Reinstalls the v0025 closed seven-value CHECK constraint and the v0025
    append function body (from the first ``CREATE OR REPLACE FUNCTION``
    marker onward); the table, indexes, and remaining constraints are owned
    by migration 0030 and are untouched by this migration.
    """
    op.execute(
        "ALTER TABLE ati.datasource_log DROP CONSTRAINT datasource_log_event_type_check"
    )
    op.execute(
        "ALTER TABLE ati.datasource_log "
        "ADD CONSTRAINT datasource_log_event_type_check CHECK ("
        "event_type IN ("
        "'started', 'acquired', 'decoded', 'converted', "
        "'completed', 'failed', 'cancelled'"
        ")"
        ")"
    )
    v0025 = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0025/datasource_log.sql")
        .read_text()
    )
    op.execute(v0025[v0025.index("CREATE OR REPLACE FUNCTION") :])
