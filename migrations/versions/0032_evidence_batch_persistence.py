# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0027: bounded at-least-once Evidence batch persistence (PR 28E).

PR 28E connects the PR 28D Evidence-consumer seam to the PR 28B global
Evidence model. This migration adds exactly two objects:

- ``ati.evidence_message_receipt``: narrow transactional idempotency keyed
  by the stable PR 28C ``message_id`` (the approved PR 28E amendment to
  STOP #16). It holds no Kafka/log position, no partition, no
  consumer-group, and no Investigation semantics; it is written in the same
  transaction as the Evidence/graph persistence it records, so a redelivered
  message returns its previously established authoritative result without
  invoking the Evidence transition or recreating derived graph state.
- ``ati.persist_evidence_batch(p_items jsonb)``: one bounded top-level batch
  call that stages the prepared batch in input (log) order, reuses the
  authoritative PR 28B/18C transition functions per record, records receipts
  atomically, appends derived graph provenance only for CREATED/APPENDED
  observations, and returns one ordered authoritative outcome row per input
  record.

Observation identity follows the chosen Option A: PostgreSQL's returned
``evidence_observation_id`` is authoritative; ``observation_candidate_id``
is proposed to the PR 28B transition (used by its CREATED branch) but is not
required to become the persisted ID on APPENDED.

No authoritative table is redesigned and no existing SQL file is edited; the
downgrade removes exactly the objects introduced here.
"""

from pathlib import Path

from alembic import op
from sqlalchemy import text

revision = "0032_evidence_batch_persistence"
down_revision = "0031_global_evidence_persistence"


def _read(name: str) -> str:
    """Read one immutable SQL API v0027 file."""
    return Path(__file__).parents[1].joinpath(f"sql/ati/v0027/{name}").read_text()


def upgrade() -> None:
    """Install the PR 28E batch persistence SQL API."""
    op.execute(_read("evidence_batch_persistence.sql"))
    op.execute(text("COMMENT ON TABLE ati.evidence_message_receipt IS "
                    "'PR 28E at-least-once message processing receipt (idempotency only)'"))


def downgrade() -> None:
    """Remove exactly the PR 28E objects introduced by this migration."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.persist_evidence_batch(jsonb)"
    )
    op.execute("DROP TABLE IF EXISTS ati.evidence_message_receipt")