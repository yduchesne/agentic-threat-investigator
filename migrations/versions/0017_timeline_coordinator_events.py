# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 21 coordinator timeline event types and bounded fields.

Extends the append-only investigation timeline with the coordinator event
types (pivot enqueued/executed/skipped, assessment requested, investigation
stopped) and the bounded pivot-depth/reason-code/counter fields consumed by
coordinator trajectory evaluation.
"""

from pathlib import Path

from alembic import op

revision = "0017_timeline_coordinator_events"
down_revision = "0016_coordinator_transition"


def upgrade() -> None:
    """Extend the timeline table with coordinator types and bounded fields."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0014/timeline_coordinator_events.sql")
        .read_text()
    )


def downgrade() -> None:
    """Drop the coordinator columns and restore the original event-type set."""
    op.execute(
        """
        ALTER TABLE ati.investigation_timeline_event
          DROP CONSTRAINT investigation_timeline_event_reason_code_check;
        ALTER TABLE ati.investigation_timeline_event
          DROP CONSTRAINT investigation_timeline_event_type_check;
        ALTER TABLE ati.investigation_timeline_event
          ADD CONSTRAINT investigation_timeline_event_type_check CHECK (
            event_type IN (
              'investigation_started',
              'provider_work_started',
              'provider_work_completed',
              'provider_work_failed',
              'evidence_persisted',
              'entities_discovered'
            )
          );
        ALTER TABLE ati.investigation_timeline_event
          DROP COLUMN pivot_depth,
          DROP COLUMN reason_code,
          DROP COLUMN provider_calls_used,
          DROP COLUMN replans_used,
          DROP COLUMN entity_count;
        """
    )
