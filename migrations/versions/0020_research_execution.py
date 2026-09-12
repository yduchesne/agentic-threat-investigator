# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 22C research execution state and coordinator transitions.

Extends the versioned coordinator transition function
``ati.update_investigation_coordinator_state`` with two bounded transition
kinds:

- ``request_research`` — may change only ``research_executions`` (append one
  new REQUESTED first-attempt execution, or increment exactly one existing
  REQUESTED execution's attempt counter by one, never above 2);
- ``record_research_outcome`` — may change only ``research_executions`` and
  ``research_result_ids`` (resolve exactly one REQUESTED execution to
  COMPLETED with an authoritative result link, or EXHAUSTED with no link).

``research_executions`` lives inside the existing ``operational_state``
JSONB document, so no new relational table is created; pre-existing
investigations simply retain an empty array. Optimistic concurrency, budget
maxima, counter ownership, lifecycle revalidation, and history behavior are
unchanged.
"""

from pathlib import Path

from alembic import op

revision = "0020_research_execution"
down_revision = "0019_research_foundation"


def upgrade() -> None:
    """Extend the coordinator transition function with research transitions."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0017/research_execution.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the pre-22C coordinator transition function and timeline check."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0015/coordinator_selection_investigated.sql")
        .read_text()
    )
    op.execute("DROP FUNCTION IF EXISTS ati.research_execution_valid(jsonb)")
    op.execute(
        "ALTER TABLE ati.investigation_timeline_event "
        "DROP CONSTRAINT investigation_timeline_event_type_check"
    )
    op.execute(
        "ALTER TABLE ati.investigation_timeline_event "
        "ADD CONSTRAINT investigation_timeline_event_type_check CHECK ("
        "event_type IN ("
        "'investigation_started', 'provider_work_started', "
        "'provider_work_completed', 'provider_work_failed', "
        "'evidence_persisted', 'entities_discovered', "
        "'pivot_enqueued', 'pivot_executed', 'pivot_skipped', "
        "'assessment_requested', 'investigation_stopped'))"
    )
