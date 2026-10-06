# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0034: authoritative finding criticality and Final Report.

PR 35-5 adds an authoritative bounded ``criticality`` to Assessment findings,
a deterministic criticality-first Final Report with a finding-centric Summary,
and a coherent persisted Status snapshot. The whole change is a versioned
stored-function/schema evolution:

- ``ati.assessment_finding.criticality`` is added, backfilled explicitly to
  the neutral ``medium`` value (never derived from confidence or verdict),
  and constrained; ``ati.append_assessment`` requires it for every finding;
- ``ati.investigation_report`` gains ``criticality``, ``summary``,
  ``started_at``, ``ended_at``, ``outcome_status``, and ``stop_reason``;
  legacy rows are mapped forward coherently and
  ``ati.append_investigation_report`` re-derives the maximum criticality,
  requires the canonical ordered finding set and the exact Summary
  projection, and validates the lifecycle snapshot.

The Python repository binds parameters and maps returned rows; no
application SQL is introduced. The downgrade restores the archived v0026
function definitions and drops the new columns/types.
"""

from pathlib import Path

from alembic import op

revision = "0039_final_report"
down_revision = "0038_mandatory_enrichment"


def _read(name: str) -> str:
    """Read one immutable SQL API v0034 file."""
    return Path(__file__).parents[1].joinpath(f"sql/ati/v0034/{name}").read_text()


def _archived_function(name: str) -> str:
    """Return one archived v0026 function definition verbatim."""
    text = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0026/repointed_write_functions.sql")
        .read_text()
    )
    start = text.index(f"CREATE OR REPLACE FUNCTION ati.{name}(")
    end = text.index("\nEND $$;", start) + len("\nEND $$;")
    return text[start:end]


def upgrade() -> None:
    """Install the criticality and Final Report stored-function API."""
    op.execute(_read("final_report.sql"))


def downgrade() -> None:
    """Restore the archived v0026 criticality-less function definitions.

    The downgrade is forward-only for analytical data: the new criticality
    values cannot be represented by the v0026 functions, so the new columns
    and types are removed and the archived v0026 assessment/report write
    functions are reinstalled. No historical assessment/report row is
    deleted; the criticality column is dropped as part of the downgrade.
    """
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_investigation_report("
        "uuid, uuid, uuid, text, text, text, text, "
        "ati.report_summary_item[], ati.report_finding_item[], "
        "ati.report_finding_support_item[], ati.report_research_item[], "
        "text[], text[], text[], timestamptz, timestamptz, text, text, "
        "uuid[], uuid[], uuid[], uuid, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_assessment("
        "uuid, uuid, text, text, text, uuid[], text[], text[], text[], "
        "ati.assessment_finding_item[], ati.assessment_finding_support_item[], "
        "uuid, uuid)"
    )
    op.execute("DROP TYPE IF EXISTS ati.report_summary_item")
    op.execute("DROP TYPE IF EXISTS ati.report_finding_item")
    op.execute("DROP TYPE IF EXISTS ati.assessment_finding_item")
    op.execute("ALTER TABLE ati.investigation_report DROP COLUMN IF EXISTS criticality")
    op.execute(
        "ALTER TABLE ati.investigation_report DROP CONSTRAINT IF EXISTS "
        "investigation_report_criticality_check"
    )
    op.execute(
        "ALTER TABLE ati.investigation_report DROP CONSTRAINT IF EXISTS "
        "investigation_report_outcome_status_check"
    )
    op.execute("ALTER TABLE ati.investigation_report DROP COLUMN IF EXISTS started_at")
    op.execute("ALTER TABLE ati.investigation_report DROP COLUMN IF EXISTS ended_at")
    op.execute(
        "ALTER TABLE ati.investigation_report DROP COLUMN IF EXISTS outcome_status"
    )
    op.execute("ALTER TABLE ati.investigation_report DROP COLUMN IF EXISTS stop_reason")
    op.execute(
        "ALTER TABLE ati.investigation_report "
        "RENAME COLUMN summary TO executive_summary"
    )
    op.execute(
        "ALTER TABLE ati.investigation_report "
        "ALTER COLUMN executive_summary SET DEFAULT '[]'::jsonb"
    )
    op.execute(
        "ALTER TABLE ati.assessment_finding DROP CONSTRAINT IF EXISTS "
        "assessment_finding_criticality_check"
    )
    op.execute("ALTER TABLE ati.assessment_finding DROP COLUMN IF EXISTS criticality")
    # Recreate the archived v0026 composite types and functions.
    op.execute(
        """
        CREATE TYPE ati.assessment_finding_item AS (
          ordinal bigint,
          category text,
          disposition text,
          statement text,
          confidence text
        );
        CREATE TYPE ati.report_finding_item AS (
          ordinal bigint,
          category text,
          disposition text,
          statement text,
          confidence text
        );
        """
    )
    op.execute(_archived_function("append_assessment"))
    op.execute(_archived_function("append_investigation_report"))
