# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 20A normalized, versioned Assessment persistence.

Approved migration policy (PR 20A fix plan 01, Phase 0.1): the v0002 flat
``ati.assessment`` table shipped with the original PR 3 schema and has never
been written by any repository or service, so it is treated as guaranteed
empty. The migration verifies that guarantee explicitly: any existing row
fails the upgrade with a clear error BEFORE the drop, so no legacy Assessment
data can ever be silently destroyed. If a deployed database ever carries rows
here, the migration must be replaced by a maintainer-approved data-migration
mapping rather than extended to discard them.
"""

from pathlib import Path

from alembic import op
from sqlalchemy import text

revision = "0014_assessment_persistence"
down_revision = "0013_investigation_timeline"


def upgrade() -> None:
    """Verify the flat table is empty, then install the normalized API."""
    connection = op.get_bind()
    row_count = connection.execute(
        text("SELECT count(*) FROM ati.assessment")
    ).scalar_one()
    if int(row_count) > 0:
        raise RuntimeError(
            "migration 0014 refuses to drop ati.assessment: the legacy flat "
            f"table contains {int(row_count)} row(s). Approved policy treats "
            "the legacy table as guaranteed empty; a nonempty table requires "
            "an explicit maintainer-approved data-migration mapping."
        )
    op.execute("DROP TABLE ati.assessment")
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0011/assessment_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the flat assessment table and drop the v0011 API."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_assessment("
        "uuid, uuid, text, text, text, uuid[], text[], text[], text[], "
        "ati.assessment_finding_item[], ati.assessment_finding_support_item[], uuid, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.set_investigation_assessment("
        "uuid, uuid, uuid, uuid, bigint)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.soft_delete_assessment(uuid, uuid, bigint, uuid)"
    )
    op.execute("DROP FUNCTION IF EXISTS ati.soft_delete_assessment(uuid, uuid, bigint)")
    op.execute("DROP TABLE IF EXISTS ati.assessment_finding_support")
    op.execute("DROP TABLE IF EXISTS ati.assessment_finding")
    op.execute("DROP TABLE IF EXISTS ati.assessment")
    op.execute("DROP TYPE IF EXISTS ati.assessment_finding_support_item")
    op.execute("DROP TYPE IF EXISTS ati.assessment_finding_item")
    op.execute("""
        CREATE TABLE ati.assessment (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), investigation_id uuid NOT NULL,
          verdict text NOT NULL, confidence text NOT NULL, summary text NOT NULL,
          analyzed_evidence_ids jsonb NOT NULL DEFAULT '[]',
          supporting_evidence jsonb NOT NULL DEFAULT '[]',
          contradicting_evidence jsonb NOT NULL DEFAULT '[]',
          limitations jsonb NOT NULL DEFAULT '[]',
          unresolved_questions jsonb NOT NULL DEFAULT '[]',
          recommended_next_steps jsonb NOT NULL DEFAULT '[]', version bigint NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        )
    """)
