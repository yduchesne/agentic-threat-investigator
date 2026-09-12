# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 23B versioned InvestigationReport persistence.

Creates the normalized ``ati.investigation_report`` root table with
validated JSONB snapshots for the immutable nested report presentation
structures, the report version sequence, the report listing index, the
versioned SQL API (append/set-pointer/soft-delete), and preserves the
existing durable Investigation ``report_id`` operational-state field that
PR 21 already carried in the Investigation domain contract. No existing data
is rewritten and no shipped SQL version is edited.
"""

from pathlib import Path

from alembic import op

revision = "0023_investigation_report"
down_revision = "0022_api_query_indexes"


def upgrade() -> None:
    """Install the v0019 report persistence SQL API."""
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0019/report_persistence.sql")
        .read_text()
    )


def downgrade() -> None:
    """Remove the report persistence API, table, types, and sequence."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_investigation_report("
        "uuid, uuid, uuid, text, text, text, "
        "ati.report_narrative_item[], ati.report_narrative_support_item[], "
        "ati.report_finding_item[], ati.report_finding_support_item[], "
        "ati.report_research_item[], text[], text[], text[], uuid[], "
        "uuid[], uuid[], uuid, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.set_investigation_report("
        "uuid, uuid, uuid, uuid, bigint)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.soft_delete_investigation_report("
        "uuid, uuid, bigint, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.soft_delete_investigation_report(uuid, uuid, bigint)"
    )
    op.execute("DROP TABLE IF EXISTS ati.investigation_report")
    op.execute("DROP TYPE IF EXISTS ati.report_research_item")
    op.execute("DROP TYPE IF EXISTS ati.report_finding_item")
    op.execute("DROP TYPE IF EXISTS ati.report_finding_support_item")
    op.execute("DROP TYPE IF EXISTS ati.report_narrative_item")
    op.execute("DROP TYPE IF EXISTS ati.report_narrative_support_item")
    op.execute("DROP SEQUENCE IF EXISTS ati.investigation_report_version_seq")
    # The Investigation operational_state contract already carried report_id
    # since PR 21; a downgrade leaves any persisted report_id value in the
    # operational JSONB document untouched, so no data rewrite is needed.
