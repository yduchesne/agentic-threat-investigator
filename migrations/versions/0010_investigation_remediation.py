"""Remediate PR 18A investigation/evidence integrity and concurrency."""

from pathlib import Path

from alembic import op

revision = "0010_investigation_remediation"
down_revision = "0009_investigation_persistence"

_V0006_FUNCTION_MARKER = "CREATE OR REPLACE FUNCTION"


def upgrade() -> None:
    """Tighten PR 18A schema and install the v0007 write functions.

    PR 18A is not merged: the only rows these tables can contain come from
    this branch's disposable integration databases, so no supported
    deployment can hold a NULL ``started_at`` or an Evidence row whose
    Investigation parent is missing. Tightening therefore needs no data
    remediation; nothing is rewritten or guessed.
    """
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0007/investigation_persistence.sql")
        .read_text()
    )
    op.execute("""
        ALTER TABLE ati.investigation
          ALTER COLUMN started_at SET NOT NULL;
        ALTER TABLE ati.evidence ADD CONSTRAINT evidence_investigation_fk
          FOREIGN KEY (investigation_id) REFERENCES ati.investigation(id);
        CREATE INDEX evidence_investigation_listing_idx
          ON ati.evidence(investigation_id, retrieved_at DESC, id ASC);
        """)


def downgrade() -> None:
    """Restore the v0006 schema and archived v0006 write functions."""
    op.execute("DROP INDEX IF EXISTS ati.evidence_investigation_listing_idx")
    op.execute(
        "ALTER TABLE ati.evidence DROP CONSTRAINT IF EXISTS evidence_investigation_fk"
    )
    op.execute("ALTER TABLE ati.investigation ALTER COLUMN started_at DROP NOT NULL")
    v0006 = (
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0006/investigation_persistence.sql")
        .read_text()
    )
    op.execute(v0006[v0006.index(_V0006_FUNCTION_MARKER) :])
