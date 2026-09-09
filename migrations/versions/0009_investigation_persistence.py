"""Add PR 18A investigation and evidence write paths."""

from pathlib import Path

from alembic import op

revision = "0009_investigation_persistence"
down_revision = "0008_rag_documents"


def upgrade() -> None:
    """Install the authoritative investigation/evidence write functions."""
    sql_path = (
        Path(__file__).parents[1] / "sql/ati/v0006/investigation_persistence.sql"
    )
    op.execute(sql_path.read_text())


def downgrade() -> None:
    """Remove only PR 18A write functions; shipped schema stays unchanged."""
    op.execute("DROP FUNCTION IF EXISTS ati.append_evidence(uuid,uuid,text,uuid,text,text,text,timestamptz,timestamptz,jsonb,jsonb,uuid,uuid)")
    op.execute("DROP FUNCTION IF EXISTS ati.soft_delete_investigation(uuid,uuid,uuid,bigint)")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.update_investigation_status(uuid,text,uuid,uuid,bigint)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.create_investigation(uuid,text,text,text,jsonb,jsonb,timestamptz,timestamptz,uuid,uuid)"
    )
