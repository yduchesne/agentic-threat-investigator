"""Add normalized source records and resumable ingestion checkpoints."""

from pathlib import Path

from alembic import op

revision = "0007_source_ingestion"
down_revision = "0006_entity_batch_v0003"


def upgrade() -> None:
    """Install PR 8 source persistence objects."""
    sql_path = Path(__file__).parents[1] / "sql/ati/v0004/source_ingestion.sql"
    op.execute(sql_path.read_text())


def downgrade() -> None:
    """Remove only PR 8 objects in dependency-safe order."""
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "ati.upsert_source_records(ati.source_record_batch_item[])"
    )
    op.execute("DROP TYPE IF EXISTS ati.source_record_batch_item")
    op.execute("DROP TABLE IF EXISTS ati.ingestion_checkpoint")
    op.execute("DROP TABLE IF EXISTS ati.source_record")
    op.execute("DROP SEQUENCE IF EXISTS ati.source_record_version_seq")
