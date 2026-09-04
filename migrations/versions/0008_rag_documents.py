"""Add RAG document and chunk persistence."""

from pathlib import Path

from alembic import op

revision = "0008_rag_documents"
down_revision = "0007_source_ingestion"


def upgrade() -> None:
    """Install document and chunk schema."""
    op.execute(
        (Path(__file__).parents[1] / "sql/ati/v0005/rag_documents.sql").read_text()
    )


def downgrade() -> None:
    """Remove RAG objects in dependency order."""
    op.execute("DROP INDEX IF EXISTS ati.document_chunk_embedding_hnsw_idx")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.replace_document_chunks(uuid[],ati.document_chunk_batch_item[])"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.upsert_documents(ati.document_batch_item[])"
    )
    op.execute("DROP TYPE IF EXISTS ati.document_chunk_batch_item")
    op.execute("DROP TYPE IF EXISTS ati.document_batch_item")
    op.execute("DROP TABLE IF EXISTS ati.document_chunk")
    op.execute("DROP TABLE IF EXISTS ati.document")
    op.execute("DROP SEQUENCE IF EXISTS ati.document_chunk_version_seq")
    op.execute("DROP SEQUENCE IF EXISTS ati.document_version_seq")
