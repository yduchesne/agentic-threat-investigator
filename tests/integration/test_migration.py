# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests run against the isolated PostgreSQL container."""

import os
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agentic_threat_investigator.config import ensure_test_database_safe

EXPECTED_TABLES = {
    "domain_object_history",
    "entity",
    "relationship",
    "relationship_observation",
    "evidence",
    "investigation",
    "assessment",
    "user",
    "credential",
    "session",
    "audit_event",
    "source_record",
    "ingestion_checkpoint",
    "document",
    "document_chunk",
    "alembic_version",
}

EXPECTED_SEQUENCES = {
    "entity_version_seq",
    "relationship_version_seq",
    "relationship_observation_version_seq",
    "evidence_version_seq",
    "investigation_version_seq",
    "assessment_version_seq",
    "user_version_seq",
    "audit_event_version_seq",
    "source_record_version_seq",
    "document_version_seq",
    "document_chunk_version_seq",
}

EXPECTED_FUNCTIONS = {
    "ati_jsonb_diff",
    "upsert_entity",
    "upsert_entities",
    "upsert_source_records",
    "upsert_documents",
    "replace_document_chunks",
}


def _test_engine() -> AsyncEngine:
    """Create an engine for the guarded integration test database URL."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.fail("DATABASE_URL must point at the isolated integration test database")
    ensure_test_database_safe(url)
    return create_async_engine(
        url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_upgrade_head_installs_expected_schema() -> None:
    """Alembic head installs the PR 3 tables, sequences, functions, and extension."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            tables = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'ati'"
                    )
                )
            }
            sequences = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT sequence_name FROM information_schema.sequences "
                        "WHERE sequence_schema = 'ati'"
                    )
                )
            }
            functions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT routine_name FROM information_schema.routines "
                        "WHERE routine_schema = 'ati'"
                    )
                )
            }
            extensions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT e.extname FROM pg_extension e"
                        " JOIN pg_namespace n ON n.oid = e.extnamespace"
                        " WHERE n.nspname = 'ati'"
                    )
                )
            }
    finally:
        await engine.dispose()
    assert EXPECTED_TABLES <= tables
    assert EXPECTED_SEQUENCES <= sequences
    assert EXPECTED_FUNCTIONS <= functions
    # The migration search path installs extensions into the ati schema so all
    # database objects, including pgvector support, live there.
    assert {"vector", "pgcrypto"} <= extensions


@pytest.mark.asyncio
@pytest.mark.integration
async def test_rag_schema_has_cosine_hnsw_index_and_composites() -> None:
    """RAG persistence installs both composites and the cosine HNSW index."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            types = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT typname FROM pg_type t JOIN pg_namespace n "
                        "ON n.oid=t.typnamespace WHERE n.nspname='ati'"
                    )
                )
            }
            index_definition = await connection.scalar(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname='ati' "
                    "AND indexname='document_chunk_embedding_hnsw_idx'"
                )
            )
    finally:
        await engine.dispose()
    assert {"document_batch_item", "document_chunk_batch_item"} <= types
    assert index_definition and "hnsw" in index_definition
    assert "vector_cosine_ops" in index_definition


@pytest.mark.asyncio
@pytest.mark.integration
async def test_audit_schema_contract() -> None:
    """Audit persistence has its immutable columns, check, and indexes."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            check = await connection.scalar(
                text(
                    """
                SELECT pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                WHERE ns.nspname = 'ati' AND rel.relname = 'audit_event'
                  AND con.contype = 'c'
            """
                )
            )
            indexes = {
                row[0]
                for row in await connection.execute(
                    text(
                        """
                    SELECT indexname FROM pg_indexes
                    WHERE schemaname = 'ati' AND tablename = 'audit_event'
                """
                    )
                )
            }
    finally:
        await engine.dispose()
    assert check and "success" in check and "failure" in check and "denied" in check
    assert {
        "audit_event_actor_time_idx",
        "audit_event_action_time_idx",
        "audit_event_object_time_idx",
    } <= indexes


@pytest.mark.asyncio
@pytest.mark.integration
async def test_identity_schema_contract() -> None:
    """Identity tables expose their constraints and required UTC columns."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            columns = {
                (row[0], row[1], row[2])
                for row in await connection.execute(
                    text(
                        """
                    SELECT table_name, column_name, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'ati'
                      AND table_name IN ('user', 'credential', 'session')
                """
                    )
                )
            }
            constraints = {
                row[0]
                for row in await connection.execute(
                    text(
                        """
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati'
                      AND rel.relname IN ('user', 'credential', 'session')
                """
                    )
                )
            }
    finally:
        await engine.dispose()
    assert ("user", "username", "NO") in columns
    assert ("user", "version", "NO") in columns
    assert ("credential", "password_hash", "NO") in columns
    assert ("session", "token_hash", "NO") in columns
    assert any("role" in name for name in constraints)
    assert any("credential" in name or "user" in name for name in constraints)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_jsonb_diff_semantics() -> None:
    """The shallow diff covers changes, additions, removals, and missing-vs-null."""
    engine = _test_engine()
    try:

        async def diff(old: str, new: str) -> Any:
            """Compute the versioned diff helper result for two JSON states."""
            async with engine.connect() as connection:
                result = await connection.execute(
                    text(
                        "SELECT ati.ati_jsonb_diff(CAST(:old AS jsonb), CAST(:new AS jsonb))"
                    ),
                    {"old": old, "new": new},
                )
                return result.scalar_one()

        assert await diff('{"a": 1}', '{"a": 1}') == {}
        assert await diff('{"a": 1}', '{"a": 2}') == {"a": {"old": 1, "new": 2}}
        assert await diff('{"a": 1}', '{"a": 1, "b": 2}') == {
            "b": {"old": None, "new": 2}
        }
        assert await diff('{"a": 1, "b": 2}', '{"a": 1}') == {
            "b": {"old": 2, "new": None}
        }
        # A missing key and an explicit JSON null remain distinguishable inputs
        # but both surface as JSON null in the old/new slots.
        assert await diff('{"a": 1}', '{"a": 1, "b": null}') == {
            "b": {"old": None, "new": None}
        }
        assert await diff('{"a": null}', '{"a": 1}') == {"a": {"old": None, "new": 1}}
        # Nested values are atomic at the top level.
        assert await diff('{"n": {"x": 1}}', '{"n": {"x": 2}}') == {
            "n": {"old": {"x": 1}, "new": {"x": 2}}
        }
    finally:
        await engine.dispose()
