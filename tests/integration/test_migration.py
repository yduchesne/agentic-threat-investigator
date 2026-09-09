# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests run against the isolated PostgreSQL container."""

import os
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
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
    "investigation_timeline_event",
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
    "investigation_timeline_event_seq",
}

EXPECTED_FUNCTIONS = {
    "ati_jsonb_diff",
    "upsert_entity",
    "upsert_entities",
    "upsert_source_records",
    "upsert_documents",
    "replace_document_chunks",
    "upsert_relationship",
    "append_relationship_observation",
    "soft_delete_relationship",
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
            check = await connection.scalar(text("""
                SELECT pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                WHERE ns.nspname = 'ati' AND rel.relname = 'audit_event'
                  AND con.contype = 'c'
            """))
            indexes = {row[0] for row in await connection.execute(text("""
                    SELECT indexname FROM pg_indexes
                    WHERE schemaname = 'ati' AND tablename = 'audit_event'
                """))}
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
                (row[0], row[1], row[2]) for row in await connection.execute(text("""
                    SELECT table_name, column_name, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'ati'
                      AND table_name IN ('user', 'credential', 'session')
                """))
            }
            constraints = {row[0] for row in await connection.execute(text("""
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati'
                      AND rel.relname IN ('user', 'credential', 'session')
                """))}
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_integrity_schema_contract() -> None:
    """v0009 installs the provenance FK and the relationship delete function."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            foreign_key = await connection.scalar(text("""
                SELECT pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                  AND con.conname = 'relationship_observation_evidence_fk'
            """))
            parameters = await connection.execute(text("""
                SELECT p.parameter_name, p.data_type
                FROM information_schema.parameters p
                JOIN information_schema.routines r
                  ON r.specific_schema = 'ati'
                 AND r.routine_name = 'soft_delete_relationship'
                 AND r.specific_name = p.specific_name
                WHERE p.parameter_mode = 'IN'
                ORDER BY p.ordinal_position
            """))
    finally:
        await engine.dispose()
    assert foreign_key is not None
    assert "evidence(id)" in foreign_key
    # Evidence and observations are immutable; deletion is soft only, so the
    # provenance foreign key must never cascade.
    assert "CASCADE" not in foreign_key
    assert [(row[0], row[1]) for row in parameters] == [
        ("p_id", "uuid"),
        ("p_actor_id", "uuid"),
        ("p_expected_version", "bigint"),
    ]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_integrity_migration_downgrade_and_re_upgrade() -> None:
    """Migration 0012 downgrades to v0008 and re-upgrades cleanly."""
    alembic_cfg = Config("alembic.ini")

    async def schema_state() -> tuple[bool, bool]:
        """Return (soft_delete_relationship present, FK present)."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                functions = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT routine_name FROM information_schema.routines "
                            "WHERE routine_schema = 'ati'"
                        )
                    )
                }
                foreign_key = await connection.scalar(text("""
                    SELECT con.conname FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                      AND con.conname = 'relationship_observation_evidence_fk'
                """))
        finally:
            await engine.dispose()
        return "soft_delete_relationship" in functions, foreign_key is not None

    command.downgrade(alembic_cfg, "0011_relationship_persistence")
    function_present, foreign_key_present = await schema_state()
    assert not function_present
    assert not foreign_key_present
    # The v0008 relationship write API remains installed after the downgrade.
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            functions = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT routine_name FROM information_schema.routines "
                        "WHERE routine_schema = 'ati'"
                    )
                )
            }
    finally:
        await engine.dispose()
    assert {"upsert_relationship", "append_relationship_observation"} <= functions

    command.upgrade(alembic_cfg, "head")
    function_present, foreign_key_present = await schema_state()
    assert function_present
    assert foreign_key_present


@pytest.mark.asyncio
@pytest.mark.integration
async def test_timeline_schema_contract() -> None:
    """Timeline has the error-code check, owned sequence, and no mutation routines."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            checks = {row[0]: row[1] for row in await connection.execute(text("""
                        SELECT con.conname, pg_get_constraintdef(con.oid)
                        FROM pg_constraint con
                        JOIN pg_class rel ON rel.oid = con.conrelid
                        JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                        WHERE ns.nspname = 'ati'
                          AND rel.relname = 'investigation_timeline_event'
                          AND con.contype = 'c'
                    """))}
            sequence_owner = await connection.scalar(text("""
                SELECT pg_get_serial_sequence(
                    'ati.investigation_timeline_event',
                    'sequence'
                )
            """))
            routines = {
                row[0]
                for row in await connection.execute(
                    text(
                        "SELECT routine_name FROM information_schema.routines "
                        "WHERE routine_schema = 'ati'"
                    )
                )
            }
    finally:
        await engine.dispose()
    # Both the event-type check and the error-code grammar/length check exist;
    # PostgreSQL renders IN-lists as ANY(ARRAY[...]) so matching by name and
    # by the regex literal is deterministic.
    assert "investigation_timeline_event_type_check" in checks
    assert "investigation_timeline_event_error_code_check" in checks
    assert any(
        "'^[a-z][a-z0-9_]{0,63}$'" in definition for definition in checks.values()
    )
    # The sequence is owned by its table column.
    assert sequence_owner == "ati.investigation_timeline_event_seq"
    # No application routine updates, deletes, or upserts timeline events.
    assert not any(
        "timeline_event" in name
        and any(token in name for token in ("update", "delete", "upsert"))
        for name in routines
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_timeline_migration_downgrade_and_re_upgrade() -> None:
    """Migration 0013 downgrades to v0011 and re-upgrades cleanly.

    At 0012 the timeline table and sequence are absent while the 0012
    graph-integrity objects remain; after re-upgrade the table, owned
    sequence, chronological index, and checks exist and one event round-trips.
    The database is always returned to head in the finally block so later
    tests do not depend on test order.
    """
    alembic_cfg = Config("alembic.ini")

    async def timeline_state() -> tuple[bool, bool]:
        """Return (table present, sequence present) for the ati schema."""
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
        finally:
            await engine.dispose()
        return (
            "investigation_timeline_event" in tables,
            "investigation_timeline_event_seq" in sequences,
        )

    try:
        command.downgrade(alembic_cfg, "0012_pr18c_graph_integrity")
        table_present, sequence_present = await timeline_state()
        assert not table_present
        assert not sequence_present
        # The 0012 graph-integrity objects remain installed after downgrade.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                functions = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT routine_name FROM information_schema.routines "
                            "WHERE routine_schema = 'ati'"
                        )
                    )
                }
                foreign_key = await connection.scalar(text("""
                    SELECT con.conname FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                      AND con.conname = 'relationship_observation_evidence_fk'
                """))
        finally:
            await engine.dispose()
        assert {
            "soft_delete_relationship",
            "upsert_relationship",
            "append_relationship_observation",
        } <= functions
        assert foreign_key is not None

        command.upgrade(alembic_cfg, "head")
        table_present, sequence_present = await timeline_state()
        assert table_present
        assert sequence_present
        # Ownership dependency points at the table's sequence column, and the
        # chronological index plus both checks exist.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                owner = await connection.scalar(text("""
                    SELECT pg_get_serial_sequence(
                        'ati.investigation_timeline_event', 'sequence'
                    )
                """))
                indexes = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT indexname FROM pg_indexes "
                            "WHERE schemaname = 'ati' "
                            "AND tablename = 'investigation_timeline_event'"
                        )
                    )
                }
                checks = {row[0] for row in await connection.execute(text("""
                            SELECT con.conname FROM pg_constraint con
                            JOIN pg_class rel ON rel.oid = con.conrelid
                            JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                            WHERE ns.nspname = 'ati'
                              AND rel.relname = 'investigation_timeline_event'
                              AND con.contype = 'c'
                        """))}
                await connection.execute(text("""
                        DO $$
                        DECLARE
                          investigation_id uuid;
                        BEGIN
                          INSERT INTO ati.investigation
                            (status, trigger_type, objective, budget,
                             operational_state, version, created_at, updated_at,
                             started_at)
                          VALUES ('running', 'manual', 'assess', '{}'::jsonb,
                                  '{}'::jsonb, 1, now(), now(), now())
                          RETURNING id INTO investigation_id;
                          INSERT INTO ati.investigation_timeline_event
                            (id, investigation_id, event_type, occurred_at,
                             provider, target_entity_id)
                          VALUES (gen_random_uuid(), investigation_id,
                                  'provider_work_started', now(),
                                  'urn:ati:source:google_public_dns',
                                  gen_random_uuid());
                        END
                        $$;
                    """))
                count = await connection.scalar(
                    text("SELECT count(*) FROM ati.investigation_timeline_event")
                )
        finally:
            await engine.dispose()
        assert owner == "ati.investigation_timeline_event_seq"
        assert "investigation_timeline_event_chronological_idx" in indexes
        assert {
            "investigation_timeline_event_type_check",
            "investigation_timeline_event_error_code_check",
        } <= checks
        assert count == 1
    finally:
        command.upgrade(alembic_cfg, "head")
