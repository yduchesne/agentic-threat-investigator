# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests run against the isolated PostgreSQL container."""

import os
from datetime import UTC, datetime
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
    "assessment_finding",
    "assessment_finding_support",
    "user",
    "credential",
    "session",
    "audit_event",
    "source_record",
    "ingestion_checkpoint",
    "document",
    "document_chunk",
    "research_result",
    "investigation_timeline_event",
    "investigation_job",
    "api_idempotency",
    "location",
    "entity_location_observation",
    "entity_location",
    "geo_resolution",
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
    "location_version_seq",
    "entity_location_observation_version_seq",
    "entity_location_version_seq",
    "geo_resolution_version_seq",
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
    "append_assessment",
    "set_investigation_assessment",
    "soft_delete_assessment",
    "update_investigation_budget",
    "update_investigation_coordinator_state",
    "set_investigation_analysis_result",
    "append_research_result",
    "jsonb_array_starts_with",
    "research_execution_valid",
    "create_investigation_job",
    "claim_next_investigation_job",
    "complete_investigation_job",
    "upsert_location",
    "append_entity_location_observation",
    "create_geo_resolution",
    "upsert_reference_location",
    "reference_geometry_parse",
    "reference_centroid_parse",
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
    assert tables >= EXPECTED_TABLES
    assert sequences >= EXPECTED_SEQUENCES
    assert functions >= EXPECTED_FUNCTIONS
    # The migration search path installs extensions into the ati schema so all
    # database objects — including pgvector and PostGIS (PR 26B) — live there.
    assert {"vector", "pgcrypto", "postgis"} <= extensions


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
                text("""
                SELECT pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                WHERE ns.nspname = 'ati' AND rel.relname = 'audit_event'
                  AND con.contype = 'c'
            """)
            )
            indexes = {
                row[0]
                for row in await connection.execute(
                    text("""
                    SELECT indexname FROM pg_indexes
                    WHERE schemaname = 'ati' AND tablename = 'audit_event'
                """)
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
                    text("""
                    SELECT table_name, column_name, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'ati'
                      AND table_name IN ('user', 'credential', 'session')
                """)
                )
            }
            constraints = {
                row[0]
                for row in await connection.execute(
                    text("""
                    SELECT con.conname
                    FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati'
                      AND rel.relname IN ('user', 'credential', 'session')
                """)
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_graph_integrity_schema_contract() -> None:
    """v0009 installs the provenance FK and the relationship delete function."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            foreign_key = await connection.scalar(
                text("""
                SELECT pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                  AND con.conname = 'relationship_observation_evidence_fk'
            """)
            )
            parameters = await connection.execute(
                text("""
                SELECT p.parameter_name, p.data_type
                FROM information_schema.parameters p
                JOIN information_schema.routines r
                  ON r.specific_schema = 'ati'
                 AND r.routine_name = 'soft_delete_relationship'
                 AND r.specific_name = p.specific_name
                WHERE p.parameter_mode = 'IN'
                ORDER BY p.ordinal_position
            """)
            )
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
                foreign_key = await connection.scalar(
                    text("""
                    SELECT con.conname FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                      AND con.conname = 'relationship_observation_evidence_fk'
                """)
                )
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
            checks = {
                row[0]: row[1]
                for row in await connection.execute(
                    text("""
                        SELECT con.conname, pg_get_constraintdef(con.oid)
                        FROM pg_constraint con
                        JOIN pg_class rel ON rel.oid = con.conrelid
                        JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                        WHERE ns.nspname = 'ati'
                          AND rel.relname = 'investigation_timeline_event'
                          AND con.contype = 'c'
                    """)
                )
            }
            sequence_owner = await connection.scalar(
                text("""
                SELECT pg_get_serial_sequence(
                    'ati.investigation_timeline_event',
                    'sequence'
                )
            """)
            )
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
                foreign_key = await connection.scalar(
                    text("""
                    SELECT con.conname FROM pg_constraint con
                    JOIN pg_class rel ON rel.oid = con.conrelid
                    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                    WHERE ns.nspname = 'ati' AND rel.relname = 'relationship_observation'
                      AND con.conname = 'relationship_observation_evidence_fk'
                """)
                )
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
                owner = await connection.scalar(
                    text("""
                    SELECT pg_get_serial_sequence(
                        'ati.investigation_timeline_event', 'sequence'
                    )
                """)
                )
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
                checks = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT con.conname FROM pg_constraint con
                            JOIN pg_class rel ON rel.oid = con.conrelid
                            JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                            WHERE ns.nspname = 'ati'
                              AND rel.relname = 'investigation_timeline_event'
                              AND con.contype = 'c'
                        """)
                    )
                }
                await connection.execute(
                    text("""
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
                    """)
                )
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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_schema_contract() -> None:
    """v0011 installs normalized tables, checks, FKs, and write functions."""
    engine = _test_engine()
    try:
        async with engine.connect() as connection:
            checks = {
                row[0]: row[1]
                for row in await connection.execute(
                    text("""
                        SELECT con.conname, pg_get_constraintdef(con.oid)
                        FROM pg_constraint con
                        JOIN pg_class rel ON rel.oid = con.conrelid
                        JOIN pg_namespace ns ON ns.oid = rel.relnamespace
                        WHERE ns.nspname = 'ati'
                          AND rel.relname IN (
                            'assessment',
                            'assessment_finding',
                            'assessment_finding_support'
                          )
                          AND con.contype IN ('c', 'f', 'u')
                    """)
                )
            }
            columns = {
                (row[0], row[1])
                for row in await connection.execute(
                    text("""
                        SELECT table_name, column_name
                        FROM information_schema.columns
                        WHERE table_schema = 'ati'
                          AND table_name IN (
                            'assessment',
                            'assessment_finding',
                            'assessment_finding_support'
                          )
                    """)
                )
            }
    finally:
        await engine.dispose()
    assert ("assessment", "version") in columns
    assert ("assessment", "deleted_at") in columns
    assert ("assessment_finding", "ordinal") in columns
    assert ("assessment_finding_support", "kind") in columns
    # Provenance integrity is relational.
    assert any("evidence(id)" in definition for definition in checks.values())
    assert any(
        "relationship_observation(id)" in definition for definition in checks.values()
    )
    # The finding discriminator is exclusive, not nullable-field inferred.
    assert any("kind = 'evidence'" in definition for definition in checks.values())
    assert any(
        "kind = 'relationship_observation'" in definition
        for definition in checks.values()
    )
    # No-evidence Assessments may only be inconclusive.
    assert any(
        "cardinality(analyzed_evidence_ids)" in definition
        for definition in checks.values()
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_migration_downgrade_and_re_upgrade() -> None:
    """Migration 0014 downgrades to the flat table and re-upgrades cleanly."""
    alembic_cfg = Config("alembic.ini")

    async def table_state() -> tuple[bool, bool]:
        """Return (normalized tables present, flat table present)."""
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
        finally:
            await engine.dispose()
        return (
            {"assessment", "assessment_finding", "assessment_finding_support"}
            <= tables,
            "assessment" in tables,
        )

    try:
        command.downgrade(alembic_cfg, "0013_investigation_timeline")
        normalized, flat = await table_state()
        assert not normalized
        assert flat
        command.upgrade(alembic_cfg, "head")
        normalized, _ = await table_state()
        assert normalized
    finally:
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_assessment_migration_rejects_nonempty_legacy_table() -> None:
    """Migration 0014 refuses to drop a nonempty legacy Assessment table."""
    alembic_cfg = Config("alembic.ini")

    async def legacy_row_count() -> int:
        """Return the number of rows in the flat legacy table."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                return int(
                    await connection.scalar(text("SELECT count(*) FROM ati.assessment"))
                )
        finally:
            await engine.dispose()

    async def normalized_tables_present() -> bool:
        """Return whether the normalized child tables were installed."""
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
        finally:
            await engine.dispose()
        return {"assessment_finding", "assessment_finding_support"} <= tables

    try:
        command.downgrade(alembic_cfg, "0013_investigation_timeline")
        # Insert one legal flat row (the legacy table has no FK constraints).
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                await connection.execute(
                    text("""
                        INSERT INTO ati.assessment (
                          id, investigation_id, verdict, confidence, summary,
                          analyzed_evidence_ids, supporting_evidence,
                          contradicting_evidence, limitations,
                          unresolved_questions, recommended_next_steps,
                          version)
                        VALUES (
                          gen_random_uuid(), gen_random_uuid(), 'suspicious',
                          'medium', 'legacy flat row', '[]'::jsonb, '[]'::jsonb,
                          '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, 1)
                    """)
                )
                await connection.commit()
        finally:
            await engine.dispose()

        with pytest.raises(RuntimeError, match="refuses to drop ati.assessment"):
            command.upgrade(alembic_cfg, "head")

        # The legacy row survived, no normalized schema was partially installed,
        # and the flat table is still present.
        assert await legacy_row_count() == 1
        assert not await normalized_tables_present()
    finally:
        # Clean up the guard row and restore head for later tests.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                await connection.execute(text("DELETE FROM ati.assessment"))
                await connection.commit()
        finally:
            await engine.dispose()
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_coordinator_migrations_downgrade_and_re_upgrade() -> None:
    """PR 21 functions and timeline columns are reversible and restorable."""
    alembic_cfg = Config("alembic.ini")

    async def installed_state() -> tuple[set[str], set[str]]:
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                functions = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT routine_name FROM information_schema.routines "
                            "WHERE routine_schema='ati'"
                        )
                    )
                }
                columns = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema='ati' "
                            "AND table_name='investigation_timeline_event'"
                        )
                    )
                }
        finally:
            await engine.dispose()
        return functions, columns

    coordinator_functions = {
        "update_investigation_coordinator_state",
        "set_investigation_analysis_result",
        "jsonb_array_starts_with",
    }
    coordinator_columns = {
        "pivot_depth",
        "reason_code",
        "provider_calls_used",
        "replans_used",
        "entity_count",
    }
    try:
        command.downgrade(alembic_cfg, "0015_llm_accounting")
        functions, columns = await installed_state()
        assert coordinator_functions.isdisjoint(functions)
        assert coordinator_columns.isdisjoint(columns)

        command.upgrade(alembic_cfg, "0016_coordinator_transition")
        functions, columns = await installed_state()
        assert coordinator_functions <= functions
        assert coordinator_columns.isdisjoint(columns)

        command.upgrade(alembic_cfg, "head")
        functions, columns = await installed_state()
        assert coordinator_functions <= functions
        assert coordinator_columns <= columns
    finally:
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_research_foundation_migration_downgrade_and_re_upgrade() -> None:
    """Migration 0019 downgrades to the v0005 chunk API and re-upgrades cleanly."""
    alembic_cfg = Config("alembic.ini")

    async def research_state() -> tuple[bool, bool, bool]:
        """Return (research_result present, citation column present, append fn present)."""
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
                columns = {
                    row[0]
                    for row in await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = 'ati' AND table_name = 'document_chunk'"
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
        finally:
            await engine.dispose()
        return (
            "research_result" in tables,
            "citation_id" in columns,
            "append_research_result" in functions,
        )

    try:
        command.downgrade(alembic_cfg, "0018_coordinator_selection")
        result, citation, append = await research_state()
        assert not result and not citation and not append
        # The v0005 chunk replacement API remains installed after downgrade.
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
        assert "replace_document_chunks" in functions

        command.upgrade(alembic_cfg, "head")
        result, citation, append = await research_state()
        assert result and citation and append
    finally:
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_geoint_migration_downgrade_and_re_upgrade() -> None:
    """Migration 0025 downgrades cleanly and re-upgrades without data loss.

    Representative pre-26A data (Investigation, Entity, Evidence, and a PR 25
    GEOLOCATION Evidence row) must survive both directions unchanged; the
    downgrade removes only the PR 26A GEOINT objects in dependency-safe
    order, and no PostGIS extension is ever required.
    """
    alembic_cfg = Config("alembic.ini")

    async def geoint_state() -> tuple[set[str], set[str], set[str]]:
        """Return (tables, sequences, functions) for the ati schema."""
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
        finally:
            await engine.dispose()
        return tables, sequences, functions

    geoint_tables = {
        "location",
        "entity_location_observation",
        "entity_location",
        "geo_resolution",
    }
    geoint_sequences = {
        "location_version_seq",
        "entity_location_observation_version_seq",
        "entity_location_version_seq",
        "geo_resolution_version_seq",
    }
    geoint_functions = {
        "upsert_location",
        "append_entity_location_observation",
        "create_geo_resolution",
    }
    try:
        # Seed representative pre-26A data plus one GEOINT row at head.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                await connection.execute(
                    text("""
                    DO $$
                    DECLARE
                      v_inv uuid; v_entity uuid; v_geo_ev uuid; v_loc uuid;
                      v_obs uuid;
                    BEGIN
                      INSERT INTO ati.investigation
                        (status, trigger_type, objective, budget,
                         operational_state, version, created_at, updated_at,
                         started_at)
                      VALUES ('running', 'manual', 'seed', '{}'::jsonb,
                              '{}'::jsonb, 1, now(), now(), now())
                      RETURNING id INTO v_inv;
                      INSERT INTO ati.entity
                        (entity_type, canonical_value, display_name,
                         attributes, content_hash, version, created_at,
                         updated_at)
                      VALUES ('ip_address', '203.0.113.7', '203.0.113.7',
                              '{}'::jsonb, NULL, 1, now(), now())
                      RETURNING id INTO v_entity;
                      INSERT INTO ati.evidence
                        (id, investigation_id, evidence_type,
                         subject_entity_id, source, retrieved_at, facts,
                         raw_payload, version)
                      VALUES (gen_random_uuid(), v_inv,
                              'urn:ati:evidence:geolocation', v_entity,
                              'urn:ati:source:dbip', now(), '{}'::jsonb,
                              NULL, 1)
                      RETURNING id INTO v_geo_ev;
                      SELECT id INTO v_loc FROM ati.upsert_location(
                        NULL, 'country', 'United States', 'United States',
                        'US', NULL, NULL, NULL);
                      v_obs := gen_random_uuid();
                      PERFORM ati.append_entity_location_observation(
                        v_obs, v_entity, v_loc, v_geo_ev, 'country', NULL,
                        now(), now(), 'seed_method');
                      PERFORM ati.create_geo_resolution(
                        gen_random_uuid(), v_entity, v_geo_ev);
                    END
                    $$;
                """)
                )
                await connection.commit()
        finally:
            await engine.dispose()

        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                existing_entity_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity")
                )
                existing_evidence_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.evidence")
                )
                extensions = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT e.extname FROM pg_extension e
                            JOIN pg_namespace n ON n.oid = e.extnamespace
                            WHERE n.nspname = 'ati'
                        """)
                    )
                }
        finally:
            await engine.dispose()
        # PR 26B: head installs PostGIS alongside pgvector/pgcrypto.
        assert "postgis" in extensions

        command.downgrade(alembic_cfg, "0024_api_async_foundation")
        tables, sequences, functions = await geoint_state()
        assert geoint_tables.isdisjoint(tables)
        assert geoint_sequences.isdisjoint(sequences)
        assert geoint_functions.isdisjoint(functions)
        # Existing pre-26A data survives the downgrade untouched.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                entity_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity")
                )
                evidence_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.evidence")
                )
                geo_evidence_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM ati.evidence "
                        "WHERE evidence_type = 'urn:ati:evidence:geolocation'"
                    )
                )
        finally:
            await engine.dispose()
        assert entity_count == existing_entity_count
        assert evidence_count == existing_evidence_count
        assert geo_evidence_count == 1

        command.upgrade(alembic_cfg, "head")
        tables, sequences, functions = await geoint_state()
        assert geoint_tables <= tables
        assert geoint_sequences <= sequences
        assert geoint_functions <= functions
        # Re-upgrade preserves the pre-existing data as well.
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                entity_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity")
                )
                evidence_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.evidence")
                )
        finally:
            await engine.dispose()
        assert entity_count == existing_entity_count
        assert evidence_count == existing_evidence_count
    finally:
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_geoint_spatial_migration_upgrade_and_downgrade() -> None:
    """PR 26B spatial migration round-trip preserves pre-26B GEOINT state.

    G26B-P16: upgrading a 0026 database that already holds Location rows
    leaves every existing row intact with NULL spatial fields (no invented
    geometry). G26B-P17: downgrading to 0026 removes the spatial columns,
    index, and write functions and drops the PostGIS extension (introduced by
    PR 26B) without CASCADE collateral. G26B-P18: the pgvector/RAG schema
    survives the upgrade+downgrade cycle.
    """
    alembic_cfg = Config("alembic.ini")

    async def spatial_columns() -> set[str]:
        """Return the PR 26B spatial column names on ati.location."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                return {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT column_name FROM information_schema.columns
                            WHERE table_schema = 'ati' AND table_name = 'location'
                              AND column_name IN ('geometry', 'centroid')
                        """)
                    )
                }
        finally:
            await engine.dispose()

    async def extensions_present() -> set[str]:
        """Return the extensions installed in the ati schema."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                return {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT e.extname FROM pg_extension e
                            JOIN pg_namespace n ON n.oid = e.extnamespace
                            WHERE n.nspname = 'ati'
                        """)
                    )
                }
        finally:
            await engine.dispose()

    try:
        command.downgrade(alembic_cfg, "0026_geoint_version_allocation")
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                # Pre-26B GEOINT state: one canonical Location (plus the
                # v0021 API) and one geo_resolution/observation pair.
                await connection.execute(
                    text("""
                        DO $$
                        DECLARE v_inv uuid; v_entity uuid; v_ev uuid; v_loc uuid;
                        BEGIN
                          INSERT INTO ati.investigation
                            (status, trigger_type, objective, budget,
                             operational_state, version, created_at, updated_at,
                             started_at)
                          VALUES ('running', 'manual', 'seed', '{}'::jsonb,
                                  '{}'::jsonb, 1, now(), now(), now())
                          RETURNING id INTO v_inv;
                          INSERT INTO ati.entity
                            (entity_type, canonical_value, display_name,
                             attributes, content_hash, version, created_at,
                             updated_at)
                          VALUES ('ip_address', '203.0.113.9', '203.0.113.9',
                                  '{}'::jsonb, NULL, 1, now(), now())
                          RETURNING id INTO v_entity;
                          INSERT INTO ati.evidence
                            (id, investigation_id, evidence_type,
                             subject_entity_id, source, retrieved_at, facts,
                             raw_payload, version)
                          VALUES (gen_random_uuid(), v_inv,
                                  'urn:ati:evidence:geolocation', v_entity,
                                  'urn:ati:source:dbip', now(), '{}'::jsonb,
                                  NULL, 1)
                          RETURNING id INTO v_ev;
                          SELECT id INTO v_loc FROM ati.upsert_location(
                            NULL, 'country', 'United States', 'United States',
                            'US', NULL, NULL, NULL);
                          PERFORM ati.append_entity_location_observation(
                            gen_random_uuid(), v_entity, v_loc, v_ev, 'country',
                            NULL, now(), now(), 'seed_method');
                          PERFORM ati.create_geo_resolution(
                            gen_random_uuid(), v_entity, v_ev);
                        END
                        $$;
                    """)
                )
                await connection.commit()
        finally:
            await engine.dispose()

        command.upgrade(alembic_cfg, "head")
        assert {"geometry", "centroid"} <= await spatial_columns()
        assert "postgis" in await extensions_present()
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                geometry_values = {
                    row[0]
                    for row in await connection.execute(
                        text("SELECT geometry IS NULL FROM ati.location")
                    )
                }
                row_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.location")
                )
                observation_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity_location_observation")
                )
                resolution_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.geo_resolution")
                )
                chunk_columns = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT column_name FROM information_schema.columns
                            WHERE table_schema = 'ati'
                              AND table_name = 'document_chunk'
                              AND column_name = 'embedding'
                        """)
                    )
                }
        finally:
            await engine.dispose()
        # G26B-P16: pre-26B rows survive with NULL spatial fields.
        assert row_count == 1 and geometry_values == {True}
        assert observation_count == 1 and resolution_count == 1
        assert chunk_columns == {"embedding"}

        command.downgrade(alembic_cfg, "0026_geoint_version_allocation")
        assert await spatial_columns() == set()
        assert "postgis" not in await extensions_present()
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                functions = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT routine_name FROM information_schema.routines
                            WHERE routine_schema = 'ati'
                        """)
                    )
                }
                indexes = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT indexname FROM pg_indexes
                            WHERE schemaname = 'ati' AND tablename = 'location'
                        """)
                    )
                }
                row_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.location")
                )
                extensions = await extensions_present()
        finally:
            await engine.dispose()
        # G26B-P17: PR 26B objects gone; no unrelated rows lost.
        assert not {"upsert_reference_location", "reference_geometry_parse"} & functions
        assert "location_geometry_gist_idx" not in indexes
        assert "location_resolution_name_idx" not in indexes
        assert row_count == 1
        # G26B-P18: pgvector/RAG remains available after the downgrade.
        assert "vector" in extensions
        assert "postgis" not in extensions
    finally:
        command.upgrade(alembic_cfg, "head")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_geoint_lifecycle_migration_upgrade_and_downgrade() -> None:
    """PR 26C lifecycle migration round-trip preserves authoritative data.

    G26C-P40: upgrading a 0027 database that already holds PENDING work,
    Locations, observations, and current state installs SQL API v0024 and
    the claim/constraint objects without rewriting any existing row, and the
    new lifecycle can then claim and resolve the pre-existing work.
    G26C-P41: downgrading to 0027 removes only the PR 26C functions, claim
    indexes, and CHECK constraints while preserving every authoritative row
    (including terminal work created by the new API) and restoring the
    pre-PR-26C API behavior.
    """
    alembic_cfg = Config("alembic.ini")

    async def resolution_state() -> tuple[int, int, int, int]:
        """Return (resolutions, observations, current rows, locations)."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                resolution_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.geo_resolution")
                )
                observation_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity_location_observation")
                )
                current_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.entity_location")
                )
                location_count = await connection.scalar(
                    text("SELECT count(*) FROM ati.location")
                )
        finally:
            await engine.dispose()
        return (
            int(resolution_count or 0),
            int(observation_count or 0),
            int(current_count or 0),
            int(location_count or 0),
        )

    async def lifecycle_functions() -> set[str]:
        """Return the PR 26C stored function names present in the ati schema."""
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                return {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT routine_name FROM information_schema.routines
                            WHERE routine_schema = 'ati'
                        """)
                    )
                }
        finally:
            await engine.dispose()

    lifecycle_function_names = {
        "claim_geo_resolutions",
        "complete_geo_resolution_resolved",
        "complete_geo_resolution_unresolvable",
        "record_geo_resolution_failure",
    }
    try:
        # Seed pre-26C GEOINT state on a 0027 database: one Location, one
        # observation/current pair, and one PENDING GeoResolution.
        command.downgrade(alembic_cfg, "0027_geoint_reference_spatial")
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                await connection.execute(
                    text(
                        """
                        DO $$
                        DECLARE
                          v_inv uuid; v_entity uuid; v_ev uuid; v_loc uuid;
                          v_obs uuid; v_res uuid;
                        BEGIN
                          INSERT INTO ati.investigation
                            (status, trigger_type, objective, budget,
                             operational_state, version, created_at, updated_at,
                             started_at)
                          VALUES ('running', 'manual', 'seed', '{}'::jsonb,
                                  '{}'::jsonb, 1, now(), now(), now())
                          RETURNING id INTO v_inv;
                          INSERT INTO ati.entity
                            (entity_type, canonical_value, display_name,
                             attributes, content_hash, version, created_at,
                             updated_at)
                          VALUES ('ip_address', '203.0.113.11', '203.0.113.11',
                                  '{}'::jsonb, NULL, 1, now(), now())
                          RETURNING id INTO v_entity;
                          INSERT INTO ati.evidence
                            (id, investigation_id, evidence_type,
                             subject_entity_id, source, retrieved_at, facts,
                             raw_payload, version)
                          VALUES (gen_random_uuid(), v_inv,
                                  'urn:ati:evidence:geolocation', v_entity,
                                  'urn:ati:source:dbip', now(),
                                  '{"country_code":"US"}'::jsonb, NULL, 1)
                          RETURNING id INTO v_ev;
                          SELECT id INTO v_loc FROM ati.upsert_location(
                            NULL, 'country', 'United States', 'United States',
                            'US', NULL, NULL, NULL);
                          v_obs := gen_random_uuid();
                          PERFORM ati.append_entity_location_observation(
                            v_obs, v_entity, v_loc, v_ev, 'country', NULL,
                            now(), now(), 'seed_method');
                          SELECT id INTO v_res
                            FROM ati.create_geo_resolution(
                              gen_random_uuid(), v_entity, v_ev);
                        END
                        $$;
                        """
                    )
                )
                await connection.commit()
        finally:
            await engine.dispose()
        pre_upgrade = await resolution_state()
        assert pre_upgrade == (1, 1, 1, 1)

        # G26C-P40: upgrade to head preserves data and installs the API.
        command.upgrade(alembic_cfg, "head")
        assert lifecycle_function_names <= await lifecycle_functions()
        assert await resolution_state() == pre_upgrade
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                pending = (
                    await connection.execute(
                        text(
                            "SELECT id FROM ati.geo_resolution WHERE status = 'pending'"
                        )
                    )
                ).all()
                assert len(pending) == 1
                location_id = (
                    await connection.execute(
                        text("SELECT id FROM ati.location LIMIT 1")
                    )
                ).scalar_one()
                # The pre-existing PENDING work is claimable by the new API.
                claimed = (
                    await connection.execute(
                        text(
                            "SELECT count(*) FROM ati.claim_geo_resolutions("
                            "'worker-mig', 10, 300, 3)"
                        )
                    )
                ).scalar_one()
                assert int(claimed) == 1
                # ...and the pre-existing location is a valid completion target.
                created = (
                    await connection.execute(
                        text(
                            "SELECT count(*) FROM "
                            "ati.complete_geo_resolution_resolved("
                            ":res, (SELECT version FROM ati.geo_resolution "
                            "WHERE id = :res), 'worker-mig', :obs, :loc, "
                            "'country', :ret, :ret, :ret, 'canonical_geography_v1')"
                        ),
                        {
                            "res": pending[0][0],
                            "obs": pending[0][0],
                            "loc": location_id,
                            "ret": datetime.now(UTC),
                        },
                    )
                ).scalar_one()
                assert int(created) == 1
                # The lifecycle exercise is a real durable transition: commit
                # it so the downgrade below must preserve the terminal work.
                await connection.commit()
        finally:
            await engine.dispose()

        # G26C-P41: downgrade preserves authoritative data, removes only the
        # PR 26C objects, and restores the pre-PR-26C API surface.
        terminal_state = await resolution_state()
        assert terminal_state == (1, 2, 1, 1)
        command.downgrade(alembic_cfg, "0027_geoint_reference_spatial")
        assert lifecycle_function_names.isdisjoint(await lifecycle_functions())
        assert await resolution_state() == terminal_state
        engine = _test_engine()
        try:
            async with engine.connect() as connection:
                statuses = {
                    row[0]
                    for row in await connection.execute(
                        text("SELECT status FROM ati.geo_resolution")
                    )
                }
                indexes = {
                    row[0]
                    for row in await connection.execute(
                        text("""
                            SELECT indexname FROM pg_indexes
                            WHERE schemaname = 'ati' AND tablename = 'geo_resolution'
                        """)
                    )
                }
        finally:
            await engine.dispose()
        assert statuses == {"resolved"}
        assert (
            not {
                "geo_resolution_pending_claim_idx",
                "geo_resolution_processing_claim_idx",
            }
            & indexes
        )
    finally:
        command.upgrade(alembic_cfg, "head")
