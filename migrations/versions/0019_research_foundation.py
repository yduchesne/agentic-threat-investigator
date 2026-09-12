# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 22A research foundation: chunk citation identity and research results.

PR 22A adds a deterministic semantic citation identity to replaceable
``document_chunk`` rows and an immutable, append-only ``research_result``
table for contextual research artifacts.

Upgrade data note:
    ``document_chunk`` rows are replaceable derived indexing artifacts whose
    ``citation_id`` is computed by the application citation algorithm, which
    cannot be reproduced exactly in SQL. The upgrade therefore removes all
    existing derived chunk rows and requires corpus re-indexing; Documents
    and all source/investigation/evidence/assessment records are preserved.

The chunk replacement SQL API is versioned forward (v0016): the
``document_chunk_batch_item`` composite gains the application-supplied
``citation_id`` and the ``replace_document_chunks`` function persists it.
PostgreSQL never generates citation IDs.
"""

from pathlib import Path

from alembic import op

revision = "0019_research_foundation"
down_revision = "0018_coordinator_selection"


def upgrade() -> None:
    """Add citation identity, version the chunk API, and install research results."""
    # Derived replaceable chunk rows are cleared before the NOT NULL column:
    # application re-indexing recomputes the citation identity.
    op.execute("DELETE FROM ati.document_chunk")
    op.execute("ALTER TABLE ati.document_chunk ADD COLUMN citation_id uuid")
    op.execute("ALTER TABLE ati.document_chunk ALTER COLUMN citation_id SET NOT NULL")
    op.execute(
        "ALTER TABLE ati.document_chunk "
        "ADD CONSTRAINT document_chunk_citation_key UNIQUE (citation_id)"
    )
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0016/research_foundation.sql")
        .read_text()
    )


def downgrade() -> None:
    """Restore the v0005 chunk API and remove research-result persistence."""
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_research_result("
        "uuid, uuid, uuid, text, jsonb, jsonb, timestamptz)"
    )
    op.execute("DROP TABLE IF EXISTS ati.research_result")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.replace_document_chunks("
        "uuid[], ati.document_chunk_batch_item[])"
    )
    op.execute("DROP TYPE IF EXISTS ati.document_chunk_batch_item")
    op.execute(
        "ALTER TABLE ati.document_chunk "
        "DROP CONSTRAINT IF EXISTS document_chunk_citation_key"
    )
    op.execute("ALTER TABLE ati.document_chunk DROP COLUMN citation_id")
    # Restore the v0005 composite type and replacement function unchanged.
    op.execute(
        """
        CREATE TYPE ati.document_chunk_batch_item AS (
          ordinal bigint,
          document_id uuid,
          sequence integer,
          text text,
          token_count integer,
          embedding_literal text,
          embedding_provider text,
          embedding_model text,
          embedding_model_version integer,
          embedding_dimension integer,
          content_hash bytea,
          metadata jsonb
        )
        """
    )
    op.execute(
        """
        CREATE FUNCTION ati.replace_document_chunks(
          p_document_ids uuid[], p_items ati.document_chunk_batch_item[]
        )
        RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text)
        LANGUAGE plpgsql AS $$
        DECLARE hard_limit CONSTANT integer := 10000;
        BEGIN
          IF cardinality(p_document_ids) IS NULL OR cardinality(p_document_ids) = 0
             OR cardinality(p_document_ids) > hard_limit
             OR cardinality(p_items) > hard_limit THEN
            RAISE EXCEPTION 'invalid document-chunk replacement batch'
              USING ERRCODE = '22023';
          END IF;
          DROP TABLE IF EXISTS ati_document_chunk_document_ids;
          CREATE TEMP TABLE ati_document_chunk_document_ids (
            document_id uuid PRIMARY KEY
          ) ON COMMIT DROP;
          INSERT INTO ati_document_chunk_document_ids
          SELECT DISTINCT document_id FROM unnest(p_document_ids) AS ids(document_id);
          IF EXISTS (
            SELECT 1 FROM ati_document_chunk_document_ids ids
            LEFT JOIN ati.document document ON document.id = ids.document_id
            WHERE document.id IS NULL
          ) THEN
            RAISE EXCEPTION 'document-chunk replacement references an unknown document'
              USING ERRCODE = '22023';
          END IF;
          DROP TABLE IF EXISTS ati_document_chunk_batch_input;
          CREATE TEMP TABLE ati_document_chunk_batch_input (
            ordinal bigint NOT NULL,
            primary_ordinal bigint NOT NULL,
            document_id uuid NOT NULL,
            sequence integer NOT NULL,
            text text NOT NULL,
            token_count integer NOT NULL,
            embedding vector(1536) NOT NULL,
            embedding_provider text NOT NULL,
            embedding_model text NOT NULL,
            embedding_model_version integer NOT NULL,
            embedding_dimension integer NOT NULL,
            content_hash bytea NOT NULL,
            metadata jsonb NOT NULL
          ) ON COMMIT DROP;
          INSERT INTO ati_document_chunk_batch_input
          SELECT staged.ordinal,
                 min(staged.ordinal) OVER (
                   PARTITION BY staged.document_id, staged.sequence
                 ),
                 staged.document_id, staged.sequence, staged.text,
                 staged.token_count, staged.embedding_literal::vector,
                 staged.embedding_provider, staged.embedding_model,
                 staged.embedding_model_version, staged.embedding_dimension,
                 staged.content_hash, staged.metadata
          FROM (
            SELECT COALESCE(u.item_ordinal, u.input_ordinal) AS ordinal,
                   u.item_document_id AS document_id,
                   u.item_sequence AS sequence,
                   u.item_text AS text,
                   u.item_token_count AS token_count,
                   u.item_embedding_literal AS embedding_literal,
                   u.item_embedding_provider AS embedding_provider,
                   u.item_embedding_model AS embedding_model,
                   u.item_embedding_model_version AS embedding_model_version,
                   u.item_embedding_dimension AS embedding_dimension,
                   u.item_content_hash AS content_hash,
                   COALESCE(u.item_metadata, '{}'::jsonb) AS metadata
            FROM unnest(p_items) WITH ORDINALITY AS u(
              item_ordinal, item_document_id, item_sequence, item_text,
              item_token_count, item_embedding_literal,
              item_embedding_provider, item_embedding_model,
              item_embedding_model_version, item_embedding_dimension,
              item_content_hash, item_metadata, input_ordinal
            )
          ) staged;
          IF EXISTS (
            SELECT 1 FROM ati_document_chunk_batch_input input
            LEFT JOIN ati_document_chunk_document_ids ids
              ON ids.document_id = input.document_id
            WHERE ids.document_id IS NULL
          ) THEN
            RAISE EXCEPTION 'chunk document is outside the replacement set'
              USING ERRCODE = '22023';
          END IF;
          DELETE FROM ati.document_chunk chunk
          USING ati_document_chunk_document_ids ids
          WHERE chunk.document_id = ids.document_id;
          DROP TABLE IF EXISTS ati_document_chunk_batch_result;
          CREATE TEMP TABLE ati_document_chunk_batch_result (
            ordinal bigint PRIMARY KEY,
            id uuid NOT NULL,
            version bigint NOT NULL,
            outcome text NOT NULL
          ) ON COMMIT DROP;
          WITH candidates AS (
            SELECT input.* FROM ati_document_chunk_batch_input input
            WHERE input.ordinal = input.primary_ordinal
          ), written AS (
            INSERT INTO ati.document_chunk AS target(
              document_id, sequence, text, token_count, embedding,
              embedding_provider, embedding_model, embedding_model_version,
              embedding_dimension, content_hash, metadata, version
            )
            SELECT document_id, sequence, text, token_count, embedding,
                   embedding_provider, embedding_model,
                   embedding_model_version, embedding_dimension,
                   content_hash, metadata, nextval('ati.document_chunk_version_seq')
            FROM candidates
            RETURNING target.id, target.document_id, target.sequence, target.version
          )
          INSERT INTO ati_document_chunk_batch_result
          SELECT candidates.ordinal, written.id, written.version, 'INSERTED'
          FROM candidates
          JOIN written USING (document_id, sequence);
          INSERT INTO ati_document_chunk_batch_result
          SELECT duplicate.ordinal, primary_result.id, primary_result.version, 'CONFLICT'
          FROM ati_document_chunk_batch_input duplicate
          JOIN ati_document_chunk_batch_result primary_result
            ON primary_result.ordinal = duplicate.primary_ordinal
          WHERE duplicate.ordinal <> duplicate.primary_ordinal;
          RETURN QUERY
          SELECT result.ordinal, result.id, result.version, result.outcome
          FROM ati_document_chunk_batch_result result
          ORDER BY result.ordinal;
        END $$;
        """
    )