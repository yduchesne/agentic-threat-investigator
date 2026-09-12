-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 22A: research foundation SQL API v0016.
--
-- Two additions over v0005's RAG API:
--
-- 1. document_chunk.citation_id: a deterministic semantic citation identity
--    (UUIDv5 over canonical semantic chunk JSON) that is independent of the
--    replaceable chunk row identity, the concrete vector, and the embedding
--    provider/model/version/dimension. The column is NOT NULL and globally
--    unique. Existing derived chunk rows are removed by the migration before
--    this API is installed because the citation algorithm is application-
--    owned and cannot be reproduced exactly in SQL; the corpus must be
--    re-indexed after upgrade (Documents themselves are preserved).
-- 2. ati.research_result: an append-only immutable contextual research
--    artifact (PR 22A) holding typed ResearchClaim/ResearchCitation JSONB
--    snapshots. It is deliberately NOT Evidence and NOT Assessment: no
--    version/history table, no update or delete routine, only insert/read.
--    The database enforces root foreign keys and duplicate-ID rejection;
--    citation closure and claim semantics are enforced by the application
--    domain model.

-- Chunk replacement v2: the batch composite and replacement function accept
-- the application-supplied citation identity. PostgreSQL never generates a
-- citation ID. `replace_document_chunks` remains an atomic physical rebuild
-- of complete chunk sets for the supplied documents.
DROP FUNCTION IF EXISTS ati.replace_document_chunks(
  uuid[], ati.document_chunk_batch_item[]);
DROP TYPE IF EXISTS ati.document_chunk_batch_item;

CREATE TYPE ati.document_chunk_batch_item AS (
  ordinal bigint,
  citation_id uuid,
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
);

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
    citation_id uuid NOT NULL,
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
         staged.citation_id, staged.document_id, staged.sequence,
         staged.text, staged.token_count, staged.embedding_literal::vector,
         staged.embedding_provider, staged.embedding_model,
         staged.embedding_model_version, staged.embedding_dimension,
         staged.content_hash, staged.metadata
  FROM (
    SELECT COALESCE(u.item_ordinal, u.input_ordinal) AS ordinal,
           u.item_citation_id AS citation_id,
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
      item_ordinal, item_citation_id, item_document_id, item_sequence,
      item_text, item_token_count, item_embedding_literal,
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
      document_id, citation_id, sequence, text, token_count, embedding,
      embedding_provider, embedding_model, embedding_model_version,
      embedding_dimension, content_hash, metadata, version
    )
    SELECT document_id, citation_id, sequence, text, token_count, embedding,
           embedding_provider, embedding_model, embedding_model_version,
           embedding_dimension, content_hash, metadata,
           nextval('ati.document_chunk_version_seq')
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

-- Append-only immutable contextual research artifacts (PR 22A).
--
-- ``claims`` and ``citations`` are authoritative typed JSONB snapshots
-- validated by the application domain model; the Pydantic model remains the
-- contract. The database does not teach PostgreSQL Research Agent semantics;
-- it enforces only root integrity (foreign keys, immutable insert, no update
-- or delete routine) and fails closed on duplicate identity.
CREATE TABLE ati.research_result (
  id uuid PRIMARY KEY,
  investigation_id uuid NOT NULL REFERENCES ati.investigation(id),
  subject_entity_id uuid NOT NULL REFERENCES ati.entity(id),
  query text NOT NULL CHECK (btrim(query) <> ''),
  claims jsonb NOT NULL,
  citations jsonb NOT NULL,
  created_at timestamptz NOT NULL
);
CREATE INDEX research_result_investigation_idx
  ON ati.research_result (investigation_id, created_at, id);
CREATE INDEX research_result_subject_idx
  ON ati.research_result (subject_entity_id, created_at, id);

CREATE FUNCTION ati.append_research_result(
  p_id uuid,
  p_investigation_id uuid,
  p_subject_entity_id uuid,
  p_query text,
  p_claims jsonb,
  p_citations jsonb,
  p_created_at timestamptz
)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM ati.research_result WHERE id = p_id) THEN
    RAISE EXCEPTION 'research result already exists: %', p_id
      USING ERRCODE = 'U22A1';
  END IF;
  INSERT INTO ati.research_result(
    id, investigation_id, subject_entity_id, query, claims, citations,
    created_at
  )
  VALUES (
    p_id, p_investigation_id, p_subject_entity_id, p_query, p_claims,
    p_citations, p_created_at
  );
END $$;