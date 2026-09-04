-- Immutable SQL API v0005 for RAG document/chunk persistence.
-- Documents are versioned domain resources. Chunks are replaceable indexing
-- artifacts: physical rebuild is permitted and chunks have versions but no
-- domain_object_history. The HNSW index uses cosine distance for PR 11.
-- The application invokes document upsert and chunk replacement in one
-- transaction, so a changed document is never visible with stale chunks.

CREATE SEQUENCE ati.document_version_seq;
CREATE SEQUENCE ati.document_chunk_version_seq;

CREATE TABLE ati.document (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id text NOT NULL CHECK (btrim(source_id) <> ''),
  source_record_id text NOT NULL CHECK (btrim(source_record_id) <> ''),
  document_type text NOT NULL CHECK (btrim(document_type) <> ''),
  title text,
  source_url text,
  published_at timestamptz,
  retrieved_at timestamptz NOT NULL,
  content text NOT NULL CHECK (btrim(content) <> ''),
  normalization_version integer NOT NULL CHECK (normalization_version > 0),
  chunking_version integer NOT NULL CHECK (chunking_version > 0),
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  version bigint NOT NULL DEFAULT nextval('ati.document_version_seq'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  deleted_by_actor_id uuid,
  CONSTRAINT document_external_identity_key
    UNIQUE (source_id, source_record_id),
  CONSTRAINT document_source_record_fk
    FOREIGN KEY (source_id, source_record_id)
    REFERENCES ati.source_record (source_id, source_record_id)
);
CREATE INDEX document_document_type_idx ON ati.document (document_type);
CREATE INDEX document_source_idx ON ati.document (source_id);

CREATE TABLE ati.document_chunk (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id uuid NOT NULL REFERENCES ati.document(id),
  sequence integer NOT NULL CHECK (sequence > 0),
  text text NOT NULL CHECK (btrim(text) <> ''),
  token_count integer NOT NULL CHECK (token_count > 0),
  embedding vector(1536) NOT NULL,
  embedding_provider text NOT NULL CHECK (btrim(embedding_provider) <> ''),
  embedding_model text NOT NULL CHECK (btrim(embedding_model) <> ''),
  embedding_model_version integer NOT NULL CHECK (embedding_model_version > 0),
  embedding_dimension integer NOT NULL CHECK (embedding_dimension = 1536),
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  version bigint NOT NULL DEFAULT nextval('ati.document_chunk_version_seq'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT document_chunk_identity_key UNIQUE (document_id, sequence)
);
CREATE INDEX document_chunk_document_idx ON ati.document_chunk (document_id);
CREATE INDEX document_chunk_embedding_hnsw_idx
  ON ati.document_chunk USING hnsw (embedding vector_cosine_ops);

CREATE TYPE ati.document_batch_item AS (
  ordinal bigint,
  source_id text,
  source_record_id text,
  document_type text,
  title text,
  source_url text,
  published_at timestamptz,
  retrieved_at timestamptz,
  content text,
  normalization_version integer,
  chunking_version integer,
  content_hash bytea,
  metadata jsonb,
  expected_version bigint
);

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
);

CREATE FUNCTION ati.upsert_documents(p_items ati.document_batch_item[])
RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text)
LANGUAGE plpgsql AS $$
DECLARE hard_limit CONSTANT integer := 10000;
BEGIN
  IF cardinality(p_items) > hard_limit THEN
    RAISE EXCEPTION 'document batch exceeds defensive limit of % items', hard_limit
      USING ERRCODE = '22023';
  END IF;

  DROP TABLE IF EXISTS ati_document_batch_input;
  CREATE TEMP TABLE ati_document_batch_input (
    ordinal bigint NOT NULL,
    primary_ordinal bigint NOT NULL,
    source_id text NOT NULL,
    source_record_id text NOT NULL,
    document_type text NOT NULL,
    title text,
    source_url text,
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    content text NOT NULL,
    normalization_version integer NOT NULL,
    chunking_version integer NOT NULL,
    content_hash bytea NOT NULL,
    metadata jsonb NOT NULL,
    expected_version bigint
  ) ON COMMIT DROP;

  DROP TABLE IF EXISTS ati_document_batch_reconciliation;
  CREATE TEMP TABLE ati_document_batch_reconciliation (
    ordinal bigint PRIMARY KEY,
    id uuid,
    source_id text NOT NULL,
    source_record_id text NOT NULL,
    document_type text NOT NULL,
    title text,
    source_url text,
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    content text NOT NULL,
    normalization_version integer NOT NULL,
    chunking_version integer NOT NULL,
    content_hash bytea NOT NULL,
    metadata jsonb NOT NULL,
    expected_version bigint,
    observed_version bigint,
    old_state jsonb,
    classification text NOT NULL
  ) ON COMMIT DROP;

  DROP TABLE IF EXISTS ati_document_batch_mutation;
  CREATE TEMP TABLE ati_document_batch_mutation (
    ordinal bigint PRIMARY KEY,
    id uuid NOT NULL,
    version bigint NOT NULL,
    operation text NOT NULL,
    old_state jsonb,
    new_state jsonb NOT NULL
  ) ON COMMIT DROP;

  INSERT INTO ati_document_batch_input
  SELECT staged.ordinal,
         min(staged.ordinal) OVER (
           PARTITION BY staged.source_id, staged.source_record_id
         ),
         staged.source_id, staged.source_record_id, staged.document_type,
         staged.title, staged.source_url, staged.published_at,
         staged.retrieved_at, staged.content, staged.normalization_version,
         staged.chunking_version, staged.content_hash, staged.metadata,
         staged.expected_version
  FROM (
    SELECT COALESCE(u.item_ordinal, u.input_ordinal) AS ordinal,
           u.item_source_id AS source_id,
           u.item_source_record_id AS source_record_id,
           u.item_document_type AS document_type,
           u.item_title AS title,
           u.item_source_url AS source_url,
           u.item_published_at AS published_at,
           u.item_retrieved_at AS retrieved_at,
           u.item_content AS content,
           u.item_normalization_version AS normalization_version,
           u.item_chunking_version AS chunking_version,
           u.item_content_hash AS content_hash,
           COALESCE(u.item_metadata, '{}'::jsonb) AS metadata,
           u.item_expected_version AS expected_version
    FROM unnest(p_items) WITH ORDINALITY AS u(
      item_ordinal, item_source_id, item_source_record_id, item_document_type,
      item_title, item_source_url, item_published_at, item_retrieved_at,
      item_content, item_normalization_version, item_chunking_version,
      item_content_hash, item_metadata, item_expected_version, input_ordinal
    )
  ) staged;

  INSERT INTO ati_document_batch_reconciliation
  SELECT i.ordinal, current.id, i.source_id, i.source_record_id,
         i.document_type, i.title, i.source_url, i.published_at,
         i.retrieved_at, i.content, i.normalization_version,
         i.chunking_version, i.content_hash, i.metadata, i.expected_version,
         current.version, to_jsonb(current),
         CASE
           WHEN current.id IS NULL THEN 'INSERTED'
           WHEN i.expected_version IS NOT NULL
                AND i.expected_version <> current.version THEN 'CONFLICT'
           WHEN current.content_hash = i.content_hash THEN 'UNCHANGED'
           ELSE 'UPDATED'
         END
  FROM ati_document_batch_input i
  LEFT JOIN ati.document current
    ON current.source_id = i.source_id
   AND current.source_record_id = i.source_record_id
  WHERE i.ordinal = i.primary_ordinal;

  WITH candidates AS (
    SELECT * FROM ati_document_batch_reconciliation
    WHERE classification = 'INSERTED'
  ), written AS (
    INSERT INTO ati.document AS target(
      source_id, source_record_id, document_type, title, source_url,
      published_at, retrieved_at, content, normalization_version,
      chunking_version, content_hash, metadata, version
    )
    SELECT source_id, source_record_id, document_type, title, source_url,
           published_at, retrieved_at, content, normalization_version,
           chunking_version, content_hash, metadata,
           nextval('ati.document_version_seq')
    FROM candidates
    ON CONFLICT (source_id, source_record_id) DO NOTHING
    RETURNING target.id, target.source_id, target.source_record_id,
              target.version, to_jsonb(target) AS new_state
  )
  INSERT INTO ati_document_batch_mutation
  SELECT candidates.ordinal, written.id, written.version, 'CREATE', NULL,
         written.new_state
  FROM candidates
  JOIN written USING (source_id, source_record_id);

  UPDATE ati_document_batch_reconciliation reconciliation
  SET id = current.id,
      observed_version = current.version,
      old_state = to_jsonb(current),
      classification = CASE
        WHEN reconciliation.expected_version IS NOT NULL
             AND reconciliation.expected_version <> current.version THEN 'CONFLICT'
        WHEN current.content_hash = reconciliation.content_hash THEN 'UNCHANGED'
        ELSE 'UPDATED'
      END
  FROM ati.document current
  WHERE reconciliation.classification = 'INSERTED'
    AND NOT EXISTS (
      SELECT 1 FROM ati_document_batch_mutation mutation
      WHERE mutation.ordinal = reconciliation.ordinal
    )
    AND current.source_id = reconciliation.source_id
    AND current.source_record_id = reconciliation.source_record_id;

  WITH candidates AS (
    SELECT * FROM ati_document_batch_reconciliation
    WHERE classification = 'UPDATED'
  ), written AS (
    UPDATE ati.document target
    SET document_type = candidates.document_type,
        title = candidates.title,
        source_url = candidates.source_url,
        published_at = candidates.published_at,
        retrieved_at = candidates.retrieved_at,
        content = candidates.content,
        normalization_version = candidates.normalization_version,
        chunking_version = candidates.chunking_version,
        content_hash = candidates.content_hash,
        metadata = candidates.metadata,
        version = nextval('ati.document_version_seq'),
        updated_at = now()
    FROM candidates
    WHERE target.source_id = candidates.source_id
      AND target.source_record_id = candidates.source_record_id
      AND target.version = candidates.observed_version
    RETURNING candidates.ordinal, target.id, target.version,
              candidates.old_state, to_jsonb(target) AS new_state
  )
  INSERT INTO ati_document_batch_mutation
  SELECT written.ordinal, written.id, written.version, 'UPDATE',
         written.old_state, written.new_state
  FROM written;

  UPDATE ati_document_batch_reconciliation reconciliation
  SET classification = 'CONFLICT'
  WHERE reconciliation.classification = 'UPDATED'
    AND NOT EXISTS (
      SELECT 1 FROM ati_document_batch_mutation mutation
      WHERE mutation.ordinal = reconciliation.ordinal
    );

  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff
  )
  SELECT 'document', mutation.id, mutation.version, mutation.operation,
         mutation.new_state,
         CASE
           WHEN mutation.operation = 'CREATE' THEN '{}'::jsonb
           ELSE ati.ati_jsonb_diff(
             mutation.old_state - ARRAY['version','created_at','updated_at']::text[],
             mutation.new_state - ARRAY['version','created_at','updated_at']::text[]
           )
         END
  FROM ati_document_batch_mutation mutation;

  RETURN QUERY
  SELECT reconciliation.ordinal,
         COALESCE(mutation.id, reconciliation.id),
         COALESCE(mutation.version, reconciliation.observed_version),
         reconciliation.classification
  FROM ati_document_batch_reconciliation reconciliation
  LEFT JOIN ati_document_batch_mutation mutation USING (ordinal)
  UNION ALL
  SELECT duplicate.ordinal,
         COALESCE(mutation.id, current.id),
         COALESCE(mutation.version, current.version),
         'CONFLICT'
  FROM ati_document_batch_input duplicate
  LEFT JOIN ati_document_batch_mutation mutation
    ON mutation.ordinal = duplicate.primary_ordinal
  LEFT JOIN ati.document current
    ON current.source_id = duplicate.source_id
   AND current.source_record_id = duplicate.source_record_id
  WHERE duplicate.ordinal <> duplicate.primary_ordinal
  ORDER BY 1;
END $$;

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
         staged.document_id, staged.sequence, staged.text, staged.token_count,
         staged.embedding_literal::vector, staged.embedding_provider,
         staged.embedding_model, staged.embedding_model_version,
         staged.embedding_dimension, staged.content_hash, staged.metadata
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
      item_token_count, item_embedding_literal, item_embedding_provider,
      item_embedding_model, item_embedding_model_version,
      item_embedding_dimension, item_content_hash, item_metadata,
      input_ordinal
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
