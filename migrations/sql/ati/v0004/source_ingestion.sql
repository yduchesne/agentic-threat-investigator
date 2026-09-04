-- Immutable SQL API v0004 for normalized source-record ingestion.
CREATE SEQUENCE ati.source_record_version_seq;

CREATE TABLE ati.source_record (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id text NOT NULL CHECK (btrim(source_id) <> ''),
  source_record_id text NOT NULL CHECK (btrim(source_record_id) <> ''),
  record_type text NOT NULL CHECK (btrim(record_type) <> ''),
  normalization_version integer NOT NULL CHECK (normalization_version > 0),
  observed_at timestamptz,
  published_at timestamptz,
  retrieved_at timestamptz NOT NULL,
  canonical_payload jsonb NOT NULL,
  raw_payload jsonb,
  content_hash bytea NOT NULL CHECK (octet_length(content_hash) = 32),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  version bigint NOT NULL DEFAULT nextval('ati.source_record_version_seq'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT source_record_external_identity_key UNIQUE (source_id, source_record_id)
);

CREATE TABLE ati.ingestion_checkpoint (
  source_id text NOT NULL CHECK (btrim(source_id) <> ''),
  artifact_uri text NOT NULL CHECK (btrim(artifact_uri) <> ''),
  normalization_version integer NOT NULL CHECK (normalization_version > 0),
  checkpoint text,
  complete boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (source_id, artifact_uri, normalization_version),
  CHECK (checkpoint IS NULL OR checkpoint <> '')
);

CREATE TYPE ati.source_record_batch_item AS (
  ordinal bigint,
  source_id text,
  source_record_id text,
  record_type text,
  normalization_version integer,
  observed_at timestamptz,
  published_at timestamptz,
  retrieved_at timestamptz,
  canonical_payload jsonb,
  raw_payload jsonb,
  content_hash bytea,
  metadata jsonb,
  expected_version bigint
);

CREATE FUNCTION ati.upsert_source_records(p_items ati.source_record_batch_item[])
RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text)
LANGUAGE plpgsql AS $$
DECLARE hard_limit CONSTANT integer := 10000;
BEGIN
  IF cardinality(p_items) > hard_limit THEN
    RAISE EXCEPTION 'source-record batch exceeds defensive limit of % items', hard_limit
      USING ERRCODE = '22023';
  END IF;

  DROP TABLE IF EXISTS ati_source_record_batch_input;
  CREATE TEMP TABLE ati_source_record_batch_input (
    ordinal bigint NOT NULL,
    primary_ordinal bigint NOT NULL,
    source_id text NOT NULL,
    source_record_id text NOT NULL,
    record_type text NOT NULL,
    normalization_version integer NOT NULL,
    observed_at timestamptz,
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    canonical_payload jsonb NOT NULL,
    raw_payload jsonb,
    content_hash bytea NOT NULL,
    metadata jsonb NOT NULL,
    expected_version bigint
  ) ON COMMIT DROP;

  DROP TABLE IF EXISTS ati_source_record_batch_reconciliation;
  CREATE TEMP TABLE ati_source_record_batch_reconciliation (
    ordinal bigint PRIMARY KEY,
    id uuid,
    source_id text NOT NULL,
    source_record_id text NOT NULL,
    record_type text NOT NULL,
    normalization_version integer NOT NULL,
    observed_at timestamptz,
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    canonical_payload jsonb NOT NULL,
    raw_payload jsonb,
    content_hash bytea NOT NULL,
    metadata jsonb NOT NULL,
    expected_version bigint,
    observed_version bigint,
    old_state jsonb,
    classification text NOT NULL
  ) ON COMMIT DROP;

  DROP TABLE IF EXISTS ati_source_record_batch_mutation;
  CREATE TEMP TABLE ati_source_record_batch_mutation (
    ordinal bigint PRIMARY KEY,
    id uuid NOT NULL,
    version bigint NOT NULL,
    operation text NOT NULL,
    old_state jsonb,
    new_state jsonb NOT NULL
  ) ON COMMIT DROP;

  INSERT INTO ati_source_record_batch_input
  SELECT staged.ordinal,
         min(staged.ordinal) OVER (
           PARTITION BY staged.source_id, staged.source_record_id
         ),
         staged.source_id, staged.source_record_id, staged.record_type,
         staged.normalization_version, staged.observed_at, staged.published_at,
         staged.retrieved_at, staged.canonical_payload, staged.raw_payload,
         staged.content_hash, staged.metadata, staged.expected_version
  FROM (
    SELECT COALESCE(u.item_ordinal, u.input_ordinal) AS ordinal,
           u.item_source_id AS source_id,
           u.item_source_record_id AS source_record_id,
           u.item_record_type AS record_type,
           u.item_normalization_version AS normalization_version,
           u.item_observed_at AS observed_at,
           u.item_published_at AS published_at,
           u.item_retrieved_at AS retrieved_at,
           u.item_canonical_payload AS canonical_payload,
           u.item_raw_payload AS raw_payload,
           u.item_content_hash AS content_hash,
           COALESCE(u.item_metadata, '{}'::jsonb) AS metadata,
           u.item_expected_version AS expected_version
    FROM unnest(p_items) WITH ORDINALITY AS u(
      item_ordinal, item_source_id, item_source_record_id, item_record_type,
      item_normalization_version, item_observed_at, item_published_at,
      item_retrieved_at, item_canonical_payload, item_raw_payload,
      item_content_hash, item_metadata, item_expected_version, input_ordinal
    )
  ) staged;

  INSERT INTO ati_source_record_batch_reconciliation
  SELECT i.ordinal, current.id, i.source_id, i.source_record_id, i.record_type,
         i.normalization_version, i.observed_at, i.published_at, i.retrieved_at,
         i.canonical_payload, i.raw_payload, i.content_hash, i.metadata,
         i.expected_version, current.version, to_jsonb(current),
         CASE
           WHEN current.id IS NULL THEN 'INSERTED'
           WHEN i.expected_version IS NOT NULL
                AND i.expected_version <> current.version THEN 'CONFLICT'
           WHEN current.content_hash = i.content_hash THEN 'UNCHANGED'
           ELSE 'UPDATED'
         END
  FROM ati_source_record_batch_input i
  LEFT JOIN ati.source_record current
    ON current.source_id = i.source_id
   AND current.source_record_id = i.source_record_id
  WHERE i.ordinal = i.primary_ordinal;

  WITH candidates AS (
    SELECT * FROM ati_source_record_batch_reconciliation
    WHERE classification = 'INSERTED'
  ), written AS (
    INSERT INTO ati.source_record AS target(
      source_id, source_record_id, record_type, normalization_version,
      observed_at, published_at, retrieved_at, canonical_payload, raw_payload,
      content_hash, metadata, version
    )
    SELECT source_id, source_record_id, record_type, normalization_version,
           observed_at, published_at, retrieved_at, canonical_payload, raw_payload,
           content_hash, metadata, nextval('ati.source_record_version_seq')
    FROM candidates
    ON CONFLICT (source_id, source_record_id) DO NOTHING
    RETURNING target.id, target.source_id, target.source_record_id,
              target.version, to_jsonb(target) AS new_state
  )
  INSERT INTO ati_source_record_batch_mutation
  SELECT candidates.ordinal, written.id, written.version, 'CREATE', NULL,
         written.new_state
  FROM candidates
  JOIN written USING (source_id, source_record_id);

  UPDATE ati_source_record_batch_reconciliation reconciliation
  SET id = current.id,
      observed_version = current.version,
      old_state = to_jsonb(current),
      classification = CASE
        WHEN reconciliation.expected_version IS NOT NULL
             AND reconciliation.expected_version <> current.version THEN 'CONFLICT'
        WHEN current.content_hash = reconciliation.content_hash THEN 'UNCHANGED'
        ELSE 'UPDATED'
      END
  FROM ati.source_record current
  WHERE reconciliation.classification = 'INSERTED'
    AND NOT EXISTS (
      SELECT 1 FROM ati_source_record_batch_mutation mutation
      WHERE mutation.ordinal = reconciliation.ordinal
    )
    AND current.source_id = reconciliation.source_id
    AND current.source_record_id = reconciliation.source_record_id;

  WITH candidates AS (
    SELECT * FROM ati_source_record_batch_reconciliation
    WHERE classification = 'UPDATED'
  ), written AS (
    UPDATE ati.source_record target
    SET record_type = candidates.record_type,
        normalization_version = candidates.normalization_version,
        observed_at = candidates.observed_at,
        published_at = candidates.published_at,
        retrieved_at = candidates.retrieved_at,
        canonical_payload = candidates.canonical_payload,
        raw_payload = candidates.raw_payload,
        content_hash = candidates.content_hash,
        metadata = candidates.metadata,
        version = nextval('ati.source_record_version_seq'),
        updated_at = now()
    FROM candidates
    WHERE target.source_id = candidates.source_id
      AND target.source_record_id = candidates.source_record_id
      AND target.version = candidates.observed_version
    RETURNING candidates.ordinal, target.id, target.version,
              candidates.old_state, to_jsonb(target) AS new_state
  )
  INSERT INTO ati_source_record_batch_mutation
  SELECT written.ordinal, written.id, written.version, 'UPDATE',
         written.old_state, written.new_state
  FROM written;

  UPDATE ati_source_record_batch_reconciliation reconciliation
  SET classification = 'CONFLICT'
  WHERE reconciliation.classification = 'UPDATED'
    AND NOT EXISTS (
      SELECT 1 FROM ati_source_record_batch_mutation mutation
      WHERE mutation.ordinal = reconciliation.ordinal
    );

  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff
  )
  SELECT 'source_record', mutation.id, mutation.version, mutation.operation,
         mutation.new_state,
         CASE
           WHEN mutation.operation = 'CREATE' THEN '{}'::jsonb
           ELSE ati.ati_jsonb_diff(
             mutation.old_state - ARRAY['version','created_at','updated_at']::text[],
             mutation.new_state - ARRAY['version','created_at','updated_at']::text[]
           )
         END
  FROM ati_source_record_batch_mutation mutation;

  RETURN QUERY
  SELECT reconciliation.ordinal,
         COALESCE(mutation.id, reconciliation.id),
         COALESCE(mutation.version, reconciliation.observed_version),
         reconciliation.classification
  FROM ati_source_record_batch_reconciliation reconciliation
  LEFT JOIN ati_source_record_batch_mutation mutation USING (ordinal)
  UNION ALL
  SELECT duplicate.ordinal,
         COALESCE(mutation.id, current.id),
         COALESCE(mutation.version, current.version),
         'CONFLICT'
  FROM ati_source_record_batch_input duplicate
  LEFT JOIN ati_source_record_batch_mutation mutation
    ON mutation.ordinal = duplicate.primary_ordinal
  LEFT JOIN ati.source_record current
    ON current.source_id = duplicate.source_id
   AND current.source_record_id = duplicate.source_record_id
  WHERE duplicate.ordinal <> duplicate.primary_ordinal
  ORDER BY 1;
END $$;
