-- Immutable SQL API v0032 for PR 33E: operational datasource checkpoint.
--
-- PR 33E adds a durable per-datasource incremental-retrieval checkpoint for
-- the TAXII 2.1 collection acquirer. A checkpoint is datasource operational
-- state, never Evidence, never a lifecycle-log event, never a Kafka offset,
-- and never a STIX timestamp. It is keyed by the datasource instance
-- (never a source provider) plus a bounded checkpoint-kind identifier that
-- names the interpretation (``taxii_added_after`` for TAXII date-added
-- semantics).
--
-- One row per (datasource_id, checkpoint_kind) carries only a bounded
-- canonical value, an operational updated_at, and an optimistic-concurrency
-- version. No credentials, source payload, next-token, or broker position is
-- ever persisted here, and there is deliberately no foreign key from
-- partitioned log tables.
--
-- Concurrency contract: ati.advance_datasource_checkpoint serializes
-- compare-and-advance for one (datasource_id, checkpoint_kind) with a
-- transaction-scoped advisory lock. Advance requires the caller's
-- ``expected_value`` (the value the execution actually started from) to
-- match the durable row, or the whole advance is rejected with a typed
-- SQLSTATE and nothing is overwritten. Advancing to the current value is an
-- idempotent no-op. The generic function deliberately does not decide
-- whether values are temporally ordered: ordering policy belongs to the
-- checkpoint-kind adapter (TAXII date-added timestamps) or to an explicitly
-- designed kind-specific stored-function contract.
--
-- Typed SQLSTATE mapping (new U32A* codes; the U27B* datasource-log codes
-- remain reserved for lifecycle semantics):
--   U32A1 invalid checkpoint input (malformed identifiers/value/timestamp)
--   U32A2 stale compare-and-advance (durable row does not match expectation)

CREATE TABLE ati.datasource_checkpoint (
  datasource_id text NOT NULL,
  checkpoint_kind text NOT NULL,
  checkpoint_value text NOT NULL,
  updated_at timestamptz NOT NULL,
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (datasource_id, checkpoint_kind),
  -- Canonical bounded lowercase-kebab datasource instance identity, matching
  -- the PR 27A DatasourceId contract: no padding, at most 64 characters.
  CONSTRAINT datasource_checkpoint_datasource_id_check CHECK (
    datasource_id = btrim(datasource_id)
    AND datasource_id ~ '^[a-z][a-z0-9-]*$'
    AND length(datasource_id) <= 64
  ),
  -- Stable bounded lowercase snake-case checkpoint-kind grammar.
  CONSTRAINT datasource_checkpoint_kind_check CHECK (
    checkpoint_kind = btrim(checkpoint_kind)
    AND checkpoint_kind ~ '^[a-z][a-z0-9_]{0,63}$'
  ),
  -- Bounded nonblank canonical value; never a credential or source payload.
  CONSTRAINT datasource_checkpoint_value_check CHECK (
    checkpoint_value = btrim(checkpoint_value)
    AND length(checkpoint_value) <= 512
  ),
  -- Optimistic-concurrency counters start at 1 and only increment.
  CONSTRAINT datasource_checkpoint_version_check CHECK (version >= 1)
);

CREATE OR REPLACE FUNCTION ati.get_datasource_checkpoint(
  p_datasource_id text,
  p_checkpoint_kind text)
RETURNS TABLE(
  datasource_id text, checkpoint_kind text, checkpoint_value text,
  updated_at timestamptz, version bigint)
LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY
    SELECT c.datasource_id, c.checkpoint_kind, c.checkpoint_value,
           c.updated_at, c.version
      FROM ati.datasource_checkpoint c
     WHERE c.datasource_id = p_datasource_id
       AND c.checkpoint_kind = p_checkpoint_kind;
END $$;

CREATE OR REPLACE FUNCTION ati.advance_datasource_checkpoint(
  p_datasource_id text,
  p_checkpoint_kind text,
  p_expected_value text,
  p_new_value text,
  p_updated_at timestamptz)
RETURNS TABLE(
  datasource_id text, checkpoint_kind text, checkpoint_value text,
  updated_at timestamptz, version bigint)
LANGUAGE plpgsql AS $$
DECLARE
  v_row ati.datasource_checkpoint%ROWTYPE;
BEGIN
  -- Bounded canonical input validation (fail closed even if Python model
  -- validation is bypassed).
  IF p_datasource_id IS NULL OR p_checkpoint_kind IS NULL
     OR p_new_value IS NULL OR p_updated_at IS NULL THEN
    RAISE EXCEPTION 'invalid checkpoint input' USING ERRCODE = 'U32A1';
  END IF;
  IF btrim(p_datasource_id) <> p_datasource_id
     OR p_datasource_id !~ '^[a-z][a-z0-9-]*$'
     OR length(p_datasource_id) > 64 THEN
    RAISE EXCEPTION 'invalid checkpoint input' USING ERRCODE = 'U32A1';
  END IF;
  IF btrim(p_checkpoint_kind) <> p_checkpoint_kind
     OR p_checkpoint_kind !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid checkpoint input' USING ERRCODE = 'U32A1';
  END IF;
  IF p_new_value <> btrim(p_new_value)
     OR p_new_value = ''
     OR length(p_new_value) > 512 THEN
    RAISE EXCEPTION 'invalid checkpoint input' USING ERRCODE = 'U32A1';
  END IF;
  IF p_expected_value IS NOT NULL
     AND (p_expected_value <> btrim(p_expected_value)
          OR p_expected_value = ''
          OR length(p_expected_value) > 512) THEN
    RAISE EXCEPTION 'invalid checkpoint input' USING ERRCODE = 'U32A1';
  END IF;

  -- Serialize compare-and-advance for one (datasource_id, checkpoint_kind).
  -- The lock is a deterministic transaction-scoped advisory lock; collisions
  -- only coarsen locking and never affect correctness.
  PERFORM pg_advisory_xact_lock(
    hashtextextended(p_datasource_id || ':' || p_checkpoint_kind, 0));

  SELECT * INTO v_row
    FROM ati.datasource_checkpoint
   WHERE ati.datasource_checkpoint.datasource_id = p_datasource_id
     AND ati.datasource_checkpoint.checkpoint_kind = p_checkpoint_kind;

  IF NOT FOUND THEN
    IF p_expected_value IS NOT NULL THEN
      RAISE EXCEPTION 'stale checkpoint expectation' USING ERRCODE = 'U32A2';
    END IF;
    INSERT INTO ati.datasource_checkpoint (
      datasource_id, checkpoint_kind, checkpoint_value, updated_at, version)
    VALUES (p_datasource_id, p_checkpoint_kind, p_new_value, p_updated_at, 1)
    RETURNING ati.datasource_checkpoint.datasource_id,
              ati.datasource_checkpoint.checkpoint_kind,
              ati.datasource_checkpoint.checkpoint_value,
              ati.datasource_checkpoint.updated_at,
              ati.datasource_checkpoint.version
      INTO v_row;
    datasource_id := v_row.datasource_id;
    checkpoint_kind := v_row.checkpoint_kind;
    checkpoint_value := v_row.checkpoint_value;
    updated_at := v_row.updated_at;
    version := v_row.version;
    -- ``RETURN NEXT`` emits the current OUT-parameter row and continues;
    -- the following ``RETURN`` exits so control never falls through into
    -- the compare-against-existing branch below.
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_expected_value IS NULL
     OR v_row.checkpoint_value IS DISTINCT FROM p_expected_value THEN
    RAISE EXCEPTION 'stale checkpoint expectation' USING ERRCODE = 'U32A2';
  END IF;

  IF v_row.checkpoint_value IS NOT DISTINCT FROM p_new_value THEN
    -- Idempotent no-op: the durable row already carries the candidate.
    datasource_id := v_row.datasource_id;
    checkpoint_kind := v_row.checkpoint_kind;
    checkpoint_value := v_row.checkpoint_value;
    updated_at := v_row.updated_at;
    version := v_row.version;
    RETURN NEXT;
    RETURN;
  END IF;

  UPDATE ati.datasource_checkpoint
     SET checkpoint_value = p_new_value,
         updated_at = p_updated_at,
         version = v_row.version + 1
   WHERE ati.datasource_checkpoint.datasource_id = p_datasource_id
     AND ati.datasource_checkpoint.checkpoint_kind = p_checkpoint_kind
  RETURNING ati.datasource_checkpoint.datasource_id,
            ati.datasource_checkpoint.checkpoint_kind,
            ati.datasource_checkpoint.checkpoint_value,
            ati.datasource_checkpoint.updated_at,
            ati.datasource_checkpoint.version
    INTO v_row;
  datasource_id := v_row.datasource_id;
  checkpoint_kind := v_row.checkpoint_kind;
  checkpoint_value := v_row.checkpoint_value;
  updated_at := v_row.updated_at;
  version := v_row.version;
  RETURN NEXT;
END $$;
