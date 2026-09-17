-- Immutable SQL API v0025 for PR 27B: append-only datasource execution log.
--
-- One datasource acquisition execution receives a fresh UUID execution_id
-- (application-generated, never derived from other identities). Every
-- operational event of that execution is appended to ati.datasource_log
-- carrying the same execution_id and the same datasource_id. The log is
-- append-only and carries bounded operational metadata only: no source body,
-- decoded object, Evidence body, credential, token, or raw exception text is
-- ever persisted here.
--
-- Lifecycle contract (owned by PostgreSQL, not only Python):
--   STARTED   must be the first persisted event and is unique;
--   all events of one execution share one datasource_id;
--   at most one terminal event (COMPLETED/FAILED/CANCELLED);
--   no event may be appended after a terminal event;
--   non-terminal stages (ACQUIRED/DECODED/CONVERTED) may be omitted because
--   source paths differ; no rigid stage sequence is imposed.
--
-- Concurrency: ati.append_datasource_log_event serializes lifecycle
-- validation for one execution_id with a transaction-scoped advisory lock
-- derived deterministically from the execution_id (hashtextextended). The
-- lock is only a serialization mechanism; the partial unique indexes below
-- remain the backstop for one-STARTED and at-most-one-terminal, and the
-- function's checks produce typed SQLSTATEs.
--
-- Typed SQLSTATE mapping (new U27B* codes):
--   U27B1 invalid datasource log input (malformed parameters)
--   U27B2 first event must be STARTED
--   U27B3 datasource identity mismatch for one execution
--   U27B4 duplicate STARTED for one execution
--   U27B5 append after terminal (including a second terminal event)

CREATE TABLE ati.datasource_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  execution_id uuid NOT NULL,
  datasource_id text NOT NULL,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  item_count bigint,
  byte_count bigint,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  -- Canonical bounded lowercase-kebab datasource instance identity, matching
  -- the PR 27A DatasourceId contract: no padding, at most 64 characters.
  CONSTRAINT datasource_log_datasource_id_check CHECK (
    datasource_id = btrim(datasource_id)
    AND datasource_id ~ '^[a-z][a-z0-9-]*$'
    AND length(datasource_id) <= 64
  ),
  -- Closed seven-value operational-stage vocabulary (PR 27B).
  CONSTRAINT datasource_log_event_type_check CHECK (
    event_type IN (
      'started', 'acquired', 'decoded', 'converted',
      'completed', 'failed', 'cancelled'
    )
  ),
  -- Stage-local counts are nullable and never negative.
  CONSTRAINT datasource_log_item_count_check CHECK (
    item_count IS NULL OR item_count >= 0
  ),
  CONSTRAINT datasource_log_byte_count_check CHECK (
    byte_count IS NULL OR byte_count >= 0
  ),
  -- Stable bounded error-code grammar mirroring the domain contract:
  -- lowercase snake-case, at most 64 characters, no surrounding whitespace.
  CONSTRAINT datasource_log_error_code_check CHECK (
    error_code IS NULL
    OR (error_code = btrim(error_code)
        AND error_code ~ '^[a-z][a-z0-9_]{0,63}$')
  ),
  -- error_code is bound to FAILED events: required for failed, forbidden
  -- otherwise (cancellation is never a failure and never carries a code).
  CONSTRAINT datasource_log_error_code_compat_check CHECK (
    (event_type = 'failed' AND error_code IS NOT NULL)
    OR (event_type <> 'failed' AND error_code IS NULL)
  )
);

-- At most one STARTED per execution (backstop; the function also rejects).
CREATE UNIQUE INDEX datasource_log_started_uq
  ON ati.datasource_log (execution_id) WHERE event_type = 'started';

-- At most one terminal event per execution (backstop; the function also
-- rejects any append after terminal).
CREATE UNIQUE INDEX datasource_log_terminal_uq
  ON ati.datasource_log (execution_id)
  WHERE event_type IN ('completed', 'failed', 'cancelled');

-- Deterministic per-execution correlation/order read path. No analyst-facing
-- browse index is added: datasource logs are operational, not analyst-facing.
CREATE INDEX datasource_log_execution_idx
  ON ati.datasource_log (execution_id, id);

CREATE OR REPLACE FUNCTION ati.append_datasource_log_event(
  p_execution_id uuid,
  p_datasource_id text,
  p_event_type text,
  p_occurred_at timestamptz,
  p_item_count bigint,
  p_byte_count bigint,
  p_error_code text)
RETURNS TABLE(
  id bigint, execution_id uuid, datasource_id text, event_type text,
  occurred_at timestamptz, item_count bigint, byte_count bigint,
  error_code text, created_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE
  v_existing_datasource text;
  v_id bigint;
  v_created_at timestamptz;
  v_terminal_exists boolean;
BEGIN
  -- Bounded canonical input validation (fail closed even if Python model
  -- validation is bypassed).
  IF p_execution_id IS NULL OR p_datasource_id IS NULL
     OR p_event_type IS NULL OR p_occurred_at IS NULL THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF btrim(p_datasource_id) <> p_datasource_id
     OR p_datasource_id !~ '^[a-z][a-z0-9-]*$'
     OR length(p_datasource_id) > 64 THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF p_event_type NOT IN (
      'started', 'acquired', 'decoded', 'converted',
      'completed', 'failed', 'cancelled') THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF p_item_count IS NOT NULL AND p_item_count < 0 THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF p_byte_count IS NOT NULL AND p_byte_count < 0 THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF p_error_code IS NOT NULL
     AND (btrim(p_error_code) <> p_error_code
          OR p_error_code !~ '^[a-z][a-z0-9_]{0,63}$') THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;
  IF (p_event_type = 'failed' AND p_error_code IS NULL)
     OR (p_event_type <> 'failed' AND p_error_code IS NOT NULL) THEN
    RAISE EXCEPTION 'invalid datasource log input' USING ERRCODE = 'U27B1';
  END IF;

  -- Serialize lifecycle validation for one execution. The lock is a
  -- deterministic transaction-scoped advisory lock derived from the
  -- execution_id; database constraints remain the backstop.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_execution_id::text, 0));

  SELECT l.datasource_id INTO v_existing_datasource
    FROM ati.datasource_log l
   WHERE l.execution_id = p_execution_id
   ORDER BY l.id
   LIMIT 1;
  IF NOT FOUND THEN
    IF p_event_type <> 'started' THEN
      RAISE EXCEPTION 'first datasource log event must be started'
        USING ERRCODE = 'U27B2';
    END IF;
  ELSE
    IF v_existing_datasource IS DISTINCT FROM p_datasource_id THEN
      RAISE EXCEPTION 'datasource identity mismatch for execution'
        USING ERRCODE = 'U27B3';
    END IF;
    IF p_event_type = 'started' THEN
      RAISE EXCEPTION 'duplicate started event for execution'
        USING ERRCODE = 'U27B4';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM ati.datasource_log l
        WHERE l.execution_id = p_execution_id
          AND l.event_type IN ('completed', 'failed', 'cancelled'))
      INTO v_terminal_exists;
    IF v_terminal_exists THEN
      RAISE EXCEPTION 'cannot append after a terminal event'
        USING ERRCODE = 'U27B5';
    END IF;
  END IF;

  INSERT INTO ati.datasource_log (
    execution_id, datasource_id, event_type, occurred_at,
    item_count, byte_count, error_code)
  VALUES (
    p_execution_id, p_datasource_id, p_event_type, p_occurred_at,
    p_item_count, p_byte_count, p_error_code)
  RETURNING ati.datasource_log.id, ati.datasource_log.created_at
    INTO v_id, v_created_at;

  id := v_id;
  execution_id := p_execution_id;
  datasource_id := p_datasource_id;
  event_type := p_event_type;
  occurred_at := p_occurred_at;
  item_count := p_item_count;
  byte_count := p_byte_count;
  error_code := p_error_code;
  created_at := v_created_at;
  RETURN NEXT;
END $$;