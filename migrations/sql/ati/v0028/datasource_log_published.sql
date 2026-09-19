-- Immutable SQL API v0028 for PR 28F-2: non-terminal PUBLISHED stage for the
-- append-only datasource execution log.
--
-- PR 28F-2 adds the producer-side publication stage of the v0.2 Global
-- Evidence pipeline to the PR 27B datasource lifecycle ("PUBLISHED = the
-- execution's one ordered EvidencePublisher.publish call succeeded and the
-- stage-local item_count is the accepted EvidenceMessage count"). SQL API
-- v0025 closed the event vocabulary at seven values, so this new versioned
-- API opens exactly one additional non-terminal stage without touching any
-- shipped SQL:
--
--   1. replaces the datasource_log_event_type_check CHECK constraint with
--      the identical constraint extended to 'published';
--   2. re-defines ati.append_datasource_log_event with the identical
--      signature, invariants, advisory-lock serialization, and U27B* SQLSTATE
--      mapping, extended only by 'published' in the event allowlist.
--
-- Every PR 27B invariant is preserved exactly: STARTED must be the first
-- persisted event and is unique; all events of one execution share one
-- datasource_id; at most one terminal event (COMPLETED/FAILED/CANCELLED); no
-- event may be appended after a terminal event; non-terminal stages
-- (ACQUIRED/DECODED/CONVERTED/PUBLISHED) may be omitted because source paths
-- differ; PUBLISHED remains non-terminal and never changes the terminal set.
-- The error-code/FAILED binding is unchanged: PUBLISHED never carries an
-- error_code.

-- Extend the closed event vocabulary with the non-terminal 'published' stage.
ALTER TABLE ati.datasource_log
  DROP CONSTRAINT datasource_log_event_type_check;

ALTER TABLE ati.datasource_log
  ADD CONSTRAINT datasource_log_event_type_check CHECK (
    event_type IN (
      'started', 'acquired', 'decoded', 'converted', 'published',
      'completed', 'failed', 'cancelled'
    )
  );

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
      'started', 'acquired', 'decoded', 'converted', 'published',
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