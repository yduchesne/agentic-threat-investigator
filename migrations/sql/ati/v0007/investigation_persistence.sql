-- Immutable SQL API v0007 for investigation resources and evidence observations.
--
-- Remediation of v0006 (PR 18A review 01):
-- - ati.create_investigation makes the INSERT itself authoritative for a
--   duplicate caller-supplied identity, so a concurrent losing insert raises
--   the dedicated investigation-duplicate SQLSTATE instead of a raw
--   unique_violation; the identity is never upserted;
-- - ati.update_investigation_status revalidates the confirmed lifecycle
--   against the locked row, closing the window where a concurrent writer
--   invalidates a transition that passed the caller's pre-lock check;
-- - ati.append_evidence requires an existing visible Investigation, locks the
--   parent row so it cannot be soft-deleted between validation and insertion,
--   and makes the INSERT itself authoritative for a duplicate Evidence
--   identity; Evidence is never upserted.
-- ati.soft_delete_investigation is unchanged from v0006.
-- Row-level triggers are never used for versioning or history.

CREATE OR REPLACE FUNCTION ati.create_investigation(
  p_id uuid, p_status text, p_trigger_type text, p_objective text,
  p_budget jsonb, p_operational_state jsonb, p_started_at timestamptz,
  p_completed_at timestamptz, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE new_state jsonb; result_id uuid;
BEGIN
  result_id := COALESCE(p_id, gen_random_uuid());
  version := nextval('ati.investigation_version_seq');
  BEGIN
    INSERT INTO ati.investigation(
      id, status, trigger_type, objective, budget, operational_state,
      version, started_at, completed_at)
      VALUES(result_id, p_status, p_trigger_type, p_objective,
             COALESCE(p_budget, '{}'::jsonb), COALESCE(p_operational_state, '{}'::jsonb),
             version, p_started_at, p_completed_at);
  EXCEPTION
    WHEN unique_violation THEN
      -- The primary key is the only unique identity of ati.investigation.
      -- A duplicate caller-supplied identity is a conflict, never an
      -- overwrite and never a return of the existing row.
      RAISE EXCEPTION 'investigation already exists' USING ERRCODE = 'U18A4';
  END;
  id := result_id;
  created := true;
  SELECT to_jsonb(i) INTO new_state FROM ati.investigation i WHERE i.id = result_id;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
    VALUES('investigation', result_id, version, 'CREATE', new_state, '{}'::jsonb,
           p_actor_id, p_request_id, result_id);
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.update_investigation_status(
  p_id uuid, p_status text, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint; current_status text;
BEGIN
  -- Order while holding the row lock: load, not-found, stale expected
  -- version, no-op, lifecycle validation, and only then mutation/history.
  SELECT to_jsonb(i), i.version, i.status INTO old_state, current_version, current_status
    FROM ati.investigation i WHERE i.id = p_id AND i.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;
  -- A semantic no-op must not consume a revision or create history.
  IF current_status = p_status THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;
  -- Revalidate the confirmed lifecycle against the locked row: a concurrent
  -- writer may have changed the status after the caller's pre-lock snapshot.
  IF NOT (
       (current_status = 'pending'
        AND p_status IN ('running', 'failed'))
    OR (current_status = 'running'
        AND p_status IN ('completed', 'partial', 'failed'))
  ) THEN
    RAISE EXCEPTION 'invalid investigation status transition'
      USING ERRCODE = 'U18A5';
  END IF;
  UPDATE ati.investigation AS target SET status = p_status,
    completed_at = CASE
      WHEN p_status IN ('completed', 'partial', 'failed')
        THEN COALESCE(target.completed_at, now())
      ELSE target.completed_at END,
    version = nextval('ati.investigation_version_seq'), updated_at = now()
    WHERE target.id = p_id
    RETURNING target.id, target.version, to_jsonb(target)
    INTO id, version, new_state;
  outcome := 'UPDATED';
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
    VALUES('investigation', id, version, 'UPDATE', new_state,
           ati.ati_jsonb_diff(
             old_state - ARRAY['version', 'created_at', 'updated_at']::text[],
             new_state - ARRAY['version', 'created_at', 'updated_at']::text[]),
           p_actor_id, p_request_id, id);
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.append_evidence(
  p_id uuid, p_investigation_id uuid, p_evidence_type text,
  p_subject_entity_id uuid, p_source text, p_source_record_id text,
  p_source_url text, p_observed_at timestamptz, p_retrieved_at timestamptz,
  p_facts jsonb, p_raw_payload jsonb, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
DECLARE new_state jsonb; parent_id uuid;
BEGIN
  -- Evidence requires an existing visible Investigation. The row lock keeps
  -- the parent from being soft-deleted between validation and insertion
  -- while the surrounding transaction remains short.
  SELECT ati.investigation.id INTO parent_id
    FROM ati.investigation
    WHERE ati.investigation.id = p_investigation_id AND deleted_at IS NULL
    FOR UPDATE;
  IF parent_id IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  BEGIN
    INSERT INTO ati.evidence(
      id, investigation_id, evidence_type, subject_entity_id, source,
      source_record_id, source_url, observed_at, retrieved_at, facts,
      raw_payload, version)
      VALUES(p_id, p_investigation_id, p_evidence_type, p_subject_entity_id,
             p_source, p_source_record_id, p_source_url, p_observed_at,
             p_retrieved_at, COALESCE(p_facts, '{}'::jsonb), p_raw_payload, 1);
  EXCEPTION
    WHEN unique_violation THEN
      -- Evidence is insert-only: a duplicate identity is a conflict, never an
      -- update of the prior immutable observation.
      RAISE EXCEPTION 'evidence observation already exists' USING ERRCODE = 'U18A3';
  END;
  id := p_id;
  version := 1;
  SELECT to_jsonb(e) INTO new_state FROM ati.evidence e WHERE e.id = p_id;
  -- Immutable resources receive only CREATE history.
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
    VALUES('evidence', p_id, 1, 'CREATE', new_state, '{}'::jsonb,
           p_actor_id, p_request_id, p_investigation_id);
  RETURN NEXT;
END $$;
