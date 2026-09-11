-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 20B: durable Investigation LLM-budget accounting.
--
-- ati.update_investigation_budget replaces the JSONB budget document under
-- the same deterministic lock/version/history discipline as every other
-- Investigation mutation: owning row FOR UPDATE, not-found and optimistic
-- version checks, a semantic no-op for an identical budget, and only then
-- mutation, version allocation, and immutable history. The database
-- defensively revalidates the budget counters (consumed counters are
-- nonnegative and never exceed their limits) so a computed budget can never
-- durably overrun its limits even in the face of a caller bug.

CREATE OR REPLACE FUNCTION ati.update_investigation_budget(
  p_id uuid, p_budget jsonb, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  current_budget jsonb; used bigint; maximum bigint;
BEGIN
  -- Deterministic lock discipline: owning Investigation row FOR UPDATE
  -- first, exactly like ati.update_investigation_status and
  -- ati.set_investigation_assessment.
  SELECT to_jsonb(i), i.version, i.budget
    INTO old_state, current_version, current_budget
    FROM ati.investigation i WHERE i.id = p_id AND i.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;

  -- Defensive counter validation: every consumed counter in the supplied
  -- budget must be a nonnegative integer that does not exceed its limit.
  used := COALESCE((p_budget->>'llm_calls_used')::bigint, 0);
  maximum := COALESCE((p_budget->>'max_llm_calls')::bigint, 0);
  IF used < 0 OR maximum < 0 THEN
    RAISE EXCEPTION 'invalid budget counters' USING ERRCODE = 'U20B1';
  END IF;
  IF used > maximum THEN
    RAISE EXCEPTION 'llm budget exhausted' USING ERRCODE = 'U20B2';
  END IF;
  used := COALESCE((p_budget->>'provider_calls_used')::bigint, 0);
  maximum := COALESCE((p_budget->>'max_provider_calls')::bigint, 0);
  IF used < 0 OR maximum < 0 THEN
    RAISE EXCEPTION 'invalid budget counters' USING ERRCODE = 'U20B1';
  END IF;
  IF used > maximum THEN
    RAISE EXCEPTION 'invalid budget counters' USING ERRCODE = 'U20B1';
  END IF;
  used := COALESCE((p_budget->>'replans_used')::bigint, 0);
  maximum := COALESCE((p_budget->>'max_replans')::bigint, 0);
  IF used < 0 OR maximum < 0 THEN
    RAISE EXCEPTION 'invalid budget counters' USING ERRCODE = 'U20B1';
  END IF;
  IF used > maximum THEN
    RAISE EXCEPTION 'invalid budget counters' USING ERRCODE = 'U20B1';
  END IF;

  -- A semantically identical budget must not consume a revision or history.
  IF current_budget IS NOT DISTINCT FROM p_budget THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;

  UPDATE ati.investigation AS target SET budget = p_budget,
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
