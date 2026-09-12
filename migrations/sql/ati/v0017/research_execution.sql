-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 22C: durable research execution state inside the coordinator transition.
--
-- This versioned SQL API supersedes v0015's
-- ati.update_investigation_coordinator_state: every v0015 transition kind,
-- allowlist, budget/status/lifecycle discipline, and UNCHANGED no-op
-- semantics are preserved exactly, and two bounded research transitions are
-- added:
--
--   request_research          may change ONLY research_executions
--   record_research_outcome   may change ONLY research_executions +
--                             research_result_ids
--
-- REQUEST_RESEARCH appends exactly one new REQUESTED execution (attempts=1,
-- result_id NULL) for a research-required, visible RESEARCHABLE subject, or
-- increments the attempts of exactly one existing REQUESTED execution by one
-- (never above 2) preserving the exact planned context identity.
--
-- RECORD_RESEARCH_OUTCOME transitions exactly one REQUESTED execution to
-- COMPLETED (result_id required and authoritative: the ResearchResult must
-- belong to this Investigation and match the execution subject and query) or
-- EXHAUSTED (result_id NULL, attempts == 2). A COMPLETED linkage appends the
-- result ID to research_result_ids exactly once; an EXHAUSTED outcome never
-- links a result. Optimistic concurrency, budget maxima, counter ownership,
-- and the running-status lifecycle remain enforced exactly as before, and
-- the LLM counter stays owned by PR 20B reservation alone (the completion
-- transition therefore always reloads the authoritative version after
-- Research Agent execution).

CREATE OR REPLACE FUNCTION ati.research_execution_valid(entry jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE attempts integer; max_results integer;
BEGIN
  IF entry IS NULL OR jsonb_typeof(entry) <> 'object' THEN
    RETURN false;
  END IF;
  IF jsonb_typeof(entry->'subject_entity_id') <> 'string'
     OR jsonb_typeof(entry->'context_fingerprint') <> 'string'
     OR COALESCE(entry->>'context_fingerprint', '') = ''
     OR jsonb_typeof(entry->'query') <> 'string'
     OR COALESCE(entry->>'query', '') = ''
     OR jsonb_typeof(entry->'status') <> 'string'
     OR entry->>'status' NOT IN ('requested', 'completed', 'exhausted')
     OR jsonb_typeof(entry->'attempts') <> 'number'
     OR (entry->>'attempts') !~ '^[0-9]+$' THEN
    RETURN false;
  END IF;
  attempts := (entry->>'attempts')::integer;
  IF attempts NOT BETWEEN 1 AND 2 THEN
    RETURN false;
  END IF;
  IF entry->'result_id' <> 'null'::jsonb AND jsonb_typeof(entry->'result_id') <> 'string' THEN
    RETURN false;
  END IF;
  IF entry->'result_id' IS NULL OR entry->'result_id' = 'null'::jsonb THEN
    -- No result linkage: allowed only for REQUESTED/EXHAUSTED.
    IF entry->>'status' = 'completed' THEN
      RETURN false;
    END IF;
    IF entry->>'status' = 'exhausted' AND attempts <> 2 THEN
      RETURN false;
    END IF;
  ELSIF entry->>'status' <> 'completed' THEN
    -- A result linkage is allowed only on COMPLETED.
    RETURN false;
  END IF;
  IF jsonb_typeof(entry->'entity_ids') <> 'array'
     OR jsonb_typeof(entry->'source_ids') <> 'array'
     OR jsonb_typeof(entry->'document_types') <> 'array'
     OR jsonb_typeof(entry->'max_results') <> 'number'
     OR (entry->>'max_results') !~ '^[0-9]+$' THEN
    RETURN false;
  END IF;
  max_results := (entry->>'max_results')::integer;
  IF max_results NOT BETWEEN 1 AND 100 THEN
    RETURN false;
  END IF;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION ati.update_investigation_coordinator_state(
  p_id uuid, p_transition_kind text, p_status text, p_budget jsonb,
  p_operational_state jsonb, p_consumes_replan boolean,
  p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  current_status text; current_budget jsonb; current_op jsonb;
  used bigint; maximum bigint; proposed bigint;
  allowed_operational boolean; expected_pending jsonb; selected_work jsonb;
  old_length integer; new_length integer; stop_reason text; new_pivot jsonb;
  target_id uuid; target_depth integer; appended_count integer;
  new_entry jsonb; prior_entry jsonb; changed_entries integer;
  new_result_id uuid;
  new_execution_status text; old_execution_status text;
BEGIN
  -- Pessimistic concurrency is mandatory for coordinator transitions.
  IF p_expected_version IS NULL THEN
    RAISE EXCEPTION 'optimistic version required' USING ERRCODE = 'U21A3';
  END IF;
  IF p_consumes_replan IS NULL THEN
    RAISE EXCEPTION 'replan intent is required' USING ERRCODE = 'U21A1';
  END IF;
  IF p_transition_kind NOT IN (
      'select_provider_work', 'record_provider_outcome', 'authorize_pivot',
      'mark_research_required', 'request_research', 'record_research_outcome',
      'finalize_stop') THEN
    RAISE EXCEPTION 'unknown coordinator transition kind' USING ERRCODE = 'U21A1';
  END IF;

  -- Canonical lock discipline: owning Investigation row FOR UPDATE first,
  -- exactly like ati.update_investigation_status.
  SELECT to_jsonb(i), i.version, i.status, i.budget, i.operational_state
    INTO old_state, current_version, current_status, current_budget,
         current_op
    FROM ati.investigation i WHERE i.id = p_id AND i.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;

  -- Transition-kind allowlist: no operational field outside the allowed set
  -- for this kind may change. Analysis fields, roots, discoveries, the
  -- Assessment pointer, report/research results, and trigger identity are
  -- owned by other transitions or by Assessment persistence.
  allowed_operational := (
    CASE p_transition_kind
      WHEN 'select_provider_work' THEN
        (current_op - ARRAY[
          'current_provider_work', 'pending_pivots', 'traversal',
          'investigated_entity_ids']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY[
          'current_provider_work', 'pending_pivots', 'traversal',
          'investigated_entity_ids']::text[])
      WHEN 'record_provider_outcome' THEN
        (current_op - ARRAY[
          'pending_pivots', 'pending_provider_work', 'completed_provider_work',
          'current_provider_work', 'last_provider_outcome',
          'evidence_ids', 'relationship_ids', 'discovered_entity_ids',
          'traversal', 'errors']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY[
          'pending_pivots', 'pending_provider_work', 'completed_provider_work',
          'current_provider_work', 'last_provider_outcome',
          'evidence_ids', 'relationship_ids', 'discovered_entity_ids',
          'traversal', 'errors']::text[])
      WHEN 'authorize_pivot' THEN
        (current_op - ARRAY[
          'pending_pivots', 'pending_provider_work',
          'investigated_entity_ids', 'traversal']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY[
          'pending_pivots', 'pending_provider_work',
          'investigated_entity_ids', 'traversal']::text[])
      WHEN 'mark_research_required' THEN
        (current_op - ARRAY['research_required_for_entity_ids']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY['research_required_for_entity_ids']::text[])
      WHEN 'request_research' THEN
        (current_op - ARRAY['research_executions']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY['research_executions']::text[])
      WHEN 'record_research_outcome' THEN
        (current_op - ARRAY['research_executions', 'research_result_ids']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY[
          'research_executions', 'research_result_ids']::text[])
      WHEN 'finalize_stop' THEN
        (current_op - ARRAY['stop_reason', 'errors']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY['stop_reason', 'errors']::text[])
    END
  );
  IF NOT allowed_operational THEN
    RAISE EXCEPTION 'coordinator transition changed unrelated operational fields'
      USING ERRCODE = 'U21A1';
  END IF;

  -- Budget documents are strict objects containing every required integer.
  IF jsonb_typeof(p_budget) <> 'object'
     OR EXISTS (
       SELECT 1 FROM unnest(ARRAY[
         'max_depth', 'max_entities', 'max_provider_calls', 'max_replans',
         'max_llm_calls', 'provider_calls_used', 'replans_used',
         'llm_calls_used']) AS key
       WHERE NOT (p_budget ? key)
          OR jsonb_typeof(p_budget->key) <> 'number'
          OR (p_budget->>key) !~ '^[0-9]+$') THEN
    RAISE EXCEPTION 'invalid coordinator budget document' USING ERRCODE = 'U21A1';
  END IF;

  -- Budget maxima are immutable during every coordinator transition.
  IF NOT (
        COALESCE((p_budget->>'max_llm_calls')::bigint, 0)
        = COALESCE((current_budget->>'max_llm_calls')::bigint, 0)
    AND COALESCE((p_budget->>'max_provider_calls')::bigint, 0)
        = COALESCE((current_budget->>'max_provider_calls')::bigint, 0)
    AND COALESCE((p_budget->>'max_replans')::bigint, 0)
        = COALESCE((current_budget->>'max_replans')::bigint, 0)
    AND COALESCE((p_budget->>'max_depth')::bigint, 0)
        = COALESCE((current_budget->>'max_depth')::bigint, 0)
    AND COALESCE((p_budget->>'max_entities')::bigint, 0)
        = COALESCE((current_budget->>'max_entities')::bigint, 0)
  ) THEN
    RAISE EXCEPTION 'budget maxima may not change' USING ERRCODE = 'U21A1';
  END IF;

  -- LLM calls are owned by PR 20B reservation alone.
  IF COALESCE((p_budget->>'llm_calls_used')::bigint, 0)
     <> COALESCE((current_budget->>'llm_calls_used')::bigint, 0) THEN
    RAISE EXCEPTION 'llm counter is not owned by this transition'
      USING ERRCODE = 'U21A1';
  END IF;

  -- provider_calls_used may increment by exactly one only on
  -- RECORD_PROVIDER_OUTCOME; replans_used may increment by at most one only
  -- on AUTHORIZE_PIVOT. No counter may decrease.
  IF p_transition_kind = 'record_provider_outcome' THEN
    IF COALESCE((p_budget->>'provider_calls_used')::bigint, 0)
       <> COALESCE((current_budget->>'provider_calls_used')::bigint, 0) + 1 THEN
      RAISE EXCEPTION 'provider counter must increment by exactly one'
        USING ERRCODE = 'U21A1';
    END IF;
  ELSE
    IF COALESCE((p_budget->>'provider_calls_used')::bigint, 0)
       <> COALESCE((current_budget->>'provider_calls_used')::bigint, 0) THEN
      RAISE EXCEPTION 'provider counter may not change on this transition'
        USING ERRCODE = 'U21A1';
    END IF;
  END IF;
  IF p_transition_kind = 'authorize_pivot' THEN
    proposed := COALESCE((p_budget->>'replans_used')::bigint, 0);
    IF (p_consumes_replan AND proposed
          <> COALESCE((current_budget->>'replans_used')::bigint, 0) + 1)
       OR (NOT p_consumes_replan AND proposed
          <> COALESCE((current_budget->>'replans_used')::bigint, 0)) THEN
      RAISE EXCEPTION 'replan counter does not match explicit intent'
        USING ERRCODE = 'U21A1';
    END IF;
  ELSE
    IF p_consumes_replan THEN
      RAISE EXCEPTION 'only pivot authorization may consume a replan'
        USING ERRCODE = 'U21A1';
    END IF;
    IF COALESCE((p_budget->>'replans_used')::bigint, 0)
       <> COALESCE((current_budget->>'replans_used')::bigint, 0) THEN
      RAISE EXCEPTION 'replan counter may not change on this transition'
        USING ERRCODE = 'U21A1';
    END IF;
  END IF;

  -- Collection/dispatch transitions never own Investigation lifecycle.
  IF p_transition_kind <> 'finalize_stop'
     AND (current_status <> 'running' OR p_status <> current_status) THEN
    RAISE EXCEPTION 'non-final transition requires running status'
      USING ERRCODE = 'U21A1';
  END IF;

  -- Validate the exact operational delta for each transition kind. Field
  -- allowlists above prevent cross-owner mutation; these checks preserve
  -- ordered append/history and lifecycle semantics inside allowed fields.
  IF p_transition_kind = 'select_provider_work' THEN
    IF current_op->'current_provider_work' <> 'null'::jsonb
       OR jsonb_array_length(current_op->'pending_provider_work') = 0 THEN
      RAISE EXCEPTION 'provider selection requires idle nonempty queue'
        USING ERRCODE = 'U21A1';
    END IF;
    selected_work := current_op->'pending_provider_work'->0;
    IF p_operational_state->'current_provider_work' IS DISTINCT FROM selected_work
       OR p_operational_state->'pending_provider_work'
          IS DISTINCT FROM current_op->'pending_provider_work'
       OR p_operational_state->'completed_provider_work'
          IS DISTINCT FROM current_op->'completed_provider_work'
       OR jsonb_array_length(p_operational_state->'pending_pivots')
          <> jsonb_array_length(current_op->'pending_pivots')
       OR NOT (
          jsonb_array_length(p_operational_state->'traversal')
            = jsonb_array_length(current_op->'traversal')
          OR (
            jsonb_array_length(current_op->'traversal') = 0
            AND jsonb_array_length(p_operational_state->'traversal')
                = jsonb_array_length(current_op->'root_entity_ids')
          ))
       OR (jsonb_array_length(current_op->'traversal') = 0 AND EXISTS (
          SELECT 1 FROM
            jsonb_array_elements(p_operational_state->'traversal')
              WITH ORDINALITY entry(item, n)
          WHERE item->'entity_id'
                  IS DISTINCT FROM current_op->'root_entity_ids'->(n::integer - 1)
             OR (item->>'first_discovery_ordinal')::integer <> n - 1
             OR (item->>'minimum_depth')::integer <> 0
             OR (
               item->'entity_id' IS DISTINCT FROM selected_work->'entity_id'
               AND item->'best_investigated_depth' <> 'null'::jsonb)
             OR (
               item->'entity_id' IS NOT DISTINCT FROM selected_work->'entity_id'
               AND (item->>'best_investigated_depth')::integer
                   <> (selected_work->>'depth')::integer)))
       OR (SELECT count(*) FROM
             jsonb_array_elements(current_op->'pending_pivots') WITH ORDINALITY oldp(item, n)
             JOIN jsonb_array_elements(p_operational_state->'pending_pivots') WITH ORDINALITY newp(item, n) USING (n)
           WHERE oldp.item IS DISTINCT FROM newp.item) > 1
       OR NOT (
          p_operational_state->'investigated_entity_ids'
            IS NOT DISTINCT FROM current_op->'investigated_entity_ids'
          OR (
            ati.jsonb_array_starts_with(
              p_operational_state->'investigated_entity_ids',
              current_op->'investigated_entity_ids')
            AND jsonb_array_length(p_operational_state->'investigated_entity_ids')
                = jsonb_array_length(current_op->'investigated_entity_ids') + 1
            AND p_operational_state->'investigated_entity_ids'->-1
                IS NOT DISTINCT FROM selected_work->'entity_id'
          ))
       OR EXISTS (
             SELECT 1 FROM
             jsonb_array_elements(current_op->'pending_pivots') WITH ORDINALITY oldp(item, n)
             JOIN jsonb_array_elements(p_operational_state->'pending_pivots') WITH ORDINALITY newp(item, n) USING (n)
             WHERE oldp.item IS DISTINCT FROM newp.item
               AND (oldp.item - 'status' IS DISTINCT FROM newp.item - 'status'
                    OR oldp.item->>'status' <> 'pending'
                    OR newp.item->>'status' <> 'in_progress'
                    OR oldp.item->'entity_id' IS DISTINCT FROM selected_work->'entity_id'
                    OR oldp.item->'depth' IS DISTINCT FROM selected_work->'depth'))
       OR EXISTS (
             SELECT 1 FROM
             jsonb_array_elements(current_op->'traversal') WITH ORDINALITY oldt(item, n)
             JOIN jsonb_array_elements(p_operational_state->'traversal') WITH ORDINALITY newt(item, n) USING (n)
             WHERE oldt.item IS DISTINCT FROM newt.item
               AND (oldt.item - 'best_investigated_depth'
                      IS DISTINCT FROM newt.item - 'best_investigated_depth'
                    OR oldt.item->'entity_id'
                      IS DISTINCT FROM selected_work->'entity_id'
                    OR (newt.item->>'best_investigated_depth')::bigint
                      <> LEAST(
                        COALESCE(
                          (oldt.item->>'best_investigated_depth')::bigint,
                          (selected_work->>'depth')::bigint),
                        (selected_work->>'depth')::bigint))) THEN
      RAISE EXCEPTION 'invalid provider selection delta' USING ERRCODE = 'U21A1';
    END IF;
  ELSIF p_transition_kind = 'record_provider_outcome' THEN
    selected_work := current_op->'current_provider_work';
    IF selected_work = 'null'::jsonb
       OR p_operational_state->'current_provider_work' <> 'null'::jsonb
       OR p_operational_state->'last_provider_outcome'->'work_item'
          IS DISTINCT FROM selected_work
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'completed_provider_work',
          current_op->'completed_provider_work')
       OR jsonb_array_length(p_operational_state->'completed_provider_work')
          <> jsonb_array_length(current_op->'completed_provider_work') + 1
       OR p_operational_state->'completed_provider_work'->-1
          IS DISTINCT FROM selected_work
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'evidence_ids', current_op->'evidence_ids')
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'relationship_ids', current_op->'relationship_ids')
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'discovered_entity_ids',
          current_op->'discovered_entity_ids')
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'errors', current_op->'errors')
       OR jsonb_array_length(p_operational_state->'pending_pivots')
          <> jsonb_array_length(current_op->'pending_pivots')
       OR EXISTS (
          SELECT 1 FROM
          jsonb_array_elements(current_op->'pending_pivots') WITH ORDINALITY oldp(item, n)
          JOIN jsonb_array_elements(p_operational_state->'pending_pivots') WITH ORDINALITY newp(item, n) USING (n)
          WHERE oldp.item - 'status' IS DISTINCT FROM newp.item - 'status'
             OR (oldp.item->>'status' <> newp.item->>'status'
                 AND NOT (oldp.item->>'status' = 'in_progress'
                          AND newp.item->>'status' = 'completed'
                          AND oldp.item->'entity_id'
                              IS NOT DISTINCT FROM selected_work->'entity_id'
                          AND oldp.item->'depth'
                              IS NOT DISTINCT FROM selected_work->'depth'))) THEN
      RAISE EXCEPTION 'invalid provider outcome delta' USING ERRCODE = 'U21A1';
    END IF;
    SELECT COALESCE(jsonb_agg(item ORDER BY ordinal), '[]'::jsonb)
      INTO expected_pending
      FROM jsonb_array_elements(current_op->'pending_provider_work')
           WITH ORDINALITY AS work(item, ordinal)
      WHERE item IS DISTINCT FROM selected_work;
    IF p_operational_state->'pending_provider_work'
       IS DISTINCT FROM expected_pending THEN
      RAISE EXCEPTION 'provider outcome did not remove exactly selected work'
        USING ERRCODE = 'U21A1';
    END IF;
    -- Every newly referenced durable object belongs to this Investigation and
    -- is backed by this provider outcome.
    IF EXISTS (
      SELECT 1 FROM jsonb_array_elements(p_operational_state->'evidence_ids')
        WITH ORDINALITY added(item, n)
      LEFT JOIN ati.evidence e ON e.id = (added.item #>> '{}')::uuid
      WHERE n > jsonb_array_length(current_op->'evidence_ids')
        AND (e.id IS NULL OR e.investigation_id <> p_id
             OR e.source <> selected_work->>'provider'))
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(p_operational_state->'relationship_ids')
        WITH ORDINALITY added(item, n)
      WHERE n > jsonb_array_length(current_op->'relationship_ids')
        AND NOT EXISTS (
          SELECT 1 FROM ati.relationship_observation ro
          WHERE ro.relationship_id = (added.item #>> '{}')::uuid
            AND ro.investigation_id = p_id
            AND (p_operational_state->'evidence_ids')
                  @> jsonb_build_array(to_jsonb(ro.evidence_id::text))))
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(p_operational_state->'discovered_entity_ids')
        WITH ORDINALITY added(item, n)
      LEFT JOIN ati.entity e ON e.id = (added.item #>> '{}')::uuid
      WHERE n > jsonb_array_length(current_op->'discovered_entity_ids')
        AND (e.id IS NULL OR e.deleted_at IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM ati.relationship_observation ro
          JOIN ati.relationship r ON r.id = ro.relationship_id
          WHERE ro.investigation_id = p_id
            AND (p_operational_state->'evidence_ids')
                  @> jsonb_build_array(to_jsonb(ro.evidence_id::text))
            AND (r.source_entity_id = e.id OR r.target_entity_id = e.id)))) THEN
      RAISE EXCEPTION 'provider outcome references invalid provenance'
        USING ERRCODE = 'U21A1';
    END IF;
    -- Existing traversal identity/order/investigation depth are immutable;
    -- minimum depth may lower only for an entity rediscovered in this outcome.
    IF jsonb_array_length(p_operational_state->'traversal')
         <> jsonb_array_length(current_op->'traversal')
            + jsonb_array_length(p_operational_state->'discovered_entity_ids')
            - jsonb_array_length(current_op->'discovered_entity_ids')
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(current_op->'traversal')
            WITH ORDINALITY oldt(item, n)
          JOIN jsonb_array_elements(p_operational_state->'traversal')
            WITH ORDINALITY newt(item, n) USING (n)
          WHERE oldt.item - 'minimum_depth' IS DISTINCT FROM newt.item - 'minimum_depth'
             OR (oldt.item->>'minimum_depth')::integer
                  < (newt.item->>'minimum_depth')::integer
             OR ((oldt.item->>'minimum_depth')::integer
                   <> (newt.item->>'minimum_depth')::integer
                 AND NOT ((p_operational_state->'last_provider_outcome'
                           ->'discovered_entity_ids')
                          @> jsonb_build_array(oldt.item->'entity_id'))))
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(p_operational_state->'traversal')
            WITH ORDINALITY entry(item, n)
          WHERE n > jsonb_array_length(current_op->'traversal')
            AND (item->'entity_id' IS DISTINCT FROM
                  p_operational_state->'discovered_entity_ids'->(
                    jsonb_array_length(current_op->'discovered_entity_ids')
                    + n::integer
                    - jsonb_array_length(current_op->'traversal') - 1)
              OR (item->>'minimum_depth')::integer
                    <> (selected_work->>'depth')::integer + 1
              OR item->'best_investigated_depth' <> 'null'::jsonb)) THEN
      RAISE EXCEPTION 'invalid provider outcome traversal delta'
        USING ERRCODE = 'U21A1';
    END IF;
  ELSIF p_transition_kind = 'authorize_pivot' THEN
    old_length := jsonb_array_length(current_op->'pending_pivots');
    new_length := jsonb_array_length(p_operational_state->'pending_pivots');
    IF NOT ati.jsonb_array_starts_with(
          p_operational_state->'pending_pivots', current_op->'pending_pivots')
       OR new_length <> old_length + 1
       OR p_operational_state->'pending_pivots'->-1->>'status' <> 'pending'
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'pending_provider_work',
          current_op->'pending_provider_work')
       OR jsonb_array_length(p_operational_state->'pending_provider_work')
          <= jsonb_array_length(current_op->'pending_provider_work')
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'investigated_entity_ids',
          current_op->'investigated_entity_ids')
       OR NOT (
          p_operational_state->'investigated_entity_ids'
            IS NOT DISTINCT FROM current_op->'investigated_entity_ids'
          OR (
            jsonb_array_length(p_operational_state->'investigated_entity_ids')
              = jsonb_array_length(current_op->'investigated_entity_ids') + 1
            AND p_operational_state->'investigated_entity_ids'->-1
              IS NOT DISTINCT FROM
              p_operational_state->'pending_pivots'->-1->'entity_id'
          ))
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            p_operational_state->'pending_provider_work') WITH ORDINALITY work(item, n)
          WHERE n > jsonb_array_length(current_op->'pending_provider_work')
            AND (item->'entity_id' IS DISTINCT FROM
                   p_operational_state->'pending_pivots'->-1->'entity_id'
                 OR item->'depth' IS DISTINCT FROM
                   p_operational_state->'pending_pivots'->-1->'depth'))
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            p_operational_state->'pending_provider_work') WITH ORDINALITY added(item, n)
          WHERE n > jsonb_array_length(current_op->'pending_provider_work')
            AND EXISTS (
              SELECT 1 FROM jsonb_array_elements(
                (current_op->'pending_provider_work')
                || (current_op->'completed_provider_work')) prior(item)
              WHERE prior.item->'provider' IS NOT DISTINCT FROM added.item->'provider'
                AND prior.item->'entity_id' IS NOT DISTINCT FROM added.item->'entity_id'
                AND (prior.item->>'depth')::integer
                    <= (added.item->>'depth')::integer)) THEN
      RAISE EXCEPTION 'invalid pivot authorization delta' USING ERRCODE = 'U21A1';
    END IF;
    new_pivot := p_operational_state->'pending_pivots'->-1;
    BEGIN
      IF jsonb_typeof(new_pivot->'entity_id') <> 'string'
         OR jsonb_typeof(new_pivot->'depth') <> 'number'
         OR (new_pivot->>'depth') !~ '^[0-9]+$' THEN
        RAISE EXCEPTION 'invalid pivot shape' USING ERRCODE = 'U21A1';
      END IF;
      target_id := (new_pivot->>'entity_id')::uuid;
      target_depth := (new_pivot->>'depth')::integer;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
      RAISE EXCEPTION 'invalid pivot shape' USING ERRCODE = 'U21A1';
    END;
    IF NOT ((current_op->'root_entity_ids') @> jsonb_build_array(to_jsonb(target_id::text))
            OR (current_op->'discovered_entity_ids') @> jsonb_build_array(to_jsonb(target_id::text)))
       OR NOT EXISTS (SELECT 1 FROM ati.entity e
                      WHERE e.id = target_id AND e.deleted_at IS NULL)
       OR target_depth > (current_budget->>'max_depth')::integer
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(current_op->'pending_pivots') prior(item)
          WHERE prior.item->>'status' <> 'skipped'
            AND prior.item->>'entity_id' = target_id::text
            AND (prior.item->>'depth')::integer <= target_depth) THEN
      RAISE EXCEPTION 'pivot target is not eligible' USING ERRCODE = 'U21A1';
    END IF;
    appended_count := jsonb_array_length(p_operational_state->'pending_provider_work')
                      - jsonb_array_length(current_op->'pending_provider_work');
    IF appended_count > (current_budget->>'max_provider_calls')::integer
                         - (current_budget->>'provider_calls_used')::integer
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            p_operational_state->'pending_provider_work') WITH ORDINALITY added(item, n)
          WHERE n > jsonb_array_length(current_op->'pending_provider_work')
            AND (jsonb_typeof(item->'provider') <> 'string'
              OR jsonb_typeof(item->'entity_id') <> 'string'
              OR jsonb_typeof(item->'depth') <> 'number'))
       OR (SELECT count(*) FROM (
            SELECT item FROM jsonb_array_elements(
              p_operational_state->'pending_provider_work') WITH ORDINALITY added(item, n)
            WHERE n > jsonb_array_length(current_op->'pending_provider_work')
            GROUP BY item HAVING count(*) > 1) duplicates) > 0
       OR p_operational_state->'traversal' IS DISTINCT FROM current_op->'traversal' THEN
      RAISE EXCEPTION 'invalid authorized provider work' USING ERRCODE = 'U21A1';
    END IF;
    IF p_consumes_replan
       AND jsonb_array_length(p_operational_state->'pending_provider_work')
           = jsonb_array_length(current_op->'pending_provider_work') THEN
      RAISE EXCEPTION 'replan increment requires additional provider work'
        USING ERRCODE = 'U21A1';
    END IF;
  ELSIF p_transition_kind = 'mark_research_required' THEN
    IF NOT ati.jsonb_array_starts_with(
          p_operational_state->'research_required_for_entity_ids',
          current_op->'research_required_for_entity_ids')
       OR jsonb_array_length(
          p_operational_state->'research_required_for_entity_ids')
          <= jsonb_array_length(current_op->'research_required_for_entity_ids')
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            p_operational_state->'research_required_for_entity_ids')
            WITH ORDINALITY marker(item, n)
          WHERE n > jsonb_array_length(
              current_op->'research_required_for_entity_ids')
            AND NOT ((current_op->'root_entity_ids') @> jsonb_build_array(item)
              OR (current_op->'discovered_entity_ids') @> jsonb_build_array(item)))
       OR (SELECT count(*) FROM jsonb_array_elements(
             p_operational_state->'research_required_for_entity_ids'))
          <> (SELECT count(DISTINCT item) FROM jsonb_array_elements(
             p_operational_state->'research_required_for_entity_ids') marker(item))
       OR EXISTS (
          SELECT 1 FROM jsonb_array_elements(
            p_operational_state->'research_required_for_entity_ids')
            WITH ORDINALITY marker(item, n)
          LEFT JOIN ati.entity e ON e.id = (marker.item #>> '{}')::uuid
          WHERE n > jsonb_array_length(current_op->'research_required_for_entity_ids')
            AND (e.id IS NULL OR e.deleted_at IS NOT NULL OR e.entity_type NOT IN
              ('malware', 'attack_technique', 'vulnerability'))) THEN
      RAISE EXCEPTION 'research markers must append' USING ERRCODE = 'U21A1';
    END IF;
  ELSIF p_transition_kind = 'request_research' THEN
    -- Exactly one research execution entry is appended (new context, first
    -- attempt) or exactly one existing REQUESTED entry's attempt counter
    -- increments by one (bounded retry). No other operational field changes.
    IF jsonb_array_length(p_operational_state->'research_executions')
         = jsonb_array_length(current_op->'research_executions') THEN
      -- Retry/resume: exactly one existing entry changes, attempts +1 <= 2,
      -- identity fields preserved, status stays REQUESTED, no result ID.
      changed_entries := 0;
      FOR new_entry, prior_entry IN
          SELECT newp.item, oldp.item
          FROM jsonb_array_elements(p_operational_state->'research_executions')
               WITH ORDINALITY newp(item, n)
          JOIN jsonb_array_elements(current_op->'research_executions')
               WITH ORDINALITY oldp(item, n) USING (n)
          WHERE newp.item IS DISTINCT FROM oldp.item
      LOOP
        changed_entries := changed_entries + 1;
        IF changed_entries > 1 THEN
          RAISE EXCEPTION 'research request must change exactly one execution'
            USING ERRCODE = 'U21A1';
        END IF;
        IF NOT ati.research_execution_valid(new_entry)
           OR new_entry->>'status' <> 'requested'
           OR prior_entry->>'status' <> 'requested'
           OR (new_entry - ARRAY['status', 'attempts']::text[])
              IS DISTINCT FROM (prior_entry - ARRAY['status', 'attempts']::text[])
           OR (new_entry->>'attempts')::integer
              <> (prior_entry->>'attempts')::integer + 1
           OR (prior_entry->>'attempts')::integer >= 2
           OR new_entry->'result_id' <> 'null'::jsonb
           OR prior_entry->'result_id' <> 'null'::jsonb THEN
          RAISE EXCEPTION 'invalid research request retry delta'
            USING ERRCODE = 'U21A1';
        END IF;
      END LOOP;
      IF changed_entries <> 1 THEN
        RAISE EXCEPTION 'research request must change exactly one execution'
          USING ERRCODE = 'U21A1';
      END IF;
    ELSE
      -- New context: exactly one appended entry, attempts = 1, REQUESTED.
      IF jsonb_array_length(p_operational_state->'research_executions')
           <> jsonb_array_length(current_op->'research_executions') + 1
         OR NOT ati.jsonb_array_starts_with(
            p_operational_state->'research_executions',
            current_op->'research_executions') THEN
        RAISE EXCEPTION 'research request must append exactly one execution'
          USING ERRCODE = 'U21A1';
      END IF;
      new_entry := p_operational_state->'research_executions'->-1;
      IF NOT ati.research_execution_valid(new_entry)
         OR new_entry->>'status' <> 'requested'
         OR (new_entry->>'attempts')::integer <> 1
         OR new_entry->'result_id' <> 'null'::jsonb THEN
        RAISE EXCEPTION 'invalid new research execution entry' USING ERRCODE = 'U21A1';
      END IF;
      IF EXISTS (
        SELECT 1 FROM jsonb_array_elements(
          current_op->'research_executions') prior(item)
        WHERE prior.item->>'subject_entity_id'
                = new_entry->>'subject_entity_id'
          AND prior.item->>'context_fingerprint'
                = new_entry->>'context_fingerprint') THEN
        RAISE EXCEPTION 'research context already has execution state'
          USING ERRCODE = 'U21A1';
      END IF;
      -- The subject must be an already-marked, visible RESEARCHABLE entity.
      IF NOT ((current_op->'research_required_for_entity_ids')
                @> jsonb_build_array(to_jsonb(new_entry->>'subject_entity_id')))
         OR NOT EXISTS (
           SELECT 1 FROM ati.entity e
           WHERE e.id = (new_entry->>'subject_entity_id')::uuid
             AND e.deleted_at IS NULL
             AND e.entity_type IN ('malware', 'attack_technique', 'vulnerability')) THEN
        RAISE EXCEPTION 'research subject is not a marked eligible entity'
          USING ERRCODE = 'U21A1';
      END IF;
    END IF;
  ELSIF p_transition_kind = 'record_research_outcome' THEN
    -- Exactly one REQUESTED execution resolves to COMPLETED (with an
    -- authoritative result link) or EXHAUSTED (final attempt, no result).
    IF jsonb_array_length(p_operational_state->'research_executions')
         <> jsonb_array_length(current_op->'research_executions') THEN
      RAISE EXCEPTION 'research outcome must not change execution count'
        USING ERRCODE = 'U21A1';
    END IF;
    changed_entries := 0;
    FOR new_entry, prior_entry IN
        SELECT newp.item, oldp.item
        FROM jsonb_array_elements(p_operational_state->'research_executions')
             WITH ORDINALITY newp(item, n)
        JOIN jsonb_array_elements(current_op->'research_executions')
             WITH ORDINALITY oldp(item, n) USING (n)
        WHERE newp.item IS DISTINCT FROM oldp.item
    LOOP
      changed_entries := changed_entries + 1;
      IF changed_entries > 1 THEN
        RAISE EXCEPTION 'research outcome must change exactly one execution'
          USING ERRCODE = 'U21A1';
      END IF;
      IF NOT ati.research_execution_valid(new_entry)
         OR prior_entry->>'status' <> 'requested'
         OR (new_entry - ARRAY['status', 'attempts', 'result_id']::text[])
            IS DISTINCT FROM
            (prior_entry - ARRAY['status', 'attempts', 'result_id']::text[])
         OR (new_entry->>'attempts')::integer
            <> (prior_entry->>'attempts')::integer THEN
        RAISE EXCEPTION 'invalid research outcome delta' USING ERRCODE = 'U21A1';
      END IF;
      new_execution_status := new_entry->>'status';
      old_execution_status := prior_entry->>'status';
      IF new_execution_status = 'completed' THEN
        -- COMPLETED requires an authoritative result link for this exact
        -- Investigation/entity/query context; the same ID is appended to
        -- research_result_ids exactly once.
        IF jsonb_typeof(new_entry->'result_id') <> 'string' THEN
          RAISE EXCEPTION 'completed research requires a result identity'
            USING ERRCODE = 'U21A1';
        END IF;
        BEGIN
          new_result_id := (new_entry->>'result_id')::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
          RAISE EXCEPTION 'completed research requires a result identity'
            USING ERRCODE = 'U21A1';
        END;
        IF NOT EXISTS (
          SELECT 1 FROM ati.research_result r
          WHERE r.id = new_result_id
            AND r.investigation_id = p_id
            AND r.subject_entity_id = (new_entry->>'subject_entity_id')::uuid
            AND r.query = new_entry->>'query') THEN
          RAISE EXCEPTION 'research result is not authoritative for this context'
            USING ERRCODE = 'U21A1';
        END IF;
        IF NOT ati.jsonb_array_starts_with(
              p_operational_state->'research_result_ids',
              current_op->'research_result_ids')
           OR jsonb_array_length(p_operational_state->'research_result_ids')
              <> jsonb_array_length(current_op->'research_result_ids') + 1
           OR p_operational_state->'research_result_ids'->-1
              IS DISTINCT FROM new_entry->'result_id' THEN
          RAISE EXCEPTION 'research outcome must link exactly one result'
            USING ERRCODE = 'U21A1';
        END IF;
      ELSIF new_execution_status = 'exhausted' THEN
        IF new_entry->'result_id' <> 'null'::jsonb
           OR (new_entry->>'attempts')::integer <> 2
           OR p_operational_state->'research_result_ids'
              IS DISTINCT FROM current_op->'research_result_ids' THEN
          RAISE EXCEPTION 'invalid exhausted research outcome'
            USING ERRCODE = 'U21A1';
        END IF;
      ELSE
        RAISE EXCEPTION 'research outcome must complete or exhaust'
          USING ERRCODE = 'U21A1';
      END IF;
    END LOOP;
    IF changed_entries <> 1 THEN
      RAISE EXCEPTION 'research outcome must change exactly one execution'
        USING ERRCODE = 'U21A1';
    END IF;
  ELSIF p_transition_kind = 'finalize_stop' THEN
    stop_reason := p_operational_state->>'stop_reason';
    IF current_status <> 'running'
       OR current_op->>'stop_reason' IS NOT NULL
       OR stop_reason NOT IN (
          'sufficient_evidence', 'no_eligible_pivots', 'depth_limit_reached',
          'entity_budget_exhausted', 'provider_budget_exhausted',
          'replan_limit_reached', 'fatal_error')
       OR (stop_reason = 'fatal_error' AND p_status <> 'failed')
       OR (stop_reason <> 'fatal_error' AND p_status <> 'completed')
       OR NOT ati.jsonb_array_starts_with(
          p_operational_state->'errors', current_op->'errors')
       OR (stop_reason = 'fatal_error' AND (
          jsonb_array_length(p_operational_state->'errors')
            <> jsonb_array_length(current_op->'errors') + 1
          OR p_operational_state->'errors'->-1->>'recoverable' <> 'false'))
       OR (stop_reason <> 'fatal_error' AND
          jsonb_array_length(p_operational_state->'errors')
            <> jsonb_array_length(current_op->'errors'))
       OR (stop_reason <> 'fatal_error' AND (
          jsonb_array_length(current_op->'pending_provider_work') > 0
          OR current_op->'current_provider_work' <> 'null'::jsonb
          OR EXISTS (SELECT 1 FROM jsonb_array_elements(
             current_op->'pending_pivots') pivot(item)
             WHERE pivot.item->>'status' IN ('pending', 'in_progress')))) THEN
      RAISE EXCEPTION 'invalid final stop delta' USING ERRCODE = 'U21A1';
    END IF;
  END IF;

  -- Every consumed counter remains bounded after the transition.
  IF (p_budget->>'provider_calls_used')::bigint
        > (p_budget->>'max_provider_calls')::bigint
     OR (p_budget->>'replans_used')::bigint
        > (p_budget->>'max_replans')::bigint
     OR (p_budget->>'llm_calls_used')::bigint
        > (p_budget->>'max_llm_calls')::bigint THEN
    RAISE EXCEPTION 'coordinator budget exhausted' USING ERRCODE = 'U21A1';
  END IF;

  -- Status lifecycle revalidation under the lock. An identical status is a
  -- no-op for the lifecycle; a semantic no-op state must consume no revision.
  IF p_status <> current_status THEN
    IF NOT (
         (current_status = 'pending'
          AND p_status IN ('running', 'failed'))
      OR (current_status = 'running'
          AND p_status IN ('completed', 'partial', 'failed'))
    ) THEN
      RAISE EXCEPTION 'invalid investigation status transition'
        USING ERRCODE = 'U18A5';
    END IF;
  END IF;

  -- A semantically identical state (budget + operational document + status)
  -- must not consume a revision or history.
  IF current_status = p_status
     AND current_budget IS NOT DISTINCT FROM p_budget
     AND current_op IS NOT DISTINCT FROM p_operational_state THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;

  UPDATE ati.investigation AS target SET
    status = p_status,
    budget = p_budget,
    operational_state = p_operational_state,
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

-- PR 22C: the RESEARCH_REQUESTED event type is a real production timeline
-- action; extend the bounded event-type CHECK constraint to admit it.
ALTER TABLE ati.investigation_timeline_event
  DROP CONSTRAINT investigation_timeline_event_type_check;

ALTER TABLE ati.investigation_timeline_event
  ADD CONSTRAINT investigation_timeline_event_type_check CHECK (
    event_type IN (
      'investigation_started',
      'provider_work_started',
      'provider_work_completed',
      'provider_work_failed',
      'evidence_persisted',
      'entities_discovered',
      'pivot_enqueued',
      'pivot_executed',
      'pivot_skipped',
      'research_requested',
      'assessment_requested',
      'investigation_stopped'
    )
  );
