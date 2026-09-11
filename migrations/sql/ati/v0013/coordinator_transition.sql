-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 21: durable coordinator transition writes (bounded by kind).
--
-- ati.update_investigation_coordinator_state atomically replaces the
-- operational JSON document (pivots, queued provider work, research markers,
-- traversal metadata, analyzed-evidence/disposition state, stop reason), the
-- budget document, and the status under the canonical
-- lock/version/history discipline. The transition kind bounds which budget
-- counters may change (monotonicity and maximum preservation), the lifecycle
-- is revalidated under the row lock, and pessimistic concurrency is
-- mandatory (expected_version must be supplied). A semantically identical
-- state is an UNCHANGED no-op that consumes neither a revision nor history.

CREATE OR REPLACE FUNCTION ati.jsonb_array_starts_with(
  proposed jsonb, prefix jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_typeof(proposed) = 'array'
     AND jsonb_typeof(prefix) = 'array'
     AND jsonb_array_length(proposed) >= jsonb_array_length(prefix)
     AND NOT EXISTS (
       SELECT 1 FROM generate_series(0, jsonb_array_length(prefix) - 1) AS i
       WHERE proposed->i IS DISTINCT FROM prefix->i)
$$;

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
      'mark_research_required', 'finalize_stop') THEN
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
          'current_provider_work', 'pending_pivots', 'traversal']::text[])
        IS NOT DISTINCT FROM
        (p_operational_state - ARRAY[
          'current_provider_work', 'pending_pivots', 'traversal']::text[])
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

-- PR 21 combined analysis-result write (Phase 1). One coherent Investigation
-- transition records the current Assessment pointer, the exact analyzed
-- Evidence identities, and the typed disposition, allocating exactly one
-- version/history row. The function verifies the target Assessment is
-- visible, belongs to the Investigation, carries exactly the supplied
-- analyzed Evidence IDs in order, and that every ID belongs to the
-- Investigation.
CREATE OR REPLACE FUNCTION ati.set_investigation_analysis_result(
  p_id uuid, p_assessment_id uuid, p_analyzed_ids jsonb, p_disposition text,
  p_actor_id uuid DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  current_op jsonb; target_state jsonb; target_analyzed uuid[];
  input_ids uuid[]; new_op jsonb; cnt bigint;
BEGIN
  IF p_expected_version IS NULL THEN
    RAISE EXCEPTION 'optimistic version required' USING ERRCODE = 'U21A3';
  END IF;
  IF p_disposition NOT IN ('sufficient', 'needs_more_evidence', 'exhausted') THEN
    RAISE EXCEPTION 'invalid analysis disposition' USING ERRCODE = 'U21A2';
  END IF;
  -- p_analyzed_ids must be a JSON array of unique uuid strings.
  IF jsonb_typeof(p_analyzed_ids) <> 'array' THEN
    RAISE EXCEPTION 'invalid analyzed evidence ids' USING ERRCODE = 'U21A1';
  END IF;
  SELECT jsonb_array_length(p_analyzed_ids) INTO cnt;
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_analyzed_ids) AS a(value)
    WHERE jsonb_typeof(a.value) <> 'string') THEN
    RAISE EXCEPTION 'invalid analyzed evidence ids' USING ERRCODE = 'U21A1';
  END IF;
  BEGIN
    input_ids := ARRAY(
      SELECT (a.value #>> '{}')::uuid
        FROM jsonb_array_elements(p_analyzed_ids) AS a(value));
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'invalid analyzed evidence ids' USING ERRCODE = 'U21A1';
  END;
  IF input_ids IS NULL THEN
    input_ids := '{}';
  END IF;
  IF cardinality(input_ids) <> cnt THEN
    RAISE EXCEPTION 'invalid analyzed evidence ids' USING ERRCODE = 'U21A1';
  END IF;
  IF cardinality(input_ids) <> cardinality(ARRAY(SELECT DISTINCT unnest(input_ids))) THEN
    RAISE EXCEPTION 'analyzed evidence ids must be unique' USING ERRCODE = 'U21A1';
  END IF;

  -- Lock discipline: owning Investigation row first, exact version.
  SELECT to_jsonb(inv), inv.version, inv.operational_state
    INTO old_state, current_version, current_op
    FROM ati.investigation inv
    WHERE inv.id = p_id AND inv.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;

  -- Lock the target Assessment, require visibility and ownership.
  SELECT to_jsonb(a), a.analyzed_evidence_ids INTO target_state, target_analyzed
    FROM ati.assessment a
    WHERE a.id = p_assessment_id AND a.investigation_id = p_id
    FOR UPDATE;
  IF target_state IS NULL OR (target_state->>'deleted_at') IS NOT NULL THEN
    RAISE EXCEPTION 'assessment reference is invalid for this investigation'
      USING ERRCODE = 'U20A5';
  END IF;
  -- Exact ordered equality with the Assessment's persisted analyzed IDs.
  IF target_analyzed IS DISTINCT FROM input_ids THEN
    RAISE EXCEPTION 'analyzed evidence ids must equal the assessment'
      USING ERRCODE = 'U21A1';
  END IF;
  -- Every analyzed Evidence must belong to the Investigation.
  IF cardinality(input_ids) > 0 THEN
    SELECT count(*) INTO cnt FROM ati.evidence e
      WHERE e.investigation_id = p_id AND e.id = ANY(input_ids);
    IF cnt <> cardinality(input_ids) THEN
      RAISE EXCEPTION 'analyzed evidence does not belong to the investigation'
        USING ERRCODE = 'U21A1';
    END IF;
  END IF;

  -- One coherent UPDATE of the three analysis fields, one version/history row.
  new_op := jsonb_set(
    jsonb_set(
      jsonb_set(current_op, '{assessment_id}', to_jsonb(p_assessment_id)),
      '{analyzed_evidence_ids}', p_analyzed_ids),
    '{analysis_disposition}', to_jsonb(p_disposition));
  IF new_op IS NOT DISTINCT FROM current_op THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;
  UPDATE ati.investigation AS target SET operational_state = new_op,
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
