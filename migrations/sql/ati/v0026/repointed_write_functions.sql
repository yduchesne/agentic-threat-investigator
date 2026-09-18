-- Immutable SQL API v0026 (part 2): write functions repointed onto PR 28B
-- exact EvidenceObservation provenance.
--
-- The following functions are redefined in this file; the archived versions
-- remain historical and must not be resurrected:
--
--   ati.append_relationship_observation  exact EvidenceObservation FK, no
--                                        Investigation correlation parameter
--   ati.append_assessment                analyzed/support Evidence is exact
--                                        admitted EvidenceObservation values
--   ati.update_investigation_coordinator_state  record_provider_outcome and
--                                        research provenance traverse
--                                        investigation_evidence admission
--   ati.set_investigation_analysis_result      analyzed observations admitted
--                                        to the Investigation
--   ati.append_investigation_report      support/source Evidence is exact
--                                        admitted EvidenceObservation values
--   ati.append_entity_location_observation    EvidenceObservation provenance
--   ati.create_geo_resolution            EvidenceObservation provenance
--   ati.claim_geo_resolutions            returns evidence_observation_id
--   ati.complete_geo_resolution_resolved EvidenceObservation provenance
--   ati.complete_geo_resolution_unresolvable  returns evidence_observation_id
--   ati.record_geo_resolution_failure    returns evidence_observation_id
--
-- A newer global observation never alters an Investigation, Assessment, or
-- report: every provenance validation below requires the exact observation
-- to be admitted through ati.investigation_evidence for the owning
-- Investigation.

-- Drop the v0.1 8-parameter observation append before installing the new
-- 7-parameter signature (CREATE OR REPLACE requires an identical signature).
DROP FUNCTION IF EXISTS ati.append_relationship_observation(
  uuid, uuid, uuid, uuid, timestamptz, timestamptz, text, double precision);

-- Input parameter renames (p_evidence_id -> p_evidence_observation_id)
-- require DROP before CREATE OR REPLACE.
DROP FUNCTION IF EXISTS ati.append_entity_location_observation(
  uuid, uuid, uuid, uuid, text, timestamptz, timestamptz, timestamptz, text);
DROP FUNCTION IF EXISTS ati.create_geo_resolution(uuid, uuid, uuid);

-- Return-column renames (evidence_id -> evidence_observation_id) require
-- DROP before CREATE OR REPLACE.
DROP FUNCTION IF EXISTS ati.claim_geo_resolutions(
  text, integer, integer, integer);
DROP FUNCTION IF EXISTS ati.complete_geo_resolution_resolved(
  uuid, bigint, text, uuid, uuid, text, timestamptz, timestamptz,
  timestamptz, text);
DROP FUNCTION IF EXISTS ati.complete_geo_resolution_unresolvable(
  uuid, bigint, text, text);
DROP FUNCTION IF EXISTS ati.record_geo_resolution_failure(
  uuid, bigint, text, text, boolean, double precision, double precision,
  integer);

-- Append one immutable RelationshipObservation backed by an exact
-- EvidenceObservation. The v0.1 Investigation correlation parameter is
-- removed: Investigation scope comes exclusively from
-- ati.investigation_evidence admission, never from an ownership column.
CREATE OR REPLACE FUNCTION ati.append_relationship_observation(
  p_id uuid, p_relationship_id uuid, p_evidence_observation_id uuid,
  p_observed_at timestamptz, p_retrieved_at timestamptz, p_source text,
  p_confidence double precision)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
BEGIN
  -- The immutable observation row is the historical record: append it with
  -- a database-allocated version and exact provenance, and write no
  -- domain_object_history row. No update/delete path exists.
  IF NOT EXISTS (
      SELECT 1 FROM ati.relationship r
      WHERE r.id = p_relationship_id AND r.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'relationship not found' USING ERRCODE = 'U18C3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation o
      WHERE o.id = p_evidence_observation_id) THEN
    RAISE EXCEPTION 'evidence observation not found' USING ERRCODE = 'U28B8';
  END IF;
  version := nextval('ati.relationship_observation_version_seq');
  INSERT INTO ati.relationship_observation(
    id, relationship_id, evidence_observation_id, observed_at,
    retrieved_at, source, confidence, version)
    VALUES(p_id, p_relationship_id, p_evidence_observation_id,
           p_observed_at, p_retrieved_at, p_source, p_confidence, version);
  id := p_id;
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.append_assessment(
  p_id uuid, p_investigation_id uuid, p_verdict text, p_confidence text,
  p_summary text, p_analyzed_evidence_ids uuid[], p_limitations text[],
  p_unresolved_questions text[], p_recommended_next_steps text[],
  p_findings ati.assessment_finding_item[],
  p_finding_support ati.assessment_finding_support_item[],
  p_actor_id uuid DEFAULT NULL, p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE result_id uuid; result_version bigint; result_created_at timestamptz;
  new_state jsonb; parent_id uuid;
  hard_limit CONSTANT integer := 10000;
BEGIN
  -- Required arrays must be present. Optional ordered string arrays are
  -- normalized to empty arrays when omitted.
  IF p_analyzed_evidence_ids IS NULL OR p_findings IS NULL
     OR p_finding_support IS NULL THEN
    RAISE EXCEPTION 'required assessment input arrays must not be null'
      USING ERRCODE = 'U20A8';
  END IF;

  -- Defensive hard ceiling following the batch-persistence convention
  -- (configurable application limits are enforced by the service and
  -- repository before PostgreSQL; the database enforces a larger ceiling
  -- for any direct caller). Rejection happens before staging or any
  -- mutation, so an oversized input leaves no partial aggregate, history,
  -- audit, or pointer state.
  IF cardinality(p_analyzed_evidence_ids) > hard_limit
     OR cardinality(p_findings) > hard_limit
     OR cardinality(p_finding_support) > hard_limit
     OR cardinality(COALESCE(p_limitations, '{}'::text[])) > hard_limit
     OR cardinality(COALESCE(p_unresolved_questions, '{}'::text[])) > hard_limit
     OR cardinality(COALESCE(p_recommended_next_steps, '{}'::text[])) > hard_limit THEN
    RAISE EXCEPTION 'assessment input exceeds the defensive limit of % items',
      hard_limit USING ERRCODE = 'U20AD';
  END IF;

  -- No-evidence may only support an INCONCLUSIVE Assessment (defense in
  -- depth alongside the table CHECK constraint, surfaced as a typed error).
  IF cardinality(p_analyzed_evidence_ids) = 0 AND p_verdict <> 'inconclusive' THEN
    RAISE EXCEPTION 'an assessment with no analyzed evidence must be INCONCLUSIVE'
      USING ERRCODE = 'U20A8';
  END IF;

  -- Validate the parent Investigation under its row lock so a soft deletion
  -- committed after the caller's pre-lock read is still rejected.
  SELECT i.id INTO parent_id
    FROM ati.investigation i
    WHERE i.id = p_investigation_id AND i.deleted_at IS NULL
    FOR UPDATE;
  IF parent_id IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;

  -- Transaction-local staging tables. The batch-persistence rule requires
  -- composite arrays to be expanded once into temporary tables and all
  -- validation/insertion to be set-oriented from those tables.
  CREATE TEMP TABLE IF NOT EXISTS staging_analyzed_evidence(
    ordinal bigint, evidence_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_analyzed_evidence;
  CREATE TEMP TABLE IF NOT EXISTS staging_finding(
    ordinal bigint, category text, disposition text, statement text,
    confidence text) ON COMMIT DROP;
  DELETE FROM staging_finding;
  CREATE TEMP TABLE IF NOT EXISTS staging_support(
    ordinal bigint, finding_ordinal bigint, kind text, evidence_id uuid,
    relationship_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_support;

  INSERT INTO staging_analyzed_evidence(ordinal, evidence_observation_id)
  SELECT ord, v
  FROM unnest(p_analyzed_evidence_ids) WITH ORDINALITY AS t(v, ord);

  INSERT INTO staging_finding(ordinal, category, disposition, statement, confidence)
  SELECT f.ordinal, f.category, f.disposition, f.statement, f.confidence
  FROM unnest(p_findings) AS f;

  INSERT INTO staging_support(
    ordinal, finding_ordinal, kind, evidence_id, relationship_observation_id)
  SELECT s.support_ordinal, s.finding_ordinal, s.kind, s.evidence_id,
         s.relationship_observation_id
  FROM unnest(p_finding_support) AS s;

  -- Analyzed Evidence validation covers the complete analyzed set, whether
  -- or not any Finding cites it.
  IF EXISTS (SELECT 1 FROM staging_analyzed_evidence
             WHERE evidence_observation_id IS NULL) THEN
    RAISE EXCEPTION 'analyzed evidence ids must not be null' USING ERRCODE = 'U20A8';
  END IF;
  IF (SELECT count(*) FROM staging_analyzed_evidence)
     <> (SELECT count(DISTINCT evidence_observation_id)
         FROM staging_analyzed_evidence) THEN
    RAISE EXCEPTION 'duplicate analyzed evidence ids' USING ERRCODE = 'U20A1';
  END IF;
  -- Every analyzed observation must exist and be admitted to this
  -- Investigation; a global observation that was never admitted never
  -- silently appears in an Assessment.
  IF EXISTS (
    SELECT 1
    FROM staging_analyzed_evidence sae
    LEFT JOIN ati.evidence_observation eo
      ON eo.id = sae.evidence_observation_id
    WHERE eo.id IS NULL
  ) THEN
    RAISE EXCEPTION 'analyzed evidence does not exist' USING ERRCODE = 'U20A3';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_analyzed_evidence sae
    LEFT JOIN ati.investigation_evidence ie
      ON ie.evidence_observation_id = sae.evidence_observation_id
     AND ie.investigation_id = p_investigation_id
    WHERE ie.evidence_observation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'analyzed evidence is not admitted to the investigation'
      USING ERRCODE = 'U20AC';
  END IF;

  -- Finding structure: positive unique contiguous ordinals from one.
  IF (SELECT count(*) FROM staging_finding)
     <> (SELECT count(DISTINCT ordinal) FROM staging_finding)
     OR EXISTS (SELECT 1 FROM staging_finding WHERE ordinal IS NULL OR ordinal < 1)
     OR (
       (SELECT count(*) FROM staging_finding) > 0
       AND (
         (SELECT min(ordinal) FROM staging_finding) <> 1
         OR (SELECT max(ordinal) FROM staging_finding)
            <> (SELECT count(*) FROM staging_finding)
       )
     ) THEN
    RAISE EXCEPTION 'finding ordinals must be positive, unique, and contiguous from one'
      USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_finding
    WHERE category NOT IN
      ('reputation', 'geolocation', 'registration', 'network', 'association')
       OR disposition NOT IN ('supporting', 'contradicting')
       OR confidence NOT IN ('low', 'medium', 'high')
       OR btrim(statement) = ''
  ) THEN
    RAISE EXCEPTION 'finding vocabulary and statement are invalid' USING ERRCODE = 'U20A8';
  END IF;

  -- Support structure.
  IF EXISTS (
    SELECT 1 FROM staging_support
    WHERE ordinal IS NULL OR ordinal < 1
       OR finding_ordinal IS NULL OR finding_ordinal < 1
  ) THEN
    RAISE EXCEPTION 'support ordinals must be positive' USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_support
    WHERE kind NOT IN ('evidence', 'relationship_observation')
  ) THEN
    RAISE EXCEPTION 'support kind is invalid' USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_support
    WHERE (kind = 'evidence')
          <> (evidence_id IS NOT NULL AND relationship_observation_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'support discriminator does not match its reference id'
      USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    LEFT JOIN staging_finding f ON f.ordinal = s.finding_ordinal
    WHERE f.ordinal IS NULL
  ) THEN
    RAISE EXCEPTION 'support finding_ordinal does not resolve to a finding'
      USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_support s
    JOIN staging_finding f ON f.ordinal = s.finding_ordinal
    GROUP BY f.ordinal
    HAVING count(DISTINCT s.ordinal) <> count(*)
        OR min(s.ordinal) < 1
        OR max(s.ordinal) <> count(*)
  ) THEN
    RAISE EXCEPTION 'support ordinals must be unique and contiguous from one per finding'
      USING ERRCODE = 'U20A8';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    GROUP BY s.finding_ordinal, s.kind,
             COALESCE(s.evidence_id, s.relationship_observation_id)
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate finding support' USING ERRCODE = 'U20A2';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_finding f
    LEFT JOIN staging_support s ON s.finding_ordinal = f.ordinal
    GROUP BY f.ordinal
    HAVING count(s.ordinal) = 0
  ) THEN
    RAISE EXCEPTION 'every finding requires at least one support' USING ERRCODE = 'U20A8';
  END IF;

  -- Direct Evidence supports must cite staged analyzed Evidence of this
  -- Investigation: missing or outside the analyzed set is an evidence
  -- reference error; a different Investigation is a mismatch error.
  -- Direct Evidence supports must cite exact admitted observations of
  -- the analyzed set; admission of the analyzed set was already proven.
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    LEFT JOIN staging_analyzed_evidence sae
      ON s.kind = 'evidence'
     AND sae.evidence_observation_id = s.evidence_id
    WHERE s.kind = 'evidence' AND sae.ordinal IS NULL
  ) THEN
    RAISE EXCEPTION 'evidence support is missing or outside the analyzed set'
      USING ERRCODE = 'U20A3';
  END IF;

  -- Collect the graph rows referenced by observation supports so they can be
  -- locked before final eligibility validation.
  CREATE TEMP TABLE IF NOT EXISTS staging_lock_entity(entity_id uuid) ON COMMIT DROP;
  DELETE FROM staging_lock_entity;
  CREATE TEMP TABLE IF NOT EXISTS staging_lock_relationship(relationship_id uuid)
    ON COMMIT DROP;
  DELETE FROM staging_lock_relationship;

  INSERT INTO staging_lock_relationship(relationship_id)
  SELECT DISTINCT o.relationship_id
  FROM staging_support s
  JOIN ati.relationship_observation o ON o.id = s.relationship_observation_id
  WHERE s.kind = 'relationship_observation';

  INSERT INTO staging_lock_entity(entity_id)
  SELECT DISTINCT r.source_entity_id FROM staging_lock_relationship lr
  JOIN ati.relationship r ON r.id = lr.relationship_id
  UNION
  SELECT DISTINCT r.target_entity_id FROM staging_lock_relationship lr
  JOIN ati.relationship r ON r.id = lr.relationship_id;

  -- Deterministic lock order: endpoint entities first (ascending uuid),
  -- then relationships (ascending uuid). FOR UPDATE conflicts with the
  -- soft-delete UPDATE row locks, so a concurrent soft deletion either
  -- commits before this validation (and is rejected here) or waits.
  PERFORM 1
  FROM staging_lock_entity le
  JOIN ati.entity e ON e.id = le.entity_id
  ORDER BY e.id
  FOR UPDATE OF e;

  PERFORM 1
  FROM staging_lock_relationship lr
  JOIN ati.relationship r ON r.id = lr.relationship_id
  ORDER BY r.id
  FOR UPDATE OF r;

  -- Graph eligibility, rechecked under the row locks: a Relationship or
  -- endpoint Entity that is missing or soft-deleted (whether deleted before
  -- this transaction or concurrently) is a graph ineligibility failure.
  IF EXISTS (
    SELECT 1
    FROM staging_lock_relationship lr
    LEFT JOIN ati.relationship r ON r.id = lr.relationship_id
    WHERE r.id IS NULL OR r.deleted_at IS NOT NULL
  ) OR EXISTS (
    SELECT 1
    FROM staging_lock_entity le
    LEFT JOIN ati.entity e ON e.id = le.entity_id
    WHERE e.id IS NULL OR e.deleted_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'referenced graph resource is missing or ineligible'
      USING ERRCODE = 'U20A9';
  END IF;

  -- Exact observation-chain validation, re-run under the graph row locks.
  -- Order matters: a missing observation is detected before the joins that
  -- follow it, and each failure class maps to its typed SQLSTATE.
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    LEFT JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    WHERE s.kind = 'relationship_observation' AND o.id IS NULL
  ) THEN
    RAISE EXCEPTION 'relationship observation does not exist'
      USING ERRCODE = 'U20A4';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    LEFT JOIN ati.investigation_evidence ie
      ON ie.evidence_observation_id = o.evidence_observation_id
     AND ie.investigation_id = p_investigation_id
    WHERE s.kind = 'relationship_observation'
      AND ie.evidence_observation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'relationship observation is not admitted to the investigation'
      USING ERRCODE = 'U20AC';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    LEFT JOIN staging_analyzed_evidence sae
      ON sae.evidence_observation_id = o.evidence_observation_id
    WHERE s.kind = 'relationship_observation'
      AND sae.ordinal IS NULL
  ) THEN
    RAISE EXCEPTION 'observation evidence is missing or outside the analyzed set'
      USING ERRCODE = 'U20A3';
  END IF;

  result_id := COALESCE(p_id, gen_random_uuid());
  result_version := nextval('ati.assessment_version_seq');
  -- The INSERT itself is authoritative for the caller-supplied identity: a
  -- duplicate is a conflict, never an update of the prior analytical output.
  BEGIN
    INSERT INTO ati.assessment(
      id, investigation_id, verdict, confidence, summary, analyzed_evidence_ids,
      limitations, unresolved_questions, recommended_next_steps, version)
    VALUES(result_id, p_investigation_id, p_verdict, p_confidence, p_summary,
           p_analyzed_evidence_ids, COALESCE(p_limitations, '{}'),
           COALESCE(p_unresolved_questions, '{}'),
           COALESCE(p_recommended_next_steps, '{}'), result_version)
    RETURNING ati.assessment.created_at INTO result_created_at;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'assessment already exists' USING ERRCODE = 'U20A7';
  END;

  -- Children are inserted set-wise from the staging tables; no inner join
  -- may silently drop unmatched rows.
  INSERT INTO ati.assessment_finding(
    assessment_id, ordinal, category, disposition, statement, confidence)
  SELECT result_id, f.ordinal, f.category, f.disposition, f.statement, f.confidence
  FROM staging_finding f;

  INSERT INTO ati.assessment_finding_support(
    finding_id, ordinal, kind, evidence_id, relationship_observation_id)
  SELECT f.id, s.ordinal, s.kind, s.evidence_id, s.relationship_observation_id
  FROM staging_support s
  JOIN ati.assessment_finding f
    ON f.assessment_id = result_id AND f.ordinal = s.finding_ordinal;

  IF (SELECT count(*) FROM staging_support)
     <> (
       SELECT count(*)
       FROM ati.assessment_finding_support s
       JOIN ati.assessment_finding f ON f.id = s.finding_id
       WHERE f.assessment_id = result_id
     ) THEN
    RAISE EXCEPTION 'finding support rows were not persisted completely'
      USING ERRCODE = 'U20A8';
  END IF;

  SELECT to_jsonb(a) INTO new_state FROM ati.assessment a WHERE a.id = result_id;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
  VALUES('assessment', result_id, result_version, 'CREATE', new_state, '{}'::jsonb,
         p_actor_id, p_request_id, p_investigation_id);

  id := result_id; version := result_version; created_at := result_created_at;
  RETURN NEXT;
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
      LEFT JOIN ati.evidence_observation eo ON eo.id = (added.item #>> '{}')::uuid
      LEFT JOIN ati.evidence ev ON ev.id = eo.evidence_id
      LEFT JOIN ati.investigation_evidence ie
        ON ie.evidence_observation_id = eo.id AND ie.investigation_id = p_id
      WHERE n > jsonb_array_length(current_op->'evidence_ids')
        AND (eo.id IS NULL OR ie.evidence_observation_id IS NULL
             OR ev.source <> selected_work->>'provider'))
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(p_operational_state->'relationship_ids')
        WITH ORDINALITY added(item, n)
      WHERE n > jsonb_array_length(current_op->'relationship_ids')
        AND NOT EXISTS (
          SELECT 1 FROM ati.relationship_observation ro
          JOIN ati.investigation_evidence ie
            ON ie.evidence_observation_id = ro.evidence_observation_id
           AND ie.investigation_id = p_id
          WHERE ro.relationship_id = (added.item #>> '{}')::uuid
            AND (p_operational_state->'evidence_ids')
                  @> jsonb_build_array(
                    to_jsonb(ro.evidence_observation_id::text))))
    OR EXISTS (
      SELECT 1 FROM jsonb_array_elements(p_operational_state->'discovered_entity_ids')
        WITH ORDINALITY added(item, n)
      LEFT JOIN ati.entity e ON e.id = (added.item #>> '{}')::uuid
      WHERE n > jsonb_array_length(current_op->'discovered_entity_ids')
        AND (e.id IS NULL OR e.deleted_at IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM ati.relationship_observation ro
          JOIN ati.relationship r ON r.id = ro.relationship_id
          JOIN ati.investigation_evidence ie
            ON ie.evidence_observation_id = ro.evidence_observation_id
           AND ie.investigation_id = p_id
          WHERE (p_operational_state->'evidence_ids')
                  @> jsonb_build_array(
                    to_jsonb(ro.evidence_observation_id::text))
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
    SELECT count(*) INTO cnt FROM ati.investigation_evidence ie
      WHERE ie.investigation_id = p_id
        AND ie.evidence_observation_id = ANY(input_ids);
    IF cnt <> cardinality(input_ids) THEN
      RAISE EXCEPTION 'analyzed evidence is not admitted to the investigation'
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

CREATE OR REPLACE FUNCTION ati.append_investigation_report(
  p_id uuid, p_investigation_id uuid, p_assessment_id uuid,
  p_verdict text, p_confidence text, p_title text,
  p_executive_summary ati.report_narrative_item[],
  p_narrative_support ati.report_narrative_support_item[],
  p_findings ati.report_finding_item[],
  p_finding_support ati.report_finding_support_item[],
  p_research_context ati.report_research_item[],
  p_limitations text[], p_unresolved_questions text[],
  p_recommended_next_steps text[],
  p_source_evidence_ids uuid[], p_source_relationship_observation_ids uuid[],
  p_source_research_result_ids uuid[],
  p_actor_id uuid DEFAULT NULL, p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE result_id uuid; result_version bigint; result_created_at timestamptz;
  new_state jsonb; parent_id uuid; assessment_state jsonb;
  exec_summary_json jsonb; findings_json jsonb; research_json jsonb;
  hard_limit CONSTANT integer := 10000;
BEGIN
  IF p_executive_summary IS NULL OR p_narrative_support IS NULL
     OR p_findings IS NULL OR p_finding_support IS NULL
     OR p_research_context IS NULL
     OR p_source_evidence_ids IS NULL OR p_source_relationship_observation_ids IS NULL
     OR p_source_research_result_ids IS NULL THEN
    RAISE EXCEPTION 'required report input arrays must not be null'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Defensive hard ceiling following the batch-persistence convention
  -- (configurable application limits are enforced by the service and
  -- repository before PostgreSQL; the database enforces a larger ceiling
  -- for any direct caller). Rejection happens before staging or any
  -- mutation.
  IF cardinality(p_executive_summary) > hard_limit
     OR cardinality(p_narrative_support) > hard_limit
     OR cardinality(p_findings) > hard_limit
     OR cardinality(p_finding_support) > hard_limit
     OR cardinality(p_research_context) > hard_limit
     OR cardinality(COALESCE(p_limitations, '{}'::text[])) > hard_limit
     OR cardinality(COALESCE(p_unresolved_questions, '{}'::text[])) > hard_limit
     OR cardinality(COALESCE(p_recommended_next_steps, '{}'::text[])) > hard_limit
     OR cardinality(p_source_evidence_ids) > hard_limit
     OR cardinality(p_source_relationship_observation_ids) > hard_limit
     OR cardinality(p_source_research_result_ids) > hard_limit THEN
    RAISE EXCEPTION 'report input exceeds the defensive limit of % items',
      hard_limit USING ERRCODE = 'U23A8';
  END IF;

  IF p_verdict NOT IN ('benign', 'suspicious', 'malicious', 'inconclusive')
     OR p_confidence NOT IN ('low', 'medium', 'high')
     OR btrim(p_title) = '' THEN
    RAISE EXCEPTION 'report verdict, confidence, or title is invalid'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Validate the parent Investigation under its row lock so a soft deletion
  -- committed after the caller's pre-lock read is still rejected.
  SELECT i.id INTO parent_id
    FROM ati.investigation i
    WHERE i.id = p_investigation_id AND i.deleted_at IS NULL
    FOR UPDATE;
  IF parent_id IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;

  -- Lock the target Assessment and verify it is visible and belongs to this
  -- Investigation. The Assessment lock conflicts with
  -- ati.soft_delete_assessment's Assessment lock, so a concurrent Assessment
  -- deletion serializes behind this transaction.
  SELECT to_jsonb(a) INTO assessment_state
    FROM ati.assessment a
    WHERE a.id = p_assessment_id
    FOR UPDATE;
  IF assessment_state IS NULL OR (assessment_state->>'deleted_at') IS NOT NULL THEN
    RAISE EXCEPTION 'report assessment is missing or deleted'
      USING ERRCODE = 'U23A6';
  END IF;
  IF (assessment_state->>'investigation_id')::uuid <> p_investigation_id THEN
    RAISE EXCEPTION 'report assessment belongs to another investigation'
      USING ERRCODE = 'U23A6';
  END IF;

  -- CRITICAL concurrency invariant: the report must not be persisted against
  -- an Assessment that ceased to be current between input materialization
  -- and persistence. The Investigation row is already locked FOR UPDATE, so
  -- this revalidation observes the authoritative current pointer.
  IF NOT EXISTS (
    SELECT 1 FROM ati.investigation i
    WHERE i.id = p_investigation_id
      AND (i.operational_state->>'assessment_id')::uuid
          IS NOT DISTINCT FROM p_assessment_id
  ) THEN
    RAISE EXCEPTION 'report input is stale: assessment is no longer current'
      USING ERRCODE = 'U23A1';
  END IF;

  -- Transaction-local staging tables. Composite arrays are expanded once and
  -- all validation/assembly is set-oriented from those tables.
  CREATE TEMP TABLE IF NOT EXISTS staging_report_finding(
    ordinal bigint, category text, disposition text, statement text,
    confidence text) ON COMMIT DROP;
  DELETE FROM staging_report_finding;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_finding_support(
    finding_ordinal bigint, support_ordinal bigint, kind text,
    evidence_id uuid, relationship_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_report_finding_support;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_narrative(
    ordinal bigint, statement text) ON COMMIT DROP;
  DELETE FROM staging_report_narrative;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_narrative_support(
    narrative_ordinal bigint, support_ordinal bigint, kind text,
    assessment_id uuid, finding_ordinal bigint, research_result_id uuid,
    research_claim_id uuid) ON COMMIT DROP;
  DELETE FROM staging_report_narrative_support;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_research(
    research_result_id uuid, research_claim_id uuid, subject_entity_id uuid,
    claim_text text, citation_ids uuid[], citations jsonb) ON COMMIT DROP;
  DELETE FROM staging_report_research;

  INSERT INTO staging_report_finding(ordinal, category, disposition, statement, confidence)
  SELECT f.ordinal, f.category, f.disposition, f.statement, f.confidence
  FROM unnest(p_findings) AS f;

  INSERT INTO staging_report_finding_support(
    finding_ordinal, support_ordinal, kind, evidence_id, relationship_observation_id)
  SELECT s.finding_ordinal, s.support_ordinal, s.kind, s.evidence_id,
         s.relationship_observation_id
  FROM unnest(p_finding_support) AS s;

  INSERT INTO staging_report_narrative(ordinal, statement)
  SELECT n.ordinal, n.statement
  FROM unnest(p_executive_summary) AS n;

  INSERT INTO staging_report_narrative_support(
    narrative_ordinal, support_ordinal, kind, assessment_id, finding_ordinal,
    research_result_id, research_claim_id)
  SELECT s.narrative_ordinal, s.support_ordinal, s.kind, s.assessment_id,
         s.finding_ordinal, s.research_result_id, s.research_claim_id
  FROM unnest(p_narrative_support) AS s;

  INSERT INTO staging_report_research(
    research_result_id, research_claim_id, subject_entity_id, claim_text,
    citation_ids, citations)
  SELECT r.research_result_id, r.research_claim_id, r.subject_entity_id,
         r.claim_text, r.citation_ids, r.citations
  FROM unnest(p_research_context) AS r;

  -- Finding structure: positive, unique ordinals (a report may select a
  -- subset of Assessment findings, so contiguity is not required).
  IF (SELECT count(*) FROM staging_report_finding)
     <> (SELECT count(DISTINCT ordinal) FROM staging_report_finding)
     OR EXISTS (SELECT 1 FROM staging_report_finding
                WHERE ordinal IS NULL OR ordinal < 1) THEN
    RAISE EXCEPTION 'report finding ordinals must be positive and unique'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding
    WHERE category NOT IN
      ('reputation', 'geolocation', 'registration', 'network', 'association')
       OR disposition NOT IN ('supporting', 'contradicting')
       OR confidence NOT IN ('low', 'medium', 'high')
       OR btrim(statement) = ''
  ) THEN
    RAISE EXCEPTION 'report finding vocabulary and statement are invalid'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support
    WHERE support_ordinal IS NULL OR support_ordinal < 1
       OR finding_ordinal IS NULL OR finding_ordinal < 1
  ) THEN
    RAISE EXCEPTION 'report finding support ordinals must be positive'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding f
    LEFT JOIN staging_report_finding_support s ON s.finding_ordinal = f.ordinal
    GROUP BY f.ordinal
    HAVING count(s.support_ordinal) = 0
  ) THEN
    RAISE EXCEPTION 'every report finding requires at least one support'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support
    WHERE kind NOT IN ('evidence', 'relationship_observation')
       OR (kind = 'evidence')
          <> (evidence_id IS NOT NULL AND relationship_observation_id IS NULL)
       OR (kind = 'relationship_observation')
          <> (relationship_observation_id IS NOT NULL AND evidence_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'report finding support discriminator does not match its reference id'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support s
    LEFT JOIN staging_report_finding f ON f.ordinal = s.finding_ordinal
    WHERE f.ordinal IS NULL
  ) THEN
    RAISE EXCEPTION 'report finding support references an unknown finding'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support
    GROUP BY finding_ordinal, kind,
             COALESCE(evidence_id, relationship_observation_id)
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate report finding support' USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support s
    LEFT JOIN ati.investigation_evidence ie
      ON s.kind = 'evidence'
     AND ie.evidence_observation_id = s.evidence_id
     AND ie.investigation_id = p_investigation_id
    WHERE s.kind = 'evidence'
      AND ie.evidence_observation_id IS NULL
  ) THEN
    RAISE EXCEPTION 'report finding evidence support is missing or unadmitted'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support s
    LEFT JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    LEFT JOIN ati.investigation_evidence ie
      ON s.kind = 'relationship_observation'
     AND ie.evidence_observation_id = o.evidence_observation_id
     AND ie.investigation_id = p_investigation_id
    WHERE s.kind = 'relationship_observation'
      AND (o.id IS NULL OR ie.evidence_observation_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'report finding observation support is missing or unadmitted'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Research snapshot structure: unique claim selections, persisted results
  -- of this Investigation, and exact claim membership in the persisted
  -- result's JSONB claims (defense in depth alongside the application
  -- validator).
  IF EXISTS (
    SELECT 1 FROM staging_report_research
    WHERE research_result_id IS NULL OR research_claim_id IS NULL
       OR subject_entity_id IS NULL OR btrim(claim_text) = ''
  ) THEN
    RAISE EXCEPTION 'report research snapshot fields are invalid'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_research
    GROUP BY research_result_id, research_claim_id
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate report research claim selection'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_research r
    LEFT JOIN ati.research_result rr ON rr.id = r.research_result_id
    WHERE rr.id IS NULL OR rr.investigation_id <> p_investigation_id
  ) THEN
    RAISE EXCEPTION 'report research context references an unknown or cross-investigation result'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_research r
    WHERE NOT EXISTS (
      SELECT 1 FROM ati.research_result rr,
             jsonb_array_elements(rr.claims) AS claim
      WHERE rr.id = r.research_result_id
        AND (claim->>'id')::uuid = r.research_claim_id
    )
  ) THEN
    RAISE EXCEPTION 'report research context references a claim outside the persisted result'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Narrative structure: nonblank statements, at least one unique support,
  -- Assessment refs naming the report Assessment and a persisted ordinal of
  -- it, and Research refs resolving to persisted claims of this
  -- Investigation.
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative WHERE btrim(statement) = ''
  ) THEN
    RAISE EXCEPTION 'report narrative statements must not be blank'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative_support
    WHERE support_ordinal IS NULL OR support_ordinal < 1
       OR narrative_ordinal IS NULL OR narrative_ordinal < 1
  ) THEN
    RAISE EXCEPTION 'report narrative support ordinals must be positive'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative n
    LEFT JOIN staging_report_narrative_support s ON s.narrative_ordinal = n.ordinal
    GROUP BY n.ordinal
    HAVING count(s.support_ordinal) = 0
  ) THEN
    RAISE EXCEPTION 'every report narrative statement requires at least one support'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative_support
    WHERE kind NOT IN ('assessment_finding', 'research_claim')
       OR (kind = 'assessment_finding')
          <> (assessment_id IS NOT NULL AND finding_ordinal IS NOT NULL
              AND research_result_id IS NULL AND research_claim_id IS NULL)
       OR (kind = 'research_claim')
          <> (research_result_id IS NOT NULL AND research_claim_id IS NOT NULL
              AND assessment_id IS NULL AND finding_ordinal IS NULL)
  ) THEN
    RAISE EXCEPTION 'report narrative support discriminator does not match its reference ids'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative_support
    GROUP BY narrative_ordinal, kind,
             COALESCE(assessment_id, research_result_id),
             CASE WHEN kind = 'assessment_finding'
                  THEN finding_ordinal::text
                  ELSE research_claim_id::text END
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate report narrative support reference'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative_support s
    WHERE s.kind = 'assessment_finding'
      AND (s.assessment_id IS DISTINCT FROM p_assessment_id
           OR NOT EXISTS (
             SELECT 1 FROM ati.assessment_finding f
             WHERE f.assessment_id = p_assessment_id AND f.ordinal = s.finding_ordinal
           ))
  ) THEN
    RAISE EXCEPTION 'report narrative assessment reference is invalid'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_narrative_support s
    WHERE s.kind = 'research_claim'
      AND NOT EXISTS (
        SELECT 1 FROM ati.research_result rr,
               jsonb_array_elements(rr.claims) AS claim
        WHERE rr.id = s.research_result_id
          AND rr.investigation_id = p_investigation_id
          AND (claim->>'id')::uuid = s.research_claim_id
      )
  ) THEN
    RAISE EXCEPTION 'report narrative research reference is invalid'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Assemble the authoritative JSONB snapshots from the staged rows. The
  -- object shapes below are the exact Pydantic deserialization contract;
  -- absent discriminator fields are omitted so validation stays strict.
  WITH narrative_support_json AS (
    SELECT s.narrative_ordinal,
           jsonb_agg(
             CASE WHEN s.kind = 'assessment_finding' THEN
               jsonb_build_object(
                 'kind', 'assessment_finding',
                 'assessment_id', s.assessment_id,
                 'finding_ordinal', s.finding_ordinal)
             ELSE
               jsonb_build_object(
                 'kind', 'research_claim',
                 'research_result_id', s.research_result_id,
                 'research_claim_id', s.research_claim_id)
             END ORDER BY s.support_ordinal
           ) AS support
    FROM staging_report_narrative_support s
    GROUP BY s.narrative_ordinal
  ), narrative_json AS (
    SELECT n.ordinal,
           jsonb_build_object(
             'text', n.statement,
             'support', COALESCE(njs.support, '[]'::jsonb)) AS item
    FROM staging_report_narrative n
    LEFT JOIN narrative_support_json njs ON njs.narrative_ordinal = n.ordinal
  )
  SELECT jsonb_agg(item ORDER BY ordinal) INTO exec_summary_json FROM narrative_json;
  exec_summary_json := COALESCE(exec_summary_json, '[]'::jsonb);

  WITH finding_support_json AS (
    SELECT s.finding_ordinal,
           jsonb_agg(
             CASE WHEN s.kind = 'evidence' THEN
               jsonb_build_object('kind', 'evidence', 'evidence_id', s.evidence_id)
             ELSE
               jsonb_build_object(
                 'kind', 'relationship_observation',
                 'relationship_observation_id', s.relationship_observation_id)
             END ORDER BY s.support_ordinal
           ) AS support
    FROM staging_report_finding_support s
    GROUP BY s.finding_ordinal
  ), finding_json AS (
    SELECT f.ordinal,
           jsonb_build_object(
             'assessment_finding_ordinal', f.ordinal,
             'category', f.category,
             'disposition', f.disposition,
             'statement', f.statement,
             'confidence', f.confidence,
             'support', COALESCE(fjs.support, '[]'::jsonb)) AS item
    FROM staging_report_finding f
    LEFT JOIN finding_support_json fjs ON fjs.finding_ordinal = f.ordinal
  )
  SELECT jsonb_agg(item ORDER BY ordinal) INTO findings_json FROM finding_json;
  findings_json := COALESCE(findings_json, '[]'::jsonb);

  SELECT jsonb_agg(
           jsonb_build_object(
             'research_result_id', r.research_result_id,
             'research_claim_id', r.research_claim_id,
             'subject_entity_id', r.subject_entity_id,
             'claim_text', r.claim_text,
             'citation_ids', r.citation_ids,
             'citations', r.citations)
           ORDER BY r.research_result_id, r.research_claim_id)
    INTO research_json
    FROM staging_report_research r;
  research_json := COALESCE(research_json, '[]'::jsonb);

  result_id := COALESCE(p_id, gen_random_uuid());
  result_version := nextval('ati.investigation_report_version_seq');
  BEGIN
    INSERT INTO ati.investigation_report(
      id, investigation_id, assessment_id, verdict, confidence, title,
      executive_summary, findings, research_context,
      limitations, unresolved_questions, recommended_next_steps,
      source_evidence_ids, source_relationship_observation_ids,
      source_research_result_ids, version)
    VALUES(result_id, p_investigation_id, p_assessment_id, p_verdict,
           p_confidence, p_title, exec_summary_json, findings_json,
           research_json, COALESCE(p_limitations, '{}'),
           COALESCE(p_unresolved_questions, '{}'),
           COALESCE(p_recommended_next_steps, '{}'),
           p_source_evidence_ids, p_source_relationship_observation_ids,
           p_source_research_result_ids, result_version)
    RETURNING ati.investigation_report.created_at INTO result_created_at;
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'investigation report already exists'
        USING ERRCODE = 'U23A4';
  END;

  SELECT to_jsonb(r) INTO new_state
    FROM ati.investigation_report r WHERE r.id = result_id;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
  VALUES('investigation_report', result_id, result_version, 'CREATE', new_state,
         '{}'::jsonb, p_actor_id, p_request_id, p_investigation_id);

  id := result_id; version := result_version; created_at := result_created_at;
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.append_entity_location_observation(
  p_id uuid, p_entity_id uuid, p_location_id uuid, p_evidence_observation_id uuid,
  p_precision text, p_observed_at timestamptz, p_retrieved_at timestamptz,
  p_resolved_at timestamptz, p_resolution_method text)
RETURNS TABLE(
  id uuid, version bigint,
  entity_id uuid, location_id uuid, "precision" text,
  latest_observation_id uuid, first_observed_at timestamptz,
  last_observed_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE v_effective timestamptz;
BEGIN
  IF p_precision NOT IN ('country', 'administrative_area', 'city') THEN
    RAISE EXCEPTION 'invalid observation precision' USING ERRCODE = 'U26A9';
  END IF;
  IF p_retrieved_at IS NULL OR p_resolved_at IS NULL THEN
    RAISE EXCEPTION 'retrieved_at and resolved_at are required'
      USING ERRCODE = 'U26A9';
  END IF;
  IF btrim(p_resolution_method) = '' OR length(btrim(p_resolution_method)) > 200 THEN
    RAISE EXCEPTION 'invalid resolution method' USING ERRCODE = 'U26A9';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.entity e
      WHERE e.id = p_entity_id AND e.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'geo entity not found' USING ERRCODE = 'U26A1';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ati.location l WHERE l.id = p_location_id) THEN
    RAISE EXCEPTION 'geo location not found' USING ERRCODE = 'U26A2';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      WHERE eo.id = p_evidence_observation_id) THEN
    RAISE EXCEPTION 'geo evidence observation not found'
      USING ERRCODE = 'U26A3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      JOIN ati.evidence ev ON ev.id = eo.evidence_id
      WHERE eo.id = p_evidence_observation_id
        AND ev.evidence_type = 'urn:ati:evidence:geolocation') THEN
    RAISE EXCEPTION 'geo evidence is not geolocation' USING ERRCODE = 'U26A4';
  END IF;
  -- The exact observation must be associated with the work Entity (the
  -- v0.1 privileged-subject binding is an observation-level association).
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation_entity eoe
      WHERE eoe.evidence_observation_id = p_evidence_observation_id
        AND eoe.entity_id = p_entity_id) THEN
    RAISE EXCEPTION 'geo evidence subject mismatch' USING ERRCODE = 'U26A5';
  END IF;

  v_effective := COALESCE(p_observed_at, p_retrieved_at);
  version := nextval('ati.entity_location_observation_version_seq');
  BEGIN
    INSERT INTO ati.entity_location_observation(
      id, entity_id, location_id, evidence_observation_id, "precision",
      observed_at,
      retrieved_at, resolved_at, resolution_method, version)
      VALUES(p_id, p_entity_id, p_location_id, p_evidence_observation_id, p_precision,
             p_observed_at, p_retrieved_at, p_resolved_at,
             btrim(p_resolution_method), version);
  EXCEPTION
    WHEN unique_violation THEN
      RAISE EXCEPTION 'geo observation duplicate identity'
        USING ERRCODE = 'U26A6';
  END;

  -- Reconcile current EntityLocation. The WHERE clause restricts the
  -- mutation (and therefore the version bump) to rows whose current state
  -- actually changes: either a newer observation wins the deterministic
  -- ordering or the effective time extends the earliest window. Every actual
  -- mutation receives its version from ati.entity_location_version_seq;
  -- versions are never derived arithmetically from target.version.
  INSERT INTO ati.entity_location AS target(
    entity_id, location_id, "precision", latest_observation_id,
    first_observed_at, last_observed_at, version)
    VALUES(p_entity_id, p_location_id, p_precision, p_id,
           v_effective, v_effective,
           nextval('ati.entity_location_version_seq'))
  ON CONFLICT ON CONSTRAINT entity_location_pkey DO UPDATE
    SET location_id = CASE
          WHEN (v_effective, p_id) > (target.last_observed_at,
                                      target.latest_observation_id)
          THEN p_location_id ELSE target.location_id END,
        "precision" = CASE
          WHEN (v_effective, p_id) > (target.last_observed_at,
                                      target.latest_observation_id)
          THEN p_precision ELSE target."precision" END,
        latest_observation_id = CASE
          WHEN (v_effective, p_id) > (target.last_observed_at,
                                      target.latest_observation_id)
          THEN p_id ELSE target.latest_observation_id END,
        last_observed_at = CASE
          WHEN (v_effective, p_id) > (target.last_observed_at,
                                      target.latest_observation_id)
          THEN v_effective ELSE target.last_observed_at END,
        first_observed_at = LEAST(target.first_observed_at, v_effective),
        version = nextval('ati.entity_location_version_seq'),
        updated_at = now()
    WHERE (v_effective, p_id) > (target.last_observed_at,
                                 target.latest_observation_id)
       OR v_effective < target.first_observed_at;

  SELECT el.entity_id, el.location_id, el."precision",
         el.latest_observation_id, el.first_observed_at, el.last_observed_at
    INTO entity_id, location_id, "precision", latest_observation_id,
         first_observed_at, last_observed_at
    FROM ati.entity_location el
    WHERE el.entity_id = p_entity_id;
  id := p_id;
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.create_geo_resolution(
  p_id uuid, p_entity_id uuid, p_evidence_observation_id uuid)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE existing_id uuid; existing_version bigint; existing_status text;
  existing_attempts integer; existing_claimed_by text;
  existing_lease timestamptz; existing_location uuid; existing_error text;
  result_id uuid; v_constraint text;
BEGIN
  IF NOT EXISTS (
      SELECT 1 FROM ati.entity e
      WHERE e.id = p_entity_id AND e.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'geo entity not found' USING ERRCODE = 'U26A1';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      WHERE eo.id = p_evidence_observation_id) THEN
    RAISE EXCEPTION 'geo evidence observation not found'
      USING ERRCODE = 'U26A3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      JOIN ati.evidence ev ON ev.id = eo.evidence_id
      WHERE eo.id = p_evidence_observation_id
        AND ev.evidence_type = 'urn:ati:evidence:geolocation') THEN
    RAISE EXCEPTION 'geo evidence is not geolocation' USING ERRCODE = 'U26A4';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation_entity eoe
      WHERE eoe.evidence_observation_id = p_evidence_observation_id
        AND eoe.entity_id = p_entity_id) THEN
    RAISE EXCEPTION 'geo evidence subject mismatch' USING ERRCODE = 'U26A5';
  END IF;

  SELECT r.id, r.version, r.status, r.attempt_count, r.claimed_by,
         r.lease_expires_at, r.resolved_location_id, r.last_error_code
    INTO existing_id, existing_version, existing_status, existing_attempts,
         existing_claimed_by, existing_lease, existing_location, existing_error
    FROM ati.geo_resolution r
    WHERE r.entity_id = p_entity_id
      AND r.evidence_observation_id = p_evidence_observation_id;
  IF existing_id IS NOT NULL THEN
    IF existing_status <> 'pending' OR existing_attempts <> 0
       OR existing_claimed_by IS NOT NULL OR existing_lease IS NOT NULL
       OR existing_location IS NOT NULL OR existing_error IS NOT NULL THEN
      RAISE EXCEPTION 'invalid geo resolution duplicate state'
        USING ERRCODE = 'U26A8';
    END IF;
    id := existing_id;
    version := existing_version;
    created := false;
    RETURN NEXT;
    RETURN;
  END IF;

  result_id := COALESCE(p_id, gen_random_uuid());
  version := nextval('ati.geo_resolution_version_seq');
  BEGIN
    INSERT INTO ati.geo_resolution AS gr(
      id, entity_id, evidence_observation_id, status, attempt_count, version)
      VALUES(result_id, p_entity_id, p_evidence_observation_id, 'pending', 0, version);
  EXCEPTION
    WHEN unique_violation THEN
      GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
      IF v_constraint IS DISTINCT FROM 'geo_resolution_pair_unique' THEN
        -- A caller-supplied id already bound to a different pair is an
        -- incompatible duplicate state rather than a pair reuse.
        RAISE EXCEPTION 'invalid geo resolution duplicate state'
          USING ERRCODE = 'U26A8';
      END IF;
      SELECT r.id, r.version, r.status, r.attempt_count, r.claimed_by,
             r.lease_expires_at, r.resolved_location_id, r.last_error_code
        INTO existing_id, existing_version, existing_status, existing_attempts,
             existing_claimed_by, existing_lease, existing_location, existing_error
        FROM ati.geo_resolution r
        WHERE r.entity_id = p_entity_id
          AND r.evidence_observation_id = p_evidence_observation_id;
      IF existing_id IS NULL THEN
        RAISE EXCEPTION 'geo resolution conflict returned no row';
      END IF;
      IF existing_status <> 'pending' OR existing_attempts <> 0
         OR existing_claimed_by IS NOT NULL OR existing_lease IS NOT NULL
         OR existing_location IS NOT NULL OR existing_error IS NOT NULL THEN
        RAISE EXCEPTION 'invalid geo resolution duplicate state'
          USING ERRCODE = 'U26A8';
      END IF;
      id := existing_id;
      version := existing_version;
      created := false;
      RETURN NEXT;
      RETURN;
  END;
  id := result_id;
  created := true;
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.claim_geo_resolutions(
  p_claimed_by text,
  p_claim_limit integer,
  p_lease_seconds integer,
  p_max_attempts integer)
RETURNS TABLE(
  id uuid, entity_id uuid, evidence_observation_id uuid, status text,
  attempt_count integer, next_attempt_at timestamptz, claimed_by text,
  lease_expires_at timestamptz, resolved_location_id uuid,
  last_error_code text, version bigint, created_at timestamptz,
  updated_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE
  r ati.geo_resolution%ROWTYPE;
  v_lease_expires timestamptz;
BEGIN
  IF p_claimed_by IS NULL OR btrim(p_claimed_by) = ''
     OR length(btrim(p_claimed_by)) > 200 THEN
    RAISE EXCEPTION 'invalid geo resolution claimant' USING ERRCODE = 'U26A9';
  END IF;
  IF p_claim_limit IS NULL OR p_claim_limit < 1 OR p_claim_limit > 1000 THEN
    RAISE EXCEPTION 'invalid geo resolution claim limit'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_lease_seconds IS NULL OR p_lease_seconds < 1
     OR p_lease_seconds > 86400 THEN
    RAISE EXCEPTION 'invalid geo resolution lease duration'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_max_attempts IS NULL OR p_max_attempts < 1 THEN
    RAISE EXCEPTION 'invalid geo resolution max attempts'
      USING ERRCODE = 'U26A9';
  END IF;
  v_lease_expires := now() + make_interval(secs => p_lease_seconds);

  FOR r IN
    SELECT gr.*
      FROM ati.geo_resolution gr
     WHERE (gr.status = 'pending'
            AND (gr.next_attempt_at IS NULL OR gr.next_attempt_at <= now()))
        OR (gr.status = 'processing' AND gr.lease_expires_at <= now())
     ORDER BY CASE
       WHEN gr.status = 'pending' THEN COALESCE(gr.next_attempt_at, gr.created_at)
       ELSE gr.lease_expires_at END,
       gr.created_at, gr.id
     LIMIT p_claim_limit
     FOR UPDATE SKIP LOCKED
  LOOP
    IF r.attempt_count >= p_max_attempts THEN
      IF r.status = 'processing' THEN
        -- Expired PROCESSING work already at the attempt budget: FAILED,
        -- never reclaimed, never attempt max_attempts + 1.
        UPDATE ati.geo_resolution
           SET status = 'failed',
               claimed_by = NULL,
               lease_expires_at = NULL,
               last_error_code = 'attempts_exhausted',
               updated_at = now(),
               version = nextval('ati.geo_resolution_version_seq')
         WHERE ati.geo_resolution.id = r.id;
      ELSE
        -- A PENDING row at/beyond the budget is inconsistent state (the
        -- budget can only be lowered after claims started). Fail closed
        -- instead of starting attempt max_attempts + 1.
        RAISE EXCEPTION 'invalid geo resolution retry budget'
          USING ERRCODE = 'U26C6';
      END IF;
      CONTINUE;
    END IF;

    UPDATE ati.geo_resolution
       SET status = 'processing',
           attempt_count = r.attempt_count + 1,
           claimed_by = btrim(p_claimed_by),
           lease_expires_at = v_lease_expires,
           next_attempt_at = NULL,
           last_error_code = NULL,
           updated_at = now(),
           version = nextval('ati.geo_resolution_version_seq')
     WHERE ati.geo_resolution.id = r.id;
    SELECT gr.* INTO r
      FROM ati.geo_resolution gr
     WHERE gr.id = r.id;
    id := r.id;
    entity_id := r.entity_id;
    evidence_observation_id := r.evidence_observation_id;
    status := r.status;
    attempt_count := r.attempt_count;
    next_attempt_at := r.next_attempt_at;
    claimed_by := r.claimed_by;
    lease_expires_at := r.lease_expires_at;
    resolved_location_id := r.resolved_location_id;
    last_error_code := r.last_error_code;
    version := r.version;
    created_at := r.created_at;
    updated_at := r.updated_at;
    RETURN NEXT;
  END LOOP;
  RETURN;
END $$;

-- Atomically complete one claimed row as RESOLVED: validate the exact
-- provenance, append the immutable observation (reusing the versioned
-- v0022 append semantics), reconcile EntityLocation, and terminate the
-- work. An exact replay of the same successful completion (deterministic
-- observation identity) is an idempotent no-op; a disagreeing terminal
-- replay is U26C7.

CREATE OR REPLACE FUNCTION ati.complete_geo_resolution_resolved(
  p_resolution_id uuid,
  p_expected_version bigint,
  p_claimed_by text,
  p_observation_id uuid,
  p_location_id uuid,
  p_precision text,
  p_observed_at timestamptz,
  p_retrieved_at timestamptz,
  p_resolved_at timestamptz,
  p_resolution_method text)
RETURNS TABLE(
  id uuid, entity_id uuid, evidence_observation_id uuid, status text,
  attempt_count integer, next_attempt_at timestamptz, claimed_by text,
  lease_expires_at timestamptz, resolved_location_id uuid,
  last_error_code text, version bigint, created_at timestamptz,
  updated_at timestamptz,
  observation_id uuid)
LANGUAGE plpgsql AS $$
DECLARE
  r ati.geo_resolution%ROWTYPE;
  v_unused integer;
BEGIN
  IF p_precision NOT IN ('country', 'administrative_area', 'city') THEN
    RAISE EXCEPTION 'invalid observation precision' USING ERRCODE = 'U26A9';
  END IF;
  IF p_retrieved_at IS NULL OR p_resolved_at IS NULL THEN
    RAISE EXCEPTION 'retrieved_at and resolved_at are required'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_observation_id IS NULL OR p_location_id IS NULL THEN
    RAISE EXCEPTION 'observation and location ids are required'
      USING ERRCODE = 'U26A9';
  END IF;
  IF btrim(p_resolution_method) = ''
     OR length(btrim(p_resolution_method)) > 200 THEN
    RAISE EXCEPTION 'invalid resolution method' USING ERRCODE = 'U26A9';
  END IF;

  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'geo resolution not found' USING ERRCODE = 'U26C1';
  END IF;

  IF r.status = 'resolved' THEN
    -- Replay idempotency: the exact same successful completion is a no-op.
    -- The deterministic observation identity proves it is the same work.
    IF r.resolved_location_id IS DISTINCT FROM p_location_id THEN
      RAISE EXCEPTION 'geo resolution terminal replay conflict'
        USING ERRCODE = 'U26C7';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM ati.entity_location_observation obs
        WHERE obs.id = p_observation_id
          AND obs.entity_id = r.entity_id
          AND obs.location_id = p_location_id
          AND obs.evidence_observation_id = r.evidence_observation_id) THEN
      RAISE EXCEPTION 'geo resolution terminal replay conflict'
        USING ERRCODE = 'U26C7';
    END IF;
    id := r.id;
    entity_id := r.entity_id;
    evidence_observation_id := r.evidence_observation_id;
    status := r.status;
    attempt_count := r.attempt_count;
    next_attempt_at := r.next_attempt_at;
    claimed_by := r.claimed_by;
    lease_expires_at := r.lease_expires_at;
    resolved_location_id := r.resolved_location_id;
    last_error_code := r.last_error_code;
    version := r.version;
    created_at := r.created_at;
    updated_at := r.updated_at;
    observation_id := p_observation_id;
    RETURN NEXT;
    RETURN;
  END IF;

  IF r.status <> 'processing' THEN
    RAISE EXCEPTION 'invalid geo resolution transition'
      USING ERRCODE = 'U26C2';
  END IF;
  IF r.version <> p_expected_version THEN
    RAISE EXCEPTION 'stale geo resolution version' USING ERRCODE = 'U26C3';
  END IF;
  IF r.claimed_by IS DISTINCT FROM btrim(p_claimed_by) THEN
    RAISE EXCEPTION 'geo resolution claim owner mismatch'
      USING ERRCODE = 'U26C4';
  END IF;
  IF r.lease_expires_at IS NULL OR r.lease_expires_at <= now() THEN
    RAISE EXCEPTION 'geo resolution lease expired' USING ERRCODE = 'U26C5';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM ati.entity e
      WHERE e.id = r.entity_id AND e.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'geo entity not found' USING ERRCODE = 'U26A1';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ati.location l WHERE l.id = p_location_id) THEN
    RAISE EXCEPTION 'geo location not found' USING ERRCODE = 'U26A2';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      WHERE eo.id = r.evidence_observation_id) THEN
    RAISE EXCEPTION 'geo evidence observation not found'
      USING ERRCODE = 'U26A3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation eo
      JOIN ati.evidence ev ON ev.id = eo.evidence_id
      WHERE eo.id = r.evidence_observation_id
        AND ev.evidence_type = 'urn:ati:evidence:geolocation') THEN
    RAISE EXCEPTION 'geo evidence is not geolocation' USING ERRCODE = 'U26A4';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation_entity eoe
      WHERE eoe.evidence_observation_id = r.evidence_observation_id
        AND eoe.entity_id = r.entity_id) THEN
    RAISE EXCEPTION 'geo evidence subject mismatch' USING ERRCODE = 'U26A5';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM ati.entity_location_observation obs
      WHERE obs.id = p_observation_id) THEN
    -- Reuse the versioned observation append + current-state reconciliation
    -- of SQL API v0022 so PR 26C never forks the reconciliation algorithm.
    SELECT 1 INTO v_unused
      FROM ati.append_entity_location_observation(
        p_observation_id, r.entity_id, p_location_id,
        r.evidence_observation_id,
        p_precision, p_observed_at, p_retrieved_at, p_resolved_at,
        btrim(p_resolution_method));
  ELSIF NOT EXISTS (
      SELECT 1 FROM ati.entity_location_observation obs
      WHERE obs.id = p_observation_id
        AND obs.entity_id = r.entity_id
        AND obs.location_id = p_location_id
        AND obs.evidence_observation_id = r.evidence_observation_id) THEN
    -- A deterministic observation identity already bound to a different
    -- tuple is a genuine duplicate-identity conflict, never a silent adopt.
    RAISE EXCEPTION 'geo observation duplicate identity'
      USING ERRCODE = 'U26A6';
  END IF;

  UPDATE ati.geo_resolution
     SET status = 'resolved',
         resolved_location_id = p_location_id,
         claimed_by = NULL,
         lease_expires_at = NULL,
         next_attempt_at = NULL,
         last_error_code = NULL,
         updated_at = now(),
         version = nextval('ati.geo_resolution_version_seq')
   WHERE ati.geo_resolution.id = p_resolution_id;
  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id;

  id := r.id;
  entity_id := r.entity_id;
  evidence_observation_id := r.evidence_observation_id;
  status := r.status;
  attempt_count := r.attempt_count;
  next_attempt_at := r.next_attempt_at;
  claimed_by := r.claimed_by;
  lease_expires_at := r.lease_expires_at;
  resolved_location_id := r.resolved_location_id;
  last_error_code := r.last_error_code;
  version := r.version;
  created_at := r.created_at;
  updated_at := r.updated_at;
  observation_id := p_observation_id;
  RETURN NEXT;
END $$;

-- Terminate one claimed row as UNRESOLVABLE with a stable reason code.
-- Canonical AMBIGUOUS is mapped here in v0.1 (error code
-- 'ambiguous_location'): it is terminal, never retried, and never guessed.
-- No observation and no EntityLocation mutation are created.

CREATE OR REPLACE FUNCTION ati.complete_geo_resolution_unresolvable(
  p_resolution_id uuid,
  p_expected_version bigint,
  p_claimed_by text,
  p_error_code text)
RETURNS TABLE(
  id uuid, entity_id uuid, evidence_observation_id uuid, status text,
  attempt_count integer, next_attempt_at timestamptz, claimed_by text,
  lease_expires_at timestamptz, resolved_location_id uuid,
  last_error_code text, version bigint, created_at timestamptz,
  updated_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE r ati.geo_resolution%ROWTYPE;
BEGIN
  IF p_error_code IS NULL OR btrim(p_error_code) = ''
     OR length(btrim(p_error_code)) > 64
     OR btrim(p_error_code) !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid geo resolution error code'
      USING ERRCODE = 'U26A9';
  END IF;

  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'geo resolution not found' USING ERRCODE = 'U26C1';
  END IF;

  IF r.status = 'unresolvable' THEN
    IF r.last_error_code IS DISTINCT FROM btrim(p_error_code) THEN
      RAISE EXCEPTION 'geo resolution terminal replay conflict'
        USING ERRCODE = 'U26C7';
    END IF;
    id := r.id;
    entity_id := r.entity_id;
    evidence_observation_id := r.evidence_observation_id;
    status := r.status;
    attempt_count := r.attempt_count;
    next_attempt_at := r.next_attempt_at;
    claimed_by := r.claimed_by;
    lease_expires_at := r.lease_expires_at;
    resolved_location_id := r.resolved_location_id;
    last_error_code := r.last_error_code;
    version := r.version;
    created_at := r.created_at;
    updated_at := r.updated_at;
    RETURN NEXT;
    RETURN;
  END IF;

  IF r.status IN ('resolved', 'failed') THEN
    RAISE EXCEPTION 'geo resolution terminal replay conflict'
      USING ERRCODE = 'U26C7';
  END IF;
  IF r.status <> 'processing' THEN
    RAISE EXCEPTION 'invalid geo resolution transition'
      USING ERRCODE = 'U26C2';
  END IF;
  IF r.version <> p_expected_version THEN
    RAISE EXCEPTION 'stale geo resolution version' USING ERRCODE = 'U26C3';
  END IF;
  IF r.claimed_by IS DISTINCT FROM btrim(p_claimed_by) THEN
    RAISE EXCEPTION 'geo resolution claim owner mismatch'
      USING ERRCODE = 'U26C4';
  END IF;
  IF r.lease_expires_at IS NULL OR r.lease_expires_at <= now() THEN
    RAISE EXCEPTION 'geo resolution lease expired' USING ERRCODE = 'U26C5';
  END IF;

  UPDATE ati.geo_resolution
     SET status = 'unresolvable',
         resolved_location_id = NULL,
         last_error_code = btrim(p_error_code),
         claimed_by = NULL,
         lease_expires_at = NULL,
         next_attempt_at = NULL,
         updated_at = now(),
         version = nextval('ati.geo_resolution_version_seq')
   WHERE ati.geo_resolution.id = p_resolution_id;
  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id;

  id := r.id;
  entity_id := r.entity_id;
  evidence_observation_id := r.evidence_observation_id;
  status := r.status;
  attempt_count := r.attempt_count;
  next_attempt_at := r.next_attempt_at;
  claimed_by := r.claimed_by;
  lease_expires_at := r.lease_expires_at;
  resolved_location_id := r.resolved_location_id;
  last_error_code := r.last_error_code;
  version := r.version;
  created_at := r.created_at;
  updated_at := r.updated_at;
  RETURN NEXT;
END $$;

-- Record one bounded failure on the claimed row. A retryable failure with
-- attempt budget remaining returns PROCESSING -> PENDING with a
-- deterministic bounded backoff and clears the lease; an exhausted budget or
-- a non-retryable failure terminates the row as FAILED with no next attempt.

CREATE OR REPLACE FUNCTION ati.record_geo_resolution_failure(
  p_resolution_id uuid,
  p_expected_version bigint,
  p_claimed_by text,
  p_error_code text,
  p_retryable boolean,
  p_retry_base_seconds double precision,
  p_retry_max_seconds double precision,
  p_max_attempts integer)
RETURNS TABLE(
  id uuid, entity_id uuid, evidence_observation_id uuid, status text,
  attempt_count integer, next_attempt_at timestamptz, claimed_by text,
  lease_expires_at timestamptz, resolved_location_id uuid,
  last_error_code text, version bigint, created_at timestamptz,
  updated_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE r ati.geo_resolution%ROWTYPE;
  v_next_attempt timestamptz;
BEGIN
  IF p_error_code IS NULL OR btrim(p_error_code) = ''
     OR length(btrim(p_error_code)) > 64
     OR btrim(p_error_code) !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid geo resolution error code'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_retry_base_seconds IS NULL OR p_retry_base_seconds <= 0
     OR p_retry_max_seconds IS NULL
     OR p_retry_max_seconds < p_retry_base_seconds THEN
    RAISE EXCEPTION 'invalid geo resolution retry bounds'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_max_attempts IS NULL OR p_max_attempts < 1
     OR p_max_attempts > 1000 THEN
    RAISE EXCEPTION 'invalid geo resolution max attempts'
      USING ERRCODE = 'U26A9';
  END IF;

  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'geo resolution not found' USING ERRCODE = 'U26C1';
  END IF;

  IF r.status = 'failed' THEN
    IF r.last_error_code IS DISTINCT FROM btrim(p_error_code) THEN
      RAISE EXCEPTION 'geo resolution terminal replay conflict'
        USING ERRCODE = 'U26C7';
    END IF;
    id := r.id;
    entity_id := r.entity_id;
    evidence_observation_id := r.evidence_observation_id;
    status := r.status;
    attempt_count := r.attempt_count;
    next_attempt_at := r.next_attempt_at;
    claimed_by := r.claimed_by;
    lease_expires_at := r.lease_expires_at;
    resolved_location_id := r.resolved_location_id;
    last_error_code := r.last_error_code;
    version := r.version;
    created_at := r.created_at;
    updated_at := r.updated_at;
    RETURN NEXT;
    RETURN;
  END IF;

  IF r.status IN ('resolved', 'unresolvable') THEN
    RAISE EXCEPTION 'geo resolution terminal replay conflict'
      USING ERRCODE = 'U26C7';
  END IF;
  IF r.status <> 'processing' THEN
    RAISE EXCEPTION 'invalid geo resolution transition'
      USING ERRCODE = 'U26C2';
  END IF;
  IF r.version <> p_expected_version THEN
    RAISE EXCEPTION 'stale geo resolution version' USING ERRCODE = 'U26C3';
  END IF;
  IF r.claimed_by IS DISTINCT FROM btrim(p_claimed_by) THEN
    RAISE EXCEPTION 'geo resolution claim owner mismatch'
      USING ERRCODE = 'U26C4';
  END IF;
  IF r.lease_expires_at IS NULL OR r.lease_expires_at <= now() THEN
    RAISE EXCEPTION 'geo resolution lease expired' USING ERRCODE = 'U26C5';
  END IF;

  IF p_retryable AND r.attempt_count < p_max_attempts THEN
    -- Deterministic bounded exponential backoff, no jitter:
    -- base * 2^(attempt_count - 1), capped at the configured maximum.
    v_next_attempt := now() + LEAST(
      p_retry_max_seconds,
      p_retry_base_seconds
      * power(2::double precision, r.attempt_count - 1))
      * interval '1 second';
    UPDATE ati.geo_resolution
       SET status = 'pending',
           next_attempt_at = v_next_attempt,
           last_error_code = btrim(p_error_code),
           claimed_by = NULL,
           lease_expires_at = NULL,
           updated_at = now(),
           version = nextval('ati.geo_resolution_version_seq')
     WHERE ati.geo_resolution.id = p_resolution_id;
  ELSE
    -- Terminal failure: exhausted budget or non-retryable condition. Never
    -- schedule a next attempt.
    UPDATE ati.geo_resolution
       SET status = 'failed',
           next_attempt_at = NULL,
           last_error_code = btrim(p_error_code),
           claimed_by = NULL,
           lease_expires_at = NULL,
           updated_at = now(),
           version = nextval('ati.geo_resolution_version_seq')
     WHERE ati.geo_resolution.id = p_resolution_id;
  END IF;
  SELECT gr.* INTO r
    FROM ati.geo_resolution gr
   WHERE gr.id = p_resolution_id;

  id := r.id;
  entity_id := r.entity_id;
  evidence_observation_id := r.evidence_observation_id;
  status := r.status;
  attempt_count := r.attempt_count;
  next_attempt_at := r.next_attempt_at;
  claimed_by := r.claimed_by;
  lease_expires_at := r.lease_expires_at;
  resolved_location_id := r.resolved_location_id;
  last_error_code := r.last_error_code;
  version := r.version;
  created_at := r.created_at;
  updated_at := r.updated_at;
  RETURN NEXT;
END $$;
