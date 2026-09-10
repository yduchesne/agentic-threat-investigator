-- Immutable SQL API v0011 for PR 20A versioned Assessment persistence.
--
-- Assessments are versioned analytical outputs: each analysis appends a new
-- Assessment row (never a silent overwrite) whose exact Findings and typed
-- support references are preserved forever. The write path is a stored
-- function; Python never mutates tables directly.
--
-- Relational provenance integrity:
--   assessment -> investigation
--   assessment_finding_support.evidence_id -> evidence(id)
--   assessment_finding_support.relationship_observation_id
--     -> relationship_observation(id)
-- Foreign keys supplement application validation; they do not replace
-- cross-investigation validation, which this API revalidates under the
-- parent Investigation row lock.
--
-- Lock discipline: every Assessment-pointer operation uses the deterministic
-- lock order "owning Investigation row first, then Assessment row".
-- ati.set_investigation_assessment and ati.soft_delete_assessment both lock
-- the Investigation row FOR UPDATE and then lock the target Assessment row
-- FOR UPDATE before observing pointer state or deletion visibility. A
-- concurrent pointer assignment and Assessment deletion therefore serialize
-- on the Investigation row and can never both commit to a visible
-- Investigation pointing at a deleted Assessment. ati.append_assessment does
-- not lock an existing Assessment (it inserts a new row); it acquires only
-- the parent Investigation row and the referenced graph rows.
--
-- Validation contract (all failures are typed SQLSTATEs, all validation of
-- graph eligibility happens under row locks, and no mutation occurs unless
-- every validation succeeds):
--   - required input arrays must not be NULL (U20A8);
--   - every bounded input array count is capped by the defensive hard
--     ceiling (U20AD, see below) before any staging or mutation;
--   - analyzed Evidence is validated in full, whether or not any Finding
--     cites it: no NULL ids, no duplicates (U20A1), every id resolves to
--     persisted Evidence (U20A3) of p_investigation_id (U20AC);
--   - Findings require positive, unique, contiguous ordinals from one,
--     nonblank statements, allowed vocabulary values, and at least one
--     support each (U20A8);
--   - supports require positive, unique, contiguous ordinals per Finding,
--     exactly one of the two discriminators with exactly its matching ID
--     field, a resolvable finding_ordinal, and no duplicate
--     (kind, referenced id) within one Finding (U20A8 / U20A2);
--   - Evidence supports must cite persisted Evidence of p_investigation_id
--     (missing/unanalyzed -> U20A3, wrong Investigation -> U20AC);
--   - RelationshipObservation supports resolve the exact persisted chain:
--     missing observation -> U20A4; observation bound to another
--     Investigation -> U20AC; observation Evidence missing or unanalyzed ->
--     U20A3, wrong Investigation -> U20AC; missing or deleted Relationship /
--     endpoint Entities -> U20A9;
--   - referenced Relationships and both endpoint Entities are locked in a
--     deterministic UUID order (entities before relationships) with a lock
--     mode that conflicts with the soft-delete UPDATE row locks, then
--     revalidated after locking, so a concurrent soft deletion cannot
--     invalidate the eligibility snapshot (U20A9);
--   - child rows are inserted set-wise from the staging tables; the
--     function verifies no staged support row was silently dropped (U20A8).
--
-- SQLSTATE map:
--   U20A1 duplicate analyzed evidence
--   U20A2 duplicate support within one finding
--   U20A3 evidence reference missing or outside the analyzed set
--   U20A4 relationship observation reference missing
--   U20A5 assessment reference invalid for its investigation (pointer)
--   U20A6 assessment not found or already deleted
--   U20A7 duplicate assessment identity
--   U20A8 malformed finding/support structure
--   U20A9 graph resource missing/ineligible/concurrently deleted
--   U20AB deletion of the current Assessment of a visible Investigation
--   U20AC cross-Investigation evidence/observation reference
--   U20AD input array exceeds the defensive hard ceiling
--
-- Row-level triggers are never used for versioning or history.

CREATE TYPE ati.assessment_finding_item AS (
  ordinal bigint,
  category text,
  disposition text,
  statement text,
  confidence text
);

CREATE TYPE ati.assessment_finding_support_item AS (
  finding_ordinal bigint,
  support_ordinal bigint,
  kind text,
  evidence_id uuid,
  relationship_observation_id uuid
);

CREATE TABLE ati.assessment (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid NOT NULL REFERENCES ati.investigation(id),
  verdict text NOT NULL,
  confidence text NOT NULL,
  summary text NOT NULL,
  analyzed_evidence_ids uuid[] NOT NULL,
  limitations text[] NOT NULL DEFAULT '{}',
  unresolved_questions text[] NOT NULL DEFAULT '{}',
  recommended_next_steps text[] NOT NULL DEFAULT '{}',
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  deleted_by_actor_id uuid,
  CONSTRAINT assessment_verdict_check CHECK (
    verdict IN ('benign', 'suspicious', 'malicious', 'inconclusive')),
  CONSTRAINT assessment_confidence_check CHECK (
    confidence IN ('low', 'medium', 'high')),
  -- No-evidence may only support an INCONCLUSIVE Assessment.
  CONSTRAINT assessment_no_evidence_verdict_check CHECK (
    cardinality(analyzed_evidence_ids) > 0 OR verdict = 'inconclusive')
);

CREATE INDEX assessment_investigation_listing_idx
  ON ati.assessment(investigation_id, created_at DESC, id ASC) WHERE deleted_at IS NULL;

CREATE TABLE ati.assessment_finding (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES ati.assessment(id),
  ordinal bigint NOT NULL,
  category text NOT NULL,
  disposition text NOT NULL,
  statement text NOT NULL,
  confidence text NOT NULL,
  CONSTRAINT assessment_finding_category_check CHECK (
    category IN ('reputation', 'geolocation', 'registration', 'network', 'association')),
  CONSTRAINT assessment_finding_disposition_check CHECK (
    disposition IN ('supporting', 'contradicting')),
  CONSTRAINT assessment_finding_confidence_check CHECK (
    confidence IN ('low', 'medium', 'high')),
  CONSTRAINT assessment_finding_statement_check CHECK (btrim(statement) <> ''),
  CONSTRAINT assessment_finding_assessment_ordinal_key UNIQUE (assessment_id, ordinal)
);

CREATE INDEX assessment_finding_assessment_idx
  ON ati.assessment_finding(assessment_id, ordinal);

CREATE TABLE ati.assessment_finding_support (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL REFERENCES ati.assessment_finding(id),
  ordinal bigint NOT NULL,
  kind text NOT NULL,
  evidence_id uuid,
  relationship_observation_id uuid,
  CONSTRAINT assessment_finding_support_kind_check CHECK (
    kind IN ('evidence', 'relationship_observation')),
  CONSTRAINT assessment_finding_support_exclusive_check CHECK (
    (kind = 'evidence' AND evidence_id IS NOT NULL AND relationship_observation_id IS NULL)
    OR (kind = 'relationship_observation' AND evidence_id IS NULL AND relationship_observation_id IS NOT NULL)),
  CONSTRAINT assessment_finding_support_ordinal_key UNIQUE (finding_id, ordinal),
  CONSTRAINT assessment_finding_support_evidence_fk
    FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id),
  CONSTRAINT assessment_finding_support_observation_fk
    FOREIGN KEY (relationship_observation_id) REFERENCES ati.relationship_observation(id)
);

CREATE INDEX assessment_finding_support_finding_idx
  ON ati.assessment_finding_support(finding_id, ordinal);

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
    ordinal bigint, evidence_id uuid) ON COMMIT DROP;
  DELETE FROM staging_analyzed_evidence;
  CREATE TEMP TABLE IF NOT EXISTS staging_finding(
    ordinal bigint, category text, disposition text, statement text,
    confidence text) ON COMMIT DROP;
  DELETE FROM staging_finding;
  CREATE TEMP TABLE IF NOT EXISTS staging_support(
    ordinal bigint, finding_ordinal bigint, kind text, evidence_id uuid,
    relationship_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_support;

  INSERT INTO staging_analyzed_evidence(ordinal, evidence_id)
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
  IF EXISTS (SELECT 1 FROM staging_analyzed_evidence WHERE evidence_id IS NULL) THEN
    RAISE EXCEPTION 'analyzed evidence ids must not be null' USING ERRCODE = 'U20A8';
  END IF;
  IF (SELECT count(*) FROM staging_analyzed_evidence)
     <> (SELECT count(DISTINCT evidence_id) FROM staging_analyzed_evidence) THEN
    RAISE EXCEPTION 'duplicate analyzed evidence ids' USING ERRCODE = 'U20A1';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_analyzed_evidence sae
    LEFT JOIN ati.evidence e ON e.id = sae.evidence_id
    WHERE e.id IS NULL
  ) THEN
    RAISE EXCEPTION 'analyzed evidence does not exist' USING ERRCODE = 'U20A3';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_analyzed_evidence sae
    JOIN ati.evidence e ON e.id = sae.evidence_id
    WHERE e.investigation_id <> p_investigation_id
  ) THEN
    RAISE EXCEPTION 'analyzed evidence belongs to another investigation'
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
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    LEFT JOIN ati.evidence e
      ON s.kind = 'evidence' AND e.id = s.evidence_id
    LEFT JOIN staging_analyzed_evidence sae
      ON s.kind = 'evidence' AND sae.evidence_id = s.evidence_id
    WHERE s.kind = 'evidence' AND (e.id IS NULL OR sae.ordinal IS NULL)
  ) THEN
    RAISE EXCEPTION 'evidence support is missing or outside the analyzed set'
      USING ERRCODE = 'U20A3';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    JOIN ati.evidence e ON s.kind = 'evidence' AND e.id = s.evidence_id
    WHERE s.kind = 'evidence' AND e.investigation_id <> p_investigation_id
  ) THEN
    RAISE EXCEPTION 'evidence support belongs to another investigation'
      USING ERRCODE = 'U20AC';
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
    WHERE s.kind = 'relationship_observation'
      AND o.investigation_id IS NOT NULL
      AND o.investigation_id <> p_investigation_id
  ) THEN
    RAISE EXCEPTION 'relationship observation belongs to another investigation'
      USING ERRCODE = 'U20AC';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    LEFT JOIN ati.evidence e ON e.id = o.evidence_id
    LEFT JOIN staging_analyzed_evidence sae ON sae.evidence_id = o.evidence_id
    WHERE s.kind = 'relationship_observation'
      AND (e.id IS NULL OR sae.ordinal IS NULL)
  ) THEN
    RAISE EXCEPTION 'observation evidence is missing or outside the analyzed set'
      USING ERRCODE = 'U20A3';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM staging_support s
    JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    JOIN ati.evidence e ON e.id = o.evidence_id
    WHERE s.kind = 'relationship_observation'
      AND e.investigation_id <> p_investigation_id
  ) THEN
    RAISE EXCEPTION 'observation evidence belongs to another investigation'
      USING ERRCODE = 'U20AC';
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

CREATE OR REPLACE FUNCTION ati.set_investigation_assessment(
  p_id uuid, p_assessment_id uuid, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  current_assessment uuid; target_state jsonb;
BEGIN
  -- Deterministic lock discipline for every Assessment-pointer operation:
  -- owning Investigation row FOR UPDATE first, then the target Assessment
  -- row FOR UPDATE. The Assessment lock conflicts with
  -- ati.soft_delete_assessment's Assessment lock, so a concurrent deletion
  -- serializes behind this transaction and a visible Investigation can
  -- never be pointed at a deleted Assessment.
  SELECT to_jsonb(i), i.version, (i.operational_state->>'assessment_id')::uuid
    INTO old_state, current_version, current_assessment
    FROM ati.investigation i WHERE i.id = p_id AND i.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;
  -- Lock the target Assessment and verify it belongs to this Investigation
  -- and is still visible after the lock. The authoritative row cannot be
  -- soft-deleted concurrently while this pointer mutation is serialized.
  SELECT to_jsonb(a) INTO target_state
    FROM ati.assessment a
    WHERE a.id = p_assessment_id AND a.investigation_id = p_id
    FOR UPDATE;
  IF target_state IS NULL OR (target_state->>'deleted_at') IS NOT NULL THEN
    RAISE EXCEPTION 'assessment reference is invalid for this investigation'
      USING ERRCODE = 'U20A5';
  END IF;
  -- A same-pointer request is a semantic no-op: no version, no history.
  IF current_assessment IS NOT DISTINCT FROM p_assessment_id THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;
  UPDATE ati.investigation AS target SET
    operational_state = jsonb_set(
      COALESCE(target.operational_state, '{}'::jsonb),
      '{assessment_id}', to_jsonb(p_assessment_id)),
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

CREATE OR REPLACE FUNCTION ati.soft_delete_assessment(
  p_id uuid, p_actor_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL,
  p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  owner_id uuid; owner_deleted boolean; current_assessment uuid;
BEGIN
  -- Non-authoritative discovery of the owning Investigation: used only to
  -- acquire the deterministic lock order (owning Investigation row first,
  -- then the Assessment row). No deletion decision is made from this
  -- snapshot read.
  SELECT a.investigation_id INTO owner_id
    FROM ati.assessment a WHERE a.id = p_id;
  IF owner_id IS NULL THEN
    RAISE EXCEPTION 'assessment not found or already deleted'
      USING ERRCODE = 'U20A6';
  END IF;
  -- Lock the owning Investigation row first, then the Assessment row. Both
  -- ati.soft_delete_assessment and ati.set_investigation_assessment follow
  -- this exact order, so a concurrent pointer assignment and this deletion
  -- serialize on the Investigation row and can never interleave into a
  -- visible Investigation pointing at a deleted Assessment.
  SELECT (i.deleted_at IS NOT NULL), (i.operational_state->>'assessment_id')::uuid
    INTO owner_deleted, current_assessment
    FROM ati.investigation i WHERE i.id = owner_id FOR UPDATE;
  SELECT to_jsonb(a), a.version INTO old_state, current_version
    FROM ati.assessment a WHERE a.id = p_id AND a.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'assessment not found or already deleted'
      USING ERRCODE = 'U20A6';
  END IF;
  IF (old_state->>'investigation_id')::uuid <> owner_id THEN
    RAISE EXCEPTION 'assessment does not belong to its owning investigation'
      USING ERRCODE = 'U20A6';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;
  -- Approved deletion policy (PR 20A fixes-01 Phase 0.2, kept by fixes-02):
  -- deletion is rejected while the Assessment's visible owning Investigation
  -- still points at it as its current analytical output. The pointer is read
  -- from the locked Investigation row, so a concurrent pointer assignment
  -- serialized by the Investigation lock either committed first (deletion
  -- rejected) or is still queued behind this transaction.
  IF NOT owner_deleted AND current_assessment IS NOT DISTINCT FROM p_id THEN
    RAISE EXCEPTION 'assessment is the current assessment of a visible investigation'
      USING ERRCODE = 'U20AB';
  END IF;
  UPDATE ati.assessment AS target SET deleted_at = now(),
    deleted_by_actor_id = p_actor_id, version = nextval('ati.assessment_version_seq')
    WHERE target.id = p_id
    RETURNING target.id, target.version, to_jsonb(target)
    INTO id, version, new_state;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
  VALUES('assessment', id, version, 'DELETE', new_state,
         ati.ati_jsonb_diff(old_state, new_state), p_actor_id, p_request_id,
         (new_state->>'investigation_id')::uuid);
  RETURN NEXT;
END $$;
