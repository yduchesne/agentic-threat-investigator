-- Immutable SQL API v0034 for PR 35-5 authoritative finding criticality and
-- the canonical Final Report.
--
-- This API evolves two versioned analytical resources in place:
--
--   * ``ati.assessment_finding`` gains an authoritative bounded
--     ``criticality`` value, and ``ati.append_assessment`` requires it for
--     every finding;
--   * ``ati.investigation_report`` gains an authoritative overall
--     ``criticality`` derived as the maximum finding criticality, a
--     finding-centric ``summary`` projection, and a coherent Status snapshot
--     (``started_at``/``ended_at``/``outcome_status``/``stop_reason``), and
--     ``ati.append_investigation_report`` requires the canonical ordered
--     finding set (criticality-first, contiguous reader numbers), one
--     Summary projection item per canonical finding, and the exact
--     lifecycle snapshot.
--
-- Historical compatibility is explicit and never derives criticality from
-- confidence: pre-35-5 findings are backfilled to the neutral ``medium``
-- value, pre-35-5 report Status is backfilled from the owning Investigation
-- lifecycle, and the legacy executive-summary JSONB is replaced by a
-- finding-centric summary projection built from the migrated findings. No
-- value is inferred from verdict or confidence.
--
-- Production access remains stored-function-only: the Python repository
-- binds parameters and maps rows/results; no application SQL is embedded.

-- ---------------------------------------------------------------------------
-- Assessment criticality
-- ---------------------------------------------------------------------------

ALTER TABLE ati.assessment_finding ADD COLUMN criticality text;

-- Explicit historical compatibility: no analytical basis exists to recover a
-- pre-35-5 criticality, and criticality is never inferred from confidence or
-- verdict. The neutral middle value ``medium`` is applied and documented.
UPDATE ati.assessment_finding SET criticality = 'medium' WHERE criticality IS NULL;

ALTER TABLE ati.assessment_finding ALTER COLUMN criticality SET NOT NULL;
ALTER TABLE ati.assessment_finding
  ADD CONSTRAINT assessment_finding_criticality_check
  CHECK (criticality IN ('critical', 'high', 'medium', 'low', 'informational'));

DROP TYPE ati.assessment_finding_item CASCADE;

CREATE TYPE ati.assessment_finding_item AS (
  ordinal bigint,
  category text,
  disposition text,
  statement text,
  confidence text,
  criticality text
);

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
    confidence text, criticality text) ON COMMIT DROP;
  DELETE FROM staging_finding;
  CREATE TEMP TABLE IF NOT EXISTS staging_support(
    ordinal bigint, finding_ordinal bigint, kind text, evidence_id uuid,
    relationship_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_support;

  INSERT INTO staging_analyzed_evidence(ordinal, evidence_observation_id)
  SELECT ord, v
  FROM unnest(p_analyzed_evidence_ids) WITH ORDINALITY AS t(v, ord);

  INSERT INTO staging_finding(
    ordinal, category, disposition, statement, confidence, criticality)
  SELECT f.ordinal, f.category, f.disposition, f.statement, f.confidence,
         f.criticality
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
       OR criticality NOT IN
          ('critical', 'high', 'medium', 'low', 'informational')
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

  -- Direct Evidence supports must cite exact admitted observations of the
  -- analyzed set; admission of the analyzed set was already proven.
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

  INSERT INTO ati.assessment_finding(
    assessment_id, ordinal, category, disposition, statement, confidence,
    criticality)
  SELECT result_id, f.ordinal, f.category, f.disposition, f.statement,
         f.confidence, f.criticality
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

-- ---------------------------------------------------------------------------
-- Final Report criticality, Summary, and Status snapshot
-- ---------------------------------------------------------------------------

ALTER TABLE ati.investigation_report ADD COLUMN criticality text;
ALTER TABLE ati.investigation_report ADD COLUMN started_at timestamptz;
ALTER TABLE ati.investigation_report ADD COLUMN ended_at timestamptz;
ALTER TABLE ati.investigation_report ADD COLUMN outcome_status text;
ALTER TABLE ati.investigation_report ADD COLUMN stop_reason text;
ALTER TABLE ati.investigation_report RENAME COLUMN executive_summary TO summary;
ALTER TABLE ati.investigation_report
  ALTER COLUMN summary SET DEFAULT '[]'::jsonb;

-- Explicit historical compatibility: the persisted Status snapshot is copied
-- from the owning Investigation lifecycle (never from report creation time)
-- and legacy findings are mapped forward to the neutral ``medium``
-- criticality. The legacy executive-summary narrative cannot be mapped
-- one-to-one onto canonical findings, so it is replaced by the deterministic
-- finding-centric summary projection.
UPDATE ati.investigation_report r
SET criticality = CASE
      WHEN jsonb_array_length(r.findings) > 0 THEN 'medium'
      ELSE 'informational'
    END,
    started_at = i.started_at,
    ended_at = i.completed_at,
    outcome_status = i.status,
    stop_reason = i.operational_state->>'stop_reason'
FROM ati.investigation i
WHERE i.id = r.investigation_id;

WITH exploded AS (
  SELECT r.id AS report_id,
         f AS finding,
         row_number() OVER (
           PARTITION BY r.id
           ORDER BY (f->>'assessment_finding_ordinal')::bigint
         )::bigint AS report_number
  FROM ati.investigation_report r,
       jsonb_array_elements(r.findings) AS f
),
grouped AS (
  SELECT report_id,
         jsonb_agg(
           jsonb_build_object(
             'assessment_finding_ordinal', finding->'assessment_finding_ordinal',
             'report_finding_number', report_number,
             'criticality', 'medium',
             'title', btrim(finding->>'statement'),
             'category', finding->'category',
             'disposition', finding->'disposition',
             'statement', finding->'statement',
             'confidence', finding->'confidence',
             'summary', btrim(finding->>'statement'),
             'description', btrim(finding->>'statement'),
             'support', COALESCE(finding->'support', '[]'::jsonb)
           )
           ORDER BY report_number
         ) AS findings
  FROM exploded
  GROUP BY report_id
)
UPDATE ati.investigation_report r
SET findings = g.findings
FROM grouped g
WHERE r.id = g.report_id;

UPDATE ati.investigation_report r
SET summary = COALESCE(
      (
        SELECT jsonb_agg(
                 jsonb_build_object(
                   'report_finding_number', f->'report_finding_number',
                   'assessment_finding_ordinal', f->'assessment_finding_ordinal',
                   'text', f->>'summary',
                   'support', jsonb_build_array(
                     jsonb_build_object(
                       'kind', 'assessment_finding',
                       'assessment_id', r.assessment_id,
                       'finding_ordinal',
                       (f->>'assessment_finding_ordinal')::bigint
                     )
                   )
                 )
                 ORDER BY (f->>'report_finding_number')::bigint
               )
        FROM jsonb_array_elements(r.findings) AS f
      ),
      '[]'::jsonb
    );

ALTER TABLE ati.investigation_report ALTER COLUMN criticality SET NOT NULL;
ALTER TABLE ati.investigation_report ALTER COLUMN outcome_status SET NOT NULL;
ALTER TABLE ati.investigation_report
  ADD CONSTRAINT investigation_report_criticality_check
  CHECK (criticality IN ('critical', 'high', 'medium', 'low', 'informational'));
ALTER TABLE ati.investigation_report
  ADD CONSTRAINT investigation_report_outcome_status_check
  CHECK (outcome_status IN ('pending', 'running', 'completed', 'partial', 'failed'));

DROP TYPE ati.report_finding_item CASCADE;

CREATE TYPE ati.report_finding_item AS (
  ordinal bigint,
  report_number bigint,
  criticality text,
  title text,
  category text,
  disposition text,
  statement text,
  confidence text,
  summary text,
  description text
);

CREATE TYPE ati.report_summary_item AS (
  ordinal bigint,
  report_number bigint,
  assessment_finding_ordinal bigint,
  text text,
  assessment_id uuid,
  finding_ordinal bigint
);

CREATE OR REPLACE FUNCTION ati.append_investigation_report(
  p_id uuid, p_investigation_id uuid, p_assessment_id uuid,
  p_verdict text, p_confidence text, p_criticality text, p_title text,
  p_summary ati.report_summary_item[],
  p_findings ati.report_finding_item[],
  p_finding_support ati.report_finding_support_item[],
  p_research_context ati.report_research_item[],
  p_limitations text[], p_unresolved_questions text[],
  p_recommended_next_steps text[],
  p_started_at timestamptz, p_ended_at timestamptz,
  p_outcome_status text, p_stop_reason text,
  p_source_evidence_ids uuid[], p_source_relationship_observation_ids uuid[],
  p_source_research_result_ids uuid[],
  p_actor_id uuid DEFAULT NULL, p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE result_id uuid; result_version bigint; result_created_at timestamptz;
  new_state jsonb; parent_id uuid; assessment_state jsonb;
  findings_json jsonb; summary_json jsonb; research_json jsonb;
  hard_limit CONSTANT integer := 10000;
BEGIN
  IF p_summary IS NULL OR p_findings IS NULL OR p_finding_support IS NULL
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
  IF cardinality(p_summary) > hard_limit
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
     OR p_criticality NOT IN
        ('critical', 'high', 'medium', 'low', 'informational')
     OR p_outcome_status NOT IN
        ('pending', 'running', 'completed', 'partial', 'failed')
     OR btrim(p_title) = '' THEN
    RAISE EXCEPTION 'report verdict, confidence, criticality, outcome, or title is invalid'
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
    ordinal bigint, report_number bigint, criticality text, title text,
    category text, disposition text, statement text, confidence text,
    summary text, description text) ON COMMIT DROP;
  DELETE FROM staging_report_finding;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_finding_support(
    finding_ordinal bigint, support_ordinal bigint, kind text,
    evidence_id uuid, relationship_observation_id uuid) ON COMMIT DROP;
  DELETE FROM staging_report_finding_support;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_summary(
    ordinal bigint, report_number bigint, assessment_finding_ordinal bigint,
    statement text, assessment_id uuid, finding_ordinal bigint) ON COMMIT DROP;
  DELETE FROM staging_report_summary;
  CREATE TEMP TABLE IF NOT EXISTS staging_report_research(
    research_result_id uuid, research_claim_id uuid, subject_entity_id uuid,
    claim_text text, citation_ids uuid[], citations jsonb) ON COMMIT DROP;
  DELETE FROM staging_report_research;

  INSERT INTO staging_report_finding(
    ordinal, report_number, criticality, title, category, disposition,
    statement, confidence, summary, description)
  SELECT f.ordinal, f.report_number, f.criticality, f.title, f.category,
         f.disposition, f.statement, f.confidence, f.summary, f.description
  FROM unnest(p_findings) AS f;

  INSERT INTO staging_report_finding_support(
    finding_ordinal, support_ordinal, kind, evidence_id, relationship_observation_id)
  SELECT s.finding_ordinal, s.support_ordinal, s.kind, s.evidence_id,
         s.relationship_observation_id
  FROM unnest(p_finding_support) AS s;

  INSERT INTO staging_report_summary(
    ordinal, report_number, assessment_finding_ordinal, statement,
    assessment_id, finding_ordinal)
  SELECT s.ordinal, s.report_number, s.assessment_finding_ordinal, s.text,
         s.assessment_id, s.finding_ordinal
  FROM unnest(p_summary) AS s;

  INSERT INTO staging_report_research(
    research_result_id, research_claim_id, subject_entity_id, claim_text,
    citation_ids, citations)
  SELECT r.research_result_id, r.research_claim_id, r.subject_entity_id,
         r.claim_text, r.citation_ids, r.citations
  FROM unnest(p_research_context) AS r;

  -- Finding structure: each Assessment ordinal appears exactly once, reader
  -- numbers are positive, unique, and contiguous from one, and the
  -- vocabularies are bounded.
  IF (SELECT count(*) FROM staging_report_finding)
     <> (SELECT count(DISTINCT ordinal) FROM staging_report_finding)
     OR EXISTS (SELECT 1 FROM staging_report_finding
                WHERE ordinal IS NULL OR ordinal < 1) THEN
    RAISE EXCEPTION 'report finding ordinals must be positive and unique'
      USING ERRCODE = 'U23A5';
  END IF;
  IF (SELECT count(*) FROM staging_report_finding)
     <> (SELECT count(DISTINCT report_number) FROM staging_report_finding)
     OR EXISTS (SELECT 1 FROM staging_report_finding
                WHERE report_number IS NULL OR report_number < 1)
     OR (
       (SELECT count(*) FROM staging_report_finding) > 0
       AND (
         (SELECT min(report_number) FROM staging_report_finding) <> 1
         OR (SELECT max(report_number) FROM staging_report_finding)
            <> (SELECT count(*) FROM staging_report_finding)
       )
     ) THEN
    RAISE EXCEPTION 'report finding numbers must be contiguous from one'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding
    WHERE category NOT IN
      ('reputation', 'geolocation', 'registration', 'network', 'association')
       OR disposition NOT IN ('supporting', 'contradicting')
       OR confidence NOT IN ('low', 'medium', 'high')
       OR criticality NOT IN
          ('critical', 'high', 'medium', 'low', 'informational')
       OR btrim(statement) = ''
       OR btrim(title) = ''
       OR btrim(summary) = ''
       OR btrim(description) = ''
  ) THEN
    RAISE EXCEPTION 'report finding vocabulary and text are invalid'
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
    LEFT JOIN ati.evidence_observation e
      ON s.kind = 'evidence' AND e.id = s.evidence_id
    LEFT JOIN ati.investigation_evidence ie
      ON ie.evidence_observation_id = s.evidence_id
     AND ie.investigation_id = p_investigation_id
    WHERE s.kind = 'evidence'
      AND (e.id IS NULL OR ie.evidence_observation_id IS NULL)
  ) THEN
    RAISE EXCEPTION 'report finding evidence support is missing or not admitted'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support s
    LEFT JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    WHERE s.kind = 'relationship_observation'
      AND o.id IS NULL
  ) THEN
    RAISE EXCEPTION 'report finding observation support is missing'
      USING ERRCODE = 'U23A5';
  END IF;

  -- The application enforces the authoritative maximum finding criticality;
  -- the database independently re-derives it so a direct caller cannot
  -- understate it.
  IF p_criticality IS DISTINCT FROM (
    SELECT COALESCE(
      (SELECT c.criticality
       FROM (VALUES ('critical', 0), ('high', 1), ('medium', 2),
                    ('low', 3), ('informational', 4)) AS c(criticality, rank)
       JOIN staging_report_finding f ON f.criticality = c.criticality
       ORDER BY c.rank
       LIMIT 1),
      'informational')
  ) THEN
    RAISE EXCEPTION 'report criticality is not the maximum finding criticality'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Summary closure: exactly one item per canonical finding, matching
  -- the finding's reader number, ordinal, and Summary sentence, with exactly
  -- one typed support reference to that same finding.
  IF (SELECT count(*) FROM staging_report_summary)
     <> (SELECT count(*) FROM staging_report_finding) THEN
    RAISE EXCEPTION 'report summary must contain exactly the canonical findings'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_summary s
    LEFT JOIN staging_report_finding f ON f.ordinal = s.assessment_finding_ordinal
    WHERE f.ordinal IS NULL
       OR s.report_number <> f.report_number
       OR s.statement <> f.summary
  ) THEN
    RAISE EXCEPTION 'report summary item does not match its canonical finding'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_summary
    WHERE assessment_id IS DISTINCT FROM p_assessment_id
       OR finding_ordinal IS DISTINCT FROM assessment_finding_ordinal
  ) THEN
    RAISE EXCEPTION 'report summary support must reference its exact finding'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_summary
    GROUP BY report_number
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'duplicate report summary item'
      USING ERRCODE = 'U23A5';
  END IF;

  -- Research snapshot structure: unique claim selections, persisted results
  -- of this Investigation, and exact claim membership in the persisted
  -- result's JSONB claims.
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

  -- Assemble the authoritative JSONB snapshots from the staged rows.
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
             'report_finding_number', f.report_number,
             'criticality', f.criticality,
             'title', f.title,
             'category', f.category,
             'disposition', f.disposition,
             'statement', f.statement,
             'confidence', f.confidence,
             'summary', f.summary,
             'description', f.description,
             'support', COALESCE(fjs.support, '[]'::jsonb)) AS item
    FROM staging_report_finding f
    LEFT JOIN finding_support_json fjs ON fjs.finding_ordinal = f.ordinal
  )
  SELECT jsonb_agg(item ORDER BY ordinal) INTO findings_json FROM finding_json;
  findings_json := COALESCE(findings_json, '[]'::jsonb);

  SELECT jsonb_agg(
           jsonb_build_object(
             'report_finding_number', s.report_number,
             'assessment_finding_ordinal', s.assessment_finding_ordinal,
             'text', s.statement,
             'support', jsonb_build_array(
               jsonb_build_object(
                 'kind', 'assessment_finding',
                 'assessment_id', s.assessment_id,
                 'finding_ordinal', s.finding_ordinal
               )
             )
           )
           ORDER BY s.ordinal)
    INTO summary_json
    FROM staging_report_summary s;
  summary_json := COALESCE(summary_json, '[]'::jsonb);

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
      id, investigation_id, assessment_id, verdict, confidence, criticality,
      title, summary, findings, research_context,
      limitations, unresolved_questions, recommended_next_steps,
      started_at, ended_at, outcome_status, stop_reason,
      source_evidence_ids, source_relationship_observation_ids,
      source_research_result_ids, version)
    VALUES(result_id, p_investigation_id, p_assessment_id, p_verdict,
           p_confidence, p_criticality, p_title, summary_json, findings_json,
           research_json, COALESCE(p_limitations, '{}'),
           COALESCE(p_unresolved_questions, '{}'),
           COALESCE(p_recommended_next_steps, '{}'),
           p_started_at, p_ended_at, p_outcome_status, p_stop_reason,
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
