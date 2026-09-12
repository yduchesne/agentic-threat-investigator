-- Immutable SQL API v0019 for PR 23B versioned InvestigationReport persistence.
--
-- Reports are versioned analytical presentation outputs: each generation
-- appends a new report row (never a silent overwrite) whose exact structured
-- snapshots are preserved forever. The write path is a stored function;
-- Python never mutates tables directly.
--
-- Relational root integrity:
--   investigation_report -> investigation(id)
--   investigation_report -> assessment(id)
-- Nested report presentation structures (executive summary, finding
-- snapshots, research snapshots) are authoritative typed JSONB snapshots
-- validated by the application domain model and provenance validator; the
-- database enforces root integrity, structural vocabulary, hard ceilings,
-- and the critical current-Assessment invariant under the parent
-- Investigation row lock (see below).
--
-- Input composites follow the batch-persistence convention: bounded arrays
-- of flat resource-specific composite input types (parallel arrays with
-- parent ordinals, matching the Assessment write path) expanded once into
-- temporary tables; all validation and JSONB assembly is set-oriented from
-- those tables. Nested presentation structure is never normalized into
-- mutable child tables: the report is an immutable versioned presentation
-- snapshot.
--
-- Lock discipline: every report-pointer operation uses the deterministic
-- lock order "owning Investigation row first, then target Assessment/Report
-- row". ati.append_investigation_report locks the Investigation row FOR
-- UPDATE and then the target Assessment row FOR UPDATE, and revalidates
-- under the Investigation lock that the Assessment is STILL the
-- Investigation's current ``assessment_id``: a report whose input was
-- materialized against an Assessment that ceased to be current is rejected
-- as stale with a typed conflict, so a report is never persisted against an
-- outdated Assessment. ati.set_investigation_report and
-- ati.soft_delete_investigation_report lock the Investigation row first and
-- then the target report row, matching the Assessment-pointer lock order so
-- concurrent pointer assignment and report deletion serialize without
-- deadlock.
--
-- Validation contract (all failures are typed SQLSTATEs and no mutation
-- occurs unless every validation succeeds):
--   - required input arrays must not be NULL (U23A5);
--   - every bounded input collection count is capped by the defensive hard
--     ceiling (U23A8) before any staging or mutation;
--   - verdict/confidence must be bounded enum values and title nonblank
--     (U23A5);
--   - the parent Investigation must be visible under its row lock (U18A1);
--   - the target Assessment must exist, be visible, and belong to the
--     Investigation (U23A6), and must still be the Investigation's current
--     assessment under lock (U23A1 stale report input);
--   - finding snapshots require positive, unique ordinals, allowed
--     vocabulary, nonblank statements, and at least one valid support each
--     (U23A5);
--   - finding supports require positive unique ordinals per finding, a
--     valid discriminator with exactly its matching id field, no duplicate
--     (kind, referenced id) within one finding, and referenced
--     Evidence/RelationshipObservation rows of this Investigation (U23A5);
--   - research snapshots require unique (research_result_id,
--     research_claim_id) pairs, persisted results of this Investigation,
--     and claims that exist inside the persisted result (U23A5);
--   - narrative statements require nonblank text and at least one unique
--     valid support reference; Assessment-finding references must name the
--     report's Assessment and a persisted ordinal of it, and
--     Research-claim references must name a persisted claim of this
--     Investigation (U23A5);
--   - a duplicate report identity is a typed conflict, never an update
--     (U23A4).
--
-- SQLSTATE map:
--   U18A1 investigation not found
--   U18A2 optimistic version conflict
--   U23A1 stale report input (assessment no longer current)
--   U23A2 report reference invalid for its investigation (pointer)
--   U23A3 report not found or already deleted
--   U23A4 duplicate report identity
--   U23A5 malformed report structure
--   U23A6 report assessment missing/invisible/cross-investigation
--   U23A7 deletion of the current report of a visible Investigation
--   U23A8 input exceeds the defensive hard ceiling
--
-- Row-level triggers are never used for versioning or history.

CREATE SEQUENCE ati.investigation_report_version_seq AS bigint;

CREATE TYPE ati.report_narrative_item AS (
  ordinal bigint,
  statement text
);

CREATE TYPE ati.report_narrative_support_item AS (
  narrative_ordinal bigint,
  support_ordinal bigint,
  kind text,
  assessment_id uuid,
  finding_ordinal bigint,
  research_result_id uuid,
  research_claim_id uuid
);

CREATE TYPE ati.report_finding_item AS (
  ordinal bigint,
  category text,
  disposition text,
  statement text,
  confidence text
);

CREATE TYPE ati.report_finding_support_item AS (
  finding_ordinal bigint,
  support_ordinal bigint,
  kind text,
  evidence_id uuid,
  relationship_observation_id uuid
);

CREATE TYPE ati.report_research_item AS (
  research_result_id uuid,
  research_claim_id uuid,
  subject_entity_id uuid,
  claim_text text,
  citation_ids uuid[],
  citations jsonb
);

CREATE TABLE ati.investigation_report (
  id uuid PRIMARY KEY,
  investigation_id uuid NOT NULL REFERENCES ati.investigation(id),
  assessment_id uuid NOT NULL REFERENCES ati.assessment(id),
  verdict text NOT NULL,
  confidence text NOT NULL,
  title text NOT NULL,
  executive_summary jsonb NOT NULL,
  findings jsonb NOT NULL,
  research_context jsonb NOT NULL,
  limitations text[] NOT NULL,
  unresolved_questions text[] NOT NULL,
  recommended_next_steps text[] NOT NULL,
  source_evidence_ids uuid[] NOT NULL,
  source_relationship_observation_ids uuid[] NOT NULL,
  source_research_result_ids uuid[] NOT NULL,
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  deleted_by_actor_id uuid,
  CONSTRAINT investigation_report_verdict_check CHECK (
    verdict IN ('benign', 'suspicious', 'malicious', 'inconclusive')),
  CONSTRAINT investigation_report_confidence_check CHECK (
    confidence IN ('low', 'medium', 'high')),
  CONSTRAINT investigation_report_title_check CHECK (btrim(title) <> ''),
  -- Deletion-metadata coherence: a non-deleted row never carries an actor,
  -- while an anonymously deleted row (NULL actor) remains valid, matching
  -- the Assessment soft-delete semantics.
  CONSTRAINT investigation_report_deletion_coherence_check CHECK (
    deleted_at IS NOT NULL OR deleted_by_actor_id IS NULL),
  CONSTRAINT investigation_report_investigation_version_key
    UNIQUE (investigation_id, version)
);

CREATE INDEX investigation_report_version_listing_idx
  ON ati.investigation_report(investigation_id, version DESC, id ASC)
  WHERE deleted_at IS NULL;

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
    LEFT JOIN ati.evidence e
      ON s.kind = 'evidence' AND e.id = s.evidence_id
    WHERE s.kind = 'evidence'
      AND (e.id IS NULL OR e.investigation_id <> p_investigation_id)
  ) THEN
    RAISE EXCEPTION 'report finding evidence support is missing or cross-investigation'
      USING ERRCODE = 'U23A5';
  END IF;
  IF EXISTS (
    SELECT 1 FROM staging_report_finding_support s
    LEFT JOIN ati.relationship_observation o
      ON s.kind = 'relationship_observation' AND o.id = s.relationship_observation_id
    WHERE s.kind = 'relationship_observation'
      AND (o.id IS NULL
           OR (o.investigation_id IS NOT NULL
               AND o.investigation_id <> p_investigation_id))
  ) THEN
    RAISE EXCEPTION 'report finding observation support is missing or cross-investigation'
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

CREATE OR REPLACE FUNCTION ati.set_investigation_report(
  p_id uuid, p_report_id uuid, p_actor_id uuid DEFAULT NULL,
  p_request_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, outcome text) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  current_report uuid; target_state jsonb;
BEGIN
  -- Deterministic lock discipline for every report-pointer operation:
  -- owning Investigation row FOR UPDATE first, then the target report row
  -- FOR UPDATE. The report lock conflicts with
  -- ati.soft_delete_investigation_report's report lock, so a concurrent
  -- deletion serializes behind this transaction and a visible Investigation
  -- can never be pointed at a deleted report.
  SELECT to_jsonb(i), i.version, (i.operational_state->>'report_id')::uuid
    INTO old_state, current_version, current_report
    FROM ati.investigation i WHERE i.id = p_id AND i.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;
  SELECT to_jsonb(r) INTO target_state
    FROM ati.investigation_report r
    WHERE r.id = p_report_id AND r.investigation_id = p_id
    FOR UPDATE;
  IF target_state IS NULL OR (target_state->>'deleted_at') IS NOT NULL THEN
    RAISE EXCEPTION 'report reference is invalid for this investigation'
      USING ERRCODE = 'U23A2';
  END IF;
  IF current_report IS NOT DISTINCT FROM p_report_id THEN
    id := p_id; version := current_version; outcome := 'UNCHANGED';
    RETURN NEXT; RETURN;
  END IF;
  UPDATE ati.investigation AS target SET
    operational_state = jsonb_set(
      COALESCE(target.operational_state, '{}'::jsonb),
      '{report_id}', to_jsonb(p_report_id)),
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

CREATE OR REPLACE FUNCTION ati.soft_delete_investigation_report(
  p_id uuid, p_actor_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL,
  p_request_id uuid DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
  owner_id uuid; owner_deleted boolean; current_report uuid;
BEGIN
  -- Non-authoritative discovery of the owning Investigation: used only to
  -- acquire the deterministic lock order (owning Investigation row first,
  -- then the report row). No deletion decision is made from this snapshot
  -- read.
  SELECT r.investigation_id INTO owner_id
    FROM ati.investigation_report r WHERE r.id = p_id;
  IF owner_id IS NULL THEN
    RAISE EXCEPTION 'report not found or already deleted'
      USING ERRCODE = 'U23A3';
  END IF;
  SELECT (i.deleted_at IS NOT NULL), (i.operational_state->>'report_id')::uuid
    INTO owner_deleted, current_report
    FROM ati.investigation i WHERE i.id = owner_id FOR UPDATE;
  SELECT to_jsonb(r), r.version INTO old_state, current_version
    FROM ati.investigation_report r
    WHERE r.id = p_id AND r.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN
    RAISE EXCEPTION 'report not found or already deleted'
      USING ERRCODE = 'U23A3';
  END IF;
  IF (old_state->>'investigation_id')::uuid <> owner_id THEN
    RAISE EXCEPTION 'report does not belong to its owning investigation'
      USING ERRCODE = 'U23A3';
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict' USING ERRCODE = 'U18A2';
  END IF;
  -- Approved deletion policy mirrors Assessment: deletion is rejected while
  -- the report's visible owning Investigation still points at it as its
  -- current report. The pointer is read from the locked Investigation row,
  -- so a concurrent pointer assignment serialized by the Investigation lock
  -- either committed first (deletion rejected) or is still queued behind
  -- this transaction.
  IF NOT owner_deleted AND current_report IS NOT DISTINCT FROM p_id THEN
    RAISE EXCEPTION 'report is the current report of a visible investigation'
      USING ERRCODE = 'U23A7';
  END IF;
  UPDATE ati.investigation_report AS target SET
    deleted_at = now(), deleted_by_actor_id = p_actor_id,
    version = nextval('ati.investigation_report_version_seq')
    WHERE target.id = p_id
    RETURNING target.id, target.version, to_jsonb(target)
    INTO id, version, new_state;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff,
    actor_id, request_id, investigation_id)
  VALUES('investigation_report', id, version, 'DELETE', new_state,
         ati.ati_jsonb_diff(old_state, new_state), p_actor_id, p_request_id,
         (new_state->>'investigation_id')::uuid);
  RETURN NEXT;
END $$;