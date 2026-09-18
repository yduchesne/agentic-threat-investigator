-- Immutable SQL API v0026 for PR 28B: global Evidence persistence and
-- Investigation-scoped admission.
--
-- Makes the PR 28A global Evidence model authoritative in PostgreSQL:
--
--   ati.evidence                 stable global source-intelligence identity
--                                (deterministic PR 28A UUID; no Investigation,
--                                subject, observation state, soft delete, or
--                                generic history)
--   ati.evidence_observation     one immutable material state of an Evidence
--                                item; (evidence_id, version) unique; version 1
--                                is the first material state; material change
--                                appends the next version with the canonical
--                                shallow {old, new} diff; retrieved_at-only
--                                replays create no row
--   ati.evidence_observation_entity  structural many-to-many provenance of the
--                                canonical Entities materially represented in
--                                one exact observation (no role field)
--   ati.investigation_evidence   exact append-only/idempotent admission of one
--                                immutable observation into one Investigation
--
-- RelationshipObservation provenance is repointed to
-- ati.evidence_observation(id) and loses its v0.1 Investigation correlation
-- column. GEOINT observation/resolution provenance is repointed the same way.
-- Assessment/report finding support FK and analyzed-evidence/report-source
-- semantics are repointed to exact EvidenceObservation values, and the
-- database validates that every referenced observation is admitted to the
-- same Investigation (never inferred from Evidence ownership).
--
-- The v0.1 legacy table (ati.evidence with Investigation/subject/observation
-- state) is transformed in place: old rows become evidence_observation rows
-- preserving their immutable observation UUIDs, the old subject becomes an
-- EvidenceObservationEntity association, the old Investigation becomes an
-- InvestigationEvidence admission, and a fresh deterministic stable
-- Evidence row is derived through ati.evidence_id_for_source_record (the
-- SQL twin of the PR 28A domain contract). Only rows whose source has an
-- approved stable identity contract AND that carry the exact upstream
-- source-record identity are migratable; any other legacy row fails the
-- migration closed (no identity is ever invented by hashing payloads,
-- IOCs, retrieval timestamps, or old random UUIDs).
--
-- Concurrency: ati.persist_evidence_observation serializes per-Evidence
-- writers with a deterministic transaction-scoped advisory lock derived from
-- the Evidence identity; version allocation (never MAX(version)+1 without
-- the lock) is owned entirely by PostgreSQL.
--
-- Typed SQLSTATE mapping (new U28B* codes):
--   U28B0 PR 28B migration STOP: legacy row without approved stable identity
--   U28B1 stable Evidence metadata conflict under one deterministic ID
--   U28B2 committed Evidence with no observation / missing observation
--   U28B3 invalid evidence-observation input or impossible transition
--   U28B5 admission vocabulary/metadata conflict on idempotent replay
--   U28B6 invalid discovered-from provenance (not admitted to the same
--         Investigation)
--   U28B7 invalid EvidenceObservationEntity association
--   U28B8 invalid RelationshipObservation provenance

-- ---------------------------------------------------------------------------
-- SQL API v0026 (part 1): the deterministic PR 28A Evidence identity is
-- computed by the application domain contract (evidence_id_for_source_record)
-- and by the migration backfill below in Python; PostgreSQL only ever
-- STORES the deterministic identity and never derives it. No SQL-side
-- uuid5 helper is installed.
-- Part 2: free the stable name and create the authoritative tables
-- ---------------------------------------------------------------------------
-- The v0.1 legacy table keeps its rows (they become observations) and its
-- dependent FKs (repointed in Part 5) under the transitional name.

ALTER TABLE ati.evidence RENAME TO evidence_legacy_v01;

CREATE TABLE ati.evidence (
  id uuid PRIMARY KEY,
  evidence_type text NOT NULL,
  source text NOT NULL,
  source_record_id text NOT NULL
);
-- No (source, source_record_id) uniqueness tuple is added: the deterministic
-- PR 28A UUID is the canonical cross-format identity, and two different
-- semantic formats may legally derive different Evidence IDs from the same
-- (source, source_record_id) pair. The PK is the only identity constraint.

CREATE TABLE ati.evidence_observation (
  id uuid PRIMARY KEY,
  evidence_id uuid NOT NULL REFERENCES ati.evidence(id),
  version bigint NOT NULL CHECK (version >= 1),
  source_url text,
  observed_at timestamptz,
  retrieved_at timestamptz NOT NULL,
  facts jsonb NOT NULL,
  raw_payload jsonb,
  diff jsonb,
  created_at timestamptz NOT NULL,
  CONSTRAINT evidence_observation_pair_unique UNIQUE (evidence_id, version)
);
-- The UNIQUE (evidence_id, version) index serves latest-observation lookups
-- by reverse scan; no redundant DESC index is added.

CREATE TABLE ati.evidence_observation_entity (
  evidence_observation_id uuid NOT NULL REFERENCES ati.evidence_observation(id),
  entity_id uuid NOT NULL REFERENCES ati.entity(id),
  PRIMARY KEY (evidence_observation_id, entity_id)
);

CREATE TABLE ati.investigation_evidence (
  investigation_id uuid NOT NULL REFERENCES ati.investigation(id),
  evidence_observation_id uuid NOT NULL REFERENCES ati.evidence_observation(id),
  inclusion_reason text NOT NULL,
  discovered_from_evidence_observation_id uuid
    REFERENCES ati.evidence_observation(id),
  added_at timestamptz NOT NULL,
  added_by text NOT NULL,
  PRIMARY KEY (investigation_id, evidence_observation_id),
  CONSTRAINT investigation_evidence_reason_check CHECK (
    inclusion_reason IN (
      'initial', 'provider_result', 'correlation',
      'agent_selected', 'analyst_added')),
  CONSTRAINT investigation_evidence_actor_check CHECK (
    added_by IN ('system', 'agent', 'analyst'))
);

-- Investigation admission -> exact observation traversal.
CREATE INDEX investigation_evidence_observation_idx
  ON ati.investigation_evidence(evidence_observation_id, investigation_id);

-- Entity-side association traversal (observation-side is covered by the PK).
CREATE INDEX evidence_observation_entity_entity_idx
  ON ati.evidence_observation_entity(entity_id, evidence_observation_id);

-- ---------------------------------------------------------------------------
-- Part 3: existing-data migration (fail closed on unsupported identity).
-- The backfill of the legacy table into the new Evidence/
-- EvidenceObservation/EvidenceObservationEntity/InvestigationEvidence
-- tables is performed by the migration in Python using the domain
-- evidence_id_for_source_record contract, see migration 0031.
-- Part 4/5 repointing ALTERs (RelationshipObservation /
-- EntityLocationObservation / GeoResolution / assessment_finding_support
-- provenance FKs) live in repoint_provenance_fks.sql, which migration 0031
-- applies AFTER the Python backfill populates ati.evidence_observation; the
-- ALTERs must not run before the backfill or the FK validation fails on
-- legacy rows.
-- Part 6: drop the legacy seam
-- ---------------------------------------------------------------------------
-- All dependent FKs were repointed in Parts 4/5. The v0.1 append function
-- is dropped here (its plpgsql body tracks a dependency on the legacy
-- table); the legacy table itself is dropped by the migration in Python
-- after the backfill in Part 3. EvidenceObservation is authoritative
-- intelligence history: no generic domain_object_history rows are created
-- for Evidence or EvidenceObservation, and pre-28B legacy Evidence history
-- rows (if any) are preserved untouched as legacy audit data.

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS signature
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'ati' AND p.proname = 'append_evidence'
  LOOP
    EXECUTE format('DROP FUNCTION %s', r.signature);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Part 7: authoritative global Evidence write functions
-- ---------------------------------------------------------------------------

-- Persist one observation candidate for one stable Evidence and return the
-- authoritative result. PostgreSQL owns: stable metadata validation, atomic
-- Evidence + observation v1 creation, latest material-state comparison,
-- no-op detection, per-Evidence serialization, next-version allocation, and
-- the canonical diff. Outcome is CREATED | UNCHANGED | APPENDED.
CREATE OR REPLACE FUNCTION ati.persist_evidence_observation(
  p_evidence_id uuid,
  p_evidence_type text,
  p_source text,
  p_source_record_id text,
  p_source_url text,
  p_observed_at timestamptz,
  p_retrieved_at timestamptz,
  p_facts jsonb,
  p_raw_payload jsonb,
  p_created_at timestamptz DEFAULT NULL,
  p_observation_id uuid DEFAULT NULL)
RETURNS TABLE(
  evidence_id uuid, evidence_observation_id uuid, version bigint,
  outcome text)
LANGUAGE plpgsql AS $$
DECLARE
  v_version bigint;
  v_observation_id uuid;
  v_latest_material jsonb;
  v_candidate_material jsonb;
  v_diff jsonb;
  v_stable_type text;
  v_stable_source text;
  v_stable_record text;
  v_created_at timestamptz;
BEGIN
  -- Bounded input validation (fail closed even if Python model validation
  -- is bypassed).
  IF p_evidence_id IS NULL OR p_evidence_type IS NULL OR p_source IS NULL
     OR p_source_record_id IS NULL OR p_retrieved_at IS NULL THEN
    RAISE EXCEPTION 'invalid evidence observation input'
      USING ERRCODE = 'U28B3';
  END IF;
  IF btrim(p_source) <> p_source OR btrim(p_source_record_id) <> p_source_record_id
     OR btrim(p_source) = '' OR btrim(p_source_record_id) = '' THEN
    RAISE EXCEPTION 'invalid evidence observation input'
      USING ERRCODE = 'U28B3';
  END IF;
  v_created_at := COALESCE(p_created_at, now());

  -- Serialize every write for one Evidence identity. The lock is a
  -- deterministic transaction-scoped advisory lock derived from the
  -- Evidence identity; it serializes both first-write and append races
  -- without blocking unrelated Evidence identities.
  PERFORM pg_advisory_xact_lock(hashtextextended(p_evidence_id::text, 0));

  SELECT e.evidence_type, e.source, e.source_record_id
    INTO v_stable_type, v_stable_source, v_stable_record
    FROM ati.evidence e WHERE e.id = p_evidence_id;
  IF NOT FOUND THEN
    -- Create Evidence + observation v1 atomically. A committed Evidence can
    -- never exist without its first observation. The optional
    -- p_observation_id supports deterministic evaluation seams; production
    -- callers leave it NULL so PostgreSQL owns the observation identity.
    INSERT INTO ati.evidence(id, evidence_type, source, source_record_id)
      VALUES(p_evidence_id, p_evidence_type, p_source, p_source_record_id);
    v_observation_id := COALESCE(p_observation_id, gen_random_uuid());
    INSERT INTO ati.evidence_observation(
      id, evidence_id, version, source_url, observed_at, retrieved_at,
      facts, raw_payload, diff, created_at)
      VALUES(v_observation_id, p_evidence_id, 1, p_source_url, p_observed_at,
             p_retrieved_at, COALESCE(p_facts, '{}'::jsonb), p_raw_payload,
             NULL, v_created_at);
    evidence_id := p_evidence_id;
    evidence_observation_id := v_observation_id;
    version := 1;
    outcome := 'CREATED';
    RETURN NEXT;
    RETURN;
  END IF;

  -- The same deterministic Evidence ID must never carry different stable
  -- metadata: conflicting identity is a typed conflict with no mutation.
  IF v_stable_type IS DISTINCT FROM p_evidence_type
     OR v_stable_source IS DISTINCT FROM p_source
     OR v_stable_record IS DISTINCT FROM p_source_record_id THEN
    RAISE EXCEPTION 'stable evidence metadata conflict'
      USING ERRCODE = 'U28B1';
  END IF;

  -- A committed Evidence must always have at least observation version 1.
  SELECT MAX(o.version) INTO v_version
    FROM ati.evidence_observation o WHERE o.evidence_id = p_evidence_id;
  IF v_version IS NULL THEN
    RAISE EXCEPTION 'committed evidence has no observation'
      USING ERRCODE = 'U28B2';
  END IF;

  -- Material-state comparison against the latest persisted observation.
  SELECT o.id, jsonb_build_object(
           'observed_at', o.observed_at,
           'source_url', o.source_url,
           'facts', o.facts,
           'raw_payload', o.raw_payload)
    INTO v_observation_id, v_latest_material
    FROM ati.evidence_observation o
    WHERE o.evidence_id = p_evidence_id AND o.version = v_version;

  v_candidate_material := jsonb_build_object(
    'observed_at', p_observed_at,
    'source_url', p_source_url,
    'facts', COALESCE(p_facts, '{}'::jsonb),
    'raw_payload', p_raw_payload);

  -- A retrieval whose material state is unchanged creates no observation;
  -- only retrieved_at/operational telemetry may differ.
  IF v_candidate_material IS NOT DISTINCT FROM v_latest_material THEN
    evidence_id := p_evidence_id;
    evidence_observation_id := v_observation_id;
    version := v_version;
    outcome := 'UNCHANGED';
    RETURN NEXT;
    RETURN;
  END IF;

  -- Material change: append the next version with the canonical diff from
  -- the immediate predecessor. Version allocation is owned by this function
  -- under the per-Evidence lock (never MAX(version)+1 without it).
  v_version := v_version + 1;
  v_diff := ati.ati_jsonb_diff(v_latest_material, v_candidate_material);
  v_observation_id := gen_random_uuid();
  INSERT INTO ati.evidence_observation(
    id, evidence_id, version, source_url, observed_at, retrieved_at,
    facts, raw_payload, diff, created_at)
    VALUES(v_observation_id, p_evidence_id, v_version, p_source_url,
           p_observed_at, p_retrieved_at,
           COALESCE(p_facts, '{}'::jsonb), p_raw_payload, v_diff,
           v_created_at);
  evidence_id := p_evidence_id;
  evidence_observation_id := v_observation_id;
  version := v_version;
  outcome := 'APPENDED';
  RETURN NEXT;
END $$;

-- Idempotent observation-level Entity association (no role field).
CREATE OR REPLACE FUNCTION ati.associate_evidence_observation_entity(
  p_evidence_observation_id uuid, p_entity_id uuid)
RETURNS TABLE(evidence_observation_id uuid, entity_id uuid)
LANGUAGE plpgsql AS $$
BEGIN
  IF p_evidence_observation_id IS NULL OR p_entity_id IS NULL THEN
    RAISE EXCEPTION 'invalid entity association' USING ERRCODE = 'U28B7';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation o
      WHERE o.id = p_evidence_observation_id) THEN
    RAISE EXCEPTION 'evidence observation not found' USING ERRCODE = 'U28B2';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.entity e
      WHERE e.id = p_entity_id AND e.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'invalid entity association' USING ERRCODE = 'U28B7';
  END IF;
  INSERT INTO ati.evidence_observation_entity(
    evidence_observation_id, entity_id)
    VALUES(p_evidence_observation_id, p_entity_id)
    ON CONFLICT DO NOTHING;
  evidence_observation_id := p_evidence_observation_id;
  entity_id := p_entity_id;
  RETURN NEXT;
END $$;

-- Exact append-only/idempotent admission of one observation into one
-- Investigation. Replaying the exact admission is a harmless no-op;
-- changing immutable admission metadata is a typed conflict.
CREATE OR REPLACE FUNCTION ati.admit_investigation_evidence(
  p_investigation_id uuid,
  p_evidence_observation_id uuid,
  p_inclusion_reason text,
  p_discovered_from_evidence_observation_id uuid,
  p_added_at timestamptz,
  p_added_by text)
RETURNS TABLE(investigation_id uuid, evidence_observation_id uuid, admitted boolean)
LANGUAGE plpgsql AS $$
DECLARE
  v_existing_reason text;
  v_existing_added_by text;
  v_existing_discovered uuid;
BEGIN
  IF p_investigation_id IS NULL OR p_evidence_observation_id IS NULL
     OR p_inclusion_reason IS NULL OR p_added_at IS NULL OR p_added_by IS NULL THEN
    RAISE EXCEPTION 'invalid investigation admission input'
      USING ERRCODE = 'U28B5';
  END IF;
  IF p_inclusion_reason NOT IN (
      'initial', 'provider_result', 'correlation',
      'agent_selected', 'analyst_added')
     OR p_added_by NOT IN ('system', 'agent', 'analyst') THEN
    RAISE EXCEPTION 'invalid investigation admission vocabulary'
      USING ERRCODE = 'U28B5';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.investigation i
      WHERE i.id = p_investigation_id AND i.deleted_at IS NULL) THEN
    RAISE EXCEPTION 'investigation not found' USING ERRCODE = 'U18A1';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence_observation o
      WHERE o.id = p_evidence_observation_id) THEN
    RAISE EXCEPTION 'evidence observation not found' USING ERRCODE = 'U28B2';
  END IF;
  -- discovered-from must be an exact observation already admitted to the
  -- same Investigation; it is never inferred from stable Evidence identity,
  -- Entity equality, or graph adjacency.
  IF p_discovered_from_evidence_observation_id IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM ati.investigation_evidence ie
       WHERE ie.investigation_id = p_investigation_id
         AND ie.evidence_observation_id = p_discovered_from_evidence_observation_id)
  THEN
    RAISE EXCEPTION 'invalid discovered-from provenance'
      USING ERRCODE = 'U28B6';
  END IF;

  SELECT ie.inclusion_reason, ie.added_by,
         ie.discovered_from_evidence_observation_id
    INTO v_existing_reason, v_existing_added_by, v_existing_discovered
    FROM ati.investigation_evidence ie
    WHERE ie.investigation_id = p_investigation_id
      AND ie.evidence_observation_id = p_evidence_observation_id;
  IF FOUND THEN
    -- Exact idempotent replay: the identical admission is a no-op; any
    -- change to immutable admission metadata is a typed conflict.
    IF v_existing_reason IS DISTINCT FROM p_inclusion_reason
       OR v_existing_added_by IS DISTINCT FROM p_added_by
       OR v_existing_discovered IS DISTINCT FROM
          p_discovered_from_evidence_observation_id THEN
      RAISE EXCEPTION 'investigation admission metadata conflict'
        USING ERRCODE = 'U28B5';
    END IF;
    investigation_id := p_investigation_id;
    evidence_observation_id := p_evidence_observation_id;
    admitted := false;
    RETURN NEXT;
    RETURN;
  END IF;

  INSERT INTO ati.investigation_evidence(
    investigation_id, evidence_observation_id, inclusion_reason,
    discovered_from_evidence_observation_id, added_at, added_by)
    VALUES(p_investigation_id, p_evidence_observation_id, p_inclusion_reason,
           p_discovered_from_evidence_observation_id, p_added_at, p_added_by);
  investigation_id := p_investigation_id;
  evidence_observation_id := p_evidence_observation_id;
  admitted := true;
  RETURN NEXT;
END $$;