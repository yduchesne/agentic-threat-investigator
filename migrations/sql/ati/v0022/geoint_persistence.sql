-- Immutable SQL API v0022 for PR 26A-2: EntityLocation version allocation.
--
-- PR 26A-2 is a corrective child of PR 26A. PR 26A created
-- ati.entity_location_version_seq and used it for initial EntityLocation
-- creation, but the v0021 reconciliation path advanced changed current rows
-- with `version = target.version + 1`. This version makes the sequence the
-- sole allocator for every materialized-state mutation.
--
-- Binding semantics:
--
-- 1. ati.entity_location.version is a database-issued change token allocated
--    by PostgreSQL from ati.entity_location_version_seq on initial creation
--    and on every actual current-state mutation. Python never allocates it
--    and reconciliation never derives it arithmetically from the current
--    row.
--
-- 2. Versions are monotonic database-issued change tokens, not contiguous
--    revision counters. For successive committed mutations of one current
--    row callers may rely on new_version > previous_version, never
--    new_version == previous_version + 1. Sequence gaps caused by rollback,
--    contention, or PostgreSQL evaluation are valid.
--
-- 3. An appended historical observation that does not change EntityLocation
--    leaves the persisted version unchanged (the mutation predicate below is
--    unchanged from v0021); a sequence value may nevertheless be consumed
--    internally.
--
-- 4. An older observation that extends first_observed_at is a real mutation
--    and receives a new sequence token even when Location, precision, latest
--    observation, and last_observed_at remain unchanged.
--
-- 5. Observation append and current-state reconciliation remain one
--    stored-function transaction. No Python-side version allocation or
--    reconciliation exists.
--
-- This file redefines only ati.append_entity_location_observation; every
-- other object of SQL API v0021 is unchanged and remains owned by v0021.
-- Typed SQLSTATE mapping is unchanged (U26A1-U26A6 rejections, see v0021).

-- Append exactly one immutable EntityLocationObservation and reconcile the
-- current EntityLocation atomically in the same transaction. All provenance
-- validation (Entity visibility, Location existence, Evidence existence,
-- GEOLOCATION type, exact Evidence subject) happens database-side before
-- any mutation; the deterministic currentness ordering is
-- (COALESCE(observed_at, retrieved_at), observation_id) with the greater
-- pair winning.
CREATE OR REPLACE FUNCTION ati.append_entity_location_observation(
  p_id uuid, p_entity_id uuid, p_location_id uuid, p_evidence_id uuid,
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
  IF NOT EXISTS (SELECT 1 FROM ati.evidence ev WHERE ev.id = p_evidence_id) THEN
    RAISE EXCEPTION 'geo evidence not found' USING ERRCODE = 'U26A3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence ev
      WHERE ev.id = p_evidence_id
        AND ev.evidence_type = 'urn:ati:evidence:geolocation') THEN
    RAISE EXCEPTION 'geo evidence is not geolocation' USING ERRCODE = 'U26A4';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence ev
      WHERE ev.id = p_evidence_id AND ev.subject_entity_id = p_entity_id) THEN
    RAISE EXCEPTION 'geo evidence subject mismatch' USING ERRCODE = 'U26A5';
  END IF;

  v_effective := COALESCE(p_observed_at, p_retrieved_at);
  version := nextval('ati.entity_location_observation_version_seq');
  BEGIN
    INSERT INTO ati.entity_location_observation(
      id, entity_id, location_id, evidence_id, "precision", observed_at,
      retrieved_at, resolved_at, resolution_method, version)
      VALUES(p_id, p_entity_id, p_location_id, p_evidence_id, p_precision,
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