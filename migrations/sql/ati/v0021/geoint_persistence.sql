-- Immutable SQL API v0021 for PR 26A GEOINT domain persistence.
--
-- PR 26A establishes the non-spatial GEOINT persistence foundation: four
-- tables (ati.location, ati.entity_location_observation,
-- ati.entity_location, ati.geo_resolution) plus three versioned stored
-- functions. PostgreSQL owns canonical Location identity, observation
-- append + EntityLocation reconciliation, version allocation, provenance
-- validation, and initial pending GeoResolution creation. Python
-- repositories are thin callers and never issue ad-hoc GEOINT DML.
--
-- Resource semantics:
--
-- 1. ati.location is canonical geographic/reference identity (country,
--    administrative_area, city). Canonical identity is the deterministic
--    tuple (location_type, country_code, admin1_code, admin2_code,
--    canonical_name) with null components normalized through a unique
--    COALESCE expression index; parent_location_id is reference hierarchy
--    and is NOT part of identity. ati.upsert_location creates once or
--    reuses the canonical row (no version/history churn for reuse), rejects
--    incompatible state for the same canonical identity, and allocates the
--    version database-side. Location rows are NOT duplicated into
--    domain_object_history: reference identity creation is outside the
--    historized domain-resource contract in PR 26A.
--
-- 2. ati.entity_location_observation is immutable append-only historical
--    provenance. One persisted row is one historical observation; it
--    explicitly stores the exact entity_id, location_id, and evidence_id and
--    never derives its Location through mutable EntityLocation state. The
--    observation row is itself history and is NOT duplicated into
--    domain_object_history (the RelationshipObservation precedent). There is
--    no update/delete path and no investigation_id column: Investigation
--    scope is derived through the exact Evidence provenance chain.
--
-- 3. ati.entity_location is the current materialized Entity-to-Location
--    association, maintained exclusively by
--    ati.append_entity_location_observation using the deterministic
--    currentness ordering (COALESCE(observed_at, retrieved_at),
--    observation_id) with the greater pair winning. An older historical
--    observation is still appended but never rewinds current state; the
--    earliest first_observed_at is preserved.
--
-- 4. ati.geo_resolution is durable operational geographic-enrichment work.
--    PR 26A persists initial PENDING rows and reads only; claim/lease/
--    retry/completion semantics belong to PR 26C. Exactly one row exists
--    per (entity_id, evidence_id); duplicate creation is idempotent only
--    for the exact pair in the initial pending shape and never creates a
--    second work record.
--
-- Typed SQLSTATE mapping (U26A*):
--   U26A1 geo entity not found / invisible
--   U26A2 geo location not found
--   U26A3 geo evidence not found
--   U26A4 geo evidence is not GEOLOCATION
--   U26A5 geo evidence subject mismatch
--   U26A6 geo observation duplicate identity
--   U26A7 incompatible canonical Location identity/state
--   U26A8 invalid GeoResolution duplicate state
--   U26A9 invalid GEOINT input shape
--
-- Row-level triggers are never used for versioning or history; no PostGIS
-- extension, geometry, or spatial semantics exist in this version.

CREATE TABLE IF NOT EXISTS ati.location (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  location_type text NOT NULL,
  name text NOT NULL,
  canonical_name text NOT NULL,
  country_code text NOT NULL,
  admin1_code text,
  admin2_code text,
  parent_location_id uuid REFERENCES ati.location(id),
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT location_type_check CHECK (
    location_type IN ('country', 'administrative_area', 'city')),
  CONSTRAINT location_country_code_check CHECK (
    country_code ~ '^[A-Z]{2}$'),
  CONSTRAINT location_name_check CHECK (
    length(btrim(name)) BETWEEN 1 AND 200),
  CONSTRAINT location_canonical_name_check CHECK (
    length(btrim(canonical_name)) BETWEEN 1 AND 200),
  CONSTRAINT location_admin1_code_check CHECK (
    admin1_code IS NULL OR length(btrim(admin1_code)) BETWEEN 1 AND 64),
  CONSTRAINT location_admin2_code_check CHECK (
    admin2_code IS NULL OR length(btrim(admin2_code)) BETWEEN 1 AND 64),
  CONSTRAINT location_country_shape_check CHECK (
    location_type <> 'country'
      OR (parent_location_id IS NULL AND admin1_code IS NULL
          AND admin2_code IS NULL)),
  CONSTRAINT location_admin_area_shape_check CHECK (
    location_type <> 'administrative_area'
      OR (parent_location_id IS NOT NULL AND admin1_code IS NOT NULL)),
  CONSTRAINT location_city_shape_check CHECK (
    location_type <> 'city'
      OR (parent_location_id IS NOT NULL AND admin1_code IS NOT NULL)),
  CONSTRAINT location_parent_not_self_check CHECK (
    parent_location_id IS NULL OR parent_location_id <> id)
);

-- Deterministic canonical identity with null components normalized to ''.
CREATE UNIQUE INDEX IF NOT EXISTS location_canonical_identity_idx
  ON ati.location(
    location_type,
    country_code,
    COALESCE(admin1_code, ''),
    COALESCE(admin2_code, ''),
    canonical_name);

CREATE TABLE IF NOT EXISTS ati.entity_location_observation (
  id uuid PRIMARY KEY,
  entity_id uuid NOT NULL REFERENCES ati.entity(id),
  location_id uuid NOT NULL REFERENCES ati.location(id),
  evidence_id uuid NOT NULL REFERENCES ati.evidence(id),
  "precision" text NOT NULL,
  observed_at timestamptz,
  retrieved_at timestamptz NOT NULL,
  resolved_at timestamptz NOT NULL,
  resolution_method text NOT NULL,
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT entity_location_observation_precision_check CHECK (
    "precision" IN ('country', 'administrative_area', 'city')),
  CONSTRAINT entity_location_observation_method_check CHECK (
    length(btrim(resolution_method)) BETWEEN 1 AND 200)
);

CREATE INDEX IF NOT EXISTS entity_location_observation_entity_retrieved_idx
  ON ati.entity_location_observation(entity_id, retrieved_at DESC, id ASC);

CREATE TABLE IF NOT EXISTS ati.entity_location (
  entity_id uuid PRIMARY KEY REFERENCES ati.entity(id),
  location_id uuid NOT NULL REFERENCES ati.location(id),
  "precision" text NOT NULL,
  latest_observation_id uuid NOT NULL,
  first_observed_at timestamptz NOT NULL,
  last_observed_at timestamptz NOT NULL,
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT entity_location_precision_check CHECK (
    "precision" IN ('country', 'administrative_area', 'city')),
  CONSTRAINT entity_location_time_order_check CHECK (
    first_observed_at <= last_observed_at)
);

-- Added after both tables exist so the dependency cycle-free creation order
-- (observation before current state) is migration-safe.
ALTER TABLE ati.entity_location
  ADD CONSTRAINT entity_location_latest_observation_fk
  FOREIGN KEY (latest_observation_id)
  REFERENCES ati.entity_location_observation(id);

CREATE TABLE IF NOT EXISTS ati.geo_resolution (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_id uuid NOT NULL REFERENCES ati.entity(id),
  evidence_id uuid NOT NULL REFERENCES ati.evidence(id),
  status text NOT NULL,
  attempt_count integer NOT NULL,
  next_attempt_at timestamptz,
  claimed_by text,
  lease_expires_at timestamptz,
  resolved_location_id uuid REFERENCES ati.location(id),
  last_error_code text,
  version bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT geo_resolution_pair_unique UNIQUE (entity_id, evidence_id),
  CONSTRAINT geo_resolution_status_check CHECK (
    status IN ('pending', 'processing', 'resolved', 'unresolvable', 'failed')),
  CONSTRAINT geo_resolution_attempt_count_check CHECK (attempt_count >= 0),
  CONSTRAINT geo_resolution_error_code_check CHECK (
    last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  CONSTRAINT geo_resolution_claimed_by_check CHECK (
    claimed_by IS NULL OR length(btrim(claimed_by)) BETWEEN 1 AND 200)
);

CREATE SEQUENCE IF NOT EXISTS ati.location_version_seq;
CREATE SEQUENCE IF NOT EXISTS ati.entity_location_observation_version_seq;
CREATE SEQUENCE IF NOT EXISTS ati.entity_location_version_seq;
CREATE SEQUENCE IF NOT EXISTS ati.geo_resolution_version_seq;

-- Create once or reuse the canonical Location row for the approved identity
-- tuple. Reuse is a semantic no-op (no version/history); a different name or
-- parent for the same canonical identity is incompatible state (U26A7).
CREATE OR REPLACE FUNCTION ati.upsert_location(
  p_id uuid, p_location_type text, p_name text, p_canonical_name text,
  p_country_code text, p_admin1_code text, p_admin2_code text,
  p_parent_location_id uuid)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE existing_id uuid; existing_version bigint; existing_name text;
  existing_parent uuid; result_id uuid;
BEGIN
  IF p_location_type NOT IN ('country', 'administrative_area', 'city') THEN
    RAISE EXCEPTION 'invalid location type' USING ERRCODE = 'U26A9';
  END IF;
  IF p_country_code IS NULL OR p_country_code !~ '^[A-Z]{2}$' THEN
    RAISE EXCEPTION 'invalid country code' USING ERRCODE = 'U26A9';
  END IF;
  IF btrim(p_name) = '' OR length(btrim(p_name)) > 200 THEN
    RAISE EXCEPTION 'invalid location name' USING ERRCODE = 'U26A9';
  END IF;
  IF btrim(p_canonical_name) = '' OR length(btrim(p_canonical_name)) > 200 THEN
    RAISE EXCEPTION 'invalid canonical location name' USING ERRCODE = 'U26A9';
  END IF;
  IF (p_admin1_code IS NOT NULL
      AND (btrim(p_admin1_code) = '' OR length(btrim(p_admin1_code)) > 64)) THEN
    RAISE EXCEPTION 'invalid admin1 code' USING ERRCODE = 'U26A9';
  END IF;
  IF (p_admin2_code IS NOT NULL
      AND (btrim(p_admin2_code) = '' OR length(btrim(p_admin2_code)) > 64)) THEN
    RAISE EXCEPTION 'invalid admin2 code' USING ERRCODE = 'U26A9';
  END IF;
  IF p_location_type = 'country'
     AND (p_parent_location_id IS NOT NULL
          OR p_admin1_code IS NOT NULL OR p_admin2_code IS NOT NULL) THEN
    RAISE EXCEPTION 'country location must not have parent or admin codes'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_location_type <> 'country'
     AND (p_parent_location_id IS NULL OR p_admin1_code IS NULL) THEN
    RAISE EXCEPTION 'area/city location requires parent and admin1 code'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_id IS NOT NULL AND p_parent_location_id = p_id THEN
    RAISE EXCEPTION 'location parent must not equal the location itself'
      USING ERRCODE = 'U26A9';
  END IF;
  IF p_parent_location_id IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM ati.location l WHERE l.id = p_parent_location_id) THEN
    RAISE EXCEPTION 'location parent not found' USING ERRCODE = 'U26A2';
  END IF;

  SELECT l.id, l.version, l.name, l.parent_location_id
    INTO existing_id, existing_version, existing_name, existing_parent
    FROM ati.location l
    WHERE l.location_type = p_location_type
      AND l.country_code = p_country_code
      AND COALESCE(l.admin1_code, '') = COALESCE(p_admin1_code, '')
      AND COALESCE(l.admin2_code, '') = COALESCE(p_admin2_code, '')
      AND l.canonical_name = p_canonical_name
    FOR UPDATE;
  IF existing_id IS NOT NULL THEN
    IF existing_name IS DISTINCT FROM btrim(p_name)
       OR existing_parent IS DISTINCT FROM p_parent_location_id THEN
      RAISE EXCEPTION 'incompatible canonical location state'
        USING ERRCODE = 'U26A7';
    END IF;
    id := existing_id;
    version := existing_version;
    created := false;
    RETURN NEXT;
    RETURN;
  END IF;

  result_id := COALESCE(p_id, gen_random_uuid());
  version := nextval('ati.location_version_seq');
  BEGIN
    INSERT INTO ati.location AS loc(
      id, location_type, name, canonical_name, country_code,
      admin1_code, admin2_code, parent_location_id, version)
      VALUES(result_id, p_location_type, btrim(p_name), btrim(p_canonical_name),
             p_country_code, p_admin1_code, p_admin2_code,
             p_parent_location_id, version)
    ON CONFLICT (location_type, country_code,
                 (COALESCE(admin1_code, '')), (COALESCE(admin2_code, '')),
                 canonical_name) DO NOTHING;
  EXCEPTION
    WHEN unique_violation THEN
      -- ON CONFLICT absorbs canonical-identity races; a violation here can
      -- only be a caller-supplied id already bound to a different identity.
      RAISE EXCEPTION 'incompatible canonical location state'
        USING ERRCODE = 'U26A7';
  END;
  IF NOT FOUND THEN
    SELECT l.id, l.version, l.name, l.parent_location_id
      INTO existing_id, existing_version, existing_name, existing_parent
      FROM ati.location l
      WHERE l.location_type = p_location_type
        AND l.country_code = p_country_code
        AND COALESCE(l.admin1_code, '') = COALESCE(p_admin1_code, '')
        AND COALESCE(l.admin2_code, '') = COALESCE(p_admin2_code, '')
        AND l.canonical_name = p_canonical_name;
    IF existing_id IS NULL THEN
      RAISE EXCEPTION 'location conflict returned no row';
    END IF;
    IF existing_name IS DISTINCT FROM btrim(p_name)
       OR existing_parent IS DISTINCT FROM p_parent_location_id THEN
      RAISE EXCEPTION 'incompatible canonical location state'
        USING ERRCODE = 'U26A7';
    END IF;
    id := existing_id;
    version := existing_version;
    created := false;
    RETURN NEXT;
    RETURN;
  END IF;
  id := result_id;
  created := true;
  RETURN NEXT;
END $$;

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
  -- ordering or the effective time extends the earliest window.
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
        version = target.version + 1,
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

-- Create (or idempotently reuse) the initial PENDING GeoResolution work
-- record for one Entity/Evidence pair. The database validates the
-- Entity/Evidence binding and the GEOLOCATION Evidence type; the unique
-- (entity_id, evidence_id) constraint makes concurrent creation race-safe.
-- A duplicate pair returns the existing record unchanged only when it still
-- has the initial pending shape; anything else is U26A8.
CREATE OR REPLACE FUNCTION ati.create_geo_resolution(
  p_id uuid, p_entity_id uuid, p_evidence_id uuid)
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

  SELECT r.id, r.version, r.status, r.attempt_count, r.claimed_by,
         r.lease_expires_at, r.resolved_location_id, r.last_error_code
    INTO existing_id, existing_version, existing_status, existing_attempts,
         existing_claimed_by, existing_lease, existing_location, existing_error
    FROM ati.geo_resolution r
    WHERE r.entity_id = p_entity_id AND r.evidence_id = p_evidence_id;
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
      id, entity_id, evidence_id, status, attempt_count, version)
      VALUES(result_id, p_entity_id, p_evidence_id, 'pending', 0, version);
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
        WHERE r.entity_id = p_entity_id AND r.evidence_id = p_evidence_id;
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