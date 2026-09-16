-- Immutable SQL API v0024 for PR 26C: asynchronous geographic-resolution
-- lifecycle.
--
-- PR 26A persisted initial PENDING GeoResolution rows and reads only
-- (SQL API v0021/v0022); PR 26B added canonical reference/spatial geography
-- (SQL API v0023). This version installs the bounded asynchronous work
-- lifecycle on the SAME ati.geo_resolution table: no second queue table,
-- no broker.
--
-- A GeoResolution row is durable work state. Workers claim bounded work in
-- one short committed transaction (claim_geo_resolutions), perform
-- geographic resolution with NO database lock or transaction held, and then
-- persist the outcome through a second short transaction:
--
--   RESOLVED      complete_geo_resolution_resolved  (observation + current
--                                                   state + terminal, one
--                                                   atomic stored function)
--   UNRESOLVABLE  complete_geo_resolution_unresolvable (terminal, no
--                                                   observation)
--   retryable     record_geo_resolution_failure    (PENDING + bounded
--                                                   next_attempt_at)
--   exhausted/    record_geo_resolution_failure    (FAILED, terminal)
--   terminal error
--
-- State machine (v0.1):
--
--   PENDING
--     -> PROCESSING on eligible claim
--   PROCESSING
--     -> RESOLVED            (successful atomic completion)
--     -> UNRESOLVABLE        (deterministic no-match/ambiguity, never guessed)
--     -> PENDING             (retryable failure with attempts remaining)
--     -> FAILED              (terminal error or attempt budget exhausted)
--   expired PROCESSING
--     -> PROCESSING under a new claim, if attempts remain
--     -> FAILED              (attempt budget already exhausted)
--
-- Terminal: RESOLVED, UNRESOLVABLE, FAILED. Terminal rows are never claimed.
--
-- Claim semantics:
--   - eligible = PENDING and (next_attempt_at IS NULL or <= DB now)
--                OR PROCESSING with expired lease (lease_expires_at <= now);
--   - deterministic ordering: eligibility time ASC (COALESCE(next_attempt_at,
--     created_at) for PENDING, lease_expires_at for PROCESSING), then
--     created_at ASC, then id ASC;
--   - bounded rows are locked with FOR UPDATE SKIP LOCKED inside one short
--     stored-function transaction and transitioned to PROCESSING with the
--     claimant, lease expiry, attempt +1, and a fresh database version.
--     Repositories never commit; the caller's UnitOfWork is the commit
--     boundary, and the COMMIT always precedes resolution work;
--   - attempt_count counts started processing attempts: new PENDING = 0,
--     first claim = 1, each retry transition retains N, the next claim is
--     N+1, and an expired-lease reclaim is N+1. Attempt max_attempts + 1 is
--     never started: expired work already at the budget becomes FAILED
--     instead of being reclaimed;
--   - PROCESSING requires non-null claimant and lease expiry; leaving
--     PROCESSING clears the lease fields. DB time is authoritative for
--     eligibility and expiry. Leases coordinate workers; long-held row locks
--     never do.
--
-- Stale-worker protection: every completion/failure request supplies
-- (resolution id, expected version, claimed_by); the database verifies
-- PROCESSING status, matching version, matching claimant, and a live lease
-- before any mutation. A stale worker (A) whose lease expired and whose row
-- was reclaimed by B can never create an observation or overwrite B.
--
-- Retry policy: deterministic bounded exponential backoff
-- (base * 2^(attempt_count - 1), capped at the max; no jitter). A retryable
-- failure with budget returns PROCESSING -> PENDING with a fresh version and
-- next_attempt_at = DB now + bounded delay; at exhaustion the row becomes
-- FAILED with no next attempt. Non-transient conditions (malformed Evidence,
-- provenance violations, deterministic ambiguity/no-match) are never retried.
--
-- Successful completion is ONE atomic stored function
-- (complete_geo_resolution_resolved): it validates status/version/claimant/
-- live lease and the exact Entity/Evidence/Location provenance, appends
-- exactly one immutable EntityLocationObservation (reusing the versioned
-- append semantics of SQL API v0022 for observation insert + current-state
-- reconciliation), records the resolved Location, clears lease/retry/error
-- state, and allocates a fresh DB version. Observation identity is
-- deterministic (UUIDv5 of the GeoResolution id under the fixed ATI
-- observation namespace), so an uncertain-commit replay of the exact same
-- successful completion is an idempotent no-op that can never duplicate an
-- observation; a terminal replay that disagrees with the settled outcome is
-- a typed conflict with no mutation.
--
-- Typed SQLSTATE mapping (new U26C* codes; U26A* provenance codes are
-- reused when semantics match, see SQL API v0021):
--   U26A1 geo entity not found / invisible
--   U26A2 geo location not found
--   U26A3 geo evidence not found
--   U26A4 geo evidence is not GEOLOCATION
--   U26A5 geo evidence subject mismatch
--   U26A6 geo observation duplicate identity
--   U26A9 invalid GEOINT input shape
--   U26C1 geo resolution not found
--   U26C2 invalid geo resolution transition
--   U26C3 stale geo resolution version
--   U26C4 geo resolution claim owner mismatch
--   U26C5 geo resolution lease expired
--   U26C6 invalid geo resolution retry/exhaustion (defensive)
--   U26C7 geo resolution terminal replay conflict
--
-- Row-level triggers are never used for versioning or history; every
-- lifecycle mutation is owned by these versioned stored functions.

-- Claim a bounded batch of eligible work and transition it to PROCESSING.
-- Expired PROCESSING rows already at the attempt budget become FAILED and are
-- never returned as claimed; a PENDING row already at the budget (corrupt
-- state or a lowered budget) also fails closed as U26C6 instead of starting
-- attempt max_attempts + 1.
CREATE OR REPLACE FUNCTION ati.claim_geo_resolutions(
  p_claimed_by text,
  p_claim_limit integer,
  p_lease_seconds integer,
  p_max_attempts integer)
RETURNS TABLE(
  id uuid, entity_id uuid, evidence_id uuid, status text,
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
    evidence_id := r.evidence_id;
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
  id uuid, entity_id uuid, evidence_id uuid, status text,
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
          AND obs.evidence_id = r.evidence_id) THEN
      RAISE EXCEPTION 'geo resolution terminal replay conflict'
        USING ERRCODE = 'U26C7';
    END IF;
    id := r.id;
    entity_id := r.entity_id;
    evidence_id := r.evidence_id;
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
  IF NOT EXISTS (SELECT 1 FROM ati.evidence ev WHERE ev.id = r.evidence_id) THEN
    RAISE EXCEPTION 'geo evidence not found' USING ERRCODE = 'U26A3';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence ev
      WHERE ev.id = r.evidence_id
        AND ev.evidence_type = 'urn:ati:evidence:geolocation') THEN
    RAISE EXCEPTION 'geo evidence is not geolocation' USING ERRCODE = 'U26A4';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM ati.evidence ev
      WHERE ev.id = r.evidence_id AND ev.subject_entity_id = r.entity_id) THEN
    RAISE EXCEPTION 'geo evidence subject mismatch' USING ERRCODE = 'U26A5';
  END IF;

  IF NOT EXISTS (
      SELECT 1 FROM ati.entity_location_observation obs
      WHERE obs.id = p_observation_id) THEN
    -- Reuse the versioned observation append + current-state reconciliation
    -- of SQL API v0022 so PR 26C never forks the reconciliation algorithm.
    SELECT 1 INTO v_unused
      FROM ati.append_entity_location_observation(
        p_observation_id, r.entity_id, p_location_id, r.evidence_id,
        p_precision, p_observed_at, p_retrieved_at, p_resolved_at,
        btrim(p_resolution_method));
  ELSIF NOT EXISTS (
      SELECT 1 FROM ati.entity_location_observation obs
      WHERE obs.id = p_observation_id
        AND obs.entity_id = r.entity_id
        AND obs.location_id = p_location_id
        AND obs.evidence_id = r.evidence_id) THEN
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
  evidence_id := r.evidence_id;
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
  id uuid, entity_id uuid, evidence_id uuid, status text,
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
    evidence_id := r.evidence_id;
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
  evidence_id := r.evidence_id;
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
  id uuid, entity_id uuid, evidence_id uuid, status text,
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
    evidence_id := r.evidence_id;
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
  evidence_id := r.evidence_id;
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