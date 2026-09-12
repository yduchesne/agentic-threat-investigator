-- Immutable SQL API v0020 for PR 23C asynchronous investigation submission.
--
-- PR 23C exposes /api/v1 over FastAPI. POST /api/v1/investigations persists
-- the PENDING Investigation, its durable investigation job, the mutation
-- audit event, and the actor-scoped idempotency record in ONE transaction,
-- then returns 202 Accepted. The FastAPI process never runs the
-- investigation; a worker claims the durable job and invokes
-- InvestigationRunner later.
--
-- Two operational tables are introduced:
--
-- 1. ati.investigation_job — the minimal durable investigation-level
--    scheduler used by PR 23C. One job row exists per Investigation (the
--    unique investigation_id constraint makes a "logical job" exact).
--    Statuses are pending -> claimed -> succeeded|failed. Claiming uses
--    SELECT ... FOR UPDATE SKIP LOCKED so concurrent workers claim distinct
--    jobs without blocking; the claim and completion transitions are owned
--    by the stored functions below (Python never mutates this table
--    directly). PR 26 owns job administration/monitoring surfaces; this
--    file deliberately adds no scheduling vocabulary beyond the claim.
--
-- 2. ati.api_idempotency — durable idempotency records scoped by
--    (actor_id, operation, key_hash). The raw Idempotency-Key is never
--    stored: only its SHA-256 digest is persisted. The request fingerprint
--    is a canonical SHA-256 over the semantic normalized request, so
--    equivalent replays return the same Investigation while a different
--    semantic request with the same key fails closed (409). PostgreSQL
--    uniqueness makes concurrent identical submissions race-safe: exactly
--    one Investigation and one logical job are created.
--
-- Both tables are plain operational infrastructure: no version allocation,
-- no immutable history, no reconciliation, no row-level triggers.

CREATE TABLE IF NOT EXISTS ati.investigation_job (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  claimed_at timestamptz,
  completed_at timestamptz,
  error_code text,
  CONSTRAINT investigation_job_investigation_unique UNIQUE (investigation_id),
  CONSTRAINT investigation_job_status_check CHECK (
    status IN ('pending', 'claimed', 'succeeded', 'failed')),
  CONSTRAINT investigation_job_error_code_check CHECK (
    error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,63}$')
);

CREATE INDEX IF NOT EXISTS investigation_job_claim_idx
  ON ati.investigation_job(status, created_at, id);

CREATE TABLE IF NOT EXISTS ati.api_idempotency (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL,
  operation text NOT NULL,
  key_hash bytea NOT NULL,
  request_fingerprint text NOT NULL,
  resource_type text NOT NULL,
  resource_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT api_idempotency_scope_unique UNIQUE (actor_id, operation, key_hash),
  CONSTRAINT api_idempotency_operation_check CHECK (
    operation ~ '^[a-z][a-z0-9_]{0,63}$'),
  CONSTRAINT api_idempotency_fingerprint_check CHECK (
    request_fingerprint ~ '^[0-9a-f]{64}$'),
  CONSTRAINT api_idempotency_resource_type_check CHECK (
    resource_type ~ '^[a-z][a-z0-9_]{0,63}$')
);

CREATE INDEX IF NOT EXISTS api_idempotency_resource_idx
  ON ati.api_idempotency(resource_type, resource_id);

-- Claim the oldest pending job atomically. SKIP LOCKED lets concurrent
-- worker processes claim distinct jobs; the returned row is authoritative.
CREATE OR REPLACE FUNCTION ati.claim_next_investigation_job(
  p_claimed_at timestamptz DEFAULT now())
RETURNS TABLE(
  id uuid, investigation_id uuid, status text, created_at timestamptz,
  claimed_at timestamptz, completed_at timestamptz, error_code text)
LANGUAGE plpgsql AS $$
DECLARE claimed_id uuid;
BEGIN
  SELECT j.id INTO claimed_id
    FROM ati.investigation_job j
   WHERE j.status = 'pending'
   ORDER BY j.created_at, j.id
   FOR UPDATE SKIP LOCKED
   LIMIT 1;
  IF claimed_id IS NULL THEN
    RETURN;
  END IF;
  UPDATE ati.investigation_job AS target
     SET status = 'claimed', claimed_at = p_claimed_at
   WHERE target.id = claimed_id
   RETURNING target.id, target.investigation_id, target.status,
             target.created_at, target.claimed_at, target.completed_at,
             target.error_code
   INTO id, investigation_id, status, created_at, claimed_at, completed_at,
        error_code;
  RETURN NEXT;
END $$;

-- Complete a claimed job as succeeded or failed. A job that is not claimed
-- cannot be completed by a worker (the claim owns the execution lease).
CREATE OR REPLACE FUNCTION ati.complete_investigation_job(
  p_id uuid, p_status text, p_completed_at timestamptz DEFAULT now(),
  p_error_code text DEFAULT NULL)
RETURNS TABLE(id uuid, investigation_id uuid, status text, completed_at timestamptz)
LANGUAGE plpgsql AS $$
DECLARE current_status text;
BEGIN
  SELECT j.status INTO current_status
    FROM ati.investigation_job j
   WHERE j.id = p_id
   FOR UPDATE;
  IF current_status IS NULL THEN
    RAISE EXCEPTION 'investigation job not found' USING ERRCODE = 'U23C1';
  END IF;
  IF current_status <> 'claimed' THEN
    RAISE EXCEPTION 'investigation job is not claimed' USING ERRCODE = 'U23C2';
  END IF;
  IF p_status NOT IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'invalid investigation job status' USING ERRCODE = 'U23C3';
  END IF;
  IF p_error_code IS NOT NULL AND p_error_code !~ '^[a-z][a-z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'invalid investigation job error_code' USING ERRCODE = 'U23C4';
  END IF;
  UPDATE ati.investigation_job AS target
     SET status = p_status, completed_at = p_completed_at,
         error_code = p_error_code
   WHERE target.id = p_id
   RETURNING target.id, target.investigation_id, target.status,
             target.completed_at
   INTO id, investigation_id, status, completed_at;
  RETURN NEXT;
END $$;

-- Persist the durable job for one Investigation inside the submission
-- transaction. The unique investigation_id constraint rejects a duplicate
-- job for the same Investigation with a typed conflict.
CREATE OR REPLACE FUNCTION ati.create_investigation_job(
  p_investigation_id uuid, p_created_at timestamptz DEFAULT now())
RETURNS TABLE(id uuid, investigation_id uuid, status text, created_at timestamptz)
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO ati.investigation_job AS target
    (investigation_id, status, created_at)
    VALUES (p_investigation_id, 'pending', p_created_at)
  RETURNING target.id, target.investigation_id, target.status,
            target.created_at
  INTO id, investigation_id, status, created_at;
  RETURN NEXT;
END $$;