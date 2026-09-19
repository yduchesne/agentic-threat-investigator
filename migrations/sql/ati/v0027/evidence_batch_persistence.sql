-- Immutable SQL API v0027 for PR 28E: bounded at-least-once Evidence batch
-- persistence with message-receipt idempotency.
--
-- PR 28E connects the PR 28D Evidence-consumer seam to the PR 28B global
-- Evidence model. The application submits one bounded JSONB array (one
-- polled EvidenceBatch) and PostgreSQL persists the whole batch atomically
-- in one top-level call:
--
--   ati.persist_evidence_batch(p_items jsonb)
--     -> one row per input record, in input order, with the authoritative
--        outcome CREATED | UNCHANGED | APPENDED, the exact authoritative
--        EvidenceObservation.id, and the per-Evidence version.
--
-- The batch function reuses the authoritative PR 28B Evidence transition
-- (ati.persist_evidence_observation), the PR 18C Entity/Relationship
-- functions, the PR 28B association function, and the PR 28B
-- relationship-observation append; it never reimplements those algorithms.
--
-- Message receipts (the approved PR 28E amendment to STOP #16):
--
--   ati.evidence_message_receipt  transactional idempotency ONLY, keyed by
--                                 the stable PR 28C message_id. It contains
--                                 no Kafka/log position, no partition, no
--                                 consumer-group, and no Investigation
--                                 semantics. A receipt is written in the
--                                 same transaction as the Evidence/graph
--                                 persistence it records; a redelivered
--                                 message_id returns its previously
--                                 established authoritative result WITHOUT
--                                 invoking the Evidence transition or
--                                 recreating derived graph state.
--
-- Replay semantics under at-least-once delivery:
--
--   - exact redelivery of a committed message_id -> receipt hit,
--     established result returned, no state transition, no derived writes;
--   - the same message twice within one batch -> second occurrence is a
--     receipt hit inside the same transaction;
--   - a later acquisition with the same material state but a NEW message_id
--     -> still processed through the authoritative transition (UNCHANGED);
--     receipts are never matched by material state or by searching
--     historical observations;
--   - multiple messages of one Evidence inside one batch -> processed in
--     input (log) order; the receipt never reorders versions;
--   - PostgreSQL commit succeeded / consumer commit failed -> the same
--     batch is redelivered, every receipt hits, and no additional
--     observation or derived row is created.
--
-- Observation identity (chosen Option A): PostgreSQL's returned
-- evidence_observation_id is authoritative; observation_candidate_id is
-- proposed to ati.persist_evidence_observation (used by the CREATED branch)
-- but is NOT required to become the persisted ID on APPENDED.
--
-- Typed SQLSTATE mapping (new PR 28E codes):
--   U28E1 invalid evidence batch input (shape, empty, endpoint not covered)
--   U28E2 evidence batch too large (SQL-side hard bound)
-- Reused inner SQLSTATEs keep their established meaning; where the batch
-- function re-raises them it attaches the failing bounded identity in
-- DETAIL so the adapter can build the identical typed application error:
--   U28B1/U28B2/U28B3 DETAIL = failing evidence_id
--   U18C2                       DETAIL = soft-deleted entity id
--   U18C1                       DETAIL = soft-deleted relationship id

CREATE TABLE ati.evidence_message_receipt (
  message_id uuid PRIMARY KEY,
  evidence_id uuid NOT NULL REFERENCES ati.evidence(id),
  evidence_observation_id uuid NOT NULL REFERENCES ati.evidence_observation(id),
  version bigint NOT NULL CHECK (version >= 1),
  outcome text NOT NULL CHECK (outcome IN ('CREATED', 'UNCHANGED', 'APPENDED')),
  processed_at timestamptz NOT NULL DEFAULT now()
);
-- Index evidence_id for the operational diagnostics of one Evidence's
-- processed messages; the receipt table is never a broker-offset store.
CREATE INDEX evidence_message_receipt_evidence_idx
  ON ati.evidence_message_receipt(evidence_id, message_id);

-- Persist one bounded prepared Evidence batch atomically and return the
-- ordered authoritative results. The SQL-side bound is independent of the
-- application bound (defense in depth): oversized input is rejected with no
-- mutation.
CREATE OR REPLACE FUNCTION ati.persist_evidence_batch(p_items jsonb)
RETURNS TABLE(
  batch_ordinal bigint, out_message_id uuid, out_evidence_id uuid,
  out_evidence_observation_id uuid, out_version bigint, out_outcome text)
LANGUAGE plpgsql AS $$
DECLARE
  v_hard_limit CONSTANT integer := 500;
  v_index bigint := 0;
  v_item jsonb;
  v_evidence jsonb;
  v_observation jsonb;
  v_entities jsonb;
  v_relationships jsonb;
  v_entity jsonb;
  v_rel jsonb;
  v_message_id uuid;
  v_candidate_id uuid;
  v_evidence_id uuid;
  v_evidence_type text;
  v_source text;
  v_source_record_id text;
  v_observation_id uuid;
  v_observed_at timestamptz;
  v_retrieved_at timestamptz;
  v_facts jsonb;
  v_raw_payload jsonb;
  v_outcome text;
  v_version bigint;
  v_receipt_won uuid;
  v_entity_map jsonb;
  v_entity_id uuid;
  v_source_entity_id uuid;
  v_target_entity_id uuid;
  v_relationship_id uuid;
  v_deleted_id uuid;
BEGIN
  -- Bounded input validation (fail closed even if Python validation is
  -- bypassed).
  IF p_items IS NULL OR jsonb_typeof(p_items) <> 'array' THEN
    RAISE EXCEPTION 'invalid evidence batch input'
      USING ERRCODE = 'U28E1';
  END IF;
  IF jsonb_array_length(p_items) = 0 THEN
    RAISE EXCEPTION 'invalid evidence batch input: empty batch'
      USING ERRCODE = 'U28E1';
  END IF;
  IF jsonb_array_length(p_items) > v_hard_limit THEN
    RAISE EXCEPTION 'evidence batch too large'
      USING ERRCODE = 'U28E2';
  END IF;

  FOR v_item IN SELECT * FROM jsonb_array_elements(p_items) LOOP
    v_index := v_index + 1;
    IF jsonb_typeof(v_item) <> 'object' THEN
      RAISE EXCEPTION 'invalid evidence batch input: item shape'
        USING ERRCODE = 'U28E1';
    END IF;
    v_message_id := (v_item->>'message_id')::uuid;
    v_candidate_id := (v_item->>'observation_candidate_id')::uuid;
    v_evidence := v_item->'evidence';
    v_observation := v_item->'observation';
    IF v_message_id IS NULL OR v_candidate_id IS NULL
       OR v_evidence IS NULL OR v_observation IS NULL
       OR jsonb_typeof(v_evidence) <> 'object'
       OR jsonb_typeof(v_observation) <> 'object' THEN
      RAISE EXCEPTION 'invalid evidence batch input: item shape'
        USING ERRCODE = 'U28E1';
    END IF;
    v_evidence_id := (v_evidence->>'id')::uuid;
    v_evidence_type := v_evidence->>'type';
    v_source := v_evidence->>'source';
    v_source_record_id := v_evidence->>'source_record_id';
    v_retrieved_at := (v_observation->>'retrieved_at')::timestamptz;
    IF v_evidence_id IS NULL OR v_evidence_type IS NULL OR v_source IS NULL
       OR v_source_record_id IS NULL OR v_retrieved_at IS NULL THEN
      RAISE EXCEPTION 'invalid evidence batch input: item shape'
        USING ERRCODE = 'U28E1';
    END IF;
    v_observed_at := (v_observation->>'observed_at')::timestamptz;
    v_facts := v_observation->'facts';
    v_raw_payload := v_observation->'raw_payload';

    -- 1. Receipt lookup: a committed message returns its established
    -- authoritative result without invoking the Evidence transition or any
    -- derived graph write. PL/pgSQL ``SELECT INTO`` writes NULL when no row
    -- is found, so the lookup variables are reset first to preserve the
    -- already-parsed input identity for the transition below.
    v_evidence_id := NULL;
    v_observation_id := NULL;
    v_version := NULL;
    v_outcome := NULL;
    SELECT r.evidence_id, r.evidence_observation_id, r.version, r.outcome
      INTO v_evidence_id, v_observation_id, v_version, v_outcome
      FROM ati.evidence_message_receipt r
      WHERE r.message_id = v_message_id;
    IF FOUND THEN
      batch_ordinal := v_index;
      out_message_id := v_message_id;
      out_evidence_id := v_evidence_id;
      out_evidence_observation_id := v_observation_id;
      out_version := v_version;
      out_outcome := v_outcome;
      RETURN NEXT;
      CONTINUE;
    END IF;

    -- 2. Authoritative Evidence transition (PR 28B; unchanged semantics).
    v_evidence_id := (v_evidence->>'id')::uuid;
    BEGIN
      SELECT p.evidence_id, p.evidence_observation_id, p.version, p.outcome
        INTO v_evidence_id, v_observation_id, v_version, v_outcome
        FROM ati.persist_evidence_observation(
          v_evidence_id, v_evidence_type, v_source, v_source_record_id,
          v_observation->>'source_url', v_observed_at, v_retrieved_at,
          v_facts, v_raw_payload, NULL, v_candidate_id) AS p;
    EXCEPTION WHEN others THEN
      IF SQLSTATE = 'U28B1' THEN
        RAISE EXCEPTION 'stable evidence metadata conflict'
          USING ERRCODE = 'U28B1', DETAIL = v_evidence_id::text;
      ELSIF SQLSTATE = 'U28B2' THEN
        RAISE EXCEPTION 'evidence observation not found'
          USING ERRCODE = 'U28B2', DETAIL = v_evidence_id::text;
      ELSIF SQLSTATE = 'U28B3' THEN
        RAISE EXCEPTION 'invalid evidence observation input'
          USING ERRCODE = 'U28B3', DETAIL = v_evidence_id::text;
      END IF;
      RAISE;
    END;

    -- 3. Record the receipt atomically with the transition. A concurrent
    -- winner (same message_id committed elsewhere) wins the receipt; its
    -- authoritative result is returned and no derived work is repeated by
    -- this transaction.
    INSERT INTO ati.evidence_message_receipt(
      message_id, evidence_id, evidence_observation_id, version, outcome)
      VALUES(v_message_id, v_evidence_id, v_observation_id, v_version, v_outcome)
      ON CONFLICT (message_id) DO NOTHING
      RETURNING message_id INTO v_receipt_won;
    IF v_receipt_won IS NULL THEN
      v_evidence_id := NULL;
      v_observation_id := NULL;
      v_version := NULL;
      v_outcome := NULL;
      SELECT r.evidence_id, r.evidence_observation_id, r.version, r.outcome
        INTO v_evidence_id, v_observation_id, v_version, v_outcome
        FROM ati.evidence_message_receipt r
        WHERE r.message_id = v_message_id;
      batch_ordinal := v_index;
      out_message_id := v_message_id;
      out_evidence_id := v_evidence_id;
      out_evidence_observation_id := v_observation_id;
      out_version := v_version;
      out_outcome := v_outcome;
      RETURN NEXT;
      CONTINUE;
    END IF;

    -- 4. Derived graph provenance only for a new/appended observation of
    -- this transaction; an unchanged retrieval and every receipt hit create
    -- no Entity/Relationship churn and no duplicate RelationshipObservation.
    IF v_outcome IN ('CREATED', 'APPENDED') THEN
      v_entities := v_item->'entities';
      IF v_entities IS NULL OR jsonb_typeof(v_entities) <> 'array' THEN
        RAISE EXCEPTION 'invalid evidence batch input: entities shape'
          USING ERRCODE = 'U28E1';
      END IF;
      v_entity_map := '{}'::jsonb;
      FOR v_entity IN SELECT * FROM jsonb_array_elements(v_entities) LOOP
        IF jsonb_typeof(v_entity) <> 'object'
           OR v_entity->>'type' IS NULL OR v_entity->>'value' IS NULL THEN
          RAISE EXCEPTION 'invalid evidence batch input: entity shape'
            USING ERRCODE = 'U28E1';
        END IF;
        BEGIN
          SELECT ent.id INTO v_entity_id
            FROM ati.upsert_entity(
              NULL, v_entity->>'type', v_entity->>'value',
              v_entity->>'display_name', '{}'::jsonb, NULL, NULL) AS ent;
        EXCEPTION WHEN others THEN
          IF SQLSTATE = 'U18C2' THEN
            SELECT e.id INTO v_deleted_id
              FROM ati.entity e
              WHERE e.entity_type = v_entity->>'type'
                AND e.canonical_value = v_entity->>'value'
                AND e.deleted_at IS NOT NULL;
            RAISE EXCEPTION 'soft-deleted entity rediscovered'
              USING ERRCODE = 'U18C2',
                DETAIL = COALESCE(v_deleted_id::text, 'unknown');
          END IF;
          RAISE;
        END;
        v_entity_map := jsonb_set(
          v_entity_map,
          ARRAY[(v_entity->>'type') || '|' || (v_entity->>'value')],
          to_jsonb(v_entity_id),
          true);
        PERFORM a.evidence_observation_id
          FROM ati.associate_evidence_observation_entity(
            v_observation_id, v_entity_id) AS a;
      END LOOP;

      -- Stable edge resolution + exactly one immutable RelationshipObservation
      -- per unique extracted assertion, referencing the exact authoritative
      -- EvidenceObservation created/appended by this transaction.
      v_relationships := v_item->'relationships';
      IF v_relationships IS NULL OR jsonb_typeof(v_relationships) <> 'array' THEN
        RAISE EXCEPTION 'invalid evidence batch input: relationships shape'
          USING ERRCODE = 'U28E1';
      END IF;
      FOR v_rel IN SELECT * FROM jsonb_array_elements(v_relationships) LOOP
        IF jsonb_typeof(v_rel) <> 'object'
           OR v_rel->>'source_type' IS NULL OR v_rel->>'source_value' IS NULL
           OR v_rel->>'type' IS NULL
           OR v_rel->>'target_type' IS NULL OR v_rel->>'target_value' IS NULL THEN
          RAISE EXCEPTION 'invalid evidence batch input: relationship shape'
            USING ERRCODE = 'U28E1';
        END IF;
        v_source_entity_id := (v_entity_map
          ->> ((v_rel->>'source_type') || '|' || (v_rel->>'source_value')))::uuid;
        v_target_entity_id := (v_entity_map
          ->> ((v_rel->>'target_type') || '|' || (v_rel->>'target_value')))::uuid;
        IF v_source_entity_id IS NULL OR v_target_entity_id IS NULL THEN
          RAISE EXCEPTION
            'invalid evidence batch input: relationship endpoint not covered'
            USING ERRCODE = 'U28E1';
        END IF;
        BEGIN
          SELECT rel.id INTO v_relationship_id
            FROM ati.upsert_relationship(
              v_source_entity_id, v_target_entity_id, v_rel->>'type') AS rel;
        EXCEPTION WHEN others THEN
          IF SQLSTATE = 'U18C1' THEN
            SELECT r.id INTO v_deleted_id
              FROM ati.relationship r
              WHERE r.source_entity_id = v_source_entity_id
                AND r.target_entity_id = v_target_entity_id
                AND r.relationship_type_urn = v_rel->>'type'
                AND r.deleted_at IS NOT NULL;
            RAISE EXCEPTION 'soft-deleted relationship rediscovered'
              USING ERRCODE = 'U18C1',
                DETAIL = COALESCE(v_deleted_id::text, 'unknown');
          END IF;
          RAISE;
        END;
        PERFORM o.id
          FROM ati.append_relationship_observation(
            gen_random_uuid(), v_relationship_id, v_observation_id,
            v_observed_at, v_retrieved_at, v_source, NULL) AS o;
      END LOOP;
    END IF;

    batch_ordinal := v_index;
    out_message_id := v_message_id;
    out_evidence_id := v_evidence_id;
    out_evidence_observation_id := v_observation_id;
    out_version := v_version;
    out_outcome := v_outcome;
    RETURN NEXT;
  END LOOP;
END $$;