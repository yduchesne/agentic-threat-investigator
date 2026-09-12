-- Immutable SQL API v0018 for relationship persistence and relationship observations.
--
-- PR 22E: RelationshipObservation is itself historical data. The immutable
-- relationship_observation row (caller-supplied identity, evidence
-- provenance, database-allocated version, observation timestamps) is the
-- authoritative historical record for an observed edge. PR 18C's v0008
-- additionally appended a redundant CREATE domain_object_history row for
-- every observation; this version removes that duplicate history write.
-- All observation provenance and integrity semantics are unchanged.
--
-- The stable Relationship resource remains a distinct, historized concept:
-- - ati.upsert_relationship resolves the stable three-part edge identity,
--   returns the observed row unchanged for reuse (no version/history), makes
--   creation race-safe through the authoritative unique index, writes
--   immutable CREATE history for new edges, and raises the dedicated
--   SQLSTATE when the identity exists only as a soft-deleted row.
-- - ati.append_relationship_observation appends one immutable observation
--   with a database-allocated version and no domain_object_history row.
--   No update/delete path exists.
-- Row-level triggers are never used for versioning or history.

CREATE OR REPLACE FUNCTION ati.upsert_relationship(
  p_source_entity_id uuid, p_target_entity_id uuid,
  p_relationship_type_urn text)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE current_state jsonb; current_version bigint; result_id uuid;
BEGIN
  -- Order while holding the row lock: load, soft-deleted, unchanged,
  -- create. A concurrent creator is resolved by re-reading the observed
  -- row instead of surfacing a raw unique violation.
  SELECT to_jsonb(r), r.version INTO current_state, current_version
    FROM ati.relationship r
    WHERE r.source_entity_id = p_source_entity_id
      AND r.target_entity_id = p_target_entity_id
      AND r.relationship_type_urn = p_relationship_type_urn
    FOR UPDATE;
  IF current_state IS NOT NULL THEN
    IF (current_state->>'deleted_at') IS NOT NULL THEN
      RAISE EXCEPTION 'soft-deleted relationship rediscovered'
        USING ERRCODE = 'U18C1';
    END IF;
    -- Reuse is a semantic no-op: no version and no history.
    id := (current_state->>'id')::uuid;
    version := current_version;
    created := false;
    RETURN NEXT;
    RETURN;
  END IF;
  version := nextval('ati.relationship_version_seq');
  BEGIN
    INSERT INTO ati.relationship AS rel(
      id, source_entity_id, target_entity_id, relationship_type_urn, version)
      VALUES(gen_random_uuid(), p_source_entity_id, p_target_entity_id,
             p_relationship_type_urn, version)
    RETURNING rel.id INTO result_id;
  EXCEPTION
    WHEN unique_violation THEN
      -- A concurrent transaction created the same canonical edge; observed
      -- state wins and is never silently overwritten.
      SELECT to_jsonb(r), r.version INTO current_state, current_version
        FROM ati.relationship r
        WHERE r.source_entity_id = p_source_entity_id
          AND r.target_entity_id = p_target_entity_id
          AND r.relationship_type_urn = p_relationship_type_urn
        FOR UPDATE;
      IF current_state IS NULL THEN  -- pragma-free defensive recheck
        RAISE EXCEPTION 'relationship conflict returned no row';
      END IF;
      IF (current_state->>'deleted_at') IS NOT NULL THEN
        RAISE EXCEPTION 'soft-deleted relationship rediscovered'
          USING ERRCODE = 'U18C1';
      END IF;
      id := (current_state->>'id')::uuid;
      version := current_version;
      created := false;
      RETURN NEXT;
      RETURN;
  END;
  id := result_id;
  created := true;
  SELECT to_jsonb(r) INTO current_state
    FROM ati.relationship r WHERE r.id = result_id;
  INSERT INTO ati.domain_object_history(
    object_type, object_id, version, operation, state, diff)
    VALUES('relationship', result_id, version, 'CREATE', current_state,
           '{}'::jsonb);
  RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.append_relationship_observation(
  p_id uuid, p_relationship_id uuid, p_evidence_id uuid,
  p_investigation_id uuid, p_observed_at timestamptz,
  p_retrieved_at timestamptz, p_source text, p_confidence double precision)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
BEGIN
  -- The immutable observation row is the historical record: append it with
  -- a database-allocated version and provenance, and write no
  -- domain_object_history row. No update/delete path exists.
  version := nextval('ati.relationship_observation_version_seq');
  INSERT INTO ati.relationship_observation(
    id, relationship_id, evidence_id, investigation_id, observed_at,
    retrieved_at, source, confidence, version)
    VALUES(p_id, p_relationship_id, p_evidence_id, p_investigation_id,
           p_observed_at, p_retrieved_at, p_source, p_confidence, version);
  id := p_id;
  RETURN NEXT;
END $$;