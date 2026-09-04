-- Immutable SQL API version v0003 of the entity batch upsert.
-- Differences from v0002:
--   * outcomes are INSERTED/UPDATED/UNCHANGED/CONFLICT (the application enum
--     contract); v0002 returned INSERT/UPDATE, which the repository could not
--     deserialize.
--   * within-batch duplicates on (entity_type, canonical_value) keep the
--     lowest input ordinal; later duplicates are classified CONFLICT and
--     reported with the winning row's identity instead of raising a unique
--     violation that aborts the transaction.
--   * inserts are conflict-aware; rows that lose an insert race against a
--     concurrent transaction are re-classified from the observed row state
--     (UNCHANGED/UPDATED/CONFLICT) rather than aborting the transaction.
--   * staging tables are dropped before creation so the function can run
--     more than once per transaction.
-- The ati.entity_batch_item composite type is owned by v0002 and is reused
-- unchanged.
CREATE OR REPLACE FUNCTION ati.upsert_entities(p_items ati.entity_batch_item[])
RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text)
LANGUAGE plpgsql AS $$
DECLARE hard_limit CONSTANT integer := 10000;
BEGIN
  IF cardinality(p_items) > hard_limit THEN
    RAISE EXCEPTION 'entity batch exceeds defensive limit of % items', hard_limit USING ERRCODE = '22023';
  END IF;
  DROP TABLE IF EXISTS ati_entity_batch_input;
  CREATE TEMP TABLE ati_entity_batch_input (ordinal bigint NOT NULL, primary_ordinal bigint NOT NULL, id uuid, entity_type text NOT NULL, canonical_value text NOT NULL, display_name text, attributes jsonb, content_hash bytea, expected_version bigint) ON COMMIT DROP;
  DROP TABLE IF EXISTS ati_entity_batch_reconciliation;
  CREATE TEMP TABLE ati_entity_batch_reconciliation (ordinal bigint PRIMARY KEY, id uuid, entity_type text NOT NULL, canonical_value text NOT NULL, display_name text, attributes jsonb, content_hash bytea, expected_version bigint, observed_version bigint, old_state jsonb, classification text NOT NULL) ON COMMIT DROP;
  DROP TABLE IF EXISTS ati_entity_batch_mutation;
  CREATE TEMP TABLE ati_entity_batch_mutation (ordinal bigint PRIMARY KEY, id uuid NOT NULL, version bigint NOT NULL, operation text NOT NULL, old_state jsonb, new_state jsonb) ON COMMIT DROP;

  INSERT INTO ati_entity_batch_input
  SELECT staged.ordinal, min(staged.ordinal) OVER (PARTITION BY staged.entity_type, staged.canonical_value), staged.id, staged.entity_type, staged.canonical_value, staged.display_name, staged.attributes, staged.content_hash, staged.expected_version
  FROM (SELECT COALESCE(u.item_ordinal, u.input_ordinal) AS ordinal, u.item_id AS id, u.item_entity_type AS entity_type, u.item_canonical_value AS canonical_value, u.item_display_name AS display_name, COALESCE(u.item_attributes, '{}'::jsonb) AS attributes, u.item_content_hash AS content_hash, u.item_expected_version AS expected_version
        FROM unnest(p_items) WITH ORDINALITY AS u(item_ordinal, item_id, item_entity_type, item_canonical_value, item_display_name, item_attributes, item_content_hash, item_expected_version, input_ordinal)) staged;

  INSERT INTO ati_entity_batch_reconciliation
  SELECT i.ordinal, COALESCE(e.id, i.id), i.entity_type, i.canonical_value, i.display_name, i.attributes, i.content_hash, i.expected_version, e.version, to_jsonb(e),
    CASE WHEN e.id IS NULL THEN 'INSERTED' WHEN i.expected_version IS NOT NULL AND i.expected_version <> e.version THEN 'CONFLICT' WHEN e.display_name IS NOT DISTINCT FROM i.display_name AND e.attributes IS NOT DISTINCT FROM i.attributes AND e.content_hash IS NOT DISTINCT FROM i.content_hash THEN 'UNCHANGED' ELSE 'UPDATED' END
  FROM ati_entity_batch_input i LEFT JOIN ati.entity e ON e.entity_type = i.entity_type AND e.canonical_value = i.canonical_value
  WHERE i.ordinal = i.primary_ordinal;

  WITH candidates AS (SELECT r.* FROM ati_entity_batch_reconciliation r WHERE r.classification = 'INSERTED'), written AS (
    INSERT INTO ati.entity AS target(id, entity_type, canonical_value, display_name, attributes, content_hash, version)
    SELECT COALESCE(candidates.id, gen_random_uuid()), candidates.entity_type, candidates.canonical_value, candidates.display_name, candidates.attributes, candidates.content_hash, nextval('ati.entity_version_seq') FROM candidates
    ON CONFLICT (entity_type, canonical_value) DO NOTHING
    RETURNING target.id, target.entity_type, target.canonical_value, target.version, to_jsonb(target) AS new_state)
  INSERT INTO ati_entity_batch_mutation SELECT c.ordinal, w.id, w.version, 'CREATE', NULL, w.new_state FROM candidates c JOIN written w USING (entity_type, canonical_value);

  UPDATE ati_entity_batch_reconciliation r
  SET id = e.id, observed_version = e.version, old_state = to_jsonb(e),
      classification = CASE WHEN r.expected_version IS NOT NULL AND r.expected_version <> e.version THEN 'CONFLICT' WHEN e.display_name IS NOT DISTINCT FROM r.display_name AND e.attributes IS NOT DISTINCT FROM r.attributes AND e.content_hash IS NOT DISTINCT FROM r.content_hash THEN 'UNCHANGED' ELSE 'UPDATED' END
  FROM ati.entity e
  WHERE r.classification = 'INSERTED'
    AND NOT EXISTS (SELECT 1 FROM ati_entity_batch_mutation m WHERE m.ordinal = r.ordinal)
    AND e.entity_type = r.entity_type AND e.canonical_value = r.canonical_value;

  WITH candidates AS (SELECT r.* FROM ati_entity_batch_reconciliation r WHERE r.classification = 'UPDATED'), written AS (
    UPDATE ati.entity e SET display_name=c.display_name, attributes=c.attributes, content_hash=c.content_hash, version=nextval('ati.entity_version_seq'), updated_at=now()
    FROM candidates c WHERE e.entity_type=c.entity_type AND e.canonical_value=c.canonical_value AND e.version=c.observed_version
    RETURNING c.ordinal, e.id, e.version, c.old_state, to_jsonb(e) AS new_state)
  INSERT INTO ati_entity_batch_mutation SELECT w.ordinal, w.id, w.version, 'UPDATE', w.old_state, w.new_state FROM written w;

  UPDATE ati_entity_batch_reconciliation r SET classification = 'CONFLICT' WHERE r.classification = 'UPDATED' AND NOT EXISTS (SELECT 1 FROM ati_entity_batch_mutation m WHERE m.ordinal=r.ordinal);

  INSERT INTO ati.domain_object_history(object_type, object_id, version, operation, state, diff)
  SELECT 'entity', m.id, m.version, m.operation, m.new_state, CASE WHEN m.operation = 'CREATE' THEN '{}'::jsonb ELSE ati.ati_jsonb_diff(m.old_state - ARRAY['version','created_at','updated_at','deleted_at','deleted_by_actor_id']::text[], m.new_state - ARRAY['version','created_at','updated_at','deleted_at','deleted_by_actor_id']::text[]) END FROM ati_entity_batch_mutation m;

  RETURN QUERY
  SELECT r.ordinal, COALESCE(m.id, r.id), COALESCE(m.version, r.observed_version), r.classification
  FROM ati_entity_batch_reconciliation r LEFT JOIN ati_entity_batch_mutation m USING (ordinal)
  UNION ALL
  SELECT d.ordinal, COALESCE(m.id, e.id, d.id), COALESCE(m.version, e.version), 'CONFLICT'
  FROM ati_entity_batch_input d
  LEFT JOIN ati_entity_batch_mutation m ON m.ordinal = d.primary_ordinal
  LEFT JOIN ati.entity e ON e.entity_type = d.entity_type AND e.canonical_value = d.canonical_value
  WHERE d.ordinal <> d.primary_ordinal
  ORDER BY 1;
END $$;
