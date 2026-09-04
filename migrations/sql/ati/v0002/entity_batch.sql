CREATE TYPE ati.entity_batch_item AS (
  ordinal bigint, id uuid, entity_type text, canonical_value text,
  display_name text, attributes jsonb, content_hash bytea, expected_version bigint
);

CREATE OR REPLACE FUNCTION ati.upsert_entities(p_items ati.entity_batch_item[])
RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text)
LANGUAGE plpgsql AS $$
DECLARE hard_limit CONSTANT integer := 10000;
BEGIN
  IF cardinality(p_items) > hard_limit THEN
    RAISE EXCEPTION 'entity batch exceeds defensive limit of % items', hard_limit USING ERRCODE = '22023';
  END IF;
  CREATE TEMP TABLE ati_entity_batch_input (ordinal bigint NOT NULL, id uuid, entity_type text NOT NULL, canonical_value text NOT NULL, display_name text, attributes jsonb, content_hash bytea, expected_version bigint) ON COMMIT DROP;
  CREATE TEMP TABLE ati_entity_batch_reconciliation (ordinal bigint PRIMARY KEY, id uuid, entity_type text NOT NULL, canonical_value text NOT NULL, display_name text, attributes jsonb, content_hash bytea, expected_version bigint, observed_version bigint, old_state jsonb, classification text NOT NULL) ON COMMIT DROP;
  CREATE TEMP TABLE ati_entity_batch_mutation (ordinal bigint PRIMARY KEY, id uuid NOT NULL, version bigint NOT NULL, operation text NOT NULL, old_state jsonb, new_state jsonb) ON COMMIT DROP;

  INSERT INTO ati_entity_batch_input
  SELECT COALESCE(u.item_ordinal, u.input_ordinal), u.item_id, u.item_entity_type, u.item_canonical_value, u.item_display_name, COALESCE(u.item_attributes, '{}'::jsonb), u.item_content_hash, u.item_expected_version
  FROM unnest(p_items) WITH ORDINALITY AS u(item_ordinal, item_id, item_entity_type, item_canonical_value, item_display_name, item_attributes, item_content_hash, item_expected_version, input_ordinal);

  INSERT INTO ati_entity_batch_reconciliation
  SELECT i.ordinal, COALESCE(e.id, i.id), i.entity_type, i.canonical_value, i.display_name, i.attributes, i.content_hash, i.expected_version, e.version, to_jsonb(e),
    CASE WHEN e.id IS NULL THEN 'INSERT' WHEN i.expected_version IS NOT NULL AND i.expected_version <> e.version THEN 'CONFLICT' WHEN e.display_name IS NOT DISTINCT FROM i.display_name AND e.attributes IS NOT DISTINCT FROM i.attributes AND e.content_hash IS NOT DISTINCT FROM i.content_hash THEN 'UNCHANGED' ELSE 'UPDATE' END
  FROM ati_entity_batch_input i LEFT JOIN ati.entity e ON e.entity_type = i.entity_type AND e.canonical_value = i.canonical_value;

  WITH candidates AS (SELECT r.* FROM ati_entity_batch_reconciliation r WHERE r.classification = 'INSERT'), written AS (
    INSERT INTO ati.entity AS target(id, entity_type, canonical_value, display_name, attributes, content_hash, version)
    SELECT COALESCE(candidates.id, gen_random_uuid()), candidates.entity_type, candidates.canonical_value, candidates.display_name, candidates.attributes, candidates.content_hash, nextval('ati.entity_version_seq') FROM candidates
    RETURNING target.id, target.entity_type, target.canonical_value, target.version, to_jsonb(target) AS new_state)
  INSERT INTO ati_entity_batch_mutation SELECT c.ordinal, w.id, w.version, 'CREATE', NULL, w.new_state FROM candidates c JOIN written w USING (entity_type, canonical_value);

  WITH candidates AS (SELECT r.* FROM ati_entity_batch_reconciliation r WHERE r.classification = 'UPDATE'), written AS (
    UPDATE ati.entity e SET display_name=c.display_name, attributes=c.attributes, content_hash=c.content_hash, version=nextval('ati.entity_version_seq'), updated_at=now()
    FROM candidates c WHERE e.entity_type=c.entity_type AND e.canonical_value=c.canonical_value AND e.version=c.observed_version
    RETURNING c.ordinal, e.id, e.version, c.old_state, to_jsonb(e) AS new_state)
  INSERT INTO ati_entity_batch_mutation SELECT w.ordinal, w.id, w.version, 'UPDATE', w.old_state, w.new_state FROM written w;

  UPDATE ati_entity_batch_reconciliation r SET classification = 'CONFLICT' WHERE r.classification = 'UPDATE' AND NOT EXISTS (SELECT 1 FROM ati_entity_batch_mutation m WHERE m.ordinal=r.ordinal);

  INSERT INTO ati.domain_object_history(object_type, object_id, version, operation, state, diff)
  SELECT 'entity', m.id, m.version, m.operation, m.new_state, CASE WHEN m.operation = 'CREATE' THEN '{}'::jsonb ELSE ati.ati_jsonb_diff(m.old_state - ARRAY['version','created_at','updated_at','deleted_at','deleted_by_actor_id']::text[], m.new_state - ARRAY['version','created_at','updated_at','deleted_at','deleted_by_actor_id']::text[]) END FROM ati_entity_batch_mutation m;

  RETURN QUERY SELECT r.ordinal, COALESCE(m.id, r.id), COALESCE(m.version, r.observed_version), r.classification FROM ati_entity_batch_reconciliation r LEFT JOIN ati_entity_batch_mutation m USING (ordinal) ORDER BY r.ordinal;
END $$;
