-- Versioned PostgreSQL write path for canonical entities.
CREATE OR REPLACE FUNCTION ati.upsert_entity(
  p_id uuid, p_entity_type text, p_canonical_value text, p_display_name text,
  p_attributes jsonb, p_content_hash bytea, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint; result_id uuid;
  old_display_name text; old_attributes jsonb; old_content_hash bytea;
BEGIN
  SELECT to_jsonb(e), e.version, e.display_name, e.attributes, e.content_hash
    INTO old_state, current_version, old_display_name, old_attributes, old_content_hash
    FROM ati.entity e
    WHERE e.entity_type=p_entity_type AND e.canonical_value=p_canonical_value FOR UPDATE;
  IF old_state IS NULL THEN
    result_id := COALESCE(p_id, gen_random_uuid()); version := nextval('ati.entity_version_seq');
    INSERT INTO ati.entity(id,entity_type,canonical_value,display_name,attributes,content_hash,version)
      VALUES(result_id,p_entity_type,p_canonical_value,p_display_name,COALESCE(p_attributes,'{}'),p_content_hash,version);
    id := result_id;
    SELECT to_jsonb(e) INTO new_state FROM ati.entity e WHERE e.id=result_id;
    INSERT INTO ati.domain_object_history(object_type,object_id,version,operation,state,diff)
      VALUES('entity',result_id,version,'CREATE',new_state,'{}');
    created := true; RETURN NEXT; RETURN;
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict';
  END IF;
  -- A semantic no-op must not consume a revision or create history.
  IF old_display_name IS NOT DISTINCT FROM p_display_name
     AND old_attributes IS NOT DISTINCT FROM COALESCE(p_attributes,'{}'::jsonb)
     AND old_content_hash IS NOT DISTINCT FROM p_content_hash THEN
    id := (old_state->>'id')::uuid; version := current_version; created := false;
    RETURN NEXT; RETURN;
  END IF;
  UPDATE ati.entity SET display_name=p_display_name, attributes=COALESCE(p_attributes,'{}'),
    content_hash=p_content_hash, version=nextval('ati.entity_version_seq'), updated_at=now()
    WHERE entity_type=p_entity_type AND canonical_value=p_canonical_value
    RETURNING ati.entity.id, ati.entity.version INTO result_id, version;
  id := result_id;
  SELECT to_jsonb(e) INTO new_state FROM ati.entity e WHERE e.id=result_id;
  INSERT INTO ati.domain_object_history(object_type,object_id,version,operation,state,diff)
    VALUES('entity',result_id,version,'UPDATE',new_state,ati.ati_jsonb_diff(old_state,new_state));
  created := false; RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION ati.soft_delete_entity(
  p_id uuid, p_actor_id uuid DEFAULT NULL, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
BEGIN
  SELECT to_jsonb(e), e.version INTO old_state, current_version FROM ati.entity e
    WHERE e.id=p_id AND e.deleted_at IS NULL FOR UPDATE;
  IF old_state IS NULL THEN RAISE EXCEPTION 'entity not found'; END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN
    RAISE EXCEPTION 'optimistic version conflict';
  END IF;
  UPDATE ati.entity SET deleted_at=now(), deleted_by_actor_id=p_actor_id,
    version=nextval('ati.entity_version_seq'), updated_at=now() WHERE ati.entity.id=p_id
    RETURNING ati.entity.id, ati.entity.version INTO id, version;
  SELECT to_jsonb(e) INTO new_state FROM ati.entity e WHERE e.id=p_id;
  INSERT INTO ati.domain_object_history(object_type,object_id,version,operation,state,diff)
    VALUES('entity',id,version,'DELETE',new_state,ati.ati_jsonb_diff(old_state,new_state));
  RETURN NEXT;
END $$;
