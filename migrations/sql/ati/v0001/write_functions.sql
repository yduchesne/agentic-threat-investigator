-- Thin single-row write functions. They own version allocation and history.
CREATE OR REPLACE FUNCTION ati.upsert_entity(
  p_id uuid, p_entity_type text, p_canonical_value text, p_display_name text,
  p_attributes jsonb, p_content_hash bytea, p_expected_version bigint DEFAULT NULL)
RETURNS TABLE(id uuid, version bigint, created boolean) LANGUAGE plpgsql AS $$
DECLARE old_state jsonb; new_state jsonb; current_version bigint;
BEGIN
  SELECT to_jsonb(e), e.version INTO old_state, current_version FROM ati.entity e
    WHERE e.entity_type=p_entity_type AND e.canonical_value=p_canonical_value FOR UPDATE;
  IF old_state IS NULL THEN
    id := COALESCE(p_id, gen_random_uuid()); version := nextval('ati.entity_version_seq');
    INSERT INTO ati.entity(id,entity_type,canonical_value,display_name,attributes,content_hash,version)
      VALUES(id,p_entity_type,p_canonical_value,p_display_name,COALESCE(p_attributes,'{}'),p_content_hash,version);
    new_state := jsonb_build_object('id',id,'entity_type',p_entity_type,'canonical_value',p_canonical_value,'display_name',p_display_name,'attributes',COALESCE(p_attributes,'{}'),'version',version);
    INSERT INTO ati.domain_object_history(object_type,object_id,version,operation,state,diff) VALUES('entity',id,version,'CREATE',new_state,'{}');
    created := true; RETURN NEXT; RETURN;
  END IF;
  IF p_expected_version IS NOT NULL AND current_version <> p_expected_version THEN RAISE EXCEPTION 'optimistic version conflict'; END IF;
  UPDATE ati.entity SET display_name=p_display_name, attributes=COALESCE(p_attributes,'{}'), content_hash=p_content_hash,
    version=nextval('ati.entity_version_seq'), updated_at=now() WHERE entity_type=p_entity_type AND canonical_value=p_canonical_value
    RETURNING ati.entity.id, ati.entity.version INTO id, version;
  SELECT to_jsonb(e) INTO new_state FROM ati.entity e WHERE e.id=id;
  INSERT INTO ati.domain_object_history(object_type,object_id,version,operation,state,diff) VALUES('entity',id,version,'UPDATE',new_state,ati.ati_jsonb_diff(old_state,new_state));
  created := false; RETURN NEXT;
END $$;
