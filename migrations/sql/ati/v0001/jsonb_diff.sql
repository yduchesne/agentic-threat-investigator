-- Immutable SQL API version v0001. Shallow diff; absent and JSON null remain distinct.
CREATE OR REPLACE FUNCTION ati.ati_jsonb_diff(old_state jsonb, new_state jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT COALESCE(jsonb_object_agg(k, jsonb_build_object('old', old_state->k, 'new', new_state->k)), '{}'::jsonb)
  FROM (SELECT k FROM jsonb_object_keys(COALESCE(old_state, '{}'::jsonb)) AS k
        UNION SELECT k FROM jsonb_object_keys(COALESCE(new_state, '{}'::jsonb)) AS k) keys
  WHERE (old_state ? k) IS DISTINCT FROM (new_state ? k)
     OR (old_state->k) IS DISTINCT FROM (new_state->k)
$$;
