-- Immutable SQL API v0023 for PR 26B canonical reference/spatial Location
-- persistence.
--
-- PR 26B establishes the deterministic geographic substrate on top of the
-- PR 26A non-spatial foundation: spatial columns on ati.location, PostGIS
-- validation owned by the write function, and the reference-owned
-- enrichment/update path. SQL API v0021 and v0022 are immutable and are
-- never edited; v0023 only ADD new objects.
--
-- Ownership semantics:
--
-- 1. ati.upsert_reference_location is the ONLY mutation path for canonical
--    reference/spatial state in PR 26B. It preserves the PR 26A ownership
--    contract (no ad-hoc application-side INSERT/UPDATE), keeps the approved
--    canonical identity tuple (location_type, country_code, admin1_code,
--    admin2_code, canonical_name), and adds the deterministic outcome
--    algebra:
--
--      CREATED   canonical identity did not exist; created with reference
--                hierarchy/spatial state; version from
--                ati.location_version_seq;
--      UNCHANGED identity and complete supplied canonical state
--                (name, parent, geometry, representative point) are
--                semantically identical; no version churn;
--      ENRICHED  same canonical identity; approved previously-missing
--                reference/spatial fields are filled or a deterministic
--                reference-corpus refresh changes approved spatial state;
--                a new ati.location_version_seq token is allocated;
--      CONFLICT  raised as typed SQLSTATE U26B3: the same canonical identity
--                would be rebound with a different display name or reference
--                parent; nothing is mutated.
--
-- 2. Spatial state is attached to the canonical reference object, never part
--    of identity: geometry corrections or corpus upgrades never create a
--    second logical Location.
--
-- 3. All persisted reference geometries are SRID 4326 PostGIS ``geometry``
--    (never ``geography``). The representative ``centroid`` column stores an
--    on-surface representative point: ST_PointOnSurface(geometry) derived
--    deterministically during ingestion for polygonal objects when the source
--    record supplies no explicit point, and the same canonical point as
--    geometry for cities. It is documented as an on-surface representative
--    point, never as a mathematical ST_Centroid.
--
-- 4. Spatial validation is fail-closed inside the write function (the sole
--    mutation path): valid geometry for polygons, Point for cities, SRID
--    4326, non-empty, WGS84 lon/lat bounds, and city canonical-point
--    consistency. CHECK constraints cannot call PostGIS functions (they are
--    not immutable), so the database validates through the stored function
--    rather than duplicated CHECK expressions.
--
-- Typed SQLSTATE mapping (U26B*):
--   U26B1 invalid reference geometry (SRID/empty/validity/type/bounds/city point)
--   U26B2 invalid reference hierarchy (parent/shape/self-parent/missing parent)
--   U26B3 canonical location conflict (incompatible rebind of canonical identity)
--   U26B4 unsupported reference record (type/name/code shape)
--
-- PR 26A-2 semantics (EntityLocationObservation/EntityLocation/GeoResolution,
-- SQL API v0022) are untouched. No row-level triggers, no PostGIS
-- ``geography`` columns, and no spatial truth outside the canonical Location
-- write path exist in this version.

-- Parse and validate one optional reference geometry for a Location type.
-- Every validation failure raises U26B1; malformed input is never repaired.
CREATE OR REPLACE FUNCTION ati.reference_geometry_parse(
  p_ewkt text, p_location_type text)
RETURNS geometry LANGUAGE plpgsql AS $$
DECLARE v_geom geometry; v_type text;
BEGIN
  IF p_ewkt IS NULL THEN
    RETURN NULL;
  END IF;
  IF btrim(p_ewkt) = '' THEN
    RAISE EXCEPTION 'reference geometry must not be blank' USING ERRCODE = 'U26B1';
  END IF;
  IF LEFT(btrim(p_ewkt), 5) = 'SRID=' THEN
    -- ST_GeomFromText silently re-tags an EWKT SRID; a non-4326 declaration
    -- must fail closed instead of silently corrupting spatial state.
    IF split_part(btrim(p_ewkt), ';', 1) <> 'SRID=4326' THEN
      RAISE EXCEPTION 'reference geometry SRID must be 4326'
        USING ERRCODE = 'U26B1';
    END IF;
    BEGIN
      v_geom := ST_GeomFromEWKT(btrim(p_ewkt));
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'invalid reference geometry' USING ERRCODE = 'U26B1';
    END;
  ELSE
    BEGIN
      v_geom := ST_GeomFromText(btrim(p_ewkt), 4326);
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'invalid reference geometry' USING ERRCODE = 'U26B1';
    END;
  END IF;
  IF v_geom IS NULL OR ST_SRID(v_geom) <> 4326 THEN
    RAISE EXCEPTION 'reference geometry SRID must be 4326'
      USING ERRCODE = 'U26B1';
  END IF;
  IF ST_IsEmpty(v_geom) THEN
    RAISE EXCEPTION 'reference geometry must not be empty' USING ERRCODE = 'U26B1';
  END IF;
  v_type := ST_GeometryType(v_geom);
  IF p_location_type IN ('country', 'administrative_area') THEN
    IF v_type NOT IN ('ST_Polygon', 'ST_MultiPolygon') THEN
      RAISE EXCEPTION 'country/admin reference geometry must be polygonal'
        USING ERRCODE = 'U26B1';
    END IF;
    IF NOT ST_IsValid(v_geom) THEN
      RAISE EXCEPTION 'reference polygon is not valid' USING ERRCODE = 'U26B1';
    END IF;
  ELSE
    IF v_type <> 'ST_Point' THEN
      RAISE EXCEPTION 'city reference geometry must be a point'
        USING ERRCODE = 'U26B1';
    END IF;
  END IF;
  IF ST_XMin(v_geom) < -180.0 OR ST_XMax(v_geom) > 180.0
     OR ST_YMin(v_geom) < -90.0 OR ST_YMax(v_geom) > 90.0 THEN
    RAISE EXCEPTION 'reference geometry outside WGS84 bounds'
      USING ERRCODE = 'U26B1';
  END IF;
  RETURN v_geom;
END $$;

-- Parse and validate one optional representative point (SRID 4326, point,
-- non-empty, WGS84 bounds). Raises U26B1 on any violation.
CREATE OR REPLACE FUNCTION ati.reference_centroid_parse(p_ewkt text)
RETURNS geometry LANGUAGE plpgsql AS $$
DECLARE v_geom geometry;
BEGIN
  IF p_ewkt IS NULL THEN
    RETURN NULL;
  END IF;
  v_geom := ati.reference_geometry_parse(p_ewkt, 'city');
  RETURN v_geom;
END $$;

-- Create/enrich/reuse one canonical reference/spatial Location. See the file
-- header for outcome semantics and typed SQLSTATE mapping.
CREATE OR REPLACE FUNCTION ati.upsert_reference_location(
  p_id uuid, p_location_type text, p_name text, p_canonical_name text,
  p_country_code text, p_admin1_code text, p_admin2_code text,
  p_parent_location_id uuid, p_geometry text, p_centroid text)
RETURNS TABLE(
  id uuid, version bigint, outcome text,
  geometry_ewkt text, centroid_ewkt text)
LANGUAGE plpgsql AS $$
DECLARE
  v_geometry geometry(Geometry, 4326);
  v_centroid geometry(Point, 4326);
  v_effective_centroid geometry(Point, 4326);
  existing_id uuid; existing_version bigint; existing_name text;
  existing_parent uuid; existing_geometry geometry(Geometry, 4326);
  existing_centroid geometry(Point, 4326);
  new_version bigint; result_id uuid;
  v_geometry_equal boolean; v_centroid_equal boolean;
  v_constraint text;
BEGIN
  -- Unsupported reference record (U26B4).
  IF p_location_type NOT IN ('country', 'administrative_area', 'city') THEN
    RAISE EXCEPTION 'unsupported reference location type' USING ERRCODE = 'U26B4';
  END IF;
  IF p_country_code IS NULL OR p_country_code !~ '^[A-Z]{2}$' THEN
    RAISE EXCEPTION 'invalid reference country code' USING ERRCODE = 'U26B4';
  END IF;
  IF btrim(p_name) = '' OR length(btrim(p_name)) > 200 THEN
    RAISE EXCEPTION 'invalid reference location name' USING ERRCODE = 'U26B4';
  END IF;
  IF btrim(p_canonical_name) = '' OR length(btrim(p_canonical_name)) > 200 THEN
    RAISE EXCEPTION 'invalid canonical reference name' USING ERRCODE = 'U26B4';
  END IF;
  IF (p_admin1_code IS NOT NULL
      AND (btrim(p_admin1_code) = '' OR length(btrim(p_admin1_code)) > 64)) THEN
    RAISE EXCEPTION 'invalid reference admin1 code' USING ERRCODE = 'U26B4';
  END IF;
  IF (p_admin2_code IS NOT NULL
      AND (btrim(p_admin2_code) = '' OR length(btrim(p_admin2_code)) > 64)) THEN
    RAISE EXCEPTION 'invalid reference admin2 code' USING ERRCODE = 'U26B4';
  END IF;

  -- Reference hierarchy (U26B2).
  IF p_location_type = 'country'
     AND (p_parent_location_id IS NOT NULL
          OR p_admin1_code IS NOT NULL OR p_admin2_code IS NOT NULL) THEN
    RAISE EXCEPTION 'country reference must not have parent or admin codes'
      USING ERRCODE = 'U26B2';
  END IF;
  IF p_location_type <> 'country'
     AND (p_parent_location_id IS NULL OR p_admin1_code IS NULL) THEN
    RAISE EXCEPTION 'reference requires parent and admin1 code'
      USING ERRCODE = 'U26B2';
  END IF;
  IF p_id IS NOT NULL AND p_parent_location_id = p_id THEN
    RAISE EXCEPTION 'reference parent must not equal the location itself'
      USING ERRCODE = 'U26B2';
  END IF;
  IF p_parent_location_id IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM ati.location l WHERE l.id = p_parent_location_id) THEN
    RAISE EXCEPTION 'reference parent not found' USING ERRCODE = 'U26B2';
  END IF;

  -- Spatial validation (U26B1).
  v_geometry := ati.reference_geometry_parse(p_geometry, p_location_type);
  v_centroid := ati.reference_centroid_parse(p_centroid);
  IF p_location_type = 'city' THEN
    IF v_centroid IS NOT NULL AND v_geometry IS NOT NULL
       AND NOT ST_Equals(v_geometry, v_centroid) THEN
      RAISE EXCEPTION 'city centroid must equal the canonical point'
        USING ERRCODE = 'U26B1';
    END IF;
    -- A city stores exactly one canonical point: when either column is
    -- supplied the other derives deterministically from it (or both must
    -- agree).
    IF v_geometry IS NOT NULL THEN
      v_effective_centroid := v_geometry;
    ELSIF v_centroid IS NOT NULL THEN
      v_geometry := v_centroid;
      v_effective_centroid := v_centroid;
    END IF;
  END IF;

  -- Deterministic representative point derivation for polygonal objects:
  -- an explicitly supplied reference point wins; otherwise the on-surface
  -- representative point ST_PointOnSurface is derived from the present
  -- reference geometry. A city's representative point is its canonical
  -- point (handled above). Missing spatial data is never manufactured from
  -- nothing.
  IF p_location_type <> 'city' THEN
    IF v_centroid IS NOT NULL THEN
      v_effective_centroid := v_centroid;
    ELSIF v_geometry IS NOT NULL THEN
      v_effective_centroid := ST_PointOnSurface(v_geometry);
    END IF;
  END IF;

  SELECT l.id, l.version, l.name, l.parent_location_id, l.geometry, l.centroid
    INTO existing_id, existing_version, existing_name, existing_parent,
         existing_geometry, existing_centroid
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
      RAISE EXCEPTION 'canonical reference location rebind conflict'
        USING ERRCODE = 'U26B3';
    END IF;
    v_geometry_equal := (v_geometry IS NULL AND existing_geometry IS NULL)
      OR (v_geometry IS NOT NULL AND existing_geometry IS NOT NULL
          AND ST_Equals(v_geometry, existing_geometry));
    v_centroid_equal := (v_effective_centroid IS NULL AND existing_centroid IS NULL)
      OR (v_effective_centroid IS NOT NULL AND existing_centroid IS NOT NULL
          AND ST_Equals(v_effective_centroid, existing_centroid));
    IF v_geometry_equal AND v_centroid_equal THEN
      id := existing_id;
      version := existing_version;
      outcome := 'UNCHANGED';
      geometry_ewkt := ST_AsEWKT(existing_geometry);
      centroid_ewkt := ST_AsEWKT(existing_centroid);
      RETURN NEXT;
      RETURN;
    END IF;
    UPDATE ati.location AS l
      SET geometry = v_geometry,
          centroid = v_effective_centroid,
          version = nextval('ati.location_version_seq'),
          updated_at = now()
      WHERE l.id = existing_id
      RETURNING l.version INTO new_version;
    IF new_version IS NULL THEN
      RAISE EXCEPTION 'reference enrich returned no row' USING ERRCODE = 'U26B3';
    END IF;
    id := existing_id;
    version := new_version;
    outcome := 'ENRICHED';
    geometry_ewkt := ST_AsEWKT(v_geometry);
    centroid_ewkt := ST_AsEWKT(v_effective_centroid);
    RETURN NEXT;
    RETURN;
  END IF;

  result_id := COALESCE(p_id, gen_random_uuid());
  version := nextval('ati.location_version_seq');
  BEGIN
    INSERT INTO ati.location AS loc(
      id, location_type, name, canonical_name, country_code,
      admin1_code, admin2_code, parent_location_id, geometry, centroid,
      version)
      VALUES(result_id, p_location_type, btrim(p_name), btrim(p_canonical_name),
             p_country_code, p_admin1_code, p_admin2_code,
             p_parent_location_id, v_geometry, v_effective_centroid, version)
    ON CONFLICT (location_type, country_code,
                 (COALESCE(admin1_code, '')), (COALESCE(admin2_code, '')),
                 canonical_name) DO NOTHING;
  EXCEPTION
    WHEN unique_violation THEN
      -- ON CONFLICT absorbs canonical-identity races; a violation here can
      -- only be a caller-supplied id already bound to a different identity.
      RAISE EXCEPTION 'canonical reference location conflict'
        USING ERRCODE = 'U26B3';
  END;
  IF NOT FOUND THEN
    SELECT l.id, l.version, l.name, l.parent_location_id, l.geometry, l.centroid
      INTO existing_id, existing_version, existing_name, existing_parent,
           existing_geometry, existing_centroid
      FROM ati.location l
      WHERE l.location_type = p_location_type
        AND l.country_code = p_country_code
        AND COALESCE(l.admin1_code, '') = COALESCE(p_admin1_code, '')
        AND COALESCE(l.admin2_code, '') = COALESCE(p_admin2_code, '')
        AND l.canonical_name = p_canonical_name;
    IF existing_id IS NULL THEN
      RAISE EXCEPTION 'reference location conflict returned no row'
        USING ERRCODE = 'U26B3';
    END IF;
    IF existing_name IS DISTINCT FROM btrim(p_name)
       OR existing_parent IS DISTINCT FROM p_parent_location_id THEN
      RAISE EXCEPTION 'canonical reference location rebind conflict'
        USING ERRCODE = 'U26B3';
    END IF;
    v_geometry_equal := (v_geometry IS NULL AND existing_geometry IS NULL)
      OR (v_geometry IS NOT NULL AND existing_geometry IS NOT NULL
          AND ST_Equals(v_geometry, existing_geometry));
    v_centroid_equal := (v_effective_centroid IS NULL AND existing_centroid IS NULL)
      OR (v_effective_centroid IS NOT NULL AND existing_centroid IS NOT NULL
          AND ST_Equals(v_effective_centroid, existing_centroid));
    IF v_geometry_equal AND v_centroid_equal THEN
      id := existing_id;
      version := existing_version;
      outcome := 'UNCHANGED';
      geometry_ewkt := ST_AsEWKT(existing_geometry);
      centroid_ewkt := ST_AsEWKT(existing_centroid);
      RETURN NEXT;
      RETURN;
    END IF;
    UPDATE ati.location AS l
      SET geometry = v_geometry,
          centroid = v_effective_centroid,
          version = nextval('ati.location_version_seq'),
          updated_at = now()
      WHERE l.id = existing_id
      RETURNING l.version INTO new_version;
    IF new_version IS NULL THEN
      RAISE EXCEPTION 'reference enrich returned no row' USING ERRCODE = 'U26B3';
    END IF;
    id := existing_id;
    version := new_version;
    outcome := 'ENRICHED';
    geometry_ewkt := ST_AsEWKT(v_geometry);
    centroid_ewkt := ST_AsEWKT(v_effective_centroid);
    RETURN NEXT;
    RETURN;
  END IF;
  id := result_id;
  outcome := 'CREATED';
  geometry_ewkt := ST_AsEWKT(v_geometry);
  centroid_ewkt := ST_AsEWKT(v_effective_centroid);
  RETURN NEXT;
END $$;