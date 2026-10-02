-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- SQL API v0031 (PR 31I): bounded deterministic graph path finding.
--
-- Adds one externally invoked read-only stored function that implements the
-- entire PR 31I path query inside PostgreSQL: both-endpoint Investigation
-- visibility, eligible Relationship/RelationshipObservation selection (live
-- rows + PR 31G scope, source and half-open observed_at filters), explicit
-- Entity-path cycle-safe recursive simple-path search seeded at the source
-- Entity, deterministic shortest-first ordering with a canonical path
-- signature, a max_paths + 1 truncation probe, canonical graph closure
-- (only topology that participates in a selected path is returned, except
-- the two visible endpoints for a no-path result), observation/support
-- aggregation and endpoint Entity projection.
--
-- The function returns one explicit metadata row (kind = 'meta') carrying
-- ``endpoints_visible`` and ``truncated``, then one row per canonical node
-- (kind = 'node'), one row per canonical selected Relationship
-- (kind = 'edge') and one row per selected path (kind = 'path'), so the
-- Python adapter only binds validated parameters, invokes the function once
-- and maps rows. "Both endpoints visible but no eligible path" and "an
-- endpoint is not Investigation-visible" are therefore distinguishable
-- with a single invocation: the meta row carries endpoints_visible.
-- No path SQL, recursive CTE, join, filter, aggregation, closure or endpoint
-- projection is implemented in Python.
--
-- Path invariants (PR 31I):
--   * both endpoints must be present, live and admitted to the Investigation
--     through the exact EvidenceObservation rule, in BOTH scopes; known
--     scope may broaden intermediate/support topology only;
--   * direction and connected Entity type apply at every frontier;
--   * scope/source/time/type filters apply before recursion, so a path can
--     never cross a hidden edge;
--   * cycle prevention is per Entity path; a self-loop can never create
--     recursive growth and cannot help reach a distinct target;
--   * source == target returns exactly one zero-hop path;
--   * paths order by (hop_count ASC, canonical path signature ASC);
--   * truncated is true exactly when more qualifying simple paths existed
--     within max_depth than fit max_paths (probed with max_paths + 1);
--   * edge summaries come from the eligible filtered observation set, never
--     from path multiplicity;
--   * no node/edge is returned solely because it was explored but did not
--     participate in a selected path; a no-path result still projects the
--     two visible endpoints.
--
-- The downgrade drops the path function only; no index/schema change is part
-- of this migration (PR 31I adds an index only with measured EXPLAIN
-- evidence; the plan's default expectation is no new index).

CREATE OR REPLACE FUNCTION ati.find_graph_paths(
  p_investigation_id uuid,
  p_source_entity_id uuid,
  p_target_entity_id uuid,
  p_max_depth integer,
  p_max_paths integer,
  p_scope text,
  p_direction text,
  p_relationship_type text,
  p_entity_type text,
  p_source text,
  p_observed_from timestamptz,
  p_observed_to timestamptz
)
RETURNS TABLE(
  kind text,
  endpoints_visible boolean,
  truncated boolean,
  node_entity_id uuid,
  node_entity_type text,
  node_canonical_value text,
  node_display_name text,
  edge_relationship_id uuid,
  edge_source_entity_id uuid,
  edge_target_entity_id uuid,
  edge_relationship_type_urn text,
  edge_observation_count bigint,
  edge_investigation_observation_count bigint,
  edge_first_observed_at timestamptz,
  edge_last_observed_at timestamptz,
  path_ordinal integer,
  path_hop_count integer,
  path_entity_ids uuid[],
  path_relationship_ids uuid[]
)
LANGUAGE plpgsql AS $$
BEGIN
  -- Defensive fail-closed parameter validation: the application contract
  -- performs the same checks first; the stored function never silently
  -- reinterprets an unsupported request.
  IF p_max_depth < 1 OR p_max_depth > 6 THEN
    RAISE EXCEPTION 'graph path max_depth must be between 1 and 6'
      USING ERRCODE = '22023';
  END IF;
  IF p_max_paths < 1 OR p_max_paths > 25 THEN
    RAISE EXCEPTION 'graph path max_paths must be between 1 and 25'
      USING ERRCODE = '22023';
  END IF;
  IF p_scope NOT IN ('investigation', 'known') THEN
    RAISE EXCEPTION 'graph path scope must be investigation or known'
      USING ERRCODE = '22023';
  END IF;
  IF p_direction NOT IN ('source', 'target', 'either') THEN
    RAISE EXCEPTION 'graph path direction must be source, target or either'
      USING ERRCODE = '22023';
  END IF;
  IF p_observed_from IS NOT NULL AND p_observed_to IS NOT NULL
     AND p_observed_from >= p_observed_to THEN
    RAISE EXCEPTION 'graph observed_from must be earlier than observed_to'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH RECURSIVE
  -- Endpoint visibility (PR 31I 1.5): BOTH endpoints must be present, live
  -- and admitted through the exact EvidenceObservation rule in both scopes
  -- (known scope may broaden intermediate topology, never arbitrary global
  -- endpoint lookup). One visible row is sufficient when the IDs are equal.
  endpoints AS (
    SELECT e.id
    FROM ati.entity e
    WHERE e.id IN (p_source_entity_id, p_target_entity_id)
      AND e.deleted_at IS NULL
      AND EXISTS (
        SELECT 1
        FROM ati.evidence_observation_entity eoe
        JOIN ati.investigation_evidence ie
          ON ie.evidence_observation_id = eoe.evidence_observation_id
        WHERE eoe.entity_id = e.id
          AND ie.investigation_id = p_investigation_id
      )
  ),
  endpoint_visible AS (
    SELECT (SELECT count(*) FROM endpoints)
           = (CASE WHEN p_source_entity_id = p_target_entity_id THEN 1 ELSE 2 END)
           AS visible
  ),
  -- Active RelationshipObservations: exact source and half-open observed_at
  -- filters plus the PR 31G scope admission predicate, exactly as in
  -- ``ati.traverse_graph`` (v0030). ``admitted`` records whether the
  -- observation's exact EvidenceObservation is admitted to the requested
  -- Investigation so per-edge Investigation support counts are truthful in
  -- both scopes and never a row-multiplying admission join.
  eligible_obs AS (
    SELECT ro.relationship_id,
           ro.observed_at,
           EXISTS (
             SELECT 1
             FROM ati.investigation_evidence ie
             WHERE ie.investigation_id = p_investigation_id
               AND ie.evidence_observation_id = ro.evidence_observation_id
           ) AS admitted
    FROM ati.relationship_observation ro
    WHERE (p_source IS NULL OR ro.source = p_source)
      AND (p_observed_from IS NULL OR ro.observed_at >= p_observed_from)
      AND (p_observed_to IS NULL OR ro.observed_at < p_observed_to)
      AND (
        p_scope = 'known'
        OR EXISTS (
          SELECT 1
          FROM ati.investigation_evidence ie
          WHERE ie.investigation_id = p_investigation_id
            AND ie.evidence_observation_id = ro.evidence_observation_id
        )
      )
  ),
  -- Eligible Relationships: live Relationship + live endpoint Entities +
  -- optional Relationship type filter + at least one eligible observation.
  -- Endpoint Entity types are carried so the connected-Entity-type filter
  -- applies at every frontier inside the recursion, exactly as in v0030.
  elig AS (
    SELECT r.id,
           r.source_entity_id,
           r.target_entity_id,
           r.relationship_type_urn,
           se.entity_type AS source_entity_type,
           te.entity_type AS target_entity_type
    FROM ati.relationship r
    JOIN ati.entity se
      ON se.id = r.source_entity_id AND se.deleted_at IS NULL
    JOIN ati.entity te
      ON te.id = r.target_entity_id AND te.deleted_at IS NULL
    WHERE r.deleted_at IS NULL
      AND (p_relationship_type IS NULL
           OR r.relationship_type_urn = p_relationship_type)
      AND EXISTS (
        SELECT 1 FROM eligible_obs eo WHERE eo.relationship_id = r.id
      )
  ),
  -- Recursive simple-path search. The seed is the source Entity at depth 0
  -- with a one-Entity path (only when both endpoints are visible). Each
  -- recursive step scans the eligible Relationships incident to the current
  -- frontier Entity under ``direction`` (relative to the current Entity at
  -- every hop) and emits one row per traversed Relationship: the far
  -- endpoint, the grown Entity path and the grown Relationship path. A
  -- branch halts when it reaches the target (it qualifies and is never
  -- expanded further), when the far Entity is already in the branch path
  -- (simple-path cycle prevention; also excludes self-loops), when the
  -- connected-Entity-type filter fails on the far Entity, or when
  -- ``max_depth`` is exhausted.
  path_rec AS (
    SELECT p_source_entity_id AS current_entity_id,
           0::integer AS depth,
           ARRAY[p_source_entity_id]::uuid[] AS entity_path,
           ARRAY[]::uuid[] AS relationship_path
    FROM endpoint_visible ev
    WHERE ev.visible
    UNION ALL
    SELECT CASE
             WHEN e.source_entity_id = pr.current_entity_id THEN e.target_entity_id
             ELSE e.source_entity_id
           END AS current_entity_id,
           pr.depth + 1 AS depth,
           pr.entity_path || CASE
             WHEN e.source_entity_id = pr.current_entity_id THEN e.target_entity_id
             ELSE e.source_entity_id
           END AS entity_path,
           pr.relationship_path || e.id AS relationship_path
    FROM path_rec pr
    JOIN elig e
      ON (p_direction = 'source' AND e.source_entity_id = pr.current_entity_id)
      OR (p_direction = 'target' AND e.target_entity_id = pr.current_entity_id)
      OR (p_direction = 'either'
          AND (e.source_entity_id = pr.current_entity_id
               OR e.target_entity_id = pr.current_entity_id))
    WHERE pr.current_entity_id <> p_target_entity_id
      AND pr.depth < p_max_depth
      AND NOT (CASE
                 WHEN e.source_entity_id = pr.current_entity_id THEN e.target_entity_id
                 ELSE e.source_entity_id
               END = ANY(pr.entity_path))
      AND (p_entity_type IS NULL
           OR CASE
                WHEN e.source_entity_id = pr.current_entity_id
                  THEN e.target_entity_type
                ELSE e.source_entity_type
              END = p_entity_type)
  ),
  -- Qualifying simple paths: walks that reached the target within the depth
  -- bound, deduplicated by canonical Entity sequence (multiple eligible
  -- Relationships may connect the same Entity pair, e.g. parallel edges or a
  -- reverse traversal of a directed edge under EITHER; the connection path
  -- is one deterministic Entity sequence carrying the lexicographically
  -- smallest eligible Relationship sequence). Paths then order
  -- shortest-first with a deterministic canonical signature built only from
  -- canonical IDs (ordered Relationship UUID sequence, then ordered Entity
  -- UUID sequence as tie-breaker) so ordering never depends on row retrieval
  -- order.
  deduped AS (
    SELECT d.hop_count,
           d.entity_path,
           d.relationship_path
    FROM (
      SELECT DISTINCT ON (pr.entity_path)
             pr.depth AS hop_count,
             pr.entity_path,
             pr.relationship_path
      FROM path_rec pr
      WHERE pr.current_entity_id = p_target_entity_id
        AND pr.depth <= p_max_depth
      ORDER BY pr.entity_path ASC, pr.relationship_path ASC
    ) d
  ),
  qualified AS (
    SELECT dd.hop_count,
           dd.entity_path,
           dd.relationship_path,
           (CASE WHEN cardinality(dd.relationship_path) = 0 THEN ''
                 ELSE array_to_string(dd.relationship_path, ',') END
            || '#'
            || CASE WHEN cardinality(dd.entity_path) = 0 THEN ''
                    ELSE array_to_string(dd.entity_path, ',') END)
             AS path_signature
    FROM deduped dd
  ),
  -- The max_paths + 1 probe makes ``truncated`` truthful without a second
  -- query and without per-frontier pruning of qualifying paths.
  ranked AS (
    SELECT hop_count, entity_path, relationship_path, path_signature
    FROM qualified
    ORDER BY hop_count ASC, path_signature ASC
    LIMIT p_max_paths + 1
  ),
  selected_paths AS (
    SELECT ROW_NUMBER() OVER (
             ORDER BY hop_count ASC, path_signature ASC
           )::integer AS ordinal,
           hop_count,
           entity_path,
           relationship_path
    FROM ranked
  ),
  trunc_flag AS (
    SELECT (SELECT count(*) FROM ranked) > p_max_paths AS truncated
  ),
  returned_paths AS (
    SELECT * FROM selected_paths WHERE ordinal <= p_max_paths
  ),
  -- Canonical graph closure: only topology participating in a selected path
  -- is returned, deduplicated per canonical identity. The endpoint UNION
  -- additionally projects both visible endpoints for a no-path result.
  closure_relationship_ids AS (
    SELECT DISTINCT rel_id AS relationship_id
    FROM returned_paths rp
    CROSS JOIN LATERAL unnest(rp.relationship_path) AS rel_id
  ),
  closure_entity_ids AS (
    SELECT DISTINCT ent_id AS entity_id
    FROM returned_paths rp
    CROSS JOIN LATERAL unnest(rp.entity_path) AS ent_id
    UNION
    SELECT id FROM endpoints
  ),
  -- Canonical edge rows: one per selected Relationship, with summaries
  -- computed over the eligible filtered observation set (never from
  -- recursive/path multiplicity).
  edge_rows AS (
    SELECT 'edge'::text AS kind,
           NULL::boolean AS endpoints_visible,
           tf.truncated,
           NULL::uuid AS node_entity_id,
           NULL::text AS node_entity_type,
           NULL::text AS node_canonical_value,
           NULL::text AS node_display_name,
           e.id AS edge_relationship_id,
           e.source_entity_id AS edge_source_entity_id,
           e.target_entity_id AS edge_target_entity_id,
           e.relationship_type_urn AS edge_relationship_type_urn,
           s.observation_count,
           s.investigation_observation_count,
           s.first_observed_at,
           s.last_observed_at,
           NULL::integer AS path_ordinal,
           NULL::integer AS path_hop_count,
           NULL::uuid[] AS path_entity_ids,
           NULL::uuid[] AS path_relationship_ids
    FROM closure_relationship_ids cr
    JOIN elig e ON e.id = cr.relationship_id
    JOIN LATERAL (
      SELECT count(*)::bigint AS observation_count,
             count(*) FILTER (WHERE o.admitted)::bigint
               AS investigation_observation_count,
             min(o.observed_at) AS first_observed_at,
             max(o.observed_at) AS last_observed_at
      FROM eligible_obs o
      WHERE o.relationship_id = cr.relationship_id
    ) s ON true
    CROSS JOIN trunc_flag tf
  ),
  -- Canonical node rows: one per selected-path Entity (or per visible
  -- endpoint for a no-path result).
  node_rows AS (
    SELECT 'node'::text AS kind,
           NULL::boolean AS endpoints_visible,
           tf.truncated,
           ent.id AS node_entity_id,
           ent.entity_type AS node_entity_type,
           ent.canonical_value AS node_canonical_value,
           ent.display_name AS node_display_name,
           NULL::uuid AS edge_relationship_id,
           NULL::uuid AS edge_source_entity_id,
           NULL::uuid AS edge_target_entity_id,
           NULL::text AS edge_relationship_type_urn,
           NULL::bigint AS edge_observation_count,
           NULL::bigint AS edge_investigation_observation_count,
           NULL::timestamptz AS edge_first_observed_at,
           NULL::timestamptz AS edge_last_observed_at,
           NULL::integer AS path_ordinal,
           NULL::integer AS path_hop_count,
           NULL::uuid[] AS path_entity_ids,
           NULL::uuid[] AS path_relationship_ids
    FROM closure_entity_ids cei
    JOIN ati.entity ent ON ent.id = cei.entity_id
    CROSS JOIN trunc_flag tf
  ),
  -- Ordered path-reference rows: ordinal, hop count and the canonical
  -- ordered Entity/Relationship UUID arrays.
  path_rows AS (
    SELECT 'path'::text AS kind,
           NULL::boolean AS endpoints_visible,
           tf.truncated,
           NULL::uuid AS node_entity_id,
           NULL::text AS node_entity_type,
           NULL::text AS node_canonical_value,
           NULL::text AS node_display_name,
           NULL::uuid AS edge_relationship_id,
           NULL::uuid AS edge_source_entity_id,
           NULL::uuid AS edge_target_entity_id,
           NULL::text AS edge_relationship_type_urn,
           NULL::bigint AS edge_observation_count,
           NULL::bigint AS edge_investigation_observation_count,
           NULL::timestamptz AS edge_first_observed_at,
           NULL::timestamptz AS edge_last_observed_at,
           rp.ordinal AS path_ordinal,
           rp.hop_count AS path_hop_count,
           rp.entity_path AS path_entity_ids,
           rp.relationship_path AS path_relationship_ids
    FROM returned_paths rp
    CROSS JOIN trunc_flag tf
  ),
  -- Explicit metadata row: endpoint-validity status and truthful truncation,
  -- issued before any graph row so a single invocation can distinguish
  -- "endpoint invalid" from "visible but no path".
  meta_row AS (
    SELECT 'meta'::text AS kind,
           ev.visible AS endpoints_visible,
           tf.truncated,
           NULL::uuid AS node_entity_id,
           NULL::text AS node_entity_type,
           NULL::text AS node_canonical_value,
           NULL::text AS node_display_name,
           NULL::uuid AS edge_relationship_id,
           NULL::uuid AS edge_source_entity_id,
           NULL::uuid AS edge_target_entity_id,
           NULL::text AS edge_relationship_type_urn,
           NULL::bigint AS edge_observation_count,
           NULL::bigint AS edge_investigation_observation_count,
           NULL::timestamptz AS edge_first_observed_at,
           NULL::timestamptz AS edge_last_observed_at,
           NULL::integer AS path_ordinal,
           NULL::integer AS path_hop_count,
           NULL::uuid[] AS path_entity_ids,
           NULL::uuid[] AS path_relationship_ids
    FROM endpoint_visible ev
    CROSS JOIN trunc_flag tf
  ),
  unified AS (
    SELECT 0::integer AS row_order, * FROM meta_row
    UNION ALL
    SELECT 1::integer AS row_order, * FROM node_rows
    UNION ALL
    SELECT 2::integer AS row_order, * FROM edge_rows
    UNION ALL
    SELECT 3::integer AS row_order, * FROM path_rows
  )
  SELECT u.kind,
         u.endpoints_visible,
         u.truncated,
         u.node_entity_id,
         u.node_entity_type,
         u.node_canonical_value,
         u.node_display_name,
         u.edge_relationship_id,
         u.edge_source_entity_id,
         u.edge_target_entity_id,
         u.edge_relationship_type_urn,
         u.edge_observation_count,
         u.edge_investigation_observation_count,
         u.edge_first_observed_at,
         u.edge_last_observed_at,
         u.path_ordinal,
         u.path_hop_count,
         u.path_entity_ids,
         u.path_relationship_ids
  FROM unified u
  ORDER BY u.row_order,
           u.node_entity_id ASC NULLS LAST,
           u.edge_relationship_id ASC NULLS LAST,
           u.path_ordinal ASC NULLS LAST;
END $$;
