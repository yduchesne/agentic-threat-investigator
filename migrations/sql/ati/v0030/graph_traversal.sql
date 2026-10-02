-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- SQL API v0030 (PR 31H): bounded multi-hop graph traversal.
--
-- Adds one externally invoked read-only stored function that implements the
-- entire PR 31H traversal inside PostgreSQL: focal visibility, eligible
-- Relationship/RelationshipObservation selection (live rows + PR 31G scope,
-- source and half-open observed_at filters), direction-relative recursive
-- traversal with Entity-path cycle prevention, minimum-hop-depth derivation,
-- canonical deduplication, observation/support aggregation, endpoint Entity
-- projection, deterministic ordering, and the limit + 1 truncation probe.
--
-- The function returns one row per canonical node (kind = 'node', focal
-- first) and one row per canonical selected Relationship (kind = 'edge'),
-- so the Python adapter only binds validated parameters, invokes the
-- function and maps rows. No traversal SQL, recursive CTE, join, filter or
-- aggregation is implemented in Python.
--
-- Traversal invariants (PR 31H):
--   * depth is hop distance from the focal Entity and is hard-capped at 3;
--   * depth-1 is semantically equivalent to the one-hop neighborhood for
--     the same context and non-truncating limit;
--   * direction and connected Entity type apply at every frontier;
--   * scope/source/time/type filters apply before any recursion, so a
--     traversal can never cross a hidden edge;
--   * cycle prevention is per Entity path (a self-loop is topology once but
--     never recurses);
--   * edge summaries come from the eligible filtered observation set, never
--     from recursive occurrence counts;
--   * known scope broadens edge support globally but never removes the
--     Investigation visibility of the focal Entity.
--
-- The downgrade drops the traversal function only; no index/schema change is
-- part of this migration (PR 31H adds an index only with measured evidence).

CREATE OR REPLACE FUNCTION ati.traverse_graph(
  p_investigation_id uuid,
  p_entity_id uuid,
  p_max_depth integer,
  p_scope text,
  p_direction text,
  p_relationship_type text,
  p_entity_type text,
  p_source text,
  p_observed_from timestamptz,
  p_observed_to timestamptz,
  p_limit integer
)
RETURNS TABLE(
  kind text,
  node_entity_id uuid,
  node_entity_type text,
  node_canonical_value text,
  node_display_name text,
  node_min_depth integer,
  edge_relationship_id uuid,
  edge_source_entity_id uuid,
  edge_target_entity_id uuid,
  edge_relationship_type_urn text,
  edge_observation_count bigint,
  edge_investigation_observation_count bigint,
  edge_first_observed_at timestamptz,
  edge_last_observed_at timestamptz,
  edge_min_depth integer,
  truncated boolean
)
LANGUAGE plpgsql AS $$
BEGIN
  -- Defensive fail-closed parameter validation: the application contract
  -- performs the same checks first; the stored function never silently
  -- reinterprets an unsupported request.
  IF p_max_depth < 1 OR p_max_depth > 3 THEN
    RAISE EXCEPTION 'graph traversal max_depth must be between 1 and 3'
      USING ERRCODE = '22023';
  END IF;
  IF p_scope NOT IN ('investigation', 'known') THEN
    RAISE EXCEPTION 'graph traversal scope must be investigation or known'
      USING ERRCODE = '22023';
  END IF;
  IF p_direction NOT IN ('source', 'target', 'either') THEN
    RAISE EXCEPTION 'graph traversal direction must be source, target or either'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit < 1 THEN
    RAISE EXCEPTION 'graph traversal limit must be at least 1'
      USING ERRCODE = '22023';
  END IF;
  IF p_observed_from IS NOT NULL AND p_observed_to IS NOT NULL
     AND p_observed_from >= p_observed_to THEN
    RAISE EXCEPTION 'graph observed_from must be earlier than observed_to'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH RECURSIVE
  -- Focal visibility: live Entity + at least one EvidenceObservation exactly
  -- admitted to the requested Investigation, in BOTH scopes (PR 31G).
  focal AS (
    SELECT e.id
    FROM ati.entity e
    WHERE e.id = p_entity_id
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
  -- Active RelationshipObservations: exact source and half-open observed_at
  -- filters plus the PR 31G scope admission predicate. ``admitted`` records
  -- whether the observation's exact EvidenceObservation is admitted to the
  -- requested Investigation (independent of the scope, so the per-edge
  -- investigation support count is a set-wise conditional aggregate that is
  -- truthful in both scopes and never a row-multiplying admission join).
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
  -- The join carries both endpoint Entity types so direction and connected
  -- Entity type filters apply at every frontier inside the recursion.
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
  -- Recursive frontier occurrences. The seed is the focal Entity at depth 0
  -- with a one-Entity path. Each recursive step scans the eligible
  -- Relationships incident to the current frontier Entity under ``direction``
  -- and emits one row per traversed Relationship: the far endpoint, the
  -- grown Entity path, the Relationship that was traversed, and whether the
  -- branch may continue. A row whose far endpoint is already in the branch
  -- path (a self-loop or a cycle) is still emitted as a reached occurrence
  -- (so its edge/entity contributions are canonicalized later) but never
  -- reappears as a new frontier. Depth is capped inside the recursion, so
  -- database work is bounded by the requested depth, never by graph size.
  trav AS (
    SELECT p_entity_id AS entity_id,
           0::integer AS depth,
           ARRAY[p_entity_id]::uuid[] AS path,
           NULL::uuid AS edge_id,
           true::boolean AS recursive_row
    FROM focal
    UNION ALL
    SELECT CASE
             WHEN e.source_entity_id = trav.entity_id THEN e.target_entity_id
             ELSE e.source_entity_id
           END,
           trav.depth + 1 AS depth,
           trav.path || CASE
             WHEN e.source_entity_id = trav.entity_id THEN e.target_entity_id
             ELSE e.source_entity_id
           END,
           e.id AS edge_id,
           NOT (CASE
             WHEN e.source_entity_id = trav.entity_id THEN e.target_entity_id
             ELSE e.source_entity_id
           END = ANY(trav.path)) AS recursive_row
    FROM trav
    JOIN elig e
      ON (p_direction = 'source' AND e.source_entity_id = trav.entity_id)
      OR (p_direction = 'target' AND e.target_entity_id = trav.entity_id)
      OR (p_direction = 'either'
          AND (e.source_entity_id = trav.entity_id
               OR e.target_entity_id = trav.entity_id))
    WHERE trav.recursive_row
      AND trav.depth < p_max_depth
      AND (p_entity_type IS NULL
           OR CASE
                WHEN e.source_entity_id = trav.entity_id
                  THEN e.target_entity_type
                ELSE e.source_entity_type
              END = p_entity_type)
  ),
  -- Canonical minimum-hop-depth per traversed Relationship and per reached
  -- Entity (recursion may reach the same identity through multiple branches).
  edge_occ AS (
    SELECT edge_id, min(depth)::integer AS min_depth
    FROM trav
    WHERE edge_id IS NOT NULL
    GROUP BY edge_id
  ),
  entity_occ AS (
    SELECT entity_id, min(depth)::integer AS min_depth
    FROM trav
    GROUP BY entity_id
  ),
  -- Canonical edge selection: every traversed Relationship appears at most
  -- once with its summaries computed over the eligible filtered observation
  -- set (recursive/path multiplicity can never inflate support counts),
  -- ordered by (minimum_hop_depth, relationship_id). The probe row is not
  -- needed: ``trunc_flag`` counts every discovered eligible Relationship, so
  -- exactly ``p_limit`` rows are returned while ``truncated`` reports
  -- whether more were discovered than fit the bound.
  selected_edges AS (
    SELECT e.id AS relationship_id,
           e.source_entity_id,
           e.target_entity_id,
           e.relationship_type_urn,
           s.observation_count,
           s.investigation_observation_count,
           s.first_observed_at,
           s.last_observed_at,
           oc.min_depth AS edge_min_depth
    FROM edge_occ oc
    JOIN elig e ON e.id = oc.edge_id
    JOIN LATERAL (
      SELECT count(*)::bigint AS observation_count,
             count(*) FILTER (WHERE o.admitted)::bigint
               AS investigation_observation_count,
             min(o.observed_at) AS first_observed_at,
             max(o.observed_at) AS last_observed_at
      FROM eligible_obs o
      WHERE o.relationship_id = e.id
    ) s ON true
    ORDER BY oc.min_depth ASC, e.id ASC
    LIMIT p_limit
  ),
  -- Truthful truncation: more eligible distinct Relationships were discovered
  -- than fit in the result bound (not graph exhaustion beyond the depth).
  trunc_flag AS (
    SELECT (SELECT count(*) FROM edge_occ) > p_limit AS truncated
  ),
  -- Endpoint closure: the focal Entity plus every endpoint of every selected
  -- Relationship, projected inside the stored function (no follow-up Python
  -- or SQL entity query).
  selected_entity_ids AS (
    SELECT f.id AS entity_id
    FROM focal f
    UNION
    SELECT source_entity_id FROM selected_edges
    UNION
    SELECT target_entity_id FROM selected_edges
  ),
  node_rows AS (
    SELECT 'node'::text AS kind,
           ent.id AS node_entity_id,
           ent.entity_type AS node_entity_type,
           ent.canonical_value AS node_canonical_value,
           ent.display_name AS node_display_name,
           COALESCE(eo.min_depth, 0)::integer AS node_min_depth,
           NULL::uuid AS edge_relationship_id,
           NULL::uuid AS edge_source_entity_id,
           NULL::uuid AS edge_target_entity_id,
           NULL::text AS edge_relationship_type_urn,
           NULL::bigint AS edge_observation_count,
           NULL::bigint AS edge_investigation_observation_count,
           NULL::timestamptz AS edge_first_observed_at,
           NULL::timestamptz AS edge_last_observed_at,
           NULL::integer AS edge_min_depth,
           tf.truncated
    FROM selected_entity_ids sei
    JOIN ati.entity ent ON ent.id = sei.entity_id
    LEFT JOIN entity_occ eo ON eo.entity_id = sei.entity_id
    CROSS JOIN trunc_flag tf
  ),
  edge_rows AS (
    SELECT 'edge'::text AS kind,
           NULL::uuid AS node_entity_id,
           NULL::text AS node_entity_type,
           NULL::text AS node_canonical_value,
           NULL::text AS node_display_name,
           NULL::integer AS node_min_depth,
           se.relationship_id AS edge_relationship_id,
           se.source_entity_id AS edge_source_entity_id,
           se.target_entity_id AS edge_target_entity_id,
           se.relationship_type_urn AS edge_relationship_type_urn,
           se.observation_count AS edge_observation_count,
           se.investigation_observation_count
             AS edge_investigation_observation_count,
           se.first_observed_at AS edge_first_observed_at,
           se.last_observed_at AS edge_last_observed_at,
           se.edge_min_depth AS edge_min_depth,
           tf.truncated
    FROM selected_edges se
    CROSS JOIN trunc_flag tf
  )
  SELECT unified.kind,
         unified.node_entity_id,
         unified.node_entity_type,
         unified.node_canonical_value,
         unified.node_display_name,
         unified.node_min_depth,
         unified.edge_relationship_id,
         unified.edge_source_entity_id,
         unified.edge_target_entity_id,
         unified.edge_relationship_type_urn,
         unified.edge_observation_count,
         unified.edge_investigation_observation_count,
         unified.edge_first_observed_at,
         unified.edge_last_observed_at,
         unified.edge_min_depth,
         unified.truncated
  FROM (
    SELECT 0::integer AS row_order, *
    FROM node_rows
    UNION ALL
    SELECT 1::integer AS row_order, *
    FROM edge_rows
  ) unified
  ORDER BY unified.row_order,
           unified.node_min_depth ASC NULLS LAST,
           unified.node_entity_id ASC NULLS LAST,
           unified.edge_min_depth ASC NULLS LAST,
           unified.edge_relationship_id ASC NULLS LAST;
END $$;
