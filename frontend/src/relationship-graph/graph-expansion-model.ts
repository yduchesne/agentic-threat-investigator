// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical accumulated-graph merge contract (PR 31E).
//
// Analyst-driven expansion is a read-only exploration operation over
// topology already admitted to the current Investigation. Each explicit
// expansion action fetches the bounded one-hop neighborhood of the
// selected Entity through the existing PR 31C graph endpoint and merges
// the response into the accumulated graph by canonical identity:
// Entity -> ``entity_id``, Relationship -> ``relationship_id``. One
// canonical Relationship stays one rendered edge; the newest successful
// response wins field values for an already-present canonical object
// while its existing order position is preserved; genuinely new objects
// append in server-return order; and observation counts are never summed
// client-side. Expansion identity is ``(entity_id, direction)`` within
// the current root graph context. Nothing here infers topology, persists
// anything, or performs provider/acquisition behavior, and no React Flow
// presentation state (positions, viewport, selection) is stored.

import type {
  GraphEdge,
  GraphNeighborhood,
  GraphNode,
  RelationshipDirectionName,
} from "../api/schema-types";

/** One completed expansion identity within the current root context. */
export interface ExpandedNeighborhoodKey {
  entityId: string;
  direction: RelationshipDirectionName;
}

/** Deterministic accumulated graph state (server types only, no positions). */
export interface AccumulatedGraph {
  /** The workspace root/focal Entity; never replaced by expansion. */
  rootEntityId: string;
  /** All accumulated canonical nodes (existing canonical order first). */
  nodes: readonly GraphNode[];
  /** All accumulated canonical edges (existing canonical order first). */
  edges: readonly GraphEdge[];
  /** Successful expansion keys, in completion order, no duplicates. */
  expanded: readonly ExpandedNeighborhoodKey[];
  /** Successful expansion keys whose response carried ``truncated=true``. */
  truncatedExpansions: readonly ExpandedNeighborhoodKey[];
  /** Server truthfulness flag of the current root response. */
  rootTruncated: boolean;
}

/** One successful expansion response to merge into the accumulated graph. */
export interface ExpansionResult {
  key: ExpandedNeighborhoodKey;
  neighborhood: GraphNeighborhood;
}

/** Whether one expansion key matches an entity/direction pair exactly. */
export function expansionKeyMatches(
  key: ExpandedNeighborhoodKey,
  entityId: string,
  direction: RelationshipDirectionName,
): boolean {
  return key.entityId === entityId && key.direction === direction;
}

/** Canonical collision-safe serialization of one expansion key. */
export function expansionKeyString(key: ExpandedNeighborhoodKey): string {
  return `${key.entityId}\u0000${key.direction}`;
}

/** Accumulated graph built from a successful root neighborhood. */
export function emptyAccumulatedGraph(
  rootEntityId: string,
  neighborhood: GraphNeighborhood,
): AccumulatedGraph {
  return {
    rootEntityId,
    nodes: neighborhood.nodes,
    edges: neighborhood.edges,
    expanded: [],
    truncatedExpansions: [],
    rootTruncated: neighborhood.truncated,
  };
}

/**
 * Merge one bounded expansion response into the accumulated graph.
 *
 * Entities merge by ``entity_id`` and Relationships by ``relationship_id``.
 * A newer successful response wins field values for an already-present
 * canonical object while its existing order position is preserved; new
 * objects append in server-return order. Observation counts are never
 * summed and no topology is synthesized. The expansion key is recorded as
 * successful exactly once, and the response's ``truncated`` flag marks the
 * key when further known relationships exist.
 */
export function mergeNeighborhood(
  current: AccumulatedGraph,
  expansion: ExpansionResult,
): AccumulatedGraph {
  const { key, neighborhood } = expansion;
  // New successful response wins for duplicate canonical IDs.
  const nodesById = new Map(current.nodes.map((node) => [node.entity_id, node]));
  for (const node of neighborhood.nodes) {
    nodesById.set(node.entity_id, node);
  }
  const edgesById = new Map(
    current.edges.map((edge) => [edge.relationship_id, edge]),
  );
  for (const edge of neighborhood.edges) {
    edgesById.set(edge.relationship_id, edge);
  }
  // Existing canonical order first; genuinely new objects appended in
  // server-return order (never reordered against the current graph).
  const existingNodeIds = new Set(current.nodes.map((node) => node.entity_id));
  const nodes: GraphNode[] = [
    ...current.nodes.map((node) => nodesById.get(node.entity_id) ?? node),
    ...neighborhood.nodes.filter((node) => !existingNodeIds.has(node.entity_id)),
  ];
  const existingEdgeIds = new Set(
    current.edges.map((edge) => edge.relationship_id),
  );
  const edges: GraphEdge[] = [
    ...current.edges.map((edge) => edgesById.get(edge.relationship_id) ?? edge),
    ...neighborhood.edges.filter(
      (edge) => !existingEdgeIds.has(edge.relationship_id),
    ),
  ];
  const alreadyExpanded = current.expanded.some((entry) =>
    expansionKeyMatches(entry, key.entityId, key.direction),
  );
  const expanded = alreadyExpanded
    ? current.expanded
    : [...current.expanded, key];
  const alreadyTruncated = current.truncatedExpansions.some((entry) =>
    expansionKeyMatches(entry, key.entityId, key.direction),
  );
  const truncatedExpansions =
    neighborhood.truncated && !alreadyTruncated
      ? [...current.truncatedExpansions, key]
      : current.truncatedExpansions;
  return {
    ...current,
    nodes,
    edges,
    expanded,
    truncatedExpansions,
  };
}

/**
 * Overlay a refreshed root neighborhood onto the accumulated graph.
 *
 * Same root semantic inputs (investigation, focal Entity, direction,
 * relationship type) + a fresh successful root response: refreshed server
 * data wins for overlapping canonical IDs, local expansion topology and
 * completion state are preserved, and the root truncation flag is
 * refreshed. Never used across root semantic changes (those reset
 * accumulated state entirely).
 */
export function overlayRootNeighborhood(
  current: AccumulatedGraph,
  rootNeighborhood: GraphNeighborhood,
): AccumulatedGraph {
  const nodesById = new Map(current.nodes.map((node) => [node.entity_id, node]));
  for (const node of rootNeighborhood.nodes) {
    nodesById.set(node.entity_id, node);
  }
  const edgesById = new Map(
    current.edges.map((edge) => [edge.relationship_id, edge]),
  );
  for (const edge of rootNeighborhood.edges) {
    edgesById.set(edge.relationship_id, edge);
  }
  const existingNodeIds = new Set(current.nodes.map((node) => node.entity_id));
  const nodes: GraphNode[] = [
    ...current.nodes.map((node) => nodesById.get(node.entity_id) ?? node),
    ...rootNeighborhood.nodes.filter(
      (node) => !existingNodeIds.has(node.entity_id),
    ),
  ];
  const existingEdgeIds = new Set(
    current.edges.map((edge) => edge.relationship_id),
  );
  const edges: GraphEdge[] = [
    ...current.edges.map((edge) => edgesById.get(edge.relationship_id) ?? edge),
    ...rootNeighborhood.edges.filter(
      (edge) => !existingEdgeIds.has(edge.relationship_id),
    ),
  ];
  return {
    ...current,
    nodes,
    edges,
    rootTruncated: rootNeighborhood.truncated,
  };
}

/** Whether an entity/direction pair has already been expanded successfully. */
export function isExpansionCompleted(
  graph: AccumulatedGraph,
  entityId: string,
  direction: RelationshipDirectionName,
): boolean {
  return graph.expanded.some((key) =>
    expansionKeyMatches(key, entityId, direction),
  );
}
