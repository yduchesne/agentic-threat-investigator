// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic directed graph layout adapter (PR 38-10; PR 31E expansion;
// PR 31H multi-hop distance rings, superseded).
//
// React Flow renders graph topology but intentionally ships no automatic node
// layout. The previous ``layeredPositions`` placed nodes on concentric
// hop-distance rings: deterministic, but not edge-aware, so it wasted canvas
// space and produced visually disorderly chains/branches. PR 38-10 keeps the
// deterministic-expansion contract and replaces only the root/new-topology
// placement with Dagre running top-to-bottom over the canonical directed
// topology.
//
// Dagre stays behind this ATI-owned adapter: ``RelationshipGraph.tsx`` never
// touches Dagre. Layout is presentation-only. Canonical Entity/Relationship
// identities and topology remain authoritative (Dagre never adds, removes or
// filters a canonical Relationship), coordinates are never persisted, and
// same-root expansion continues to use :func:`positionsForExpandedNodes` so
// existing (possibly analyst-dragged) coordinates are never recomputed.

import dagre from "@dagrejs/dagre";

/** One positioned node coordinate (view-space units, React Flow top-left). */
export interface GraphPosition {
  x: number;
  y: number;
}

/** Centralized Dagre layout configuration (PR 38-10 Step 11). */
export interface RelationshipLayoutConfig {
  /** Dagre rank direction. ATI's default is top-to-bottom. */
  direction: "TB";
  /** Fixed layout node width (bounded node presentation envelope). */
  nodeWidth: number;
  /** Fixed layout node height (bounded node presentation envelope). */
  nodeHeight: number;
  /** Horizontal separation between nodes in the same rank. */
  nodeSeparation: number;
  /** Vertical separation between ranks. */
  rankSeparation: number;
}

/**
 * Conservative fixed layout dimensions matching the bounded node
 * presentation envelope.
 *
 * Fixed dimensions avoid asynchronous measure/re-layout cycles and keep the
 * first paint deterministic. The values are deliberately a little larger
 * than the measured node so labels never collide in the layout math.
 */
export const DEFAULT_RELATIONSHIP_LAYOUT_CONFIG: RelationshipLayoutConfig = {
  direction: "TB",
  nodeWidth: 200,
  nodeHeight: 72,
  nodeSeparation: 60,
  rankSeparation: 100,
};

/** Minimal canonical node input the layout adapter needs. */
interface LayoutNode {
  entityId: string;
}

/** Minimal canonical edge input; ``relationshipId`` only orders the input. */
interface LayoutEdge {
  relationshipId?: string | undefined;
  sourceEntityId: string;
  targetEntityId: string;
}

/** Stable canonical string comparison (never locale-dependent). */
function compareCanonical(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Deterministic finite fallback placement (sorted-identity grid).
 *
 * Used only if the layout engine cannot produce a result for the canonical
 * topology, so the graph always renders with finite, non-colliding, stable
 * coordinates; canonical topology is never changed.
 */
function fallbackPositions(
  orderedIds: readonly string[],
  config: RelationshipLayoutConfig,
): ReadonlyMap<string, GraphPosition> {
  const positions = new Map<string, GraphPosition>();
  const columns = Math.max(1, Math.ceil(Math.sqrt(orderedIds.length)));
  orderedIds.forEach((entityId, index) => {
    positions.set(entityId, {
      x: (index % columns) * (config.nodeWidth + config.nodeSeparation),
      y: Math.floor(index / columns) * (config.nodeHeight + config.rankSeparation),
    });
  });
  return positions;
}

/**
 * Deterministic Dagre top-to-bottom layout for one root graph topology.
 *
 * Nodes are sorted by canonical Entity ID and edges by canonical Relationship
 * ID (falling back to endpoint IDs) before anything is handed to Dagre, so
 * the same canonical topology always yields the same positions regardless of
 * API/Map/object iteration order. Edges keep their canonical direction
 * (``sourceEntityId -> targetEntityId``): inbound edges, cycles and multiple
 * parents are laid out as-authored, never reversed for appearance.
 *
 * Self-loops never constrain node rank and parallel Relationships between the
 * same endpoint pair never distort ranking. Both remain in the canonical
 * rendered model; only Dagre's rank input de-duplicates identical directed
 * pairs. Dagre node centers are converted to React Flow top-left coordinates.
 *
 * Returns a position for every canonical Entity plus the focal (at minimum);
 * an empty node set yields an empty map.
 */
export function layoutRelationshipGraph(
  focalId: string,
  nodes: readonly LayoutNode[],
  edges: readonly LayoutEdge[],
  config: RelationshipLayoutConfig = DEFAULT_RELATIONSHIP_LAYOUT_CONFIG,
): ReadonlyMap<string, GraphPosition> {
  const orderedIds = [...new Set([focalId, ...nodes.map((node) => node.entityId)])]
    .sort(compareCanonical);
  const orderedEdges = [...edges].sort((a, b) => {
    const source = compareCanonical(a.sourceEntityId, b.sourceEntityId);
    if (source !== 0) {
      return source;
    }
    const target = compareCanonical(a.targetEntityId, b.targetEntityId);
    if (target !== 0) {
      return target;
    }
    return compareCanonical(a.relationshipId ?? "", b.relationshipId ?? "");
  });

  const graph = new dagre.graphlib.Graph();
  graph.setGraph({
    rankdir: config.direction,
    nodesep: config.nodeSeparation,
    ranksep: config.rankSeparation,
  });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const entityId of orderedIds) {
    graph.setNode(entityId, {
      width: config.nodeWidth,
      height: config.nodeHeight,
    });
  }

  const seenPairs = new Set<string>();
  for (const edge of orderedEdges) {
    if (edge.sourceEntityId === edge.targetEntityId) {
      continue; // a self-loop is topology, never a rank constraint
    }
    if (!graph.hasNode(edge.sourceEntityId) || !graph.hasNode(edge.targetEntityId)) {
      continue; // never invent an endpoint
    }
    const pair = `${edge.sourceEntityId}\u0000${edge.targetEntityId}`;
    if (seenPairs.has(pair)) {
      continue; // parallel relationships do not distort ranking
    }
    seenPairs.add(pair);
    graph.setEdge(edge.sourceEntityId, edge.targetEntityId);
  }

  try {
    dagre.layout(graph);
  } catch {
    return fallbackPositions(orderedIds, config);
  }

  const positions = new Map<string, GraphPosition>();
  for (const entityId of orderedIds) {
    const node = graph.node(entityId);
    positions.set(entityId, {
      x: node.x - config.nodeWidth / 2,
      y: node.y - config.nodeHeight / 2,
    });
  }
  return positions;
}

/** Bounded expansion ring radius used for newly discovered Entities. */
const EXPANSION_RADIUS = 150;
/** Start angle (radians) for new-node placement. The root layout is
 * top-to-bottom, so the first expansion candidate is placed below its anchor
 * (away from the focal/parent side) instead of directly between them. */
const START_ANGLE = Math.PI / 2;
/** Deterministic collision-avoidance step (golden angle), applies only when
 * an exact candidate position is already occupied. */
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Deterministic positions for newly discovered Entities around an anchor.
 *
 * New Entity IDs are sorted by canonical identity before angles are
 * assigned, so the same input set always produces the same positions
 * (PR 31E L01-L03). Every candidate sits on a bounded ring around the
 * anchor; when an exact candidate coordinate is already occupied by an
 * existing node, a fixed golden-angle step rotates the candidate until a
 * free coordinate is found (bounded attempts, deterministic). Existing
 * node coordinates are never consulted for identity matching here: the
 * caller positions only genuinely new Entities. Returns an empty map for
 * an empty input set, and never returns coordinates for an Entity that is
 * not in ``newEntityIds``.
 *
 * This remains the expansion contract for same-root growth (PR 38-10 Step
 * 13): existing positions are preserved and only genuinely new Entities are
 * placed, so an explicit expansion never re-runs the root Dagre layout.
 */
export function positionsForExpandedNodes(
  anchorPosition: GraphPosition,
  newEntityIds: readonly string[],
  occupiedPositions: ReadonlyMap<string, GraphPosition>,
): ReadonlyMap<string, GraphPosition> {
  const ordered = [...newEntityIds].sort(compareCanonical);
  const occupied = new Set(
    [...occupiedPositions.values()].map(
      (position) => `${Math.round(position.x)},${Math.round(position.y)}`,
    ),
  );
  const result = new Map<string, GraphPosition>();
  const count = ordered.length;
  ordered.forEach((id, index) => {
    const step = count === 1 ? 0 : (2 * Math.PI * index) / count;
    let angle = START_ANGLE + step;
    let position: GraphPosition = {
      x: anchorPosition.x + Math.cos(angle) * EXPANSION_RADIUS,
      y: anchorPosition.y + Math.sin(angle) * EXPANSION_RADIUS,
    };
    const key = (p: GraphPosition): string =>
      `${Math.round(p.x)},${Math.round(p.y)}`;
    let attempts = 0;
    while (occupied.has(key(position)) && attempts < 8) {
      angle += GOLDEN_ANGLE;
      position = {
        x: anchorPosition.x + Math.cos(angle) * EXPANSION_RADIUS,
        y: anchorPosition.y + Math.sin(angle) * EXPANSION_RADIUS,
      };
      attempts += 1;
    }
    occupied.add(key(position));
    result.set(id, position);
  });
  return result;
}

/**
 * Approximate canvas size that contains the deterministic layout bounds.
 *
 * The canvas grows with the laid-out topology so a deep/broad graph is not
 * squeezed into a tiny viewport; the React Flow fit action then frames the
 * actual nodes. This is presentation sizing only and never affects node
 * coordinates or canonical topology.
 */
export function layoutSize(
  positions: Iterable<GraphPosition>,
  config: RelationshipLayoutConfig = DEFAULT_RELATIONSHIP_LAYOUT_CONFIG,
): { width: number; height: number } {
  let minX = Number.POSITIVE_INFINITY;
  let minY = Number.POSITIVE_INFINITY;
  let maxX = Number.NEGATIVE_INFINITY;
  let maxY = Number.NEGATIVE_INFINITY;
  let any = false;
  for (const position of positions) {
    any = true;
    minX = Math.min(minX, position.x);
    minY = Math.min(minY, position.y);
    maxX = Math.max(maxX, position.x);
    maxY = Math.max(maxY, position.y);
  }
  if (!any) {
    return { width: 640, height: 480 };
  }
  return {
    width: Math.max(640, maxX - minX + config.nodeWidth + 160),
    height: Math.max(480, maxY - minY + config.nodeHeight + 160),
  };
}
