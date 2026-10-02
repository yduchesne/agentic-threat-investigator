// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic radial / layered graph layout (PR 24E §25; PR 31E expansion;
// PR 31H multi-hop distance rings).
//
// Focal entity centered, counterparties evenly spaced on a circle (or, for
// multi-hop traversal, on minimum-distance rings). The layout depends only on
// the sorted counterparty identity order, so it is fully deterministic and
// never persisted (coordinates are presentation only; no graph physics for
// cosmetic effect). PR 31E adds incremental placement for expansion:
// genuinely new Entities are arranged on a small bounded ring around the
// expanded anchor Entity, ordered by canonical identity and never colliding
// exactly with an existing position.

/** One positioned node coordinate (view-space units). */
export interface GraphPosition {
  x: number;
  y: number;
}

const RADIUS = 220;
/** Distance-ring step for the PR 31H layered layout (ring 1 = RADIUS). */
const RING_STEP = RADIUS;
/** Half the radial base layout: expansion rings stay inside the circle. */
const EXPANSION_RADIUS = 150;
/** Extra angular offset (radians) so the first counterparty is not stuck
 * exactly at 3 o'clock for every query. */
const START_ANGLE = -Math.PI / 2;
/** Deterministic collision-avoidance step (golden angle), applies only when
 * an exact candidate position is already occupied. */
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

/**
 * Deterministic layered positions for one focal + N counterparties (PR 31H).
 *
 * Multi-hop traversal results are placed on distance rings: the focal at the
 * center, every other node on the ring of its minimum hop distance from the
 * focal computed over the RETURNED graph topology (unweighted adjacency over
 * the returned canonical edges; self-loops never contribute distance). Within
 * one ring, entity IDs are sorted before angles are assigned, so the same
 * identities always produce the same positions. For a depth-1 neighborhood
 * (every counterparty at distance 1) the result is byte-identical to
 * :func:`radialPositions`, keeping the one-hop visual unchanged. Position is
 * presentation-only and never persisted; an entity unreachable through the
 * returned edges (a closed result makes this impossible) falls back to ring 1.
 */
export function layeredPositions(
  focalId: string,
  nodes: readonly { entityId: string }[],
  edges: readonly { sourceEntityId: string; targetEntityId: string }[],
): { focal: GraphPosition; positions: ReadonlyMap<string, GraphPosition> } {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    if (edge.sourceEntityId === edge.targetEntityId) {
      continue; // a self-loop is topology, never a distance step
    }
    for (const [a, b] of [
      [edge.sourceEntityId, edge.targetEntityId],
      [edge.targetEntityId, edge.sourceEntityId],
    ]) {
      const list = adjacency.get(a) ?? [];
      list.push(b);
      adjacency.set(a, list);
    }
  }
  const distance = new Map<string, number>([[focalId, 0]]);
  const queue = [focalId];
  const depth = new Map<string, number>([[focalId, 0]]);
  while (queue.length > 0) {
    const current = queue.shift() ?? "";
    const currentDepth = depth.get(current) ?? 0;
    for (const next of adjacency.get(current) ?? []) {
      if (distance.has(next)) {
        continue;
      }
      distance.set(next, currentDepth + 1);
      depth.set(next, currentDepth + 1);
      queue.push(next);
    }
  }
  const byDistance = new Map<number, string[]>();
  for (const node of nodes) {
    if (node.entityId === focalId) {
      continue;
    }
    const ring = Math.max(1, distance.get(node.entityId) ?? 1);
    const list = byDistance.get(ring) ?? [];
    list.push(node.entityId);
    byDistance.set(ring, list);
  }
  const positions = new Map<string, GraphPosition>();
  for (const [ring, ids] of byDistance) {
    const ordered = [...ids].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const radius = RING_STEP * ring;
    const step = (2 * Math.PI) / ordered.length;
    ordered.forEach((id, index) => {
      const angle = START_ANGLE + step * index;
      positions.set(id, {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      });
    });
  }
  return { focal: { x: 0, y: 0 }, positions };
}

/**
 * Deterministic radial positions for one focal + N counterparties.
 *
 * Positions depend only on the identity set, never on the input order or on
 * server ordering: the counterparty ids are sorted internally before angles
 * are assigned, so the same identities always produce the same initial
 * positions (G31D-M12). A new focal or neighborhood may re-run this layout;
 * the result is presentation-only and never persisted.
 */
export function radialPositions(
  focalId: string,
  counterpartyIds: readonly string[],
): { focal: GraphPosition; counterparties: ReadonlyMap<string, GraphPosition> } {
  const counterparties = new Map<string, GraphPosition>();
  const ordered = [...counterpartyIds].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const count = ordered.length;
  if (count > 0) {
    const step = (2 * Math.PI) / count;
    ordered.forEach((id, index) => {
      const angle = START_ANGLE + step * index;
      counterparties.set(id, {
        x: Math.cos(angle) * RADIUS,
        y: Math.sin(angle) * RADIUS,
      });
    });
  }
  return { focal: { x: 0, y: 0 }, counterparties };
}

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
 */
export function positionsForExpandedNodes(
  anchorPosition: GraphPosition,
  newEntityIds: readonly string[],
  occupiedPositions: ReadonlyMap<string, GraphPosition>,
): ReadonlyMap<string, GraphPosition> {
  const ordered = [...newEntityIds].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
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

/** Approximate canvas size that fits the deterministic layout. */
export function layoutSize(counterpartyCount: number): { width: number; height: number } {
  const diameter = RADIUS * 2 + 240;
  // Grow only mildly with the bounded neighbour count so a packed page
  // never collapses into unusable overlap.
  const spread = Math.min(4, Math.max(0, counterpartyCount - 6)) * 40;
  return {
    width: Math.max(640, diameter + spread),
    height: Math.max(480, diameter + spread),
  };
}
