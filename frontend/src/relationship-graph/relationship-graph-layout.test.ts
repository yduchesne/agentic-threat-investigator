// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Incremental expansion placement tests (PR 31E, G31E-L01..L08).
//
// New Entities receive deterministic, collision-free positions on a bounded
// ring around the expanded anchor; existing node positions are never
// consulted for identity matching here (the caller positions only genuinely
// new Entities) and nothing is persisted.

import { describe, expect, it } from "vitest";

import {
  layeredPositions,
  positionsForExpandedNodes,
  radialPositions,
  type GraphPosition,
} from "./relationship-graph-layout";

const ANCHOR: GraphPosition = { x: 0, y: 0 };
const A = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";

describe("positionsForExpandedNodes (PR 31E incremental placement)", () => {
  it("G31E-L01: one new node gets a deterministic near-anchor position", () => {
    const positions = positionsForExpandedNodes(ANCHOR, [A], new Map());
    expect(positions.has(A)).toBe(true);
    const position = positions.get(A) as GraphPosition;
    // Bounded distance from the anchor (a ring inside the radial layout).
    expect(Math.hypot(position.x - ANCHOR.x, position.y - ANCHOR.y)).toBeGreaterThan(0);
    expect(Math.hypot(position.x - ANCHOR.x, position.y - ANCHOR.y)).toBeLessThanOrEqual(160);
  });

  it("G31E-L02: multiple new nodes get distinct deterministic positions", () => {
    const positions = positionsForExpandedNodes(ANCHOR, [A, B, C], new Map());
    expect([...positions.keys()].sort()).toEqual([A, B, C].sort());
    const coords = [...positions.values()];
    const unique = new Set(coords.map((p) => `${p.x},${p.y}`));
    expect(unique.size).toBe(3);
  });

  it("G31E-L03: repeat calculation returns identical positions", () => {
    const first = positionsForExpandedNodes(ANCHOR, [A, B], new Map());
    const second = positionsForExpandedNodes(ANCHOR, [A, B], new Map());
    expect([...first.entries()]).toEqual([...second.entries()]);
  });

  it("G31E-L04/L05: positions of existing occupied nodes are untouched", () => {
    const occupied = new Map<string, GraphPosition>([
      ["n:existing", { x: 7, y: 9 }],
      ["n:other", { x: -7, y: -9 }],
    ]);
    const positions = positionsForExpandedNodes(ANCHOR, [A], occupied);
    expect(positions.has(A)).toBe(true);
    // The function never returns coordinates for existing nodes.
    expect(positions.has("n:existing")).toBe(false);
  });

  it("G31E-L06: an empty new-node set produces no new positions", () => {
    const positions = positionsForExpandedNodes(ANCHOR, [], new Map());
    expect(positions.size).toBe(0);
  });

  it("G31E-L07: only entities present in the new set are positioned (self-loop never adds a node)", () => {
    const positions = positionsForExpandedNodes(ANCHOR, [B], new Map());
    expect(positions.has(B)).toBe(true);
    expect(positions.has(A)).toBe(false);
    expect(positions.size).toBe(1);
  });

  it("G31E-L08: later expansions do not reposition earlier nodes", () => {
    const first = positionsForExpandedNodes(ANCHOR, [A], new Map());
    const later = positionsForExpandedNodes(ANCHOR, [B], new Map(first as Map<string, GraphPosition>));
    // B gets a fresh deterministic position; A's position is never rewritten.
    expect(later.get(A)).toBeUndefined();
    expect(later.has(B)).toBe(true);
  });

  it("G31E-L08: exact coordinate collisions are avoided deterministically", () => {
    // Occupy the exact coordinate the single-node layout would choose
    // (anchor + (0, -150) for START_ANGLE=-pi/2, radius 150).
    const collision: GraphPosition = { x: 0, y: -150 };
    const occupied = new Map([["n:blocker", collision]]);
    const positions = positionsForExpandedNodes(ANCHOR, [A], occupied);
    const chosen = positions.get(A) as GraphPosition;
    expect(Math.round(chosen.x) === 0 && Math.round(chosen.y) === -150).toBe(false);
    // Still within the bounded ring.
    expect(Math.hypot(chosen.x - ANCHOR.x, chosen.y - ANCHOR.y)).toBeLessThanOrEqual(160);
  });
});

describe("layeredPositions (PR 31H multi-hop distance rings)", () => {
  const nodes = [
    { entityId: "50000000-0000-4000-8000-000000000001" },
    { entityId: "50000000-0000-4000-8000-000000000002" },
    { entityId: "50000000-0000-4000-8000-000000000003" },
    { entityId: "50000000-0000-4000-8000-000000000004" },
  ];

  it("H-L01: depth-1 topology equals the radial single-ring layout", () => {
    const focal = nodes[0].entityId;
    const ring = nodes.slice(1);
    const edges = ring.map((node) => ({
      sourceEntityId: focal,
      targetEntityId: node.entityId,
    }));
    const layered = layeredPositions(focal, nodes, edges);
    const radial = radialPositions(focal, ring.map((node) => node.entityId));
    expect(Math.round(layered.focal.x)).toBe(0);
    expect(Math.round(layered.focal.y)).toBe(0);
    for (const node of ring) {
      const layeredPos = layered.positions.get(node.entityId) as GraphPosition;
      const radialPos = radial.counterparties.get(node.entityId) as GraphPosition;
      expect(Math.round(layeredPos.x)).toBe(Math.round(radialPos.x));
      expect(Math.round(layeredPos.y)).toBe(Math.round(radialPos.y));
    }
  });

  it("H-L02: a chain places hop-2 entities on an outer distance ring", () => {
    const focal = nodes[0].entityId;
    const b = nodes[1].entityId;
    const c = nodes[2].entityId;
    const d = nodes[3].entityId;
    const edges = [
      { sourceEntityId: focal, targetEntityId: b },
      { sourceEntityId: b, targetEntityId: c },
      { sourceEntityId: c, targetEntityId: d },
    ];
    const layout = layeredPositions(focal, nodes, edges);
    const bPos = layout.positions.get(b) as GraphPosition;
    const cPos = layout.positions.get(c) as GraphPosition;
    const dPos = layout.positions.get(d) as GraphPosition;
    // Hop distance from the focal rings: 220 (hop 1), 440 (hop 2), 660 (hop 3).
    expect(Math.round(Math.hypot(bPos.x, bPos.y))).toBe(220);
    expect(Math.round(Math.hypot(cPos.x, cPos.y))).toBe(440);
    expect(Math.round(Math.hypot(dPos.x, dPos.y))).toBe(660);
  });

  it("H-L03: a diamond uses the MINIMUM hop distance per node", () => {
    const focal = nodes[0].entityId;
    const b = nodes[1].entityId;
    const c = nodes[2].entityId;
    const d = nodes[3].entityId;
    const edges = [
      { sourceEntityId: focal, targetEntityId: b },
      { sourceEntityId: focal, targetEntityId: c },
      { sourceEntityId: b, targetEntityId: d },
      { sourceEntityId: c, targetEntityId: d },
    ];
    const layout = layeredPositions(focal, nodes, edges);
    const dPos = layout.positions.get(d) as GraphPosition;
    // D is reachable in two hops through either branch: ring 2.
    expect(Math.round(Math.hypot(dPos.x, dPos.y))).toBe(440);
  });

  it("H-L04: self-loops never contribute a distance step", () => {
    const focal = nodes[0].entityId;
    const b = nodes[1].entityId;
    const edges = [
      { sourceEntityId: focal, targetEntityId: focal },
      { sourceEntityId: focal, targetEntityId: b },
    ];
    const layout = layeredPositions(focal, nodes, edges);
    const bPos = layout.positions.get(b) as GraphPosition;
    expect(Math.round(Math.hypot(bPos.x, bPos.y))).toBe(220);
  });

  it("H-L05: positions are deterministic and identity-sorted per ring", () => {
    const focal = nodes[0].entityId;
    const ring = nodes.slice(1);
    const edges = ring.map((node) => ({
      sourceEntityId: focal,
      targetEntityId: node.entityId,
    }));
    const first = layeredPositions(focal, nodes, edges);
    const second = layeredPositions(focal, [...nodes].reverse(), edges);
    for (const node of nodes) {
      if (node.entityId === focal) {
        continue; // the focal sits at the center, not in the ring map
      }
      const a = first.positions.get(node.entityId) as GraphPosition;
      const b = second.positions.get(node.entityId) as GraphPosition;
      expect(Math.round(a.x)).toBe(Math.round(b.x));
      expect(Math.round(a.y)).toBe(Math.round(b.y));
    }
  });
});
