// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Incremental expansion placement tests (PR 31E, G31E-L01..L08).
//
// New Entities receive deterministic, collision-free positions on a bounded
// ring around the expanded anchor; existing node positions are never
// consulted for identity matching here (the caller positions only genuinely
// new Entities) and nothing is persisted.

import { describe, expect, it } from "vitest";

import { positionsForExpandedNodes, type GraphPosition } from "./relationship-graph-layout";

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
