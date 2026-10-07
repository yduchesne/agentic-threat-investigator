// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic directed layout tests (PR 38-10 G-L01..G-L15) and incremental
// expansion placement tests (PR 31E G31E-L01..L08).
//
// The root layout is Dagre top-to-bottom over the canonical directed
// topology. Assertions avoid brittle exact pixel values: they check
// direction/rank order, determinism under canonical input reordering, finite
// coordinates, absence of exact collisions and identity preservation.

import { describe, expect, it } from "vitest";

import {
  DEFAULT_RELATIONSHIP_LAYOUT_CONFIG,
  layoutRelationshipGraph,
  layoutSize,
  positionsForExpandedNodes,
  type GraphPosition,
} from "./relationship-graph-layout";

const ANCHOR: GraphPosition = { x: 0, y: 0 };
const A = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";
const D = "40000000-0000-4000-8000-000000000104";
const E = "40000000-0000-4000-8000-000000000105";

interface TestEdge {
  relationshipId: string;
  sourceEntityId: string;
  targetEntityId: string;
}

function edge(
  relationshipId: string,
  sourceEntityId: string,
  targetEntityId: string,
): TestEdge {
  return { relationshipId, sourceEntityId, targetEntityId };
}

function nodeIds(...ids: string[]): { entityId: string }[] {
  return ids.map((entityId) => ({ entityId }));
}

function at(
  layout: ReadonlyMap<string, GraphPosition>,
  entityId: string,
): GraphPosition {
  const position = layout.get(entityId);
  expect(position).toBeDefined();
  return position as GraphPosition;
}

function expectFinite(layout: ReadonlyMap<string, GraphPosition>): void {
  for (const [entityId, position] of layout) {
    expect(Number.isFinite(position.x), `${entityId} x`).toBe(true);
    expect(Number.isFinite(position.y), `${entityId} y`).toBe(true);
  }
}

describe("layoutRelationshipGraph (PR 38-10 Dagre root layout)", () => {
  it("G-L01: a single focal node receives a finite deterministic position", () => {
    const first = layoutRelationshipGraph(A, nodeIds(A), []);
    const second = layoutRelationshipGraph(A, nodeIds(A), []);
    expect(first.size).toBe(1);
    expectFinite(first);
    expect(at(first, A)).toEqual(at(second, A));
  });

  it("G-L02: a simple chain is laid out top-to-bottom in canonical direction", () => {
    const layout = layoutRelationshipGraph(
      A,
      nodeIds(A, B, C),
      [edge("r1", A, B), edge("r2", B, C)],
    );
    expectFinite(layout);
    expect(at(layout, A).y).toBeLessThan(at(layout, B).y);
    expect(at(layout, B).y).toBeLessThan(at(layout, C).y);
  });

  it("G-L03: a star separates children without overlap", () => {
    const layout = layoutRelationshipGraph(
      A,
      nodeIds(A, B, C, D),
      [edge("r1", A, B), edge("r2", A, C), edge("r3", A, D)],
    );
    expectFinite(layout);
    const children = [B, C, D].map((id) => at(layout, id));
    // Every child pair is separated by at least the configured node width.
    for (let i = 0; i < children.length; i += 1) {
      for (let j = i + 1; j < children.length; j += 1) {
        expect(
          Math.abs(children[i].x - children[j].x),
        ).toBeGreaterThanOrEqual(DEFAULT_RELATIONSHIP_LAYOUT_CONFIG.nodeWidth);
      }
    }
  });

  it("G-L04: inbound and outbound focal relationships respect direction", () => {
    const layout = layoutRelationshipGraph(
      A,
      nodeIds(A, B, C),
      [edge("r1", B, A), edge("r2", A, C)],
    );
    expectFinite(layout);
    // Inbound B ranks above the focal; outbound C ranks below it.
    expect(at(layout, B).y).toBeLessThan(at(layout, A).y);
    expect(at(layout, A).y).toBeLessThan(at(layout, C).y);
  });

  it("G-L05: shuffled node order yields identical positions", () => {
    const edges = [edge("r1", A, B), edge("r2", B, C), edge("r3", A, D)];
    const first = layoutRelationshipGraph(A, nodeIds(A, B, C, D), edges);
    const second = layoutRelationshipGraph(A, nodeIds(D, B, A, C), edges);
    for (const id of [A, B, C, D]) {
      expect(at(second, id)).toEqual(at(first, id));
    }
  });

  it("G-L06: shuffled edge order yields identical positions", () => {
    const nodes = nodeIds(A, B, C, D);
    const first = layoutRelationshipGraph(A, nodes, [
      edge("r1", A, B),
      edge("r2", B, C),
      edge("r3", A, D),
    ]);
    const second = layoutRelationshipGraph(A, nodes, [
      edge("r3", A, D),
      edge("r1", A, B),
      edge("r2", B, C),
    ]);
    for (const id of [A, B, C, D]) {
      expect(at(second, id)).toEqual(at(first, id));
    }
  });

  it("G-L07: a depth-3 branching graph is finite, deterministic and collision-free", () => {
    const nodes = nodeIds(A, B, C, D, E);
    const edges = [
      edge("r1", A, B),
      edge("r2", A, C),
      edge("r3", B, D),
      edge("r4", C, E),
    ];
    const first = layoutRelationshipGraph(A, nodes, edges);
    const second = layoutRelationshipGraph(A, nodes, [...edges].reverse());
    expectFinite(first);
    for (const id of [A, B, C, D, E]) {
      expect(at(second, id)).toEqual(at(first, id));
    }
    const coords = new Set(
      [...first.values()].map((p) => `${Math.round(p.x)},${Math.round(p.y)}`),
    );
    expect(coords.size).toBe(nodes.length);
    expect(at(first, A).y).toBeLessThan(at(first, B).y);
    expect(at(first, B).y).toBeLessThan(at(first, D).y);
  });

  it("G-L08: parallel relationships never corrupt canonical topology", () => {
    const nodes = nodeIds(A, B);
    const first = layoutRelationshipGraph(A, nodes, [edge("r1", A, B)]);
    const parallel = layoutRelationshipGraph(A, nodes, [
      edge("r1", A, B),
      edge("r2", A, B),
    ]);
    // Both canonical relationships remain in the caller's model; the layout
    // adapter only de-duplicates the identical directed pair for ranking.
    expect(at(parallel, A)).toEqual(at(first, A));
    expect(at(parallel, B)).toEqual(at(first, B));
  });

  it("G-L09: a self-loop never creates a bogus rank", () => {
    const nodes = nodeIds(A, B);
    const withoutLoop = layoutRelationshipGraph(A, nodes, [edge("r1", A, B)]);
    const withLoop = layoutRelationshipGraph(A, nodes, [
      edge("r0", A, A),
      edge("r1", A, B),
    ]);
    expectFinite(withLoop);
    expect(at(withLoop, A)).toEqual(at(withoutLoop, A));
    expect(at(withLoop, B)).toEqual(at(withoutLoop, B));
  });

  it("G-L10: a small directed cycle gets a finite deterministic placement", () => {
    const nodes = nodeIds(A, B, C);
    const edges = [edge("r1", A, B), edge("r2", B, C), edge("r3", C, A)];
    const first = layoutRelationshipGraph(A, nodes, edges);
    const second = layoutRelationshipGraph(A, nodes, [...edges].reverse());
    expectFinite(first);
    expect(first.size).toBe(3);
    for (const id of [A, B, C]) {
      expect(at(second, id)).toEqual(at(first, id));
    }
  });

  it("G-L11: a disconnected node still receives a deterministic safe placement", () => {
    const layout = layoutRelationshipGraph(A, nodeIds(A, B, C), [edge("r1", A, B)]);
    expectFinite(layout);
    expect(layout.has(C)).toBe(true);
    const repeat = layoutRelationshipGraph(A, nodeIds(A, B, C), [edge("r1", A, B)]);
    expect(at(layout, C)).toEqual(at(repeat, C));
  });

  it("G-L12: nodes never share an exact coordinate", () => {
    const layout = layoutRelationshipGraph(
      A,
      nodeIds(A, B, C, D, E),
      [edge("r1", A, B), edge("r2", A, C), edge("r3", A, D), edge("r4", A, E)],
    );
    const coords = new Set(
      [...layout.values()].map((p) => `${Math.round(p.x)},${Math.round(p.y)}`),
    );
    expect(coords.size).toBe(5);
  });

  it("G-L13: re-running the same root topology yields identical positions", () => {
    const nodes = nodeIds(A, B, C);
    const edges = [edge("r1", A, B), edge("r2", B, C)];
    expect(layoutRelationshipGraph(A, nodes, edges)).toEqual(
      layoutRelationshipGraph(A, nodes, edges),
    );
  });

  it("G-L14: expansion placement leaves existing coordinates unchanged", () => {
    const existing = new Map<string, GraphPosition>([
      [A, { x: 10, y: 20 }],
      [B, { x: 30, y: 40 }],
    ]);
    const placed = positionsForExpandedNodes(ANCHOR, [C], existing);
    expect(placed.has(A)).toBe(false);
    expect(placed.has(B)).toBe(false);
    expect(placed.has(C)).toBe(true);
    // The original map is never mutated.
    expect(existing.get(A)).toEqual({ x: 10, y: 20 });
    expect(existing.get(B)).toEqual({ x: 30, y: 40 });
  });

  it("G-L15: representative fixtures never yield NaN/Infinity", () => {
    const fixtures: ReadonlyMap<string, GraphPosition>[] = [
      layoutRelationshipGraph(A, nodeIds(A), []),
      layoutRelationshipGraph(A, nodeIds(A, B, C), [
        edge("r1", A, B),
        edge("r2", B, C),
      ]),
      layoutRelationshipGraph(A, nodeIds(A), [edge("r0", A, A)]),
      layoutRelationshipGraph(A, nodeIds(A, B), []),
    ];
    for (const fixture of fixtures) {
      expectFinite(fixture);
    }
    expect(layoutSize([]).width).toBeGreaterThan(0);
    expect(layoutSize([...fixtures[1].values()]).height).toBeGreaterThan(0);
  });
});

describe("positionsForExpandedNodes (PR 31E incremental placement)", () => {
  it("G31E-L01: one new node gets a deterministic near-anchor position", () => {
    const positions = positionsForExpandedNodes(ANCHOR, [A], new Map());
    expect(positions.has(A)).toBe(true);
    const position = positions.get(A) as GraphPosition;
    // Bounded distance from the anchor (a ring inside the root layout).
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
    // (anchor + (0, 150) for the downward start angle, radius 150).
    const collision: GraphPosition = { x: 0, y: 150 };
    const occupied = new Map([["n:blocker", collision]]);
    const positions = positionsForExpandedNodes(ANCHOR, [A], occupied);
    const chosen = positions.get(A) as GraphPosition;
    expect(Math.round(chosen.x) === 0 && Math.round(chosen.y) === 150).toBe(false);
    // Still within the bounded ring.
    expect(Math.hypot(chosen.x - ANCHOR.x, chosen.y - ANCHOR.y)).toBeLessThanOrEqual(160);
  });
});
