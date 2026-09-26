// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pure accumulated-graph merge contract tests (PR 31E, G31E-M01..M15).
//
// The merge contract is intentionally free of React/network concerns:
// Entities merge by ``entity_id``, Relationships by ``relationship_id``,
// a newer successful response wins duplicate field values, existing
// canonical order is preserved while new objects append in server-return
// order, observation counts are never summed, and expansion identity is
// ``(entity_id, direction)`` within the current root graph context.

import { describe, expect, it } from "vitest";

import type {
  GraphEdge,
  GraphNeighborhood,
  GraphNode,
} from "../api/schema-types";
import { buildGraphEdge, buildGraphNode } from "../test/handlers";
import {
  emptyAccumulatedGraph,
  isExpansionCompleted,
  mergeNeighborhood,
  overlayRootNeighborhood,
  type AccumulatedGraph,
  type ExpandedNeighborhoodKey,
} from "./graph-expansion-model";

const ROOT = "40000000-0000-4000-8000-000000000001";
const B = "40000000-0000-4000-8000-000000000002";
const C = "40000000-0000-4000-8000-000000000003";
const D = "40000000-0000-4000-8000-000000000004";

function node(id: string, overrides: Partial<GraphNode> = {}): GraphNode {
  return buildGraphNode({ entity_id: id, value: `value-${id}`, ...overrides });
}

function edge(
  id: string,
  source: string,
  target: string,
  overrides: Partial<GraphEdge> = {},
): GraphEdge {
  return buildGraphEdge({
    relationship_id: id,
    source_entity_id: source,
    target_entity_id: target,
    ...overrides,
  });
}

function neighborhood(seed: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated?: boolean;
}): GraphNeighborhood {
  return {
    nodes: seed.nodes,
    edges: seed.edges,
    truncated: seed.truncated ?? false,
  };
}

function key(entityId: string, direction: ExpandedNeighborhoodKey["direction"]): ExpandedNeighborhoodKey {
  return { entityId, direction };
}

function rootGraph(nodes: GraphNode[] = [node(ROOT), node(B)], edges: GraphEdge[] = [edge("e1", ROOT, B)]): AccumulatedGraph {
  return emptyAccumulatedGraph(
    ROOT,
    neighborhood({ nodes, edges }),
  );
}

describe("AccumulatedGraph / mergeNeighborhood (PR 31E merge contract)", () => {
  it("G31E-M13: the original root focal Entity is never replaced", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
      }),
    });
    expect(merged.rootEntityId).toBe(ROOT);
  });

  it("G31E-M01: a disjoint neighborhood appends new nodes and edges", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
      }),
    });
    expect(merged.nodes.map((n) => n.entity_id)).toEqual([ROOT, B, C]);
    expect(merged.edges.map((e) => e.relationship_id)).toEqual(["e1", "e2"]);
    // Existing topology first, new objects in server-return order.
    expect(merged.nodes[2].entity_id).toBe(C);
  });

  it("G31E-M02: an overlapping Entity produces exactly one canonical node", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      // Server repeats ROOT/B with a refreshed value for B.
      neighborhood: neighborhood({
        nodes: [node(B, { value: "refreshed-b", display_name: "Refreshed B" }), node(ROOT)],
        edges: [edge("e1", ROOT, B)],
      }),
    });
    const bs = merged.nodes.filter((n) => n.entity_id === B);
    expect(bs).toHaveLength(1);
    expect(merged.nodes.map((n) => n.entity_id)).toEqual([ROOT, B]);
  });

  it("G31E-M03: an overlapping Relationship produces exactly one canonical edge", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B)],
        edges: [edge("e1", ROOT, B), edge("e2", B, C)],
      }),
    });
    const e1s = merged.edges.filter((e) => e.relationship_id === "e1");
    expect(e1s).toHaveLength(1);
    expect(merged.edges.map((e) => e.relationship_id)).toEqual(["e1", "e2"]);
  });

  it("G31E-M04: a duplicate edge is replaced by the newer response, never summed", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B)],
        edges: [
          edge("e1", ROOT, B, {
            observation_count: 7,
            last_observed_at: "2026-07-01T09:00:00Z",
          }),
        ],
      }),
    });
    const e1 = merged.edges.find((e) => e.relationship_id === "e1");
    expect(e1?.observation_count).toBe(7);
    expect(e1?.last_observed_at).toBe("2026-07-01T09:00:00Z");
    // Original 3 is replaced, not added to the new 7.
    expect(merged.edges).toHaveLength(1);
  });

  it("G31E-M05: a duplicate Entity is replaced by the newer metadata", () => {
    const graph = rootGraph([node(ROOT), node(B, { value: "old-b", display_name: "Old B" })]);
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B, { value: "new-b", display_name: "New B" })],
        edges: [],
      }),
    });
    const b = merged.nodes.find((n) => n.entity_id === B);
    expect(b?.value).toBe("new-b");
    expect(b?.display_name).toBe("New B");
    expect(merged.nodes).toHaveLength(2);
  });

  it("G31E-M06: a self-loop never duplicates its node", () => {
    const graph = rootGraph([node(ROOT), node(B)]);
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B)],
        edges: [edge("self", B, B)],
      }),
    });
    expect(merged.nodes.filter((n) => n.entity_id === B)).toHaveLength(1);
    expect(merged.edges.map((e) => e.relationship_id)).toEqual(["e1", "self"]);
    expect(merged.edges.find((e) => e.relationship_id === "self")?.source_entity_id).toBe(B);
    expect(merged.edges.find((e) => e.relationship_id === "self")?.target_entity_id).toBe(B);
  });

  it("G31E-M07: two Relationships between the same endpoints are both retained by relationship_id", () => {
    const graph = rootGraph([node(ROOT), node(B)]);
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B)],
        edges: [
          edge("e-r1", ROOT, B, { relationship_type: "urn:ati:relationship:dns:cname_of" }),
          edge("e-r2", ROOT, B, { relationship_type: "urn:ati:relationship:dns:resolves_to" }),
        ],
      }),
    });
    expect(merged.edges.map((e) => e.relationship_id)).toEqual(["e1", "e-r1", "e-r2"]);
    // The root edge e1 plus both new edges share ROOT/B endpoints; all three
    // coexist because identity is relationship_id, never the endpoint pair.
    expect(merged.edges.filter((e) => e.source_entity_id === ROOT && e.target_entity_id === B)).toHaveLength(3);
  });

  it("G31E-M08: re-merging the exact same expansion records it once", () => {
    const graph = rootGraph();
    const result = {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
      }),
    };
    const once = mergeNeighborhood(graph, result);
    const twice = mergeNeighborhood(once, result);
    expect(twice.expanded).toHaveLength(1);
    expect(twice.expanded[0]).toEqual(key(B, "either"));
    expect(twice.nodes.map((n) => n.entity_id)).toEqual(once.nodes.map((n) => n.entity_id));
    expect(twice.edges.map((e) => e.relationship_id)).toEqual(once.edges.map((e) => e.relationship_id));
  });

  it("G31E-M09: source and target expansions of the same Entity are distinct keys", () => {
    const graph = rootGraph();
    const out = mergeNeighborhood(graph, {
      key: key(B, "source"),
      neighborhood: neighborhood({ nodes: [node(B), node(C)], edges: [edge("e2", B, C)] }),
    });
    const both = mergeNeighborhood(out, {
      key: key(B, "target"),
      neighborhood: neighborhood({ nodes: [node(B), node(D)], edges: [edge("e3", D, B)] }),
    });
    expect(both.expanded).toHaveLength(2);
    expect(both.expanded.map((k) => k.direction)).toEqual(["source", "target"]);
    expect(both.nodes.map((n) => n.entity_id)).toEqual([ROOT, B, C, D]);
  });

  it("G31E-M10: a truncated expansion marks the exact key as truncated", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
        truncated: true,
      }),
    });
    expect(merged.truncatedExpansions.map((k) => k.entityId)).toEqual([B]);
    expect(merged.truncatedExpansions[0].direction).toBe("either");
    expect(isExpansionCompleted(merged, B, "either")).toBe(true);
    expect(isExpansionCompleted(merged, B, "source")).toBe(false);
  });

  it("G31E-M11: a non-truncated expansion never marks the key truncated", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
        truncated: false,
      }),
    });
    expect(merged.truncatedExpansions).toEqual([]);
  });

  it("G31E-M12: deterministic order keeps existing objects first, new ones in server order", () => {
    const graph = rootGraph();
    const merged = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(D), node(C)],
        edges: [edge("e2", B, D), edge("e3", B, C)],
      }),
    });
    expect(merged.nodes.map((n) => n.entity_id)).toEqual([ROOT, B, D, C]);
    expect(merged.edges.map((e) => e.relationship_id)).toEqual(["e1", "e2", "e3"]);
  });

  it("G31E-M15: a refreshed root overlays server data without discarding expansions", () => {
    const graph = rootGraph();
    const expanded = mergeNeighborhood(graph, {
      key: key(B, "either"),
      neighborhood: neighborhood({
        nodes: [node(B), node(C)],
        edges: [edge("e2", B, C)],
      }),
    });
    // Root refresh updates B/ROOT metadata, adds nothing new, truncated=true.
    const refreshed = overlayRootNeighborhood(
      expanded,
      neighborhood({
        nodes: [node(ROOT, { value: "root-refreshed" }), node(B, { value: "b-refreshed" })],
        edges: [edge("e1", ROOT, B, { observation_count: 9 })],
        truncated: true,
      }),
    );
    expect(refreshed.expanded).toHaveLength(1);
    expect(refreshed.nodes.map((n) => n.entity_id)).toEqual([ROOT, B, C]);
    expect(refreshed.nodes.find((n) => n.entity_id === B)?.value).toBe("b-refreshed");
    expect(refreshed.edges.find((e) => e.relationship_id === "e1")?.observation_count).toBe(9);
    expect(refreshed.rootTruncated).toBe(true);
    // Local expansion callbacks/data untouched.
    expect(refreshed.truncatedExpansions).toEqual([]);
  });

  it("G31E-I17: expansion state is not persisted and stores no presentation data", () => {
    const graph = rootGraph();
    expect(graph).not.toHaveProperty("positions");
    expect(graph).not.toHaveProperty("viewport");
    expect(graph.rootEntityId).toBe(ROOT);
  });
});
