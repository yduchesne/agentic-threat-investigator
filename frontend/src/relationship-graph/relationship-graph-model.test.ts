// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical Relationship Graph pure presentation-model tests (PR 31D M01..M12).
//
// The model is a faithful one-hop projection of the PR 31C
// ``GraphNeighborhoodResponse``: canonical Entity/Relationship identities,
// Entity metadata (type/value/display name), edge observation summaries and
// the ``truncated`` flag are copied exactly; order is preserved; one
// Relationship is one edge; a self-loop is one node/one edge; and nothing
// invents topology, lifetimes, or maliciousness. Layout is a separate
// deterministic pure function over sorted identities.

import { describe, expect, it } from "vitest";

import {
  buildGraphEdge,
  buildGraphNeighborhood,
  buildGraphNode,
} from "../test/handlers";
import { buildGraphModel, nodeLabel } from "./relationship-graph-model";
import { layoutSize, radialPositions } from "./relationship-graph-layout";

const FOCAL = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";

function focalNode(overrides: Parameters<typeof buildGraphNode>[0] = {}) {
  return buildGraphNode({ entity_id: FOCAL, ...overrides });
}

function neighbor(overrides: Parameters<typeof buildGraphNeighborhood>[0] = {}) {
  return buildGraphNeighborhood({
    nodes: [focalNode(), buildGraphNode({ entity_id: B })],
    edges: [
      buildGraphEdge({ source_entity_id: FOCAL, target_entity_id: B }),
    ],
    ...overrides,
  });
}

describe("Relationship Graph presentation model", () => {
  it("G31D-M01: a focal-only neighborhood yields exactly one focal node and zero edges", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({ nodes: [focalNode()], edges: [] }),
    );
    expect(model.focal.entityId).toBe(FOCAL);
    expect(model.focal.role).toBe("focal");
    expect(model.nodes).toHaveLength(1);
    expect(model.counterparties).toHaveLength(0);
    expect(model.edges).toHaveLength(0);
    expect(model.hasSelfEdge).toBe(false);
    expect(model.truncated).toBe(false);
  });

  it("G31D-M02: a non-empty display name is the preferred node label", () => {
    const display = "update-delivery service";
    const model = buildGraphModel(
      FOCAL,
      neighbor({ nodes: [focalNode({ display_name: display, value: "update-package.test" })] }),
    );
    expect(model.focal.label).toBe(display);
    expect(nodeLabel(display, "ignored")).toBe(display);
  });

  it("G31D-M03: a null display name falls back to the canonical value, never a UUID prefix", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        nodes: [focalNode({ display_name: null, value: "update-package.test" })],
      }),
    );
    expect(model.focal.label).toBe("update-package.test");
    expect(nodeLabel(null, "update-package.test")).toBe("update-package.test");
    expect(nodeLabel("", "update-package.test")).toBe("update-package.test");
  });

  it("G31D-M04: multiple Entity types are preserved exactly", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        nodes: [
          focalNode({ entity_type: "domain", value: "delivery.test" }),
          buildGraphNode({ entity_id: B, entity_type: "ip_address", value: "203.0.113.10" }),
          buildGraphNode({ entity_id: C, entity_type: "asn", value: "AS64500" }),
        ],
      }),
    );
    const types = model.nodes.map((node) => node.entityType).sort();
    expect(types).toEqual(["asn", "domain", "ip_address"]);
    expect(model.nodes.find((node) => node.entityId === B)?.value).toBe("203.0.113.10");
  });

  it("G31D-M05: one edge preserves the canonical identity/endpoints/type", () => {
    const edgeId = "40000000-0000-4000-8000-000000000021";
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        edges: [
          buildGraphEdge({
            relationship_id: edgeId,
            source_entity_id: FOCAL,
            target_entity_id: B,
            relationship_type: "urn:ati:relationship:dns:cname_of",
          }),
        ],
      }),
    );
    expect(model.edges).toHaveLength(1);
    expect(model.edges[0].relationshipId).toBe(edgeId);
    expect(model.edges[0].sourceEntityId).toBe(FOCAL);
    expect(model.edges[0].targetEntityId).toBe(B);
    expect(model.edges[0].relationshipType).toBe("urn:ati:relationship:dns:cname_of");
  });

  it("G31D-M06: the observation summary is copied exactly", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000021",
            source_entity_id: FOCAL,
            target_entity_id: B,
            observation_count: 4,
            first_observed_at: "2026-06-01T09:00:00Z",
            last_observed_at: "2026-06-10T09:00:00Z",
          }),
        ],
      }),
    );
    expect(model.edges[0].observationCount).toBe(4);
    expect(model.edges[0].firstObservedAt).toBe("2026-06-01T09:00:00Z");
    expect(model.edges[0].lastObservedAt).toBe("2026-06-10T09:00:00Z");
  });

  it("G31D-M07: null observed times remain null (never substituted)", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000021",
            source_entity_id: FOCAL,
            target_entity_id: B,
            first_observed_at: null,
            last_observed_at: null,
          }),
        ],
      }),
    );
    expect(model.edges[0].firstObservedAt).toBeNull();
    expect(model.edges[0].lastObservedAt).toBeNull();
  });

  it("G31D-M08: a self-loop is one node and one edge", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        nodes: [focalNode()],
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000022",
            source_entity_id: FOCAL,
            target_entity_id: FOCAL,
          }),
        ],
      }),
    );
    expect(model.nodes).toHaveLength(1);
    expect(model.edges).toHaveLength(1);
    expect(model.edges[0].sourceEntityId).toBe(FOCAL);
    expect(model.edges[0].targetEntityId).toBe(FOCAL);
    expect(model.hasSelfEdge).toBe(true);
  });

  it("G31D-M09: multiple Relationships between the same pair stay distinct edges", () => {
    const model = buildGraphModel(
      FOCAL,
      neighbor({
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000021",
            source_entity_id: FOCAL,
            target_entity_id: B,
            relationship_type: "urn:ati:relationship:dns:resolves_to",
          }),
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000022",
            source_entity_id: FOCAL,
            target_entity_id: B,
            relationship_type: "urn:ati:relationship:dns:cname_of",
          }),
        ],
      }),
    );
    expect(model.counterparties).toHaveLength(1);
    expect(model.edges).toHaveLength(2);
    expect(new Set(model.edges.map((edge) => edge.relationshipId))).toEqual(
      new Set([
        "40000000-0000-4000-8000-000000000021",
        "40000000-0000-4000-8000-000000000022",
      ]),
    );
  });

  it("G31D-M10: the truncated flag is preserved exactly", () => {
    const truncated = buildGraphModel(
      FOCAL,
      neighbor({ truncated: true, edges: [] }),
    );
    expect(truncated.truncated).toBe(true);
    const notTruncated = buildGraphModel(FOCAL, neighbor({ truncated: false }));
    expect(notTruncated.truncated).toBe(false);
  });

  it("G31D-M11: server node/edge ordering is preserved (no invented semantic reorder)", () => {
    const ordered = buildGraphModel(
      FOCAL,
      neighbor({
        nodes: [focalNode(), buildGraphNode({ entity_id: B })],
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000021",
            source_entity_id: FOCAL,
            target_entity_id: B,
          }),
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000022",
            source_entity_id: FOCAL,
            target_entity_id: B,
          }),
        ],
      }),
    );
    // Nodes and edges keep their server order.
    expect(ordered.nodes.map((node) => node.entityId)).toEqual([FOCAL, B]);
    expect(ordered.edges.map((edge) => edge.relationshipId)).toEqual([
      "40000000-0000-4000-8000-000000000021",
      "40000000-0000-4000-8000-000000000022",
    ]);
    // The focal role is decided by the request Entity ID, never by edge
    // direction: reorder the incoming edge and the role stays stable.
    const inbound = buildGraphModel(
      FOCAL,
      neighbor({
        nodes: [focalNode(), buildGraphNode({ entity_id: B })],
        edges: [
          buildGraphEdge({
            relationship_id: "40000000-0000-4000-8000-000000000021",
            source_entity_id: B,
            target_entity_id: FOCAL,
          }),
        ],
      }),
    );
    expect(inbound.focal.entityId).toBe(FOCAL);
    expect(inbound.nodes.find((node) => node.entityId === B)?.role).toBe("counterparty");
  });

  it("G31D-M12: identical identities always produce identical initial positions", () => {
    // The deterministic radial layout depends only on the sorted identity
    // set, never on server ordering or render state.
    const first = radialPositions(FOCAL, [B, C]);
    const second = radialPositions(FOCAL, [C, B]);
    expect(first.focal).toEqual({ x: 0, y: 0 });
    expect(second.focal).toEqual({ x: 0, y: 0 });
    // Same identity always yields the same position (the map iteration
    // order may follow the passed order; the component normalizes by
    // sorting identities before positioning).
    expect(first.counterparties.get(B)).toEqual(second.counterparties.get(B));
    expect(first.counterparties.get(C)).toEqual(second.counterparties.get(C));
    expect(first.counterparties.get(B)).not.toBeUndefined();
    expect(first.counterparties.get(C)).not.toBeUndefined();
    const size = layoutSize(8);
    expect(size.width).toBeGreaterThan(0);
    expect(size.height).toBeGreaterThan(0);
  });
});
