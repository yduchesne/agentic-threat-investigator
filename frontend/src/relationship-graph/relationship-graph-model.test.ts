// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Graph pure derived-model tests (PR 24E E-G01..E-G04, E-G10).
//
// One bounded Relationships page converts deterministically to focal node +
// deduplicated counterparties + exact-ID edges; self-relationships never
// duplicate the focal node; multiple types stay distinct edges; labels are
// compact IDs and never require entity N+1 resolution.

import { describe, expect, it } from "vitest";

import type { Relationship } from "../api/schema-types";
import { buildRelationship } from "../test/handlers";
import { buildGraphModel, graphEntityLabel } from "./relationship-graph-model";
import { layoutSize, radialPositions } from "./relationship-graph-layout";

const FOCAL = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";

function edge(
  relationshipId: string,
  source: string,
  target: string,
  type: Relationship["type"] = "urn:ati:relationship:dns:resolves_to",
): Relationship {
  return buildRelationship({
    id: relationshipId,
    source_entity_id: source,
    target_entity_id: target,
    type,
  });
}

describe("Relationship Graph derived model", () => {
  it("E-G01: the focal entity yields exactly one focal node", () => {
    const model = buildGraphModel(FOCAL, []);
    expect(model.focal.entityId).toBe(FOCAL);
    expect(model.focal.role).toBe("focal");
    expect(model.counterparties).toHaveLength(0);
    expect(model.edges).toHaveLength(0);
  });

  it("E-G02: one-hop relationships produce deduplicated counterparties and edges", () => {
    const model = buildGraphModel(FOCAL, [
      edge("40000000-0000-4000-8000-000000000021", FOCAL, B),
      edge("40000000-0000-4000-8000-000000000022", C, FOCAL),
    ]);
    expect(model.counterparties).toHaveLength(2);
    expect(new Set(model.counterparties.map((node) => node.entityId))).toEqual(
      new Set([B, C]),
    );
    expect(model.edges).toHaveLength(2);
    // Deterministic ordering: counterparties sort by exact entity id.
    expect(model.counterparties[0].entityId).toBe(B);
    expect(model.counterparties[1].entityId).toBe(C);
  });

  it("E-G03: a self edge is one self-loop and never duplicates the focal node", () => {
    const model = buildGraphModel(FOCAL, [
      edge("40000000-0000-4000-8000-000000000021", FOCAL, FOCAL),
    ]);
    expect(model.hasSelfEdge).toBe(true);
    expect(model.counterparties).toHaveLength(0);
    expect(model.edges).toHaveLength(1);
    expect(model.edges[0].sourceEntityId).toBe(FOCAL);
    expect(model.edges[0].targetEntityId).toBe(FOCAL);
  });

  it("E-G04: repeated counterparties and multiple types stay distinct edges", () => {
    const model = buildGraphModel(FOCAL, [
      edge("40000000-0000-4000-8000-000000000021", FOCAL, B),
      edge(
        "40000000-0000-4000-8000-000000000022",
        FOCAL,
        B,
        "urn:ati:relationship:dns:cname_of",
      ),
    ]);
    expect(model.counterparties).toHaveLength(1);
    expect(model.edges).toHaveLength(2);
    expect(new Set(model.edges.map((item) => item.relationshipType))).toEqual(
      new Set([
        "urn:ati:relationship:dns:resolves_to",
        "urn:ati:relationship:dns:cname_of",
      ]),
    );
  });

  it("E-G10: labels are compact IDs without any entity fetch", () => {
    expect(graphEntityLabel(FOCAL)).toBe(`Entity ${FOCAL.slice(0, 8)}`);
    const model = buildGraphModel(FOCAL, [
      edge("40000000-0000-4000-8000-000000000021", FOCAL, B),
    ]);
    expect(model.counterparties[0].label).toBe(`Entity ${B.slice(0, 8)}`);
  });

  it("deterministic radial layout is pure and bounded", () => {
    const { focal, counterparties } = radialPositions(FOCAL, [B, C]);
    expect(focal).toEqual({ x: 0, y: 0 });
    expect(counterparties.size).toBe(2);
    // Same input always yields identical positions (no randomness).
    const again = radialPositions(FOCAL, [B, C]);
    expect([...again.counterparties.entries()]).toEqual([...counterparties.entries()]);
    const size = layoutSize(4);
    expect(size.width).toBeGreaterThan(0);
    expect(size.height).toBeGreaterThan(0);
  });
});