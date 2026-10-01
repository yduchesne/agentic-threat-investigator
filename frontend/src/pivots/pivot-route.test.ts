// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Typed Pivot target -> route mapper tests (PR 31F-8 §14 R01..R14).
//
// The mapper is the single exhaustive translator between the capability
// registry and the canonical Investigation-scoped routes. These tests pin
// the route contract: canonical IDs own path identity, supported filters
// round-trip as validated query parameters, arbitrary objects/stack state
// are never serialized, and malformed targets fail closed without any
// navigation.

import { describe, expect, it } from "vitest";

import { uuidAt } from "../test/handlers";
import { pivotTargetToRoute } from "./pivot-route";
import {
  emptyPivotFilters,
  PIVOT_RESOURCES,
  type PivotResource,
  type PivotStep,
} from "./pivot-types";

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const ENTITY_ID = uuidAt(101);
const LOCATION_ID = uuidAt(201);
const EVIDENCE_ID = uuidAt(1);
const RELATIONSHIP_ID = uuidAt(21);
const OBSERVATION_ID = uuidAt(2);
const RESEARCH_ID = uuidAt(31);

/** Build one legal target for a resource with an optional selection. */
function target(
  resource: PivotResource,
  filters: Record<string, string | boolean> = {},
  selectedId: string | null = null,
) {
  return {
    resource,
    filters: { ...emptyPivotFilters(resource), ...filters },
    selectedId,
    label: "analyst label is presentation only",
  };
}

describe("pivotTargetToRoute (R01..R14)", () => {
  it("R01: Evidence list filters map to the Evidence route with an equivalent query", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "evidence",
      { subject_entity_id: ENTITY_ID, source: "ThreatFox", type: "obtained" },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/evidence`,
      search: `source=ThreatFox&subject_entity_id=${ENTITY_ID}&type=obtained`,
    });
  });

  it("R02: an Evidence selected ID maps to the exact Evidence route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "evidence",
      {},
      EVIDENCE_ID,
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/evidence/${EVIDENCE_ID}`,
      search: undefined,
    });
    // The exact Evidence route carries the selection's scoped filters so a
    // semantic Back can restore the list context.
    const filtered = pivotTargetToRoute(INVESTIGATION_ID, target(
      "evidence",
      { subject_entity_id: ENTITY_ID },
      EVIDENCE_ID,
    ));
    expect(filtered?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/evidence/${EVIDENCE_ID}`,
    );
    expect(filtered?.search).toBe(`subject_entity_id=${ENTITY_ID}`);
  });

  it("R03: Relationships filters map to the Relationships route with an equivalent query", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "relationships",
      { source_entity_id: ENTITY_ID, relationship_type: "connects_to" },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/relationships`,
      search: `source_entity_id=${ENTITY_ID}&relationship_type=connects_to`,
    });
  });

  it("R03b: an exact Relationship selection maps to the exact Relationship route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "relationships",
      {},
      RELATIONSHIP_ID,
    ));
    expect(route?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/relationships/${RELATIONSHIP_ID}`,
    );
  });

  it("R04: Relationship observations map to the observations route with filters", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "relationship-observations",
      { relationship_id: RELATIONSHIP_ID, source: "connector" },
    ));
    expect(route?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/relationships/observations`,
    );
    expect(route?.search).toBe(`relationship_id=${RELATIONSHIP_ID}&source=connector`);
  });

  it("R04b: an exact relationship observation maps to the exact observation route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "relationship-observations",
      {},
      OBSERVATION_ID,
    ));
    expect(route?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/relationships/observations/${OBSERVATION_ID}`,
    );
  });

  it("R05: Research maps to the Research route with filters; exact selection is a query param", () => {
    const listRoute = pivotTargetToRoute(INVESTIGATION_ID, target(
      "research",
      { subject_entity_id: ENTITY_ID },
    ));
    expect(listRoute).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/research`,
      search: `subject_entity_id=${ENTITY_ID}`,
    });
    const exactRoute = pivotTargetToRoute(INVESTIGATION_ID, target(
      "research",
      {},
      RESEARCH_ID,
    ));
    expect(exactRoute?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/research`,
    );
    expect(exactRoute?.search).toBe(`selected=${RESEARCH_ID}`);
  });

  it("R06: geoint-entity maps to the exact Entity GEOINT route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-entity",
      { entity_id: ENTITY_ID },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/geoint/entities/${ENTITY_ID}`,
      search: undefined,
    });
  });

  it("R07: geoint-location-entities maps to the exact Location Entities route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-location-entities",
      { location_id: LOCATION_ID },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/geoint/locations/${LOCATION_ID}/entities`,
      search: undefined,
    });
    // Containment toggles are semantic query state, never path state.
    const contained = pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-location-entities",
      { location_id: LOCATION_ID, include_contained: true },
    ));
    expect(contained?.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/geoint/locations/${LOCATION_ID}/entities`,
    );
    expect(contained?.search).toBe("include_contained=true");
  });

  it("R08: geoint-location-observations maps to the exact Location observations route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-location-observations",
      { location_id: LOCATION_ID },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/geoint/locations/${LOCATION_ID}/observations`,
      search: undefined,
    });
  });

  it("R09: geoint-observation maps to the exact observation route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-observation",
      { observation_id: OBSERVATION_ID },
    ));
    expect(route).toEqual({
      pathname: `/investigations/${INVESTIGATION_ID}/geoint/observations/${OBSERVATION_ID}`,
      search: undefined,
    });
  });

  it("R10: a label that differs from the ID never enters the route", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, {
      resource: "geoint-entity",
      filters: { entity_id: ENTITY_ID },
      selectedId: null,
      label: "Seattle-based infrastructure",
    });
    expect(route?.pathname).toContain(ENTITY_ID);
    expect(route?.pathname).not.toContain("Seattle");
    // Same for exact detail destinations.
    const evidence = pivotTargetToRoute(INVESTIGATION_ID, {
      resource: "evidence",
      filters: {},
      selectedId: EVIDENCE_ID,
      label: "Evidence from the report",
    });
    expect(evidence?.pathname).toContain(EVIDENCE_ID);
    expect(evidence?.pathname).not.toContain("report");
  });

  it("R11: special query characters are safely encoded", () => {
    const route = pivotTargetToRoute(INVESTIGATION_ID, target(
      "evidence",
      { source: "a&b=c %d?e#f" },
    ));
    expect(route?.pathname).toBe(`/investigations/${INVESTIGATION_ID}/evidence`);
    expect(route?.search).toBe("source=a%26b%3Dc+%25d%3Fe%23f");
    // The original value round-trips through URLSearchParams exactly.
    expect(new URLSearchParams(route?.search).get("source")).toBe("a&b=c %d?e#f");
  });

  it("R12: malformed targets fail closed without any navigation", () => {
    expect(pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-entity",
      {},
    ))).toBeNull();
    expect(pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-location-entities",
      { location_id: "not-a-uuid" },
    ))).toBeNull();
    expect(pivotTargetToRoute(INVESTIGATION_ID, target(
      "geoint-observation",
      { observation_id: "" },
    ))).toBeNull();
    expect(pivotTargetToRoute(INVESTIGATION_ID, target(
      "evidence",
      {},
      "malformed",
    ))).toBeNull();
    expect(pivotTargetToRoute(INVESTIGATION_ID, target(
      "relationships",
      {},
      "malformed",
    ))).toBeNull();
    // No permissive fallback: unknown resource shapes can never produce a
    // destination (an unknown resource is a compile-time failure; this
    // guards against runtime corruption of the target discriminant).
    // Runtime-corrupted discriminant: the exhaustive switch has no default
    // and must never produce a destination; the compiler already rejects a
    // typed unknown resource at build time.
    const bogus = {
      resource: "totally-unknown",
      filters: {},
      selectedId: null,
      label: "x",
    } as unknown as Parameters<typeof pivotTargetToRoute>[1];

    expect(pivotTargetToRoute(INVESTIGATION_ID, bogus)).toBeFalsy();
  });

  it("R13 lattice: every allowlisted PivotResource maps to a canonical route", () => {
    // Runtime lattice over the allowlist: each resource (list and exact
    // selection variants) must produce a non-null canonical destination (a
    // mapper case missing for a future resource would trip this before the
    // compile-time exhaustiveness check).
    const cases: Array<{
      resource: PivotResource;
      filters: Record<string, string | boolean>;
      selectedId: string | null;
    }> = [
      { resource: "evidence", filters: { subject_entity_id: ENTITY_ID }, selectedId: null },
      { resource: "evidence", filters: {}, selectedId: EVIDENCE_ID },
      { resource: "relationships", filters: { source_entity_id: ENTITY_ID }, selectedId: null },
      { resource: "relationships", filters: {}, selectedId: RELATIONSHIP_ID },
      {
        resource: "relationship-observations",
        filters: { relationship_id: RELATIONSHIP_ID },
        selectedId: null,
      },
      { resource: "relationship-observations", filters: {}, selectedId: OBSERVATION_ID },
      { resource: "research", filters: { subject_entity_id: ENTITY_ID }, selectedId: null },
      { resource: "research", filters: {}, selectedId: RESEARCH_ID },
      { resource: "geoint-entity", filters: { entity_id: ENTITY_ID }, selectedId: null },
      {
        resource: "geoint-location-entities",
        filters: { location_id: LOCATION_ID },
        selectedId: null,
      },
      {
        resource: "geoint-location-observations",
        filters: { location_id: LOCATION_ID },
        selectedId: null,
      },
      { resource: "geoint-observation", filters: { observation_id: OBSERVATION_ID }, selectedId: null },
    ];
    for (const candidate of cases) {
      const route = pivotTargetToRoute(
        INVESTIGATION_ID,
        target(candidate.resource, candidate.filters, candidate.selectedId),
      );
      expect(route, `resource ${candidate.resource}`).not.toBeNull();
      expect(
        route?.pathname.startsWith(`/investigations/${INVESTIGATION_ID}/`),
      ).toBe(true);
    }
    // The lattice itself covers every allowlisted resource.
    const covered = new Set(cases.map((candidate) => candidate.resource));
    for (const resource of PIVOT_RESOURCES) {
      expect(covered.has(resource), `lattice covers ${resource}`).toBe(true);
    }
  });

  it("R14: the mapper never serializes stack/component state, only target state", () => {
    const step: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "stack label",
      sourceKind: "table_cell",
      cursor: "opaque-cursor-must-never-enter",
    };
    const route = pivotTargetToRoute(INVESTIGATION_ID, {
      resource: step.resource,
      filters: step.filters,
      selectedId: step.selectedId,
      label: step.label,
    });
    expect(route?.search).toBe(`subject_entity_id=${ENTITY_ID}`);
    expect(route?.search).not.toContain("opaque-cursor");
    expect(route?.search).not.toContain("stack");
  });
});
