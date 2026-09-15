// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Map-origin entity exploration tests (PR 25C §28 C-P01..C-P12).
//
// The pure capability assertions fix the exact map-origin actions: the
// single ``map_entity`` source kind, the four independent server-backed
// entity filters, the IP display label (never coordinates), the distinct
// Entity identity of same-coordinate items, and the absence of any
// client-side Relationship OR merge or unsupported resource. Rendering
// assertions prove the Explore surface is reachable from both the marker
// popup and the non-map row while View Evidence keeps the exact PR 25A
// ``evidence_id``.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it, vi } from "vitest";

import type {
  GeoPrecisionName,
  InvestigationGeolocation,
  InvestigationGeolocationCollection,
} from "../api/schema-types";
import {
  authMeSuccess,
  buildEvidence,
  buildInvestigation,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  geolocationEntityActions,
  MAP_ENTITY_SOURCE_KIND,
} from "./GeolocationEntityActions";

vi.mock("react-leaflet", () => import("../test/react-leaflet-mock"));

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const AUTH = [authMeSuccess, runtimeFake];
const PIVOT_RESOURCES = ["evidence", "relationships", "research"];

function geoItem(
  index: number,
  overrides: Partial<InvestigationGeolocation> = {},
): InvestigationGeolocation {
  return {
    evidence_id: `40000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    entity_id: `50000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    ip_address: `203.0.113.${index}`,
    country_code: "US",
    region: "Washington",
    city: "Seattle",
    latitude: 47.6062,
    longitude: -122.3321,
    precision: "city" as GeoPrecisionName,
    provider: "urn:ati:source:dbip_city_lite",
    observed_at: null,
    retrieved_at: "2026-06-01T10:00:00Z",
    ...overrides,
  };
}

function collection(
  items: InvestigationGeolocation[] = [geoItem(1)],
): InvestigationGeolocationCollection {
  return { items, truncated: false };
}

function workspace() {
  return investigationDetailHandler(
    buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
  );
}

function geolocationsHandler(
  body: InvestigationGeolocationCollection,
): ReturnType<typeof http.get> {
  return http.get("*/api/v1/investigations/:id/geolocations", () => jsonResponse(body));
}

async function renderMap(handlers: ReturnType<typeof http.get>[]) {
  setHttpHandlers(...AUTH, workspace(), ...handlers);
  renderAtPath(`/investigations/${INVESTIGATION_ID}/map`);
  await screen.findByRole("tab", { name: "Map" });
  await waitFor(() =>
    expect(screen.queryByText("Loading geolocation context…")).not.toBeInTheDocument(),
  );
  await screen.findByText("All returned geolocation items");
}

function actionFor(key: string, item: InvestigationGeolocation) {
  const action = geolocationEntityActions(item).find((a) => a.key === key);
  expect(action).not.toBeUndefined();
  return action!;
}

describe("map-origin entity actions (C-P01..C-P12)", () => {
  it("C-P01: every Map action registers the single map_entity source kind", () => {
    const item = geoItem(1);
    const actions = geolocationEntityActions(item);
    expect(actions).toHaveLength(4);
    expect(MAP_ENTITY_SOURCE_KIND).toBe("map_entity");
    for (const action of actions) {
      expect(action.sourceKind).toBe(MAP_ENTITY_SOURCE_KIND);
    }
  });

  it("C-P02: Evidence action filters the exact subject entity", () => {
    const item = geoItem(2);
    const action = actionFor("evidenceForEntity", item);
    expect(action.target.resource).toBe("evidence");
    expect(action.target.filters).toEqual({ subject_entity_id: item.entity_id });
    expect(action.target.selectedId).toBeNull();
  });

  it("C-P03: Relationship source action keeps the exact source filter", () => {
    const item = geoItem(2);
    const action = actionFor("relationshipsSource", item);
    expect(action.target.resource).toBe("relationships");
    expect(action.target.filters).toEqual({ source_entity_id: item.entity_id });
  });

  it("C-P04: Relationship target action keeps the exact target filter", () => {
    const item = geoItem(2);
    const action = actionFor("relationshipsTarget", item);
    expect(action.target.resource).toBe("relationships");
    expect(action.target.filters).toEqual({ target_entity_id: item.entity_id });
  });

  it("C-P05: Research action filters the exact subject entity", () => {
    const item = geoItem(3);
    const action = actionFor("researchForEntity", item);
    expect(action.target.resource).toBe("research");
    expect(action.target.filters).toEqual({ subject_entity_id: item.entity_id });
  });

  it("C-P06: the pivot label is the IP display value, never coordinates", () => {
    const item = geoItem(4);
    for (const action of geolocationEntityActions(item)) {
      expect(action.target.label).toBe("203.0.113.4");
      expect(action.target.label).not.toContain("Seattle");
      expect(action.target.label).not.toContain("47.6062");
    }
  });

  it("C-P07: View Evidence remains the exact evidence_id on the row", async () => {
    const item = geoItem(1);
    const requested: string[] = [];
    const evidenceDetail = http.get(
      "*/api/v1/investigations/:id/evidence/:evidenceId",
      (request) => {
        requested.push(request.params["evidenceId"] as string);
        return jsonResponse(
          buildEvidence({
            id: item.evidence_id,
            subject_entity_id: item.entity_id,
            subject_value: item.ip_address,
          }),
        );
      },
    );
    await renderMap([geolocationsHandler(collection([item])), evidenceDetail]);
    const rows = screen.getByRole("table", {
      name: "All returned geolocation items",
    });
    const row = within(rows).getAllByRole("row")[1];
    const viewButton = within(row).getByRole("button", { name: "View Evidence" });
    expect(viewButton).toHaveAttribute("data-evidence-id", item.evidence_id);
    // The drawer opens through the Investigation-scoped exact Evidence GET.
    await userEvent.click(viewButton);
    await screen.findByRole("dialog", { name: "Evidence" });
    expect(requested).toEqual([item.evidence_id.toLowerCase()]);
  });

  it("C-P08: marker popup and non-map row expose equivalent Explore actions", async () => {
    const item = geoItem(1);
    await renderMap([geolocationsHandler(collection([item]))]);
    const actions = geolocationEntityActions(item);
    expect(actions).toHaveLength(4);

    const rows = screen.getByRole("table", {
      name: "All returned geolocation items",
    });
    expect(within(rows).getByRole("button", { name: /Explore/ })).toBeVisible();

    const markers = screen.getAllByTestId("ati-marker");
    expect(markers.length).toBeGreaterThan(0);
    await userEvent.click(markers[0]);
    const popup = screen.getByTestId("ati-popup");
    expect(within(popup).getByRole("button", { name: /Explore/ })).toBeVisible();
  });

  it("C-P09: a coordinate-less item remains actionable in the list", async () => {
    const item = geoItem(5, { latitude: null, longitude: null });
    await renderMap([geolocationsHandler(collection([item]))]);
    const rows = screen.getByRole("table", {
      name: "All returned geolocation items",
    });
    const row = within(rows).getAllByRole("row")[1];
    expect(within(row).getByRole("button", { name: "View Evidence" })).toBeVisible();
    expect(within(row).getByRole("button", { name: /Explore/ })).toBeVisible();
    // No synthetic marker is ever invented for a coordinate-less item.
    expect(screen.queryAllByTestId("ati-marker")).toHaveLength(0);
  });

  it("C-P10: same-coordinate items keep distinct Entity IDs and actions", () => {
    const first = geoItem(1);
    const second = geoItem(6, {
      ip_address: "198.51.100.30",
      entity_id: "60000000-0000-4000-8000-000000000030",
    });
    expect(first.latitude).toBe(second.latitude);
    expect(first.longitude).toBe(second.longitude);
    expect(first.entity_id).not.toBe(second.entity_id);
    const firstActions = geolocationEntityActions(first);
    const secondActions = geolocationEntityActions(second);
    for (const action of firstActions) {
      const twin = secondActions.find((candidate) => candidate.key === action.key);
      expect(twin).not.toBeUndefined();
      const firstFilter = Object.values(
        action.target.filters as Record<string, string>,
      )[0];
      const secondFilter = Object.values(
        twin!.target.filters as Record<string, string>,
      )[0];
      // Both action sets are structurally identical but bind distinct
      // Entity identities — no co-location/coordination inference.
      expect(firstFilter).toBe(first.entity_id);
      expect(secondFilter).toBe(second.entity_id);
      expect(firstFilter).not.toBe(secondFilter);
      expect(action.target.label).toBe("203.0.113.1");
      expect(twin!.target.label).toBe("198.51.100.30");
    }
  });

  it("C-P11: never a client-side Relationship source-or-target merge", () => {
    const item = geoItem(1);
    const relationshipActions = geolocationEntityActions(item).filter((action) =>
      action.target.resource === "relationships",
    );
    expect(relationshipActions.map((action) => action.key)).toEqual([
      "relationshipsSource",
      "relationshipsTarget",
    ]);
    for (const action of relationshipActions) {
      const keys = Object.keys(action.target.filters as Record<string, string>);
      // Each relationship action carries exactly one entity filter side.
      expect(keys).toHaveLength(1);
      expect(["source_entity_id", "target_entity_id"]).toContain(keys[0]);
      expect(keys[0] === "source_entity_id" ? "target_entity_id" : "source_entity_id")
        .not.toBe(keys[0]);
    }
  });

  it("C-P12: no unsupported resource or scoped selection is registered", () => {
    const item = geoItem(1);
    const actions = geolocationEntityActions(item);
    for (const action of actions) {
      expect(PIVOT_RESOURCES).toContain(action.target.resource);
      expect(action.target.selectedId).toBeNull();
    }
    expect(
      actions.filter((action) => action.key === "observationsForRelationship"),
    ).toHaveLength(0);
    expect(
      actions.filter(
        (action) =>
          action.target.resource === "relationship-observations",
      ),
    ).toHaveLength(0);
  });

  it("C-P08b: Explore opens the typed PivotWorkspace with the map_entity step", async () => {
    const item = geoItem(1);
    const evidenceList = http.get("*/api/v1/investigations/:id/evidence", () =>
      jsonResponse({ items: [], next_cursor: null }),
    );
    await renderMap([geolocationsHandler(collection([item])), evidenceList]);
    const rows = screen.getByRole("table", {
      name: "All returned geolocation items",
    });
    const row = within(rows).getAllByRole("row")[1];
    await userEvent.click(within(row).getByRole("button", { name: /Explore/ }));
    await screen.findByRole("menu");
    await userEvent.click(
      screen.getByRole("menuitem", { name: "Evidence for this entity" }),
    );
    await screen.findByRole("dialog", { name: "Evidence pivot workspace" });
    // Breadcrumb preserves the IP identity of the Map-origin launch.
    const dialog = screen.getByRole("dialog", { name: "Evidence pivot workspace" });
    expect(within(dialog).getByText("203.0.113.1")).toBeVisible();
  });
});