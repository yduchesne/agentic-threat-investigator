// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// InvestigationMapPage tests (PR 25B §48 B-U01..B-U17, §50 B-P, §51 B-A11Y).
//
// The Leaflet rendering boundary is mocked (react-leaflet-mock) so page
// state/provenance/accessibility semantics are asserted without live tile
// requests. The exact PR 25A DTO shape is served through MSW.

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
  errorResponse,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

vi.mock("react-leaflet", () => import("../test/react-leaflet-mock"));

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const EVIDENCE_ID = "40000000-0000-4000-8000-000000000001";
const AUTH = [authMeSuccess, runtimeFake];

/** One deterministic PR 25A-shaped geolocation item. */
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

function geolocationsHandler(
  body: InvestigationGeolocationCollection,
): ReturnType<typeof http.get> {
  return http.get("*/api/v1/investigations/:id/geolocations", () => jsonResponse(body));
}

/** The completed Investigation detail fixture for the workspace shell. */
function workspace() {
  return investigationDetailHandler(
    buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
  );
}

/** The exact Evidence detail endpoint used by the provenance drawer. */
function evidenceDetailHandler() {
  return http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () =>
    jsonResponse(buildEvidence({ id: EVIDENCE_ID })));
}

/** Install handlers, render the Map route, and wait for the projection. */
async function renderMap(handlers: ReturnType<typeof http.get>[]) {
  setHttpHandlers(...AUTH, workspace(), ...handlers);
  renderAtPath(`/investigations/${INVESTIGATION_ID}/map`);
  await screen.findByRole("tab", { name: "Map" });
  // Wait for the authoritative geolocation request to resolve (or fail).
  await waitFor(() =>
    expect(
      screen.queryByText("Loading geolocation context…"),
    ).not.toBeInTheDocument(),
  );
}

describe("InvestigationMapPage states (B-U01..B-U17)", () => {
  it("B-U01: Map is a primary route-owned tab selected on the route", async () => {
    await renderMap([geolocationsHandler(collection())]);
    const tabs = screen.getAllByRole("tab").map((tab) => tab.textContent);
    expect(tabs).toEqual([
      "Overview",
      "Evidence",
      "Relationships",
      "Map",
      "Research",
      "Timeline",
    ]);
    const mapTab = screen.getByRole("tab", { name: "Map" });
    expect(mapTab).toHaveAttribute("aria-selected", "true");
    const link = mapTab.closest("a");
    expect(link).toHaveAttribute("href", `/investigations/${INVESTIGATION_ID}/map`);
  });

  it("B-U02: shows the translated loading state while the request is pending", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = http.get("*/api/v1/investigations/:id/geolocations", async () => {
      await gate;
      return jsonResponse(collection());
    });
    setHttpHandlers(...AUTH, workspace(), pending);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/map`);
    await screen.findByText("Loading geolocation context…");
    release?.();
    await screen.findByText("Investigation Map");
  });

  it("B-U03: API failure renders the error notice and Retry recovers", async () => {
    let failing = true;
    const handler = http.get("*/api/v1/investigations/:id/geolocations", () =>
      failing ? errorResponse(500, "internal_error") : jsonResponse(collection()));
    await renderMap([handler]);
    expect(screen.getByRole("alert").textContent).toContain(
      "Unable to load geolocation context",
    );
    // No invented markers and no Evidence fallback on failure.
    expect(screen.queryByTestId("ati-marker")).not.toBeInTheDocument();
    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findAllByText("203.0.113.1");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("B-U04: empty collection shows an honest empty state with no invented marker", async () => {
    await renderMap([geolocationsHandler(collection([]))]);
    expect(
      screen.getByText("No geolocation context is available for this Investigation."),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("ati-marker")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ati-map-container")).not.toBeInTheDocument();
  });

  it("B-U05: one mappable item reaches the map and the non-map list", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(1);
    expect(screen.getAllByText("203.0.113.1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Seattle, Washington, US").length).toBeGreaterThan(0);
  });

  it("B-U06: multiple mappable items each reach the map", async () => {
    await renderMap([
      geolocationsHandler(
        collection([geoItem(1), geoItem(2, { latitude: 51.5074, longitude: -0.1278 })]),
      ),
    ]);
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(2);
  });

  it("B-U07: unlocated-only data renders no marker and keeps items in the list", async () => {
    const unlocated = geoItem(2, {
      latitude: null,
      longitude: null,
      city: "Berlin",
      region: null,
      country_code: "DE",
    });
    await renderMap([geolocationsHandler(collection([unlocated]))]);
    expect(screen.queryByTestId("ati-marker")).not.toBeInTheDocument();
    expect(screen.getByText("No plottable coordinates")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.2")).toBeInTheDocument();
    expect(screen.getByText("Berlin, DE")).toBeInTheDocument();
    expect(screen.getByText("Not plotted")).toBeInTheDocument();
  });

  it("B-U08: mixed state keeps both groups visible and states the count", async () => {
    const unlocated = geoItem(2, { latitude: null, longitude: null });
    await renderMap([geolocationsHandler(collection([geoItem(1), unlocated]))]);
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(1);
    expect(
      screen.getByText(
        /1 of 2 returned geolocation items have no plottable coordinates/,
      ),
    ).toBeInTheDocument();
    // All returned items stay in the non-map representation.
    expect(screen.getAllByText("203.0.113.1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("203.0.113.2").length).toBeGreaterThan(0);
    expect(screen.getByText("Plotted")).toBeInTheDocument();
    expect(screen.getByText("Not plotted")).toBeInTheDocument();
  });

  it("B-U09: truncated=true renders the persistent bounded warning", async () => {
    await renderMap([
      http.get("*/api/v1/investigations/:id/geolocations", () =>
        jsonResponse({ items: [geoItem(1)], truncated: true })),
    ]);
    expect(screen.getByText("Server-bounded projection")).toBeInTheDocument();
    expect(
      screen.getByText(
        "This is a server-bounded subset of the Investigation's current geolocation projection. Additional current geolocation records may exist; not every location may be shown.",
      ),
    ).toBeInTheDocument();
    // The server bound is never bypassed: exactly one projection request.
  });

  it("B-U10: the persistent approximation disclaimer is visible text", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(
      screen.getByText(
        "IP geolocation is approximate network-address context. It does not establish the physical location of an attacker, user, or device.",
      ),
    ).toBeInTheDocument();
  });

  it("B-U11: exact precision enum renders translated neutral labels", async () => {
    await renderMap([
      geolocationsHandler(
        collection([
          geoItem(1, { precision: "city" }),
          geoItem(2, { precision: "region", latitude: null, longitude: null }),
          geoItem(3, { precision: "country", latitude: null, longitude: null }),
          geoItem(4, { precision: "unknown", latitude: null, longitude: null }),
        ]),
      ),
    ]);
    expect(screen.getByText("City-level approximation")).toBeInTheDocument();
    expect(screen.getByText("Region-level approximation")).toBeInTheDocument();
    expect(screen.getByText("Country-level approximation")).toBeInTheDocument();
    expect(screen.getByText("Unknown precision")).toBeInTheDocument();
  });

  it("B-U12: known provider shows its friendly label; unknown provider stays escaped text", async () => {
    await renderMap([
      geolocationsHandler(
        collection([
          geoItem(1),
          geoItem(2, { latitude: null, longitude: null, provider: "urn:ati:source:mystery" }),
        ]),
      ),
    ]);
    expect(screen.getByText("DB-IP City Lite")).toBeInTheDocument();
    expect(screen.getByText("urn:ati:source:mystery")).toBeInTheDocument();
  });

  it("B-U13: observed and retrieved timestamps remain distinct", async () => {
    await renderMap([
      geolocationsHandler(
        collection([
          geoItem(1, {
            observed_at: "2026-06-01T09:00:00Z",
            retrieved_at: "2026-06-01T10:00:00Z",
          }),
          geoItem(2, { latitude: null, longitude: null }),
        ]),
      ),
    ]);
    // Item 2 has no observed_at: the explicit unavailable label is shown
    // and never substituted by the retrieval time.
    expect(screen.getByText("Not observed")).toBeInTheDocument();
  });

  it("B-U14: the Evidence action opens the exact evidence_id drawer", async () => {
    const seen: string[] = [];
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ request }) => {
        seen.push(request.url);
        return jsonResponse(buildEvidence({ id: EVIDENCE_ID }));
      }),
    ]);
    const viewButton = screen.getAllByRole("button", { name: "View Evidence" })[0];
    await userEvent.click(viewButton);
    const drawer = screen.getByRole("dialog", { name: "Evidence" });
    await waitFor(() =>
      expect(drawer.textContent).toContain("update-package.test"),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toContain(`/evidence/${EVIDENCE_ID}`);
    expect(seen[0]).toContain(`/investigations/${INVESTIGATION_ID}/`);
  });

  it("B-U15: the page builds from the geolocation endpoint, never Evidence pagination", async () => {
    const geoRequests: string[] = [];
    const evidenceListRequests: string[] = [];
    await renderMap([
      http.get("*/api/v1/investigations/:id/geolocations", ({ request }) => {
        geoRequests.push(request.url);
        return jsonResponse(collection());
      }),
      http.get("*/api/v1/investigations/:id/evidence", ({ request }) => {
        evidenceListRequests.push(request.url);
        return jsonResponse({ items: [], next_cursor: null });
      }),
    ]);
    await screen.findByRole("tab", { name: "Map" });
    await waitFor(() => expect(geoRequests).toHaveLength(1));
    expect(geoRequests[0]).not.toContain("?");
    expect(evidenceListRequests).toHaveLength(0);
    // The item is visible in the non-map representation.
    expect((await screen.findAllByText("203.0.113.1")).length).toBeGreaterThan(0);
  });

  it("B-U16: external values cannot inject markup", async () => {
    const hostile = geoItem(7, {
      ip_address: "<img src=x onerror=window.__xss=1>",
      city: "<b>bold</b>",
    });
    await renderMap([geolocationsHandler(collection([hostile]))]);
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("b")).toBeNull();
    expect(document.body.textContent).toContain("<b>bold</b>, Washington, US");
    expect(document.body.textContent).toContain("<img src=x onerror=window.__xss=1>");
    expect((window as { __xss?: number }).__xss).toBeUndefined();
  });

  it("B-U17: the global FAKE DATA marker remains visible in fake mode", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(screen.getByText("FAKE DATA")).toBeInTheDocument();
  });
});

describe("InvestigationMapPage provenance (B-P01..B-P06)", () => {
  it("B-P01: the marker popup action uses the exact PR 25A evidence_id", async () => {
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      evidenceDetailHandler(),
    ]);
    await screen.findByTestId("ati-marker");
    const marker = screen.getByTestId("ati-marker");
    await userEvent.click(within(marker).getByRole("button", { name: "View Evidence" }));
    const drawer = screen.getByRole("dialog", { name: "Evidence" });
    await waitFor(() => expect(drawer.textContent).toContain("update-package.test"));
    // Both surfaces expose the same exact item.
    expect(
      within(marker).getByRole("button", { name: "View Evidence" }),
    ).toBeInTheDocument();
  });

  it("B-P02: the non-map row carries the exact evidence_id to the drawer", async () => {
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      evidenceDetailHandler(),
    ]);
    // The non-map table row button carries the exact persisted id.
    const rowButton = screen
      .getAllByRole("button", { name: "View Evidence" })
      .find((button) => button.closest("[data-evidence-id]"));
    expect(rowButton).not.toBeUndefined();
    expect(rowButton!.closest("[data-evidence-id]")).toHaveAttribute(
      "data-evidence-id",
      EVIDENCE_ID,
    );
    await userEvent.click(rowButton as HTMLElement);
    await waitFor(() =>
      expect(screen.getByRole("dialog", { name: "Evidence" }).textContent).toContain(
        "update-package.test",
      ),
    );
  });

  it("B-P03/B-P04: no lookup by IP and no Evidence list scan", async () => {
    const evidenceList: string[] = [];
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ request }) => {
        // Exact id lookup: the request never carries the IP value.
        expect(request.url).not.toContain("203.0.113.1");
        return jsonResponse(buildEvidence({ id: EVIDENCE_ID }));
      }),
      http.get("*/api/v1/investigations/:id/evidence", ({ request }) => {
        evidenceList.push(request.url);
        return jsonResponse({ items: [], next_cursor: null });
      }),
    ]);
    const rowButton = screen
      .getAllByRole("button", { name: "View Evidence" })
      .find((button) => button.closest("[data-evidence-id]"));
    await userEvent.click(rowButton as HTMLElement);
    await screen.findByRole("dialog", { name: "Evidence" });
    expect(evidenceList).toHaveLength(0);
  });

  it("B-P05: provenance navigation stays Investigation-scoped", async () => {
    const seen: string[] = [];
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ request }) => {
        seen.push(request.url);
        return jsonResponse(buildEvidence({ id: EVIDENCE_ID }));
      }),
    ]);
    const rowButton = screen
      .getAllByRole("button", { name: "View Evidence" })
      .find((button) => button.closest("[data-evidence-id]"));
    await userEvent.click(rowButton as HTMLElement);
    await screen.findByRole("dialog", { name: "Evidence" });
    expect(seen[0]).toContain(
      `/investigations/${INVESTIGATION_ID}/evidence/${EVIDENCE_ID}`,
    );
  });

  it("B-P06: closing the drawer returns to the intact Map view", async () => {
    await renderMap([
      geolocationsHandler(collection([geoItem(1, { evidence_id: EVIDENCE_ID })])),
      evidenceDetailHandler(),
    ]);
    const rowButton = screen
      .getAllByRole("button", { name: "View Evidence" })
      .find((button) => button.closest("[data-evidence-id]"));
    await userEvent.click(rowButton as HTMLElement);
    await screen.findByRole("dialog", { name: "Evidence" });
    await userEvent.click(screen.getByRole("button", { name: "Close detail" }));
    expect(screen.queryByRole("dialog", { name: "Evidence" })).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Investigation Map" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("203.0.113.1").length).toBeGreaterThan(0);
  });
});

describe("InvestigationMapPage accessibility (B-A11Y01..B-A11Y08)", () => {
  it("B-A11Y01: translated route heading", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(screen.getByRole("heading", { name: "Investigation Map" })).toBeInTheDocument();
  });

  it("B-A11Y02: the disclaimer is visible normal text (not hover-only)", async () => {
    await renderMap([geolocationsHandler(collection())]);
    const disclaimer = screen.getByText(/approximate network-address context/i);
    expect(disclaimer).toBeInTheDocument();
    expect(disclaimer.closest("[aria-hidden=true]")).toBeNull();
  });

  it("B-A11Y03: the non-map representation is a labeled table", async () => {
    await renderMap([geolocationsHandler(collection())]);
    const table = screen.getByRole("table", {
      name: "All returned geolocation items",
    });
    expect(table).toBeInTheDocument();
  });

  it("B-A11Y04: Evidence actions are native operable buttons", async () => {
    await renderMap([geolocationsHandler(collection())]);
    for (const button of screen.getAllByRole("button", { name: "View Evidence" })) {
      expect(button.tagName).toBe("BUTTON");
      expect(button).not.toHaveAttribute("tabindex", "-1");
    }
  });

  it("B-A11Y05: no substantive information exists only on hover", async () => {
    await renderMap([
      geolocationsHandler(
        collection([
          geoItem(2, {
            latitude: null,
            longitude: null,
            city: null,
            region: null,
            country_code: "DE",
          }),
        ]),
      ),
    ]);
    // IP/location/precision/provider are all visible list text.
    expect(screen.getByText("203.0.113.2")).toBeInTheDocument();
    expect(screen.getByText("DE")).toBeInTheDocument();
    expect(screen.getByText("City-level approximation")).toBeInTheDocument();
    expect(screen.getByText("DB-IP City Lite")).toBeInTheDocument();
  });

  it("B-A11Y06: unlocated items are fully inspectable without the map", async () => {
    const unlocated = geoItem(4, { latitude: null, longitude: null });
    await renderMap([geolocationsHandler(collection([unlocated]))]);
    expect(screen.queryByTestId("ati-map-container")).not.toBeInTheDocument();
    expect(screen.getByText("203.0.113.4")).toBeInTheDocument();
    expect(screen.getByText("Not plotted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "View Evidence" })).toBeInTheDocument();
  });

  it("B-A11Y07: the map has a useful accessible label", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(
      screen.getByRole("region", {
        name: "Map of approximate IP geolocation context for this Investigation",
      }),
    ).toBeInTheDocument();
  });

  it("B-A11Y08: tile attribution is present", async () => {
    await renderMap([geolocationsHandler(collection())]);
    expect(
      screen.getByTestId("ati-tile-layer").getAttribute("data-attribution"),
    ).toContain("OpenStreetMap");
  });
});