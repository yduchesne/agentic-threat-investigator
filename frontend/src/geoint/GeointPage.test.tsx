// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT workspace route tests (PR 26E §15 U01..U05, U08..U13).

import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  authMeSuccess,
  buildGeointSummary,
  buildInvestigation,
  geointSummaryHandler,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

vi.mock("react-leaflet", () => import("../test/react-leaflet-mock"));

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const AUTH = [authMeSuccess, runtimeFake];

function workspace(status: "completed" = "completed") {
  return investigationDetailHandler(
    buildInvestigation({ id: INVESTIGATION_ID, status }),
  );
}

async function renderGeoint(handlers: ReturnType<typeof geointSummaryHandler>[]) {
  setHttpHandlers(...AUTH, workspace(), ...handlers);
  renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint`);
  await screen.findByRole("heading", { name: "Geographic context" });
}

describe("GEOINT workspace (U01..U05)", () => {
  it("U04: the GEOINT tab is a first-class workspace tab active on the route", async () => {
    setHttpHandlers(
      ...AUTH,
      workspace(),
      geointSummaryHandler(buildGeointSummary()),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint`);
    await screen.findByRole("heading", { name: "Geographic context" });
    const tabs = screen.getAllByRole("tab").map((tab) => tab.textContent);
    expect(tabs).toContain("Geographic context");
    await waitFor(() =>
      expect(screen.getByRole("tab", { name: "Geographic context" })).toHaveAttribute(
        "aria-selected",
        "true",
      ),
    );
  });

  it("U01: an empty summary renders the honest empty workspace, never a map", async () => {
    await renderGeoint([
      geointSummaryHandler(buildGeointSummary({ observation_count: 0 })),
    ]);
    await screen.findByText("No geographic observations");
    expect(screen.queryByText("Bounded summary")).not.toBeInTheDocument();
    expect(document.querySelector(".leaflet-marker-icon")).toBeNull();
    expect(screen.queryAllByTestId("ati-map-container")).toHaveLength(0);
  });

  it("U02: a truncated summary is visible", async () => {
    await renderGeoint([
      geointSummaryHandler(buildGeointSummary({ truncated: true })),
    ]);
    await screen.findByText("Server-bounded summary");
    expect(screen.getByText(/server-bounded subset/i)).toBeVisible();
  });

  it("the persistent semantic disclaimer is rendered verbatim", async () => {
    await renderGeoint([geointSummaryHandler(buildGeointSummary())]);
    expect(
      screen.getByText(
        /do not establish a cyber relationship, common ownership, coordination, targeting, or attribution/i,
      ),
    ).toBeVisible();
  });

  it("U05: a safe API error retains the workspace and offers Retry", async () => {
    const { http } = await import("msw");
    let calls = 0;
    setHttpHandlers(
      ...AUTH,
      workspace(),
      http.get("*/api/v1/investigations/:id/geoint/summary", () => {
        calls += 1;
        if (calls <= 2) {
          return jsonResponse(
            {
              error: {
                code: "internal_error",
                message: "test",
                request_id: "req-1",
              },
            },
            500,
          );
        }
        return jsonResponse(buildGeointSummary());
      }),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint`);
    await screen.findByRole("button", { name: "Retry" });
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("heading", { name: "Geographic context" });
    await screen.findByText("Bounded summary");
  });

  it("U02b: the bounded summary numbers are exact and visible", async () => {
    await renderGeoint([
      geointSummaryHandler(
        buildGeointSummary({
          entity_count_with_location: 3,
          observation_count: 4,
          location_count: 5,
          truncated: false,
        }),
      ),
    ]);
    await screen.findByText("Bounded summary");
    expect(screen.getByText("3")).toBeVisible();
    expect(screen.getByText("4")).toBeVisible();
    expect(screen.getByText("5")).toBeVisible();
  });
});

describe("map + top-location table (U08..U13)", () => {
  it("U08/U09: plottable top Locations render neutral markers with the table intact", async () => {
    const summary = buildGeointSummary();
    await renderGeoint([geointSummaryHandler(summary)]);
    await screen.findByText("Top Locations");
    const markers = screen.getAllByTestId("ati-marker");
    expect(markers).toHaveLength(2);
    // One unmappable top location (EdgeLand, no coordinates) stays in the
    // table without a marker.
    const withNonMappable = buildGeointSummary({
      top_locations: [
        ...summary.top_locations,
        {
          location: {
            location_id: "60000000-0000-4000-8000-00000000ffff",
            location_type: "country",
            canonical_name: "EdgeLand",
            country_code: "ZZ",
            admin1_code: null,
            admin2_code: null,
            parent_location_id: null,
            latitude: null,
            longitude: null,
          },
          scoped_entity_count: 1,
        },
      ],
    });
    cleanup();
    const { http } = await import("msw");
    setHttpHandlers(
      ...AUTH,
      workspace(),
      http.get("*/api/v1/investigations/:id/geoint/summary", () =>
        jsonResponse(withNonMappable)),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint`);
    await screen.findByText("Top Locations");
    await screen.findByText("EdgeLand");
    expect(await screen.findAllByTestId("ati-marker")).toHaveLength(2);
    // Mixed notice is visible and the table row remains actionable.
    expect(screen.getByText(/no plottable coordinates/i)).toBeVisible();
    const table = screen.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    expect(within(table).getByText("EdgeLand")).toBeVisible();
    expect(within(table).getByText("Not plotted")).toBeVisible();
  });

  it("U11: same-coordinate top Locations stay individually actionable", async () => {
    const summary = buildGeointSummary({
      top_locations: [
        {
          location: {
            location_id: "60000000-0000-4000-8000-000000000001",
            location_type: "city",
            canonical_name: "Seattle",
            country_code: "US",
            admin1_code: "WA",
            admin2_code: null,
            parent_location_id: null,
            latitude: 47.6062,
            longitude: -122.3321,
          },
          scoped_entity_count: 2,
        },
        {
          location: {
            location_id: "60000000-0000-4000-8000-000000000002",
            location_type: "city",
            canonical_name: "Sibling town",
            country_code: "US",
            admin1_code: "WA",
            admin2_code: null,
            parent_location_id: null,
            latitude: 47.6062,
            longitude: -122.3321,
          },
          scoped_entity_count: 1,
        },
      ],
    });
    await renderGeoint([geointSummaryHandler(summary)]);
    const markers = await screen.findAllByTestId("ati-marker");
    expect(markers).toHaveLength(2);
    // Each marker carries its own stable key (identity, never coordinates).
    expect(markers[0].getAttribute("data-title")).toBe("Seattle");
    expect(markers[1].getAttribute("data-title")).toBe("Sibling town");
    expect(markers[0].getAttribute("data-alt")).not.toBe(markers[1].getAttribute("data-alt"));
  });

  it("U12: no risk styling or concentration language exists", async () => {
    await renderGeoint([geointSummaryHandler(buildGeointSummary())]);
    for (const forbidden of [
      "hotspot",
      "threat concentration",
      "risk",
      "malicious",
      "coordinated",
    ]) {
      expect(screen.queryByText(forbidden, { exact: false })).toBeNull();
    }
  });

  it("U03: each top Location offers typed Explore actions", async () => {
    const summary = buildGeointSummary();
    await renderGeoint([geointSummaryHandler(summary)]);
    const table = screen.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    const triggers = within(table).getAllByRole("button", { name: /Explore/ });
    expect(triggers.length).toBeGreaterThan(0);
    await userEvent.click(triggers[0]);
    const menu = screen.getByRole("menu");
    expect(within(menu).getByText("Entities at this location")).toBeVisible();
    expect(within(menu).getByText("Observations at this location")).toBeVisible();
  });

  it("U13: OSM attribution is present on the tile layer", async () => {
    const summary = buildGeointSummary();
    await renderGeoint([geointSummaryHandler(summary)]);
    const tiles = await screen.findAllByTestId("ati-tile-layer");
    expect(tiles.length).toBeGreaterThan(0);
    expect(tiles[0].getAttribute("data-attribution")).toContain("OpenStreetMap");
  });
});