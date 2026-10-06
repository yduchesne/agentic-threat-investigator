// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT TABLE presentation tests (PR 26E §15 U01..U05, U08..U13;
// PR 35-2 §D U13..U17).
//
// TABLE is the non-map GEOINT presentation: bounded summary, precision
// counts, Top Locations analyst table with typed Explore actions, and the
// persistent semantic/non-inference messaging. It must never embed a
// Leaflet map.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

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

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const AUTH = [authMeSuccess, runtimeFake];

function workspace() {
  return investigationDetailHandler(
    buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
  );
}

async function renderTable(handlers: ReturnType<typeof geointSummaryHandler>[]) {
  setHttpHandlers(...AUTH, workspace(), ...handlers);
  renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint/table`);
  await screen.findByRole("heading", { name: "GEOINT" });
}

describe("GEOINT TABLE (U01..U05, U13..U17)", () => {
  it("U04/U08: TABLE is the selected GEOINT sub-tab on the route", async () => {
    setHttpHandlers(
      ...AUTH,
      workspace(),
      geointSummaryHandler(buildGeointSummary()),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint/table`);
    await screen.findByRole("heading", { name: "GEOINT" });
    const primary = screen.getByRole("tab", { name: "GEOINT" });
    expect(primary).toHaveAttribute("aria-selected", "true");
    // The active TABLE sub-tab is inert; MAP remains a semantic link.
    const tableTab = screen.getByRole("tab", { name: "TABLE" });
    expect(tableTab).toHaveAttribute("aria-selected", "true");
    expect(tableTab.closest("a")).toBeNull();
    const mapTab = screen.getByRole("tab", { name: "MAP" });
    expect(mapTab.closest("a")).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/geoint/map`,
    );
  });

  it("U01: an empty summary renders the honest empty workspace, never a map", async () => {
    await renderTable([
      geointSummaryHandler(buildGeointSummary({ observation_count: 0 })),
    ]);
    await screen.findByText("No geographic observations");
    expect(screen.queryByText("Bounded summary")).not.toBeInTheDocument();
    expect(document.querySelector(".leaflet-marker-icon")).toBeNull();
    expect(screen.queryAllByTestId("ati-map-container")).toHaveLength(0);
  });

  it("U02: a truncated summary is visible", async () => {
    await renderTable([
      geointSummaryHandler(buildGeointSummary({ truncated: true })),
    ]);
    await screen.findByText("Server-bounded summary");
    expect(screen.getByText(/server-bounded subset/i)).toBeVisible();
  });

  it("the persistent semantic disclaimer is rendered verbatim", async () => {
    await renderTable([geointSummaryHandler(buildGeointSummary())]);
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
    renderAtPath(`/investigations/${INVESTIGATION_ID}/geoint/table`);
    await screen.findByRole("button", { name: "Retry" });
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("heading", { name: "GEOINT" });
    await screen.findByText("Bounded summary");
  });

  it("U02b/U13: the bounded summary numbers are exact and visible", async () => {
    await renderTable([
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

  it("U14: Top Locations keep canonical labels/types/counts; non-mappable rows stay", async () => {
    const summary = buildGeointSummary();
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
    await renderTable([geointSummaryHandler(withNonMappable)]);
    const table = screen.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    expect(within(table).getByText("EdgeLand")).toBeVisible();
    // The honest unplottable status remains visible without a map.
    expect(within(table).getByText("Not plotted")).toBeVisible();
    expect(table.getAttribute("aria-label")).toBe(
      "Top canonical Locations in this Investigation",
    );
  });

  it("U15: TABLE never embeds a Leaflet map or tiles", async () => {
    await renderTable([geointSummaryHandler(buildGeointSummary())]);
    await screen.findByText("Top Locations");
    expect(document.querySelector(".leaflet-marker-icon")).toBeNull();
    expect(screen.queryAllByTestId("ati-map-container")).toHaveLength(0);
    expect(screen.queryAllByTestId("ati-marker")).toHaveLength(0);
    expect(screen.queryAllByTestId("ati-tile-layer")).toHaveLength(0);
  });

  it("U16: each top Location offers typed Explore actions", async () => {
    const summary = buildGeointSummary();
    await renderTable([geointSummaryHandler(summary)]);
    const table = screen.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    const triggers = within(table).getAllByRole("button", { name: /Explore/ });
    expect(triggers.length).toBeGreaterThan(0);
    await userEvent.click(triggers[0]);
    const menu = screen.getByTestId("pivot-action-bar");
    expect(within(menu).getByTestId("pivot-action-geointLocationEntities")).toBeVisible();
    expect(within(menu).getByTestId("pivot-action-geointLocationObservations")).toBeVisible();
  });

  it("U17: the no-inference warning is visible", async () => {
    await renderTable([geointSummaryHandler(buildGeointSummary())]);
    expect(
      screen.getByText(
        /does not imply that the observed Entities are related, share ownership or infrastructure, coordinate, target the same victim, or are attributed to the same actor/i,
      ),
    ).toBeVisible();
  });

  it("U12: no risk styling or concentration language exists", async () => {
    await renderTable([geointSummaryHandler(buildGeointSummary())]);
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

  it("same-coordinate top Locations stay individually actionable", async () => {
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
    await renderTable([geointSummaryHandler(summary)]);
    const table = screen.getByRole("table", {
      name: "Top canonical Locations in this Investigation",
    });
    expect(within(table).getByText("Seattle")).toBeVisible();
    expect(within(table).getByText("Sibling town")).toBeVisible();
    expect(within(table).getAllByRole("button", { name: /Explore/ })).toHaveLength(2);
  });
});
