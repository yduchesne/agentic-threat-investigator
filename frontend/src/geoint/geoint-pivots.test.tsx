// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Routed GEOINT resource navigation tests (PR 26E §16 PV10..PV13, PV17;
// PR 31F-8 §10, §16 N07/N08).
//
// The former PivotWorkspace hosting is replaced by canonical Investigation-
// scoped routes: Location Explore -> exact Location Entities route, Entity
// Explore -> exact Entity GEOINT route, one routed content surface at a
// time, and no API prefetch while a menu is open. All GEOINT requests are
// recorded so we can prove the location surface is only fetched after the
// routed navigation lands.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import {
  authMeSuccess,
  buildEvidence,
  buildGeointEntityLocation,
  buildGeointObservation,
  buildInvestigation,
  geointEntityHandler,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const ENTITY_ID = uuidAt(101);
const LOCATION_ID = uuidAt(201);
const EVIDENCE_ID = uuidAt(1);
const AUTH = [authMeSuccess, runtimeFake];

/** Shared routed GEOINT test handlers. */
function geointHandlers(locationEntitiesCalls: { count: number }) {
  return [
    ...AUTH,
    investigationDetailHandler(
      buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
    ),
    geointEntityHandler(
      buildGeointEntityLocation(1, "203.0.113.10", {
        current_observation: buildGeointObservation(1, {
          evidence_id: EVIDENCE_ID,
          location: {
            location_id: LOCATION_ID,
            location_type: "city",
            canonical_name: "Seattle",
            country_code: "US",
            admin1_code: "WA",
            admin2_code: null,
            parent_location_id: null,
            latitude: 47.6062,
            longitude: -122.3321,
          },
        }),
      }),
    ),
    http.get(
      "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
      () => jsonResponse({ items: [], next_cursor: null }),
    ),
    http.get(
      "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
      () => {
        locationEntitiesCalls.count += 1;
        return jsonResponse({
          items: [buildGeointEntityLocation(1, "203.0.113.10")],
          containment_applied: false,
        });
      },
    ),
    http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () =>
      jsonResponse(buildEvidence({ id: EVIDENCE_ID })),
    ),
  ];
}

describe("GEOINT routed resource navigation (PV10..PV13, PV17, PV18)", () => {
  it("PV13/PV17: Entity GEOINT -> Explore Location (route) fetches the Location surface only on navigation", async () => {
    const locationEntitiesCalls = { count: 0 };
    setHttpHandlers(...geointHandlers(locationEntitiesCalls));
    const { router } = renderAtPath(`${BASE}/geoint/entities/${ENTITY_ID}`);
    await screen.findByText("Current in this Investigation");
    await screen.findByText("Seattle");
    // No hosted pivot workbench exists in the routed architecture (one
    // routed content surface, N01/N02).
    expect(screen.queryAllByTestId("pivot-workbench")).toHaveLength(0);
    expect(router.state.location.pathname).toBe(`${BASE}/geoint/entities/${ENTITY_ID}`);

    // Opening the current-context Explore menu must not prefetch the
    // location surface.
    await userEvent.click(screen.getByRole("button", { name: /Explore/ }));
    const menu = screen.getByTestId("pivot-action-bar");
    expect(within(menu).getByTestId("pivot-action-geointLocationEntities")).toBeVisible();
    await waitFor(() => expect(locationEntitiesCalls.count).toBe(0));

    // Activating the semantic action navigates to the exact Location
    // Entities route: only now is the bounded page fetched, and the Entity
    // surface is replaced by the Location surface (one routed content
    // surface at a time, N07/N08).
    await userEvent.click(within(menu).getByTestId("pivot-action-geointLocationEntities"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `${BASE}/geoint/locations/${LOCATION_ID}/entities`,
      );
    });
    await waitFor(() => {
      expect(screen.getAllByText("203.0.113.10").length).toBeGreaterThan(0);
    });
    expect(locationEntitiesCalls.count).toBe(1);
    // The Location table heading is present and the Entity current/history
    // surface is unmounted (no hidden previous resource tree).
    expect(
      screen.queryByRole("heading", { name: "203.0.113.10" }),
    ).not.toBeInTheDocument();
  });

  it("PV17b: browser Back restores the previous routed Entity surface", async () => {
    const locationEntitiesCalls = { count: 0 };
    setHttpHandlers(...geointHandlers(locationEntitiesCalls));
    const { router } = renderAtPath(`${BASE}/geoint/entities/${ENTITY_ID}`);
    await screen.findByText("Current in this Investigation");
    await userEvent.click(screen.getByRole("button", { name: /Explore/ }));
    await userEvent.click(
      within(screen.getByTestId("pivot-action-bar")).getByTestId(
        "pivot-action-geointLocationEntities",
      ),
    );
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `${BASE}/geoint/locations/${LOCATION_ID}/entities`,
      );
    });
    await screen.findByText("203.0.113.10");

    // Browser Back reconstructs Entity GEOINT from route state (N16).
    await router.navigate(-1);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/geoint/entities/${ENTITY_ID}`);
    });
    await screen.findByText("Current in this Investigation");
    await screen.findByRole("heading", { name: "203.0.113.10" });
  });

  it("PV18: GEOINT breadcrumbs are route-derived, link the context root and never leak the full UUID", async () => {
    setHttpHandlers(...geointHandlers({ count: 0 }));
    renderAtPath(`${BASE}/geoint/entities/${ENTITY_ID}`);
    const nav = await screen.findByRole("navigation", {
      name: "Geographic context navigation",
    });
    const segments = within(nav).getAllByRole("listitem").map((li) => li.textContent ?? "");
    expect(segments.join(" / ")).toContain("Geographic context");
    // The root breadcrumb is a semantic link to the canonical GEOINT route.
    expect(
      within(nav).getByRole("link", { name: "Geographic context" }),
    ).toHaveAttribute("href", `${BASE}/geoint`);
    // The current segment uses the bounded compact identity/presentation
    // label, never the raw full Entity UUID.
    expect(segments.join(" / ")).not.toContain(ENTITY_ID);
    // The entity's human-readable value is the visible heading, not the
    // breadcrumb identity.
    await screen.findByRole("heading", { name: "203.0.113.10" });
  });
});
