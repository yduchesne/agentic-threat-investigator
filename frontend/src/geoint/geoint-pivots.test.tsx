// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT pivot workspace integration tests (PR 26E §16 PV10..PV13, PV17).
//
// The PR 24D PivotWorkspace is reused for the GEOINT surfaces: one modal,
// active-step-only mounting, Back/Forward/refresh through the URL-backed
// stack, and no API prefetch while a menu is open. All GEOINT requests are
// recorded so we can prove the location surface is only fetched after its
// step is pushed.

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
const ENTITY_ID = uuidAt(101);
const LOCATION_ID = uuidAt(201);
const EVIDENCE_ID = uuidAt(1);
const AUTH = [authMeSuccess, runtimeFake];

/** URL-encode one pivot envelope for the reserved ``pivot`` parameter. */
function pivotParam(steps: unknown[]): string {
  const envelope = { v: 1, steps: steps as never[] };
  const encoded = encodeURIComponent(
    btoa(JSON.stringify(envelope)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  );
  return encoded;
}

describe("GEOINT pivot workspace (PV10..PV13, PV17, PV18)", () => {
  it("PV13/PV17: a GEOINT entity step opens in the one modal, with no prefetch of deeper surfaces until pushed", async () => {
    let locationEntitiesCalls = 0;
    setHttpHandlers(
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
          locationEntitiesCalls += 1;
          return jsonResponse({
            items: [buildGeointEntityLocation(1, "203.0.113.10")],
            containment_applied: false,
          });
        },
      ),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () =>
        jsonResponse(buildEvidence({ id: EVIDENCE_ID })),
      ),
    );
    const pivot = pivotParam([
      {
        r: "geoint-entity",
        f: { entity_id: ENTITY_ID },
        s: null,
        l: "203.0.113.10",
        k: "geoint_entity",
      },
    ]);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview?pivot=${pivot}`);
    // One modal workspace only.
    const workspace = await screen.findByRole("dialog", {
      name: "Entity geographic context pivot workspace",
    });
    await within(workspace).findByText("Current in this Investigation");
    await within(workspace).findByText("Seattle");
    expect(await screen.findAllByRole("dialog")).toHaveLength(1);
    expect(locationEntitiesCalls).toBe(0);

    // Open the current context Explore menu: opening the menu alone must
    // not prefetch the location surface.
    await userEvent.click(within(workspace).getByRole("button", { name: /Explore/ }));
    const menu = screen.getByRole("menu");
    expect(within(menu).getByText("Entities at this location")).toBeVisible();
    await waitFor(() => expect(locationEntitiesCalls).toBe(0));

    // Push the Location Entities step: only now is the bounded page fetched,
    // and the same single modal swaps content (active-step-only mounting).
    await userEvent.click(within(menu).getByText("Entities at this location"));
    const locationWorkspace = await screen.findByRole("dialog", {
      name: "Entities by location pivot workspace",
    });
    await waitFor(() =>
      expect(
        within(locationWorkspace).getAllByText("203.0.113.10").length,
      ).toBeGreaterThan(0),
    );
    expect(locationEntitiesCalls).toBe(1);
    expect(await screen.findAllByRole("dialog")).toHaveLength(1);
    expect(
      screen.queryByRole("dialog", { name: "Entity geographic context pivot workspace" }),
    ).toBeNull();
  });

  it("PV18: breadcrumbs use the bounded semantic label, never raw identity noise", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
      ),
      geointEntityHandler(
        buildGeointEntityLocation(1, "203.0.113.10", {
          current_observation: buildGeointObservation(1, {
            evidence_id: EVIDENCE_ID,
          }),
        }),
      ),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse({ items: [], next_cursor: null }),
      ),
    );
    const pivot = pivotParam([
      {
        r: "geoint-entity",
        f: { entity_id: ENTITY_ID },
        s: null,
        l: "203.0.113.10",
        k: "geoint_entity",
      },
    ]);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview?pivot=${pivot}`);
    const workspace = await screen.findByRole("dialog", {
      name: "Entity geographic context pivot workspace",
    });
    const nav = within(workspace).getByRole("navigation", {
      name: "Pivot breadcrumb",
    });
    const segments = within(nav).getAllByRole("listitem").map((li) => li.textContent);
    expect(segments.join(" / ")).toContain("Investigation");
    expect(segments.join(" / ")).toContain("203.0.113.10");
    expect(segments.join(" / ")).toContain("Entity geographic context");
  });
});