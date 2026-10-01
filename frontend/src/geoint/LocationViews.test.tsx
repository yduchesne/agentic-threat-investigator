// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Location GEOINT view tests (PR 26E §15 U20..U25).

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { freshQueryClient, renderProviders } from "../test/render";
import { AppProviders } from "../app/AppProviders";
import {
  buildGeointEntityLocation,
  buildGeointObservation,
  jsonResponse,
  uuidAt,
} from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import { http } from "msw";
import type { ResourceTableState } from "../analyst-table/resource-page";
import type { GeointEntityLocation, GeointObservation } from "../api/schema-types";
import { readPivotState } from "../pivots/pivot-url";
import {
  entityLocationExploreActions,
  LocationEntitiesView,
  LocationObservationsView,
} from "./LocationViews";
import type { GeointLocationFilters } from "./geoint-filters";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const LOCATION_ID = uuidAt(201);

/** A plain URL-backed table state fake for the Location views. */
function fakeLocationTable(
  includeContained = false,
): ResourceTableState<GeointLocationFilters> {
  return {
    filters: { locationId: LOCATION_ID, includeContained },
    cursor: undefined,
    selection: null,
    canGoPrevious: false,
    applyFilters: vi.fn(),
    clearFilters: vi.fn(),
    goNext: vi.fn(),
    goPrevious: vi.fn(),
    returnToFirstPage: vi.fn(),
    openSelection: vi.fn(),
    closeSelection: vi.fn(),
  };
}

/**
 * One runtime row whose current geographic context is absent for this
 * Entity (the Location views guard this defensive null branch).
 */
function buildEntityWithoutObservation(
  ordinal: number,
  entityValue: string,
): GeointEntityLocation {
  return {
    ...buildGeointEntityLocation(ordinal, entityValue),
    current_observation: null as unknown as GeointObservation,
  };
}

const GENERIC_ENTITY_ACTION_KEYS = [
  "evidenceForEntity",
  "relationshipsSource",
  "relationshipsTarget",
  "researchForEntity",
] as const;

const OBSERVATION_DERIVED_ACTION_KEYS = [
  "evidenceExact",
  "geointLocationEntities",
  "geointLocationObservations",
] as const;

const GEOINT_ENTITY_KEY = "geointEntity";

describe("Location -> Entities (U20..U25)", () => {
  it("U20/U22: exact is the default and containment_applied=true is visible", async () => {
    let sawContained: string | null = "unset";
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        ({ request }) => {
          sawContained = new URL(request.url).searchParams.get("include_contained");
          return jsonResponse({
            items: [buildGeointEntityLocation(1)],
            containment_applied: true,
          });
        },
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable(false)}
        />
      </MemoryRouter>,
    );
    await screen.findByText("Exact Location");
    await screen.findByText("203.0.113.1");
    expect(sawContained).toBeNull();
    expect(screen.getByText("Contained Locations are included")).toBeVisible();
  });

  it("U21: toggling containment applies the semantic filter (resets cursor)", async () => {
    const table = fakeLocationTable(false);
    const applyFilters = vi.fn();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () =>
          jsonResponse({
            items: [buildGeointEntityLocation(1)],
            containment_applied: false,
          }),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={{ ...table, applyFilters }}
        />
      </MemoryRouter>,
    );
    const toggle = await screen.findByRole("button", {
      name: "Include contained Locations",
    });
    await userEvent.click(toggle);
    expect(applyFilters).toHaveBeenCalledWith({
      locationId: LOCATION_ID,
      includeContained: true,
    });
  });

  it("U23: containment_unavailable (false) explains exact results", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () =>
          jsonResponse({
            items: [buildGeointEntityLocation(1)],
            containment_applied: false,
          }),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable(true)}
        />
      </MemoryRouter>,
    );
    await waitFor(() => {
      const notes = screen.getAllByRole("note").map((note) => note.textContent);
      expect(notes).toContain("Exact results are shown");
      expect(notes).not.toContain("Contained Locations are included");
    });
  });

  it("U24: the same-location neutrality disclaimer is always visible", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () =>
          jsonResponse({
            items: [buildGeointEntityLocation(1)],
            containment_applied: false,
          }),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable()}
        />
      </MemoryRouter>,
    );
    expect(
      await screen.findByText(
        /not implied to be related, to share ownership or infrastructure, to coordinate, or to be attributed to the same actor/i,
      ),
    ).toBeVisible();
  });

  it("U25: coordinate-less current context stays actionable", async () => {
    const item = buildGeointEntityLocation(2, "203.0.113.20", {
      current_observation: buildGeointObservation(2, {
        entity_id: uuidAt(102),
        location: {
          location_id: LOCATION_ID,
          location_type: "country",
          canonical_name: "EdgeLand",
          country_code: "ZZ",
          admin1_code: null,
          admin2_code: null,
          parent_location_id: null,
          latitude: null,
          longitude: null,
        },
      }),
    });
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () => jsonResponse({ items: [item], containment_applied: false }),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable()}
        />
      </MemoryRouter>,
    );
    const table = await screen.findByRole("table", {
      name: "Entities observed at this Location",
    });
    const row = within(table).getByText("203.0.113.20");
    expect(row).toBeVisible();
    expect(within(table).getByText("EdgeLand")).toBeVisible();
    // The row stays actionable: an Evidence action and an Explore trigger.
    expect(
      within(table).getAllByRole("button", { name: "View Evidence" }).length,
    ).toBeGreaterThan(0);
    expect(within(table).getAllByRole("button", { name: /Explore/ }).length).toBeGreaterThan(
      0,
    );
  });

  it("U22b: the server order of Location Entities is authoritative", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () =>
          jsonResponse({
            items: [
              buildGeointEntityLocation(10, "203.0.113.10"),
              buildGeointEntityLocation(20, "203.0.113.20"),
            ],
            containment_applied: false,
          }),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationEntitiesView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable()}
        />
      </MemoryRouter>,
    );
    const table = await screen.findByRole("table", {
      name: "Entities observed at this Location",
    });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0].textContent).toContain("203.0.113.10");
    expect(rows[1].textContent).toContain("203.0.113.20");
  });

  it("GU09/GU10/GU11/GU12: rendered Explore exposes the GEOINT action and emits the geoint-entity PivotStep", async () => {
    const item = buildGeointEntityLocation(1, "203.0.113.10");
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        () => jsonResponse({ items: [item], containment_applied: false }),
      ),
    );
    const router = createMemoryRouter(
      [
        {
          path: "/",
          element: (
            <LocationEntitiesView
              investigationId={INVESTIGATION_ID}
              table={fakeLocationTable()}
            />
          ),
        },
      ],
      { initialEntries: ["/"] },
    );
    render(
      <AppProviders queryClient={freshQueryClient()}>
        <RouterProvider router={router} useTransitions={false} />
      </AppProviders>,
    );
    const table = await screen.findByRole("table", {
      name: "Entities observed at this Location",
    });
    const row = within(table).getByText("203.0.113.10").closest("tr");
    expect(row).not.toBeNull();
    // The row's in-flow Explore action bar exposes the registered GEOINT
    // capability as an ordinary button (no menu semantics).
    await userEvent.click(
      within(row as HTMLElement).getByRole("button", {
        name: "Explore entity actions for 203.0.113.10",
      }),
    );
    const bar = await screen.findByRole("group", { name: "Pivot actions" });
    const geointButton = within(bar).getByRole("button", {
      name: "Geographic context for this entity",
    });
    expect(geointButton).toBeVisible();
    await userEvent.click(geointButton);
    // One activation emits exactly one URL-backed PivotStep to geoint-entity.
    await waitFor(() => {
      const state = readPivotState(
        new URLSearchParams(router.state.location.search),
      );
      expect(state?.steps).toHaveLength(1);
      expect(state?.steps[0]).toMatchObject({
        resource: "geoint-entity",
        filters: { entity_id: item.entity_id },
        selectedId: null,
        sourceKind: "geoint_location",
      });
      expect(state?.steps[0].label).toBe("203.0.113.10");
    });
  });
});

describe("entityLocationExploreActions composition (GC01..GC12)", () => {
  const WITH_OBSERVATION = buildGeointEntityLocation(1, "203.0.113.10");
  const WITHOUT_OBSERVATION = buildEntityWithoutObservation(2, "203.0.113.20");

  it("GC01/GC02: exactly one GEOINT Entity action for both observation states", () => {
    for (const item of [WITH_OBSERVATION, WITHOUT_OBSERVATION]) {
      const actions = entityLocationExploreActions(item);
      expect(
        actions.filter((action) => action.key === GEOINT_ENTITY_KEY),
      ).toHaveLength(1);
    }
  });

  it("GC03/GC04/GC05/GC06/GC07: exact Entity identity, label, source and geoint-entity target", () => {
    for (const item of [WITH_OBSERVATION, WITHOUT_OBSERVATION]) {
      const action = entityLocationExploreActions(item).find(
        (candidate) => candidate.key === GEOINT_ENTITY_KEY,
      );
      expect(action?.sourceKind).toBe("geoint_location");
      expect(action?.target).toEqual({
        resource: "geoint-entity",
        filters: { entity_id: item.entity_id },
        selectedId: null,
        label: item.entity_value,
      });
    }
  });

  it("GC08: observation present preserves Evidence + both Location actions", () => {
    const actions = entityLocationExploreActions(WITH_OBSERVATION);
    const keys = actions.map((action) => action.key);
    expect(keys.slice(0, 3)).toEqual([
      "evidenceExact",
      "geointLocationEntities",
      "geointLocationObservations",
    ]);
    expect(keys).toContain(GEOINT_ENTITY_KEY);
  });

  it("GC09: observation absent invents no observation-derived actions", () => {
    const keys = entityLocationExploreActions(WITHOUT_OBSERVATION).map(
      (action) => action.key,
    );
    for (const derived of OBSERVATION_DERIVED_ACTION_KEYS) {
      expect(keys).not.toContain(derived);
    }
  });

  it("GC10: generic Entity capabilities are preserved in both states", () => {
    for (const item of [WITH_OBSERVATION, WITHOUT_OBSERVATION]) {
      const keys = entityLocationExploreActions(item).map((action) => action.key);
      for (const generic of GENERIC_ENTITY_ACTION_KEYS) {
        expect(keys).toContain(generic);
      }
    }
  });

  it("GC11: complete result has no duplicate action keys", () => {
    for (const item of [WITH_OBSERVATION, WITHOUT_OBSERVATION]) {
      const keys = entityLocationExploreActions(item).map((action) => action.key);
      expect(new Set(keys).size).toBe(keys.length);
    }
  });

  it("GC12: the input row is never mutated", () => {
    const before = JSON.stringify(WITH_OBSERVATION);
    entityLocationExploreActions(WITH_OBSERVATION);
    expect(JSON.stringify(WITH_OBSERVATION)).toBe(before);
  });
});

describe("Location -> observations (U20..U23)", () => {
  it("U20: exact default sends no containment; observations render", async () => {
    let sawContained: string | null = "unset";
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/observations",
        ({ request }) => {
          sawContained = new URL(request.url).searchParams.get("include_contained");
          return jsonResponse({
            items: [buildGeointObservation(1)],
            containment_applied: false,
          });
        },
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationObservationsView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable(false)}
        />
      </MemoryRouter>,
    );
    const table = await screen.findByRole("table", {
      name: "Geographic observations at this Location",
    });
    expect(sawContained).toBeNull();
    expect(within(table).getByText("Seattle 1")).toBeVisible();
  });

  it("U21b: contained sends include_contained=true on the exact request", async () => {
    const requests: string[] = [];
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/observations",
        ({ request }) => {
          requests.push(new URL(request.url).searchParams.get("include_contained") ?? "");
          return jsonResponse({
            items: [buildGeointObservation(1)],
            containment_applied: true,
          });
        },
      ),
    );
    renderProviders(
      <MemoryRouter>
        <LocationObservationsView
          investigationId={INVESTIGATION_ID}
          table={fakeLocationTable(true)}
        />
      </MemoryRouter>,
    );
    await screen.findByRole("table", {
      name: "Geographic observations at this Location",
    });
    expect(requests).toContain("true");
    expect(screen.getByText("Contained Locations are included")).toBeVisible();
  });
});
