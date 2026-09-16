// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Entity GEOINT view tests (PR 26E §15 U14..U19, U26..U28).

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { renderProviders } from "../test/render";
import {
  buildEvidence,
  buildGeointObservation,
  buildGeointObservationDetail,
  errorResponse,
  geointEntityHandler,
  geointObservationDetailHandler,
  jsonResponse,
  uuidAt,
} from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import { http } from "msw";
import type { ResourceTableState } from "../analyst-table/resource-page";
import type { GeointEntityFilters } from "./geoint-filters";
import { EntityGeointView } from "./EntityGeointView";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const ENTITY_ID = uuidAt(101);
const EVIDENCE_ID = uuidAt(1);
const OBSERVATION_A = uuidAt(301);
const OBSERVATION_B = uuidAt(302);

/** A plain URL-backed table state fake (the view only calls these). */
function fakeTable(
  overrides: Partial<ResourceTableState<GeointEntityFilters>> = {},
): ResourceTableState<GeointEntityFilters> {
  return {
    filters: { entityId: ENTITY_ID },
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
    ...overrides,
  };
}

function entityBody(overrides = {}) {
  return {
    entity_id: ENTITY_ID,
    entity_type: "ip_address" as const,
    entity_value: "203.0.113.10",
    display_name: "203.0.113.10",
    current_observation: buildGeointObservation(1, {
      observation_id: OBSERVATION_A,
      entity_id: ENTITY_ID,
    }),
    ...overrides,
  };
}

function historyPage(items: unknown[]) {
  return { items, next_cursor: null };
}


describe("Entity GEOINT current/history (U14..U19)", () => {
  it("U14: the current section is explicitly 'Current in this Investigation'", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse(historyPage([])),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <EntityGeointView investigationId={INVESTIGATION_ID} table={fakeTable()} />
      </MemoryRouter>,
    );
    await screen.findByText("Current in this Investigation");
    expect(screen.getByText("Current in this Investigation")).toBeVisible();
  });

  it("U15: history rows render in exact server order", async () => {
    const older = buildGeointObservation(1, {
      observation_id: OBSERVATION_A,
      entity_id: ENTITY_ID,
      location: {
        location_id: uuidAt(201),
        location_type: "city",
        canonical_name: "Seattle",
        country_code: "US",
        admin1_code: "WA",
        admin2_code: null,
        parent_location_id: null,
        latitude: 47.6062,
        longitude: -122.3321,
      },
      retrieved_at: "2026-06-01T09:05:00Z",
    });
    const newer = buildGeointObservation(2, {
      observation_id: OBSERVATION_B,
      entity_id: ENTITY_ID,
      location: {
        location_id: uuidAt(202),
        location_type: "city",
        canonical_name: "Dallas",
        country_code: "US",
        admin1_code: "TX",
        admin2_code: null,
        parent_location_id: null,
        latitude: 32.78306,
        longitude: -96.80667,
      },
      retrieved_at: "2026-06-02T09:05:00Z",
    });
    // Server order is authoritative: Dallas (newer) first, Seattle second.
    setHttpHandlers(
      geointEntityHandler(entityBody({ current_observation: newer })),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse(historyPage([newer, older])),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <EntityGeointView investigationId={INVESTIGATION_ID} table={fakeTable()} />
      </MemoryRouter>,
    );
    const rows = await screen.findAllByRole("row");
    const rowTexts = rows.map((row) => row.textContent ?? "");
    const dallasIndex = rowTexts.findIndex((text) => text.includes("Dallas"));
    const seattleIndex = rowTexts.findIndex((text) => text.includes("Seattle"));
    expect(dallasIndex).toBeGreaterThanOrEqual(0);
    expect(seattleIndex).toBeGreaterThan(dallasIndex);
  });

  it("U16: observed/retrieved/resolved stay distinct columns", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () =>
          jsonResponse(
            historyPage([
              buildGeointObservation(1, {
                observation_id: OBSERVATION_A,
                entity_id: ENTITY_ID,
                observed_at: "2026-06-01T09:00:00Z",
                retrieved_at: "2026-06-01T09:05:00Z",
                resolved_at: "2026-06-01T09:06:00Z",
              }),
            ]),
          ),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <EntityGeointView investigationId={INVESTIGATION_ID} table={fakeTable()} />
      </MemoryRouter>,
    );
    const table = await screen.findByRole("table", {
      name: "Entity geographic observation history",
    });
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual(
      expect.arrayContaining(["Observed", "Retrieved", "Resolved"]),
    );
  });

  it("U17: Evidence actions use the exact returned evidence_id", async () => {
    let seenEvidenceId: string | null = null;
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () =>
          jsonResponse(
            historyPage([
              buildGeointObservation(1, {
                observation_id: OBSERVATION_A,
                entity_id: ENTITY_ID,
                evidence_id: EVIDENCE_ID,
              }),
            ]),
          ),
      ),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ params }) => {
        seenEvidenceId = params.evidenceId as string;
        return jsonResponse(buildEvidence({ id: EVIDENCE_ID }));
      }),
    );
    renderProviders(
      <MemoryRouter>
        <EntityGeointView investigationId={INVESTIGATION_ID} table={fakeTable()} />
      </MemoryRouter>,
    );
    const table = await screen.findByRole("table", {
      name: "Entity geographic observation history",
    });
    await userEvent.click(within(table).getAllByRole("button", { name: "View Evidence" })[0]);
    const drawer = await screen.findByRole("dialog", { name: "Evidence" });
    expect(drawer).toBeVisible();
    expect(seenEvidenceId).toBe(EVIDENCE_ID);
  });

  it("U18: the next page uses the exact opaque cursor", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () =>
          jsonResponse({
            items: [
              buildGeointObservation(1, {
                observation_id: OBSERVATION_A,
                entity_id: ENTITY_ID,
              }),
            ],
            next_cursor: "opaque-cursor-7",
          }),
      ),
    );
    const table = fakeTable();
    const goNext = vi.fn();
    renderProviders(
      <MemoryRouter>
        <EntityGeointView
          investigationId={INVESTIGATION_ID}
          table={{ ...table, goNext }}
        />
      </MemoryRouter>,
    );
    await screen.findByRole("table", { name: "Entity geographic observation history" });
    await waitFor(
      () => expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled(),
      { timeout: 3000 },
    );
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(goNext).toHaveBeenCalledWith("opaque-cursor-7");
  });

  it("U19: no movement path, route, or ongoing-presence inference exists", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse(historyPage([])),
      ),
    );
    renderProviders(
      <MemoryRouter>
        <EntityGeointView investigationId={INVESTIGATION_ID} table={fakeTable()} />
      </MemoryRouter>,
    );
    await screen.findByText("Current in this Investigation");
    for (const forbidden of ["moved from", "still present"]) {
      expect(screen.queryByText(forbidden, { exact: false })).toBeNull();
    }
    // The only SVG on the page is the informational disclaimer icon; no
    // movement path, trace, or route overlay is ever rendered.
    const svgs = Array.from(document.querySelectorAll("svg"));
    expect(svgs.map((svg) => svg.getAttribute("data-testid"))).toEqual([
      "InfoOutlinedIcon",
    ]);
    expect(screen.queryByRole("img", { name: /route/i })).toBeNull();
    expect(screen.queryByText(/moved/i, { exact: false })).toBeNull();
  });
});

describe("observation detail + provenance (U26..U28)", () => {
  it("U26: opening a row shows the exact observation semantics", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () =>
          jsonResponse(
            historyPage([
              buildGeointObservation(1, {
                observation_id: OBSERVATION_A,
                entity_id: ENTITY_ID,
                evidence_id: EVIDENCE_ID,
              }),
            ]),
          ),
      ),
      geointObservationDetailHandler(
        buildGeointObservationDetail(1, {
          observation: buildGeointObservation(1, {
            observation_id: OBSERVATION_A,
            entity_id: ENTITY_ID,
            evidence_id: EVIDENCE_ID,
          }),
        }),
      ),
    );
    const table = fakeTable();
    const openSelection = vi.fn();
    renderProviders(
      <MemoryRouter>
        <EntityGeointView
          investigationId={INVESTIGATION_ID}
          table={{ ...table, selection: OBSERVATION_A, openSelection }}
        />
      </MemoryRouter>,
    );
    const drawer = await screen.findByRole("dialog", { name: "Geographic observation" });
    expect(drawer).toBeVisible();
    await within(drawer).findByText(/Seattle/);
    expect(within(drawer).getByText(/City-level context/)).toBeVisible();
    expect(
      within(drawer).getByText("Resolved through canonical reference geography"),
    ).toBeVisible();
  });

  it("U27: a scoped observation 404 renders the safe not-found", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse(historyPage([])),
      ),
      http.get(
        "*/api/v1/investigations/:id/geoint/observations/:observationId",
        () => errorResponse(404, "geoint_observation_not_found"),
      ),
    );
    const table = fakeTable();
    renderProviders(
      <MemoryRouter>
        <EntityGeointView
          investigationId={INVESTIGATION_ID}
          table={{ ...table, selection: OBSERVATION_A }}
        />
      </MemoryRouter>,
    );
    await screen.findByText("Geographic observation not found or not accessible");
  });

  it("U28: an unknown resolution method renders the raw bounded string, never a fabricated provider", async () => {
    setHttpHandlers(
      geointEntityHandler(entityBody()),
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => jsonResponse(historyPage([])),
      ),
      geointObservationDetailHandler(
        buildGeointObservationDetail(1, {
          observation: buildGeointObservation(1, {
            observation_id: OBSERVATION_A,
            entity_id: ENTITY_ID,
            resolution_method: "some_future_method_v9",
          }),
        }),
      ),
    );
    const table = fakeTable();
    renderProviders(
      <MemoryRouter>
        <EntityGeointView
          investigationId={INVESTIGATION_ID}
          table={{ ...table, selection: OBSERVATION_A }}
        />
      </MemoryRouter>,
    );
    const drawer = await screen.findByRole("dialog", { name: "Geographic observation" });
    await within(drawer).findByText(/some_future_method_v9/);
    for (const forbidden of ["DB-IP", "provider:"]) {
      expect(within(drawer).queryByText(forbidden, { exact: false })).toBeNull();
    }
  });
});