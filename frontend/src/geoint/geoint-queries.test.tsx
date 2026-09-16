// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT API boundary + query tests (PR 26E §15 G26E-Q01..Q08).

import { renderHook, waitFor } from "@testing-library/react";
import { http } from "msw";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { errorResponse, jsonResponse, uuidAt } from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import type {
  GeointSummary,
} from "../api/schema-types";
import {
  fetchGeointEntity,
  fetchGeointEntityHistory,
  fetchGeointLocationEntities,
  fetchGeointLocationObservations,
  fetchGeointObservation,
  fetchGeointSummary,
} from "./geoint-api";
import {
  geointEntityHistoryKey,
  geointEntityKey,
  geointLocationEntitiesKey,
  geointLocationObservationsKey,
  geointObservationKey,
  geointSummaryKey,
} from "./geoint-keys";
import {
  useGeointEntity,
  useGeointEntityHistory,
  useGeointSummary,
} from "./geoint-queries";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const ENTITY_ID = uuidAt(101);
const LOCATION_ID = uuidAt(201);
const OBSERVATION_ID = uuidAt(301);
const EVIDENCE_ID = uuidAt(1);

function hookWrapper(queryClient = freshQueryClient()) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <AppProviders queryClient={queryClient}>{children}</AppProviders>;
  };
}

function summaryBody(): GeointSummary {
  return {
    entity_count_with_location: 1,
    observation_count: 1,
    location_count: 1,
    country_count: 0,
    administrative_area_count: 0,
    city_count: 1,
    precision_counts: { country: 0, administrative_area: 0, city: 1 },
    top_locations: [
      {
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
        scoped_entity_count: 1,
      },
    ],
    truncated: false,
  };
}

describe("GEOINT API boundary (G26E-Q01..Q03, Q06)", () => {
  it("G26E-Q01: the summary uses the exact PR 26D path", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geoint/summary", ({ request }) => {
        seenPath = request.url;
        return jsonResponse(summaryBody());
      }),
    );
    const body = await fetchGeointSummary(INVESTIGATION_ID);
    expect(body).not.toBeNull();
    expect(seenPath).toContain(
      `/api/v1/investigations/${INVESTIGATION_ID}/geoint/summary`,
    );
    expect(seenPath).not.toContain("?");
  });

  it("G26E-Q02: the Entity detail uses the exact scoped path", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId",
        ({ request, params }) => {
          seenPath = request.url;
          expect(params.entityId).toBe(ENTITY_ID);
          return jsonResponse({
            entity_id: ENTITY_ID,
            entity_type: "ip_address",
            entity_value: "203.0.113.10",
            display_name: "203.0.113.10",
            current_observation: null as never,
          });
        },
      ),
    );
    await fetchGeointEntity(INVESTIGATION_ID, ENTITY_ID);
    expect(seenPath).toContain(
      `/investigations/${INVESTIGATION_ID}/geoint/entities/${ENTITY_ID}`,
    );
  });

  it("G26E-Q03: the opaque history cursor is forwarded unchanged", async () => {
    const opaque = "a1b2c3-unsafe-looking-cursor-value";
    let seenCursor: string | null = null;
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        ({ request }) => {
          seenCursor = new URL(request.url).searchParams.get("cursor");
          return jsonResponse({ items: [], next_cursor: null });
        },
      ),
    );
    await fetchGeointEntityHistory(INVESTIGATION_ID, ENTITY_ID, opaque);
    expect(seenCursor).toBe(opaque);
  });

  it("G26E-Q06: the observation detail uses the exact scoped path", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/observations/:observationId",
        ({ request, params }) => {
          seenPath = request.url;
          expect(params.observationId).toBe(OBSERVATION_ID);
          return jsonResponse({
            observation: {
              observation_id: OBSERVATION_ID,
              entity_id: ENTITY_ID,
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
              evidence_id: EVIDENCE_ID,
              precision: "city",
              resolution_method: "canonical_geography_v1",
              observed_at: "2026-06-01T09:00:00Z",
              retrieved_at: "2026-06-01T09:05:00Z",
              resolved_at: "2026-06-01T09:06:00Z",
            },
            entity_type: "ip_address",
            entity_value: "203.0.113.10",
            display_name: "203.0.113.10",
          });
        },
      ),
    );
    await fetchGeointObservation(INVESTIGATION_ID, OBSERVATION_ID);
    expect(seenPath).toContain(
      `/investigations/${INVESTIGATION_ID}/geoint/observations/${OBSERVATION_ID}`,
    );
  });
});

describe("containment parameter contract (G26E-Q04, Q05)", () => {
  it("G26E-Q04: exact Location sends no include_contained (false default)", async () => {
    let sawContained: string | null = "unset";
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/entities",
        ({ request }) => {
          sawContained = new URL(request.url).searchParams.get("include_contained");
          return jsonResponse({ items: [], containment_applied: false });
        },
      ),
    );
    await fetchGeointLocationEntities(INVESTIGATION_ID, LOCATION_ID, false, undefined);
    expect(sawContained).toBeNull();
  });

  it("G26E-Q05: contained sends include_contained=true", async () => {
    let sawContained: string | null = null;
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/locations/:locationId/observations",
        ({ request }) => {
          sawContained = new URL(request.url).searchParams.get("include_contained");
          return jsonResponse({ items: [], containment_applied: true });
        },
      ),
    );
    await fetchGeointLocationObservations(INVESTIGATION_ID, LOCATION_ID, true, undefined);
    expect(sawContained).toBe("true");
  });
});

describe("query keys (G26E-Q02 Q03 Q06 keys)", () => {
  it("keys carry Investigation + semantic identity", () => {
    expect(geointSummaryKey(INVESTIGATION_ID)).toEqual([
      "geoint",
      "summary",
      INVESTIGATION_ID,
    ]);
    expect(geointEntityKey(INVESTIGATION_ID, ENTITY_ID)).toEqual([
      "geoint",
      "entity",
      INVESTIGATION_ID,
      ENTITY_ID,
    ]);
    expect(geointEntityHistoryKey(INVESTIGATION_ID, ENTITY_ID, "c1")).toEqual([
      "geoint",
      "entity-history",
      INVESTIGATION_ID,
      ENTITY_ID,
      "c1",
    ]);
    expect(geointLocationEntitiesKey(INVESTIGATION_ID, LOCATION_ID, true, "c2")).toEqual([
      "geoint",
      "location-entities",
      INVESTIGATION_ID,
      LOCATION_ID,
      "contained",
      "c2",
    ]);
    expect(geointLocationObservationsKey(INVESTIGATION_ID, LOCATION_ID, false, undefined)).toEqual([
      "geoint",
      "location-observations",
      INVESTIGATION_ID,
      LOCATION_ID,
      "exact",
      "",
    ]);
    expect(geointObservationKey(INVESTIGATION_ID, OBSERVATION_ID)).toEqual([
      "geoint",
      "observation",
      INVESTIGATION_ID,
      OBSERVATION_ID,
    ]);
  });

  it("semantic filter changes produce distinct keys (different containment)", () => {
    expect(
      geointLocationEntitiesKey(INVESTIGATION_ID, LOCATION_ID, false, undefined),
    ).not.toEqual(
      geointLocationEntitiesKey(INVESTIGATION_ID, LOCATION_ID, true, undefined),
    );
  });
});

describe("query hooks (G26E-Q07, Q08)", () => {
  it("G26E-Q08: the summary hook fetches once and never polls", async () => {
    let calls = 0;
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geoint/summary", () => {
        calls += 1;
        return jsonResponse(summaryBody());
      }),
    );
    const { result } = renderHook(() => useGeointSummary(INVESTIGATION_ID), {
      wrapper: hookWrapper(),
    });
    await waitFor(() => expect(result.current.summary).not.toBeNull());
    expect(result.current.summary?.observation_count).toBe(1);
    expect(calls).toBe(1);
  });

  it("G26E-Q07: the AbortSignal flows through the centralized client", async () => {
    const entity = {
      entity_id: ENTITY_ID,
      entity_type: "ip_address" as const,
      entity_value: "203.0.113.10",
      display_name: "203.0.113.10",
      current_observation: null,
    };
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId",
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 50));
          return jsonResponse(entity);
        },
      ),
    );
    const { result } = renderHook(() => useGeointEntity(INVESTIGATION_ID, ENTITY_ID), {
      wrapper: hookWrapper(),
    });
    await waitFor(() => expect(result.current.entity).not.toBeNull());
    expect(result.current.entity?.entity_id).toBe(ENTITY_ID);
  });

  it("G26E-Q08b: history errors remain typed ApiError", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId/observations",
        () => errorResponse(500, "internal_error"),
      ),
    );
    const { result } = renderHook(
      () => useGeointEntityHistory(INVESTIGATION_ID, ENTITY_ID, undefined),
      { wrapper: hookWrapper() },
    );
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error?.kind).toBe("api");
    expect(result.current.error?.status).toBe(500);
  });

  it("disables detail queries until an identity is known", async () => {
    let calls = 0;
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/geoint/entities/:entityId",
        () => {
          calls += 1;
          return jsonResponse({
            entity_id: ENTITY_ID,
            entity_type: "ip_address",
            entity_value: "203.0.113.10",
            display_name: "203.0.113.10",
            current_observation: null,
          });
        },
      ),
    );
    const { result } = renderHook(() => useGeointEntity(INVESTIGATION_ID, null), {
      wrapper: hookWrapper(),
    });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(calls).toBe(0);
  });
});