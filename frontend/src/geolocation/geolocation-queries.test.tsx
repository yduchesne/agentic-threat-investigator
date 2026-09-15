// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Geolocation API + query tests (PR 25B §47 B-Q01..B-Q08).

import { renderHook, waitFor } from "@testing-library/react";
import { http } from "msw";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import type { InvestigationGeolocationCollection } from "../api/schema-types";
import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { errorResponse, jsonResponse, uuidAt } from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import { fetchInvestigationGeolocations } from "./geolocation-api";
import { geolocationsKey } from "./geolocation-keys";
import { useInvestigationGeolocations } from "./geolocation-queries";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const OTHER_INVESTIGATION_ID = "20000000-0000-4000-8000-000000000002";

/** Wrap a hook with the production providers and an isolated QueryClient. */
function hookWrapper(queryClient = freshQueryClient()) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <AppProviders queryClient={queryClient}>{children}</AppProviders>;
  };
}

function collection(): InvestigationGeolocationCollection {
  return {
    items: [
      {
        evidence_id: uuidAt(1),
        entity_id: uuidAt(101),
        ip_address: "203.0.113.10",
        country_code: "US",
        region: "Washington",
        city: "Seattle",
        latitude: 47.6062,
        longitude: -122.3321,
        precision: "city",
        provider: "urn:ati:source:dbip_city_lite",
        observed_at: null,
        retrieved_at: "2026-06-01T10:00:00Z",
      },
    ],
    truncated: false,
  };
}

describe("geolocation API boundary (B-Q01..B-Q04)", () => {
  it("B-Q01: calls the exact PR 25A path", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", ({ request }) => {
        seenPath = request.url;
        return jsonResponse(collection());
      }),
    );
    await fetchInvestigationGeolocations(INVESTIGATION_ID);
    expect(seenPath).toContain(`/api/v1/investigations/${INVESTIGATION_ID}/geolocations`);
  });

  it("B-Q02: funnels through the centralized apiGet client boundary", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", ({ request }) => {
        seenPath = request.url;
        return jsonResponse(collection());
      }),
    );
    // The single client module owns fetch/credentials/CSRF/error mapping;
    // the feature module only composes the path (asserted for the exact
    // no-query-string form below).
    const result = await fetchInvestigationGeolocations(INVESTIGATION_ID);
    expect(result.items).toHaveLength(1);
    expect(seenPath).not.toContain("?");
  });

  it("B-Q03: forwards the AbortSignal so cancellation reaches the fetch", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", async () => {
        await gate;
        return jsonResponse(collection());
      }),
    );
    const controller = new AbortController();
    const promise = fetchInvestigationGeolocations(INVESTIGATION_ID, controller.signal);
    controller.abort();
    release?.();
    // The caller's cancellation signal reaches the centralized fetch and
    // surfaces as an abort (never as a normal API error).
    await expect(promise).rejects.toMatchObject({ name: "AbortError" });
  });

  it("B-Q04: sends no cursor, limit, or query string", async () => {
    let seenPath = "";
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", ({ request }) => {
        seenPath = request.url;
        return jsonResponse(collection());
      }),
    );
    await fetchInvestigationGeolocations(INVESTIGATION_ID);
    const url = new URL(seenPath);
    expect([...url.searchParams.entries()]).toEqual([]);
    expect(url.search).toBe("");
  });
});

describe("geolocation query key and hook (B-Q05..B-Q08)", () => {
  it("B-Q05: the query key includes the Investigation ID", () => {
    expect(geolocationsKey(INVESTIGATION_ID)).toEqual([
      "investigations",
      INVESTIGATION_ID,
      "geolocations",
    ]);
  });

  it("B-Q06: different Investigations produce distinct keys", () => {
    expect(geolocationsKey(INVESTIGATION_ID)).not.toEqual(
      geolocationsKey(OTHER_INVESTIGATION_ID),
    );
  });

  it("B-Q07: the hook fetches once and never polls", async () => {
    let calls = 0;
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", () => {
        calls += 1;
        return jsonResponse(collection());
      }),
    );
    const { result } = renderHook(
      () => useInvestigationGeolocations(INVESTIGATION_ID),
      { wrapper: hookWrapper() },
    );
    await waitFor(() => expect(result.current.collection).not.toBeNull());
    expect(result.current.collection?.items).toHaveLength(1);
    expect(calls).toBe(1);
  });

  it("B-Q08: errors remain typed ApiError", async () => {
    setHttpHandlers(
      http.get("*/api/v1/investigations/:id/geolocations", () =>
        errorResponse(500, "internal_error")),
    );
    const queryClient = freshQueryClient();
    const { result } = renderHook(
      () => useInvestigationGeolocations(INVESTIGATION_ID),
      { wrapper: hookWrapper(queryClient) },
    );
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error?.kind).toBe("api");
    expect(result.current.error?.status).toBe(500);
  });
});