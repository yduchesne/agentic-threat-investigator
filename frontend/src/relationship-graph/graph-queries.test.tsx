// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph API + query tests (PR 31D G31D-Q01..Q10).
//
// The Graph seam requests exactly the PR 31C neighborhood endpoint with
// only ``direction``, ``relationship_type`` and ``limit``; it never sends
// cursors or Evolution-only filters, propagates AbortSignal, keys off the
// semantic inputs, disables without a focal Entity, and surfaces typed
// ApiError values without falling back to the Relationships list.

import { renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { errorResponse, jsonResponse, uuidAt } from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import type { GraphNeighborhood } from "../api/schema-types";
import { fetchGraphNeighborhood, GRAPH_NEIGHBORHOOD_LIMIT } from "./graph-api";
import { graphNeighborhoodKey } from "./graph-keys";
import { useGraphNeighborhood } from "./graph-queries";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = uuidAt(101);
const CNAME = "urn:ati:relationship:dns:cname_of";

const NEIGHBORHOOD_PATH =
  "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood";

function neighborhoodBody(): GraphNeighborhood {
  return {
    nodes: [
      {
        entity_id: FOCAL,
        entity_type: "domain",
        value: "update-package.test",
        display_name: "update-package.test",
      },
    ],
    edges: [],
    truncated: false,
  };
}

/** Record every exact neighborhood request URL parameter. */
function recordingHandler(
  recorder: { requests: { url: string; params: Record<string, string> }[] },
  body: GraphNeighborhood = neighborhoodBody(),
) {
  return http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
    const url = new URL(request.url);
    recorder.requests.push({
      url: request.url,
      params: {
        entity_id: String(params.entityId),
        investigation_id: String(params.id),
        ...Object.fromEntries(url.searchParams.entries()),
      },
    });
    return jsonResponse(body);
  });
}

function hookWrapper(queryClient = freshQueryClient()) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <AppProviders queryClient={queryClient}>{children}</AppProviders>;
  };
}

describe("Graph API boundary", () => {
  it("G31D-Q01: the exact PR 31C neighborhood path is requested", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined);
    expect(recorder.requests).toHaveLength(1);
    expect(recorder.requests[0].url).toContain(
      `/investigations/${INVESTIGATION_ID}/graph/entities/${FOCAL}/neighborhood`,
    );
  });

  it("G31D-Q02/Q03: SOURCE/TARGET directions map exactly", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "source", undefined);
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "target", undefined);
    expect(recorder.requests[0].params.direction).toBe("source");
    expect(recorder.requests[1].params.direction).toBe("target");
  });

  it("G31D-Q04: relationship type arrives as the exact URN", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", CNAME);
    expect(recorder.requests[0].params.relationship_type).toBe(CNAME);
  });

  it("G31D-Q05: the request is explicitly bounded", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined, 25);
    expect(recorder.requests[0].params.limit).toBe("25");
    expect(GRAPH_NEIGHBORHOOD_LIMIT).toBe(25);
  });

  it("G31D-Q06: only graph-supported parameters are ever sent", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined);
    // Only path identity + the two graph query parameters are present.
    expect(Object.keys(recorder.requests[0].params).sort()).toEqual([
      "direction",
      "entity_id",
      "investigation_id",
      "limit",
    ]);
    await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", CNAME);
    expect(Object.keys(recorder.requests[1].params).sort()).toEqual([
      "direction",
      "entity_id",
      "investigation_id",
      "limit",
      "relationship_type",
    ]);
    // No cursor, depth, dates, source, or counterparty anywhere.
    for (const request of recorder.requests) {
      expect(request.params.cursor).toBeUndefined();
      expect(request.params.depth).toBeUndefined();
      expect(request.params.observed_from).toBeUndefined();
      expect(request.params.observed_to).toBeUndefined();
      expect(request.params.retrieved_from).toBeUndefined();
      expect(request.params.retrieved_to).toBeUndefined();
      expect(request.params.source).toBeUndefined();
      expect(request.params.counterparty_entity_id).toBeUndefined();
    }
  });

  it("G31D-Q07: AbortSignal propagates to the transport", async () => {
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, () => new Promise<never>(() => undefined)),
    );
    const controller = new AbortController();
    const pending = fetchGraphNeighborhood(
      INVESTIGATION_ID,
      FOCAL,
      "either",
      undefined,
      GRAPH_NEIGHBORHOOD_LIMIT,
      controller.signal,
    );
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  });

  it("G31D-Q10: a server failure is a typed error, never a fallback", async () => {
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, () =>
        errorResponse(404, "graph_entity_not_found")),
    );
    let captured: unknown = null;
    try {
      await fetchGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined);
    } catch (error) {
      captured = error;
    }
    expect(captured).toBeInstanceOf(Error);
    expect((captured as Error).message).toContain("graph_entity_not_found");
  });
});

describe("Graph query seam", () => {
  it("G31D-Q08: the stable key represents every semantic input", () => {
    expect(graphNeighborhoodKey(INVESTIGATION_ID, FOCAL, "source", CNAME, 25)).toEqual([
      "graph",
      INVESTIGATION_ID,
      "neighborhood",
      FOCAL,
      "source",
      CNAME,
      25,
    ]);
    // Undefined relationship type stays distinct from any concrete value.
    expect(graphNeighborhoodKey(INVESTIGATION_ID, FOCAL, "source", undefined, 25)).not.toEqual(
      graphNeighborhoodKey(INVESTIGATION_ID, FOCAL, "source", CNAME, 25),
    );
    // Direction differentiates keys.
    expect(graphNeighborhoodKey(INVESTIGATION_ID, FOCAL, "source", undefined, 25)).not.toEqual(
      graphNeighborhoodKey(INVESTIGATION_ID, FOCAL, "target", undefined, 25),
    );
  });

  it("G31D-Q09: the query is disabled without a valid focal Entity", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    const { result } = renderHook(
      () =>
        useGraphNeighborhood(
          INVESTIGATION_ID,
          undefined,
          "either",
          undefined,
          true,
        ),
      { wrapper: hookWrapper() },
    );
    expect(result.current.neighborhood).toBeNull();
    await waitFor(() => expect(recorder.requests).toHaveLength(0));
  });

  it("G31D-Q10: an active query loads the neighborhood with typed state", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    const { result } = renderHook(
      () => useGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined),
      { wrapper: hookWrapper() },
    );
    await waitFor(() => {
      expect(result.current.neighborhood?.nodes[0].entity_id).toBe(FOCAL);
    });
    expect(result.current.isError).toBe(false);
    expect(result.current.error).toBeNull();
    expect(recorder.requests[0].params.entity_id).toBe(FOCAL);
    expect(recorder.requests[0].params.investigation_id).toBe(INVESTIGATION_ID);
  });

  it("G31D-Q10b: error state exposes the typed ApiError with Retry", async () => {
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, () => HttpResponse.error()),
    );
    const { result } = renderHook(
      () => useGraphNeighborhood(INVESTIGATION_ID, FOCAL, "either", undefined),
      { wrapper: hookWrapper() },
    );
    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });
    expect(result.current.isError).toBe(true);
    expect(result.current.neighborhood).toBeNull();
    // Retry navigates the same bounded request again.
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    result.current.refetch();
    await waitFor(() => {
      expect(recorder.requests.length).toBeGreaterThan(0);
    });
    expect(recorder.requests[0].params.limit).toBe("25");
  });
});
