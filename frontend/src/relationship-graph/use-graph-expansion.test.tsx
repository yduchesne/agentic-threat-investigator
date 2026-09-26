// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Expansion controller tests over MSW (PR 31E, G31E-Q01..Q16).
//
// Expansion always reuses the existing PR 31C one-hop neighborhood
// endpoint with the exact selected Entity, requested direction, current
// root Relationship type and the canonical bounded limit; one explicit
// action creates at most one request; completed expansions never
// refetch; overlapping responses never duplicate canonical objects;
// failures preserve the accumulated graph and record an exact Retry; a
// second action while one expansion is in flight never starts a second
// request; a root semantic change aborts/late-results are ignored; and
// cancellation is never a semantic error. No Relationships-list fallback
// ever occurs (MSW fails unhandled requests).

import { act, renderHook, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import type { GraphNeighborhood } from "../api/schema-types";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  buildGraphEdge,
  buildGraphNode,
  errorResponse,
} from "../test/handlers";
import { GRAPH_NEIGHBORHOOD_LIMIT } from "./graph-api";
import {
  useGraphExpansion,
  type GraphExpansionController,
  type GraphExpansionInputs,
} from "./use-graph-expansion";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const OTHER_FOCAL = "40000000-0000-4000-8000-000000000201";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";
const D = "40000000-0000-4000-8000-000000000104";
const E = "40000000-0000-4000-8000-000000000105";
const CNAME = "urn:ati:relationship:dns:cname_of";

const NEIGHBORHOOD_PATH =
  "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood";

function node(entityId: string, value?: string) {
  return buildGraphNode({ entity_id: entityId, value: value ?? `value-${entityId.slice(-2)}` });
}

function edge(
  relationshipId: string,
  source: string,
  target: string,
  observationCount = 1,
) {
  return buildGraphEdge({
    relationship_id: relationshipId,
    source_entity_id: source,
    target_entity_id: target,
    observation_count: observationCount,
  });
}

/** The deterministic two-hop fake world (no live anything). */
function rootNeighborhoodFake(): GraphNeighborhood {
  return {
    nodes: [node(FOCAL, "update-package.test"), node(B, "203.0.113.10")],
    edges: [edge("e-root", FOCAL, B)],
    truncated: false,
  };
}

function expandB(): GraphNeighborhood {
  return {
    nodes: [node(B, "203.0.113.10"), node(C, "malware.test"), node(D, "198.51.100.7")],
    edges: [edge("e-b-c", B, C), edge("e-b-d", B, D)],
    truncated: false,
  };
}

function expandC(): GraphNeighborhood {
  return {
    nodes: [node(C, "malware.test"), node(E, "evil.example"), node(FOCAL, "update-package.test")],
    edges: [edge("e-c-f", C, FOCAL, 5)],
    truncated: false,
  };
}

interface RecordedRequest {
  entity: string;
  direction: string | null;
  relationshipType: string | null;
  limit: string | null;
}

function recordingHandler(
  recorder: RecordedRequest[],
  bodyFor: (entityId: string) => GraphNeighborhood,
) {
  return http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
    const url = new URL(request.url);
    recorder.push({
      entity: String(params.entityId),
      direction: url.searchParams.get("direction"),
      relationshipType: url.searchParams.get("relationship_type"),
      limit: url.searchParams.get("limit"),
    });
    return HttpResponse.json(bodyFor(String(params.entityId)));
  });
}

function baseInputs(
  overrides: Partial<GraphExpansionInputs> = {},
): GraphExpansionInputs {
  return {
    investigationId: INVESTIGATION_ID,
    rootEntityId: FOCAL,
    rootDirection: "either",
    relationshipType: undefined,
    rootNeighborhood: rootNeighborhoodFake(),
    ...overrides,
  };
}

function entityIds(graph: GraphExpansionController["graph"]): string[] | null {
  return graph === null ? null : graph.nodes.map((n) => n.entity_id);
}

/**
 * Flush promise-resolved React state updates (fetches resolving outside
 * any synchronous handler) inside ``act``. ``waitFor`` alone cannot see
 * those renders; this drain makes them observable deterministically.
 */
async function drainAct(delayMs = 30): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  });
}

describe("useGraphExpansion (PR 31E Part 4)", () => {
  it("G31E-Q01/Q02/Q03: the selected Entity and requested direction map exactly", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder[0].entity).toBe(B);
    expect(recorder[0].direction).toBe("either");
    // Incoming/outgoing map to target/source on the same selected Entity.
    act(() => {
      result.current.expand(B, "source");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    act(() => {
      result.current.expand(B, "target");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder[1].entity).toBe(B);
    expect(recorder[1].direction).toBe("source");
    expect(recorder[2].entity).toBe(B);
    expect(recorder[2].direction).toBe("target");
  });

  it("G31E-Q04/Q05: the current root Relationship type and the canonical limit are sent", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs({ relationshipType: CNAME }) } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder[0].relationshipType).toBe(CNAME);
    expect(recorder[0].limit).toBe(String(GRAPH_NEIGHBORHOOD_LIMIT));
    expect(GRAPH_NEIGHBORHOOD_LIMIT).toBe(25);
  });

  it("G31E-Q06/Q07: one action makes one request and merges once", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder).toHaveLength(1);
    expect(entityIds(result.current.graph)).toEqual([FOCAL, B, C, D]);
    expect(result.current.expanded.map((k) => k.direction)).toEqual(["either"]);
  });

  it("G31E-Q08: a completed expansion never refetches on a repeated action", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    await act(async () => {
      result.current.expand(B, "either");
    });
    expect(recorder).toHaveLength(1);
    expect(result.current.isExpanded(B, "either")).toBe(true);
    expect(entityIds(result.current.graph)).toEqual([FOCAL, B, C, D]);
  });

  it("G31E-Q09: overlapping expansions never duplicate canonical objects", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) => {
      if (entityId === B) {
        return expandB();
      }
      if (entityId === C) {
        return expandC();
      }
      return rootNeighborhoodFake();
    }));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    act(() => {
      result.current.expand(C, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    const ids = entityIds(result.current.graph) ?? [];
    expect(ids.filter((id) => id === C)).toHaveLength(1);
    expect(ids).toEqual([FOCAL, B, C, D, E]);
    // e-c-f carries a refreshed observation count (5) copied, never summed.
    expect(result.current.graph?.edges.find((e) => e.relationship_id === "e-c-f")?.observation_count).toBe(5);
    expect(result.current.graph?.edges).toHaveLength(4);
  });

  it("G31E-Q10: a failure leaves the accumulated graph unchanged and records retry", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
        const url = new URL(request.url);
        recorder.push({
          entity: String(params.entityId),
          direction: url.searchParams.get("direction"),
          relationshipType: url.searchParams.get("relationship_type"),
          limit: url.searchParams.get("limit"),
        });
        return errorResponse(500, "server_error");
      }),
    );
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    const before = entityIds(result.current.graph);
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.failed).toEqual({ entityId: B, direction: "either" });
    });
    expect(result.current.inFlight).toBeNull();
    expect(entityIds(result.current.graph)).toEqual(before);
  });

  it("G31E-Q11: Retry repeats the exact failed expansion and merges on success", async () => {
    let failNext = true;
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
        const url = new URL(request.url);
        recorder.push({
          entity: String(params.entityId),
          direction: url.searchParams.get("direction"),
          relationshipType: url.searchParams.get("relationship_type"),
          limit: url.searchParams.get("limit"),
        });
        if (failNext) {
          failNext = false;
          return errorResponse(500, "server_error");
        }
        return HttpResponse.json(expandB());
      }),
    );
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.failed).not.toBeNull();
    });
    act(() => {
      result.current.retry();
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.failed).toBeNull();
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder.map((r) => r.entity)).toEqual([B, B]);
    expect(recorder.map((r) => r.direction)).toEqual(["either", "either"]);
    expect(entityIds(result.current.graph)).toEqual([FOCAL, B, C, D]);
  });

  it("G31E-Q12: a second action while one expansion is in flight never starts a second request", async () => {
    const recorder: RecordedRequest[] = [];
    let resolveFirst!: (value: HttpResponse<GraphNeighborhood>) => void;
    const gate = new Promise<HttpResponse<GraphNeighborhood>>((resolve) => {
      resolveFirst = resolve;
    });
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
        const url = new URL(request.url);
        recorder.push({
          entity: String(params.entityId),
          direction: url.searchParams.get("direction"),
          relationshipType: url.searchParams.get("relationship_type"),
          limit: url.searchParams.get("limit"),
        });
        return gate;
      }),
    );
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await waitFor(() => {
      expect(result.current.inFlight).toEqual({ entityId: B, direction: "either" });
      expect(recorder).toHaveLength(1);
    });
    // Second explicit action while in flight: rejected, no new request.
    act(() => {
      result.current.expand(C, "either");
    });
    await drainAct();
    expect(recorder).toHaveLength(1);
    await act(async () => {
      resolveFirst(HttpResponse.json<GraphNeighborhood>(expandB()));
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(recorder).toHaveLength(1);
    expect(result.current.expanded).toHaveLength(1);
  });

  it("G31E-Q13: a root change in flight aborts and late results cannot contaminate the new root", async () => {
    let resolveFirst!: (value: HttpResponse<GraphNeighborhood>) => void;
    const gate = new Promise<HttpResponse<GraphNeighborhood>>((resolve) => {
      resolveFirst = resolve;
    });
    let aborted = false;
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
        request.signal.addEventListener("abort", () => {
          aborted = true;
        });
        if (String(params.entityId) === B) {
          return gate;
        }
        return HttpResponse.json(rootNeighborhoodFake());
      }),
    );
    const { result, rerender } = renderHook(
      ({ inputs }: { inputs: GraphExpansionInputs }) => useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await waitFor(() => {
      expect(result.current.inFlight).not.toBeNull();
    });
    // Root semantic change while the expansion is in flight.
    await act(async () => {
      rerender({
        inputs: baseInputs({
          rootEntityId: OTHER_FOCAL,
          rootNeighborhood: {
            nodes: [node(OTHER_FOCAL, "other.test"), node(C, "198.51.100.9")],
            edges: [edge("e-other", OTHER_FOCAL, C)],
            truncated: false,
          },
        }),
      });
    });
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
      expect(entityIds(result.current.graph)).toEqual([OTHER_FOCAL, C]);
    });
    expect(aborted).toBe(true);
    // Late arrival of the old expansion result: ignored entirely.
    await act(async () => {
      resolveFirst(HttpResponse.json<GraphNeighborhood>(expandB()));
    });
    await drainAct();
    expect(entityIds(result.current.graph)).toEqual([OTHER_FOCAL, C]);
    expect(result.current.expanded).toHaveLength(0);
  });

  it("G31E-Q14: cancellation (abort) is not a semantic failure and merges nothing", async () => {
    const recorder: RecordedRequest[] = [];
    let resolveFirst!: (value: HttpResponse<GraphNeighborhood>) => void;
    const gate = new Promise<HttpResponse<GraphNeighborhood>>((resolve) => {
      resolveFirst = resolve;
    });
    setHttpHandlers(
      http.get(NEIGHBORHOOD_PATH, ({ request, params }) => {
        const url = new URL(request.url);
        recorder.push({
          entity: String(params.entityId),
          direction: url.searchParams.get("direction"),
          relationshipType: url.searchParams.get("relationship_type"),
          limit: url.searchParams.get("limit"),
        });
        return gate;
      }),
    );
    const { result, unmount } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await waitFor(() => {
      expect(result.current.inFlight).not.toBeNull();
    });
    await act(async () => {
      unmount();
    });
    await act(async () => {
      resolveFirst(HttpResponse.json<GraphNeighborhood>(expandB()));
    });
    await drainAct();
    // No failure state, no merge, no extra request.
    expect(recorder).toHaveLength(1);
  });

  it("G31E-Q15: a truncated expansion records the exact truncation state", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B
        ? { ...expandB(), truncated: true }
        : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(result.current.truncated.map((k) => k.entityId)).toEqual([B]);
    expect(result.current.truncated[0].direction).toBe("either");
  });

  it("G31E-Q16: expansion never falls back to the Relationships list", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    // Only graph-neighborhood requests were recorded; any Relationships
    // or RelationshipObservations request would hit MSW's unhandled-request
    // failure mode.
    expect(recorder).toHaveLength(1);
  });

  it("G31E-I14: the initial accumulated graph opens from the root neighborhood", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, () => rootNeighborhoodFake()));
    const { result } = renderHook(({ inputs }: { inputs: GraphExpansionInputs }) =>
      useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    expect(entityIds(result.current.graph)).toEqual([FOCAL, B]);
    expect(result.current.expanded).toHaveLength(0);
    expect(recorder).toHaveLength(0);
  });

  it("G31E-I15: a root reset drops all accumulated expansion state", async () => {
    const recorder: RecordedRequest[] = [];
    setHttpHandlers(recordingHandler(recorder, (entityId) =>
      entityId === B ? expandB() : rootNeighborhoodFake()));
    const { result, rerender } = renderHook(
      ({ inputs }: { inputs: GraphExpansionInputs }) => useGraphExpansion(inputs),
      { initialProps: { inputs: baseInputs() } },
    );
    await waitFor(() => {
      expect(result.current.graph).not.toBeNull();
    });
    act(() => {
      result.current.expand(B, "either");
    });
    await drainAct();
    await waitFor(() => {
      expect(result.current.inFlight).toBeNull();
    });
    expect(result.current.expanded).toHaveLength(1);
    await act(async () => {
      rerender({
        inputs: baseInputs({
          rootDirection: "source",
          rootNeighborhood: {
            nodes: [node(FOCAL), node(D, "198.51.100.7")],
            edges: [edge("e-src", FOCAL, D)],
            truncated: false,
          },
        }),
      });
    });
    await waitFor(() => {
      expect(entityIds(result.current.graph)).toEqual([FOCAL, D]);
    });
    expect(result.current.expanded).toHaveLength(0);
    expect(result.current.truncated).toHaveLength(0);
  });
});
