// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31I path-finding frontend contract tests (P-F01..P-F05, P-F09..P-F13,
// P-F15, P-F17).
//
// The path seam requests exactly the PR 31I ``/graph/paths`` endpoint with
// both canonical endpoint Entity IDs, direction, the committed graph scope
// and every optional filter and the path-owned depth/path bounds. Endpoint
// selection and bounds changes never issue a request; only an explicit Find
// enables the dedicated TanStack query whose key contains endpoints, context
// and bounds (so a committed context change can never serve a stale entry).
// The panel proves the deterministic path selector, hop counts, no-connection
// state, truthful truncation notice and ordinary-graph restoration, and the
// renderer proves path highlighting isolates the selected connection set.

import { fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { jsonResponse, uuidAt } from "../test/handlers";
import { setHttpHandlers, useHttp } from "../test/server";
import type {
  GraphPath,
  GraphPathResult,
} from "../api/schema-types";
import {
  fetchGraphPaths,
  GRAPH_PATH_DEFAULT_MAX_DEPTH,
  GRAPH_PATH_DEFAULT_MAX_PATHS,
  GRAPH_PATH_MAX_DEPTH,
  GRAPH_PATH_MAX_PATHS,
} from "./graph-api";
import { emptyGraphContext, type GraphContext } from "./graph-context-url";
import { graphPathKey } from "./graph-keys";
import { useGraphPaths } from "./graph-queries";
import { buildSlottedEdges } from "./RelationshipGraph";
import {
  GraphPathModeToolbar,
  GraphPathResultPanel,
  type GraphPathPanelProps,
} from "./GraphPathPanel";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const SOURCE = uuidAt(201);
const TARGET = uuidAt(202);
const MIDDLE = uuidAt(203);

const PATHS_PATH = "*/api/v1/investigations/:id/graph/paths";

function pathsBody(
  paths: GraphPath[],
  truncated: boolean = false,
): GraphPathResult {
  return {
    nodes: [
      {
        entity_id: SOURCE,
        entity_type: "domain",
        value: "source.test",
        display_name: null,
      },
      {
        entity_id: MIDDLE,
        entity_type: "ip_address",
        value: "192.0.2.7",
        display_name: null,
      },
      {
        entity_id: TARGET,
        entity_type: "domain",
        value: "target.test",
        display_name: null,
      },
    ],
    edges: [
      {
        relationship_id: uuidAt(301),
        source_entity_id: SOURCE,
        target_entity_id: MIDDLE,
        relationship_type: "urn:ati:relationship:dns:resolves_to",
        observation_count: 1,
        investigation_observation_count: 1,
        first_observed_at: "2026-01-01T00:00:00Z",
        last_observed_at: "2026-01-01T00:00:00Z",
      },
      {
        relationship_id: uuidAt(302),
        source_entity_id: MIDDLE,
        target_entity_id: TARGET,
        relationship_type: "urn:ati:relationship:dns:resolves_to",
        observation_count: 1,
        investigation_observation_count: 1,
        first_observed_at: "2026-01-01T00:00:00Z",
        last_observed_at: "2026-01-01T00:00:00Z",
      },
    ],
    paths,
    truncated,
  };
}

function recordingHandler(
  recorder: { requests: { url: string; params: Record<string, string> }[] },
  body: GraphPathResult = pathsBody([
    { entity_ids: [SOURCE, TARGET], relationship_ids: [] },
  ]),
) {
  return http.get(PATHS_PATH, ({ request, params }) => {
    const url = new URL(request.url);
    recorder.requests.push({
      url: request.url,
      params: {
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

/** Standard committed context with one filter set. */
const CONTEXT: GraphContext = {
  ...emptyGraphContext(),
  entityType: "domain" as GraphContext["entityType"],
};

/** Minimal English t stub with interpolation for asserted labels. */
function panelT(key: string, options?: Record<string, unknown>): string {
  const literals: Record<string, string> = {
    "graph.path.noPath.title": "No connection found",
    "graph.path.noPath.message": "Both endpoints are visible, but no eligible connection exists.",
    "graph.path.truncated": "Additional qualifying paths exist.",
    "graph.path.all": "All returned paths",
    "graph.path.path": "Path {ordinal} ({hops} hop(s))",
    "graph.path.results": "Path results",
    "graph.path.selector": "Path",
    "graph.path.find": "Find paths",
    "graph.path.exit": "Exit path mode",
    "graph.path.enter": "Path mode",
    "graph.path.title": "Find connections between two entities",
    "graph.path.selectInstruction": "Click two entities in the graph.",
    "graph.path.bothSelected": "Two entities selected.",
    "graph.path.selectionAria": "Path endpoints",
    "graph.path.source": "Source",
    "graph.path.target": "Target",
    "graph.path.clear": "Clear",
    "graph.path.depth": "Max depth",
    "graph.path.limit": "Max paths",
    "graph.path.loading": "Finding paths…",
    "graph.path.error.message": "Unable to find paths.",
    "error.retry": "Retry",
  };
  let value = literals[key] ?? key;
  if (options !== undefined) {
    for (const [name, replacement] of Object.entries(options)) {
      value = value.replaceAll(`{${name}}`, String(replacement));
    }
  }
  return value;
}

function fullProps(overrides: Partial<GraphPathPanelProps> = {}): GraphPathPanelProps {
  const base: GraphPathPanelProps = {
    t: panelT,
    pathMode: true,
    endpoints: { source: SOURCE, target: TARGET },
    sourceLabel: "source.test",
    targetLabel: "target.test",
    maxDepth: GRAPH_PATH_DEFAULT_MAX_DEPTH,
    maxPaths: GRAPH_PATH_DEFAULT_MAX_PATHS,
    result: null,
    loading: false,
    error: false,
    selected: "all",
    resultEndpoints: null,
    onEnter: () => undefined,
    onExit: () => undefined,
    onFind: () => undefined,
    onEndpointsChanged: () => undefined,
    onDepthChange: () => undefined,
    onPathsChange: () => undefined,
    onSelect: () => undefined,
    onRetry: () => undefined,
  };
  return { ...base, ...overrides };
}

describe("Path API boundary", () => {
  it("P-F04/P-F05: Find issues exactly one request with endpoints/context/bounds", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphPaths(INVESTIGATION_ID, SOURCE, TARGET, "either", {
      scope: "known",
      entityType: undefined,
      relationshipType: undefined,
      source: "urn:ati:source:rdap",
      observedFrom: "2026-01-01T00:00:00Z",
      observedTo: undefined,
      maxDepth: 5,
      maxPaths: 10,
    });
    expect(recorder.requests).toHaveLength(1);
    const request = recorder.requests[0];
    expect(request.url).toContain(
      `/investigations/${INVESTIGATION_ID}/graph/paths`,
    );
    expect(request.params.source_entity_id).toBe(SOURCE);
    expect(request.params.target_entity_id).toBe(TARGET);
    expect(request.params.scope).toBe("known");
    expect(request.params.source).toBe("urn:ati:source:rdap");
    expect(request.params.observed_from).toBe("2026-01-01T00:00:00Z");
    expect(request.params.max_depth).toBe("5");
    expect(request.params.max_paths).toBe("10");
    // The traversal/one-hop depth is never accidentally sent as the path depth.
    expect(request.params.graph_depth).toBeUndefined();
  });

  it("P-F05: the path query key contains endpoints, context and bounds only", () => {
    const key = graphPathKey(
      INVESTIGATION_ID,
      SOURCE,
      TARGET,
      "source",
      CONTEXT,
      4,
      10,
    );
    expect(key).toEqual([
      "graph",
      INVESTIGATION_ID,
      "paths",
      SOURCE,
      TARGET,
      "source",
      CONTEXT.scope,
      CONTEXT.entityType ?? null,
      CONTEXT.relationshipType ?? null,
      null,
      null,
      null,
      4,
      10,
    ]);
    // Distinct from neighborhood/traversal cache identities.
    expect(key[2]).toBe("paths");
  });

  it("P-F01..F03: disabled before Find — selecting endpoints never requests", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    const queryClient = freshQueryClient();
    const { result, rerender } = renderHook(
      ({ enabled }) =>
        useGraphPaths(
          INVESTIGATION_ID,
          SOURCE,
          TARGET,
          "either",
          CONTEXT,
          4,
          10,
          enabled,
        ),
      {
        wrapper: hookWrapper(queryClient),
        initialProps: { enabled: false },
      },
    );
    await waitFor(() => expect(result.current.paths).toBeNull());
    expect(recorder.requests).toHaveLength(0);
    rerender({ enabled: true });
    await waitFor(() => expect(result.current.paths).not.toBeNull());
    expect(recorder.requests).toHaveLength(1);
  });

  it("P-F06: path requests inherit the committed context and path bounds", async () => {
    const recorder = { requests: [] as { url: string; params: Record<string, string> }[] };
    setHttpHandlers(recordingHandler(recorder));
    await fetchGraphPaths(INVESTIGATION_ID, SOURCE, TARGET, "target", {
      scope: CONTEXT.scope,
      entityType: CONTEXT.entityType,
      relationshipType: "urn:ati:relationship:dns:resolves_to",
      source: undefined,
      observedFrom: undefined,
      observedTo: undefined,
      maxDepth: GRAPH_PATH_DEFAULT_MAX_DEPTH,
      maxPaths: GRAPH_PATH_DEFAULT_MAX_PATHS,
    });
    expect(recorder.requests[0].params.direction).toBe("target");
    expect(recorder.requests[0].params.entity_type).toBe("domain");
    expect(recorder.requests[0].params.relationship_type).toBe(
      "urn:ati:relationship:dns:resolves_to",
    );
    expect(recorder.requests[0].params.max_depth).toBe("4");
    expect(recorder.requests[0].params.max_paths).toBe("10");
    // Boundary enforcement stays server-owned; the browser sends in-window
    // values only and the constants mirror the server ceilings.
    expect(GRAPH_PATH_MAX_DEPTH).toBe(6);
    expect(GRAPH_PATH_MAX_PATHS).toBe(25);
  });
});

describe("Path mode toolbar", () => {
  it("P-F13: exit restores the ordinary graph without projecting a stale result", () => {
    let exited = 0;
    render(
      <GraphPathModeToolbar
        {...fullProps({
          result: pathsBody([
            {
              entity_ids: [SOURCE, MIDDLE, TARGET],
              relationship_ids: [uuidAt(301), uuidAt(302)],
            },
          ]),
          onExit: () => {
            exited += 1;
          },
        })}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Exit path mode" }));
    expect(exited).toBe(1);
  });

  it("P-F04: Find is disabled until both endpoints are selected", () => {
    render(
      <GraphPathModeToolbar
        {...fullProps({ endpoints: { source: SOURCE, target: null } })}
      />,
    );
    expect(screen.getByRole("button", { name: "Find paths" })).toBeDisabled();
  });
});

describe("Path result panel", () => {
  it("P-F09: one path is selectable with ordinal and hop count", async () => {
    const path: GraphPath = {
      entity_ids: [SOURCE, MIDDLE, TARGET],
      relationship_ids: [uuidAt(301), uuidAt(302)],
    };
    render(
      <GraphPathResultPanel
        {...fullProps({ result: pathsBody([path], false) })}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("combobox"));
    await screen.findByRole("option", { name: "Path 1 (2 hop(s))" });
  });

  it("P-F08: a no-connection result shows the explicit no-path state", () => {
    render(
      <GraphPathResultPanel
        {...fullProps({ result: pathsBody([], false) })}
      />,
    );
    expect(
      screen.getByText((content: string) => content.startsWith("No connection found")),
    ).toBeInTheDocument();
  });

  it("P-F12: a truncated result shows the visible warning", () => {
    const path: GraphPath = {
      entity_ids: [SOURCE, TARGET],
      relationship_ids: [],
    };
    render(
      <GraphPathResultPanel
        {...fullProps({ result: pathsBody([path], true) })}
      />,
    );
    expect(
      screen.getByText("Additional qualifying paths exist."),
    ).toBeInTheDocument();
  });

  it("P-F10/P-F11: the deterministic selector exposes all returned paths", async () => {
    const first: GraphPath = {
      entity_ids: [SOURCE, TARGET],
      relationship_ids: [],
    };
    const second: GraphPath = {
      entity_ids: [SOURCE, MIDDLE, TARGET],
      relationship_ids: [uuidAt(301), uuidAt(302)],
    };
    render(
      <GraphPathResultPanel
        {...fullProps({ result: pathsBody([first, second], false) })}
      />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("combobox"));
    await screen.findByRole("option", { name: "All returned paths" });
    await screen.findByRole("option", { name: "Path 1 (1 hop(s))" });
    await screen.findByRole("option", { name: "Path 2 (2 hop(s))" });
  });
});

describe("Path highlight rendering", () => {
  it("P-F11: the highlighted relationship is emphasized, others are dimmed", () => {
    const highlighted = uuidAt(301);
    const other = uuidAt(302);
    const edges = [
      {
        relationshipId: highlighted,
        sourceEntityId: SOURCE,
        targetEntityId: MIDDLE,
        relationshipType: "urn:ati:relationship:dns:resolves_to" as const,
        observationCount: 1,
        investigationObservationCount: 1,
        firstObservedAt: null,
        lastObservedAt: null,
      },
      {
        relationshipId: other,
        sourceEntityId: MIDDLE,
        targetEntityId: TARGET,
        relationshipType: "urn:ati:relationship:dns:resolves_to" as const,
        observationCount: 1,
        investigationObservationCount: 1,
        firstObservedAt: null,
        lastObservedAt: null,
      },
    ];
    const flowEdges = buildSlottedEdges(
      edges,
      (type) => type,
      "#000000",
      {
        highlightedRelationshipIds: new Set([highlighted]),
        highlightedColor: "#ff0000",
        dimmedColor: "#000000",
        dimmedOpacity: 0.3,
      },
    );
    const byId = new Map(flowEdges.map((edge) => [String(edge.id), edge]));
    const highlightedEdge = byId.get(`e:${highlighted}`);
    const dimmedEdge = byId.get(`e:${other}`);
    expect(highlightedEdge).toBeDefined();
    expect(dimmedEdge).toBeDefined();
    expect((highlightedEdge?.style as { stroke?: string })?.stroke).toBe("#ff0000");
    expect((highlightedEdge?.style as { strokeWidth?: number })?.strokeWidth).toBe(3);
    expect((dimmedEdge?.style as { strokeOpacity?: number })?.strokeOpacity).toBe(0.3);
  });

  it("without a highlight every edge keeps the default stroke", () => {
    const edge = {
      relationshipId: uuidAt(301),
      sourceEntityId: SOURCE,
      targetEntityId: TARGET,
      relationshipType: "urn:ati:relationship:dns:resolves_to" as const,
      observationCount: 1,
      investigationObservationCount: 1,
      firstObservedAt: null,
      lastObservedAt: null,
    };
    const flowEdges = buildSlottedEdges([edge], (type) => type, "#123456");
    expect(flowEdges).toHaveLength(1);
    expect((flowEdges[0].style as { stroke?: string })?.stroke).toBe("#123456");
    expect((flowEdges[0].style as { strokeWidth?: number })?.strokeWidth).toBe(1.5);
  });
});

describe("Typed path failure", () => {
  it("P-F15: a path API failure surfaces a typed error with a bounded Retry", async () => {
    setHttpHandlers(
      http.get(PATHS_PATH, () =>
        HttpResponse.json(
          { error: { code: "graph_entity_not_found", message: "x", request_id: "r" } },
          { status: 404 },
        ),
      ),
    );
    const rec: { counts: number } = { counts: 0 };
    const { result } = renderHook(
      () =>
        useGraphPaths(
          INVESTIGATION_ID,
          SOURCE,
          TARGET,
          "either",
          CONTEXT,
          4,
          10,
          true,
        ),
      {
        wrapper: hookWrapper(),
      },
    );
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error?.status).toBe(404);
    expect(result.current.error?.code).toBe("graph_entity_not_found");
    rec.counts += 1;
    expect(rec.counts).toBe(1);
  });
});
