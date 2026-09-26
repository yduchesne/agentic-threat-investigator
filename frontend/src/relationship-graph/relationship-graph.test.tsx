// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Graph component tests over the canonical PR 31C API (31D U01..U20).
//
// The Graph workspace is a faithful, read-only client of the graph
// neighborhood endpoint: canonical Entity/Relationship identities and
// server-provided Entity metadata render without N+1 resolves or topology
// inference; edge observation summaries are copied exactly (null times stay
// unavailable); the API ``truncated`` flag drives the bounded notice; an
// isolated focal renders as success; failures offer Retry without falling
// back to the Relationships list; and functional dragging is wired through
// the controlled node-change path. The canvas itself stays a visualization
// detail (no brittle pixel/layout snapshots).

import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { http } from "msw";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildGraphEdge,
  buildGraphNeighborhood,
  buildGraphNode,
  completedInvestigationFixture,
  errorResponse,
  graphNeighborhoodHandler,
  graphNeighborhoodNetworkErrorHandler,
  investigationDetailHandler,
  jsonResponse,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { entityTypeLabelKey } from "./relationship-graph-presentation";
import { nodeId } from "./RelationshipGraph";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const C = "40000000-0000-4000-8000-000000000103";
const D = "40000000-0000-4000-8000-000000000104";
const RELATIONSHIP = "40000000-0000-4000-8000-000000000021";

function graphEntry(params = ""): string {
  const query = new URLSearchParams({
    entity_id: FOCAL,
    view: "graph",
    ...Object.fromEntries(new URLSearchParams(params)),
  });
  return (
    `/investigations/${INVESTIGATION_ID}/relationships/evolution` +
    `?${query.toString()}`
  );
}

function neighbors() {
  const focal = buildGraphNode({
    entity_id: FOCAL,
    entity_type: "domain",
    value: "update-package.test",
    display_name: "Update Package Service",
  });
  const counterparty = buildGraphNode({
    entity_id: B,
    entity_type: "ip_address",
    value: "203.0.113.10",
    display_name: "203.0.113.10",
  });
  return {
    focal,
    counterparty,
    neighborhood: buildGraphNeighborhood({
      nodes: [focal, counterparty],
      edges: [
        buildGraphEdge({
          relationship_id: RELATIONSHIP,
          source_entity_id: FOCAL,
          target_entity_id: B,
          observation_count: 3,
          first_observed_at: "2026-06-01T09:00:00Z",
          last_observed_at: "2026-06-10T09:00:00Z",
        }),
      ],
    }),
  };
}

function renderGraph(params: string = "") {
  const recorder = resourceListRecorder();
  setHttpHandlers(
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
    graphNeighborhoodHandler({ neighborhood: neighbors().neighborhood, recorder }),
  );
  renderAtPath(graphEntry(params));
  return recorder;
}

describe("Relationship Graph workspace (PR 31C API)", () => {
  it("G31D-U01/U12/U13/U14/U20: Graph uses the canonical graph endpoint with only graph-supported filters, and never re-expands", async () => {
    const recorder = renderGraph(
      "direction=source&relationship_type=urn:ati:relationship:dns:cname_of&observed_from=2026-06-01T00:00:00Z",
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    await waitFor(() => {
      expect(recorder.requests.length).toBeGreaterThan(0);
    });
    const last = recorder.requests.at(-1);
    // Exact PR 31C path (path params recorded in params.entity_id).
    expect(last?.params.entity_id).toBe(FOCAL);
    expect(last?.params.direction).toBe("source");
    expect(last?.params.relationship_type).toBe("urn:ati:relationship:dns:cname_of");
    expect(last?.params.limit).toBe("25");
    // Evolution-only filters are never sent.
    expect(last?.params.observed_from).toBeUndefined();
    // No cursor, no Relationships-list fallback request.
    expect(last?.cursor).toBeNull();
    // The screenshot copy honestly states which filters apply to Graph.
    expect(
      screen.getByText(/counterparty filters apply only to Evolution/i),
    ).toBeInTheDocument();
    // Selection must not trigger a second neighborhood request.
    const initialRequestCount = recorder.requests.length;
    const focalNode = document.querySelector(`[data-testid="rf__node-${nodeId(FOCAL)}"]`);
    expect(focalNode).not.toBeNull();
    fireEvent.click(focalNode as Element);
    expect(
      await screen.findByText("Entity: Update Package Service"),
    ).toBeInTheDocument();
    expect(recorder.requests.length).toBe(initialRequestCount);
  });

  it("G31D-U02: node shows the server label, value and entity-type cue", async () => {
    renderGraph();
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    // Entity-aware presentation: value/display name in the list, exact
    // identity via CompactId.
    expect(within(list).getByText("Update Package Service")).toBeInTheDocument();
    expect(within(list).getByText("203.0.113.10")).toBeInTheDocument();
    // The canvas renders each label plus a visible non-color type cue.
    const canvas = screen.getByRole("group", { name: "Relationship graph (one-hop)" });
    expect(
      await within(canvas).findByText("Update Package Service"),
    ).toBeInTheDocument();
    expect(within(canvas).getByText("203.0.113.10")).toBeInTheDocument();
    expect(within(canvas).getByText("Domain")).toBeInTheDocument();
    expect(within(canvas).getByText("IP address")).toBeInTheDocument();
  });

  it("G31D-U03: entity types are differentiated with exact text (non-color cue)", () => {
    expect(entityTypeLabelKey("ip_address")).toBe("graph.entityTypes.ip_address");
    expect(entityTypeLabelKey("domain")).toBe("graph.entityTypes.domain");
    // Unknown values fail safely to the raw value (no false semantic).
    expect(entityTypeLabelKey("future_type" as never)).toBe("future_type");
  });

  it("G31D-U04/E-U09: the accessible edge list is always present with canonical navigation", async () => {
    renderGraph();
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    expect(within(list).getByText("Resolves to")).toBeInTheDocument();
    expect(within(list).getByText("3")).toBeInTheDocument();
    expect(
      within(list).getByRole("link", { name: "View" }),
    ).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/relationships?selected=${RELATIONSHIP}`,
    );
    expect(screen.getByRole("link", { name: "Open Relationships table for focal entity" }))
      .toHaveAttribute(
        "href",
        `/investigations/${INVESTIGATION_ID}/relationships?entity_id=${FOCAL}`,
      );
  });

  it("G31D-U05: selecting a node exposes canonical ID, type, value and display name", async () => {
    renderGraph();
    const focalNode = await screen.findByTestId(`rf__node-${nodeId(FOCAL)}`);
    // Canvas clicks are plain click events (no pointer drag), so d3-drag is
    // never engaged in jsdom.
    fireEvent.click(focalNode);
    const panel = await screen.findByText("Entity: Update Package Service");
    // The heading lives directly inside the selection panel box; scope
    // assertions to that box (never the outer graph container).
    const scope = panel.parentElement as HTMLElement;
    expect(within(scope).getByText("Entity ID")).toBeInTheDocument();
    expect(within(scope).getByText("Domain")).toBeInTheDocument();
    expect(within(scope).getByText("update-package.test")).toBeInTheDocument();
    expect(within(scope).getByText("Update Package Service")).toBeInTheDocument();
  });

  it("G31D-U06: edge data exposes identity, endpoints, count and observed summary", async () => {
    renderGraph();
    // jsdom cannot render React Flow edges (node measurement needs a real
    // layout engine), so canvas edge selection is exercised on the real
    // stack (G31D-E04). The same canonical summary that the canvas
    // selection panel renders is always available through the non-spatial
    // list.
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    const row = within(list).getByRole("row", { name: /Resolves to/ });
    expect(within(row).getByText("Update Package Service")).toBeInTheDocument();
    expect(within(row).getByText("203.0.113.10")).toBeInTheDocument();
    expect(within(row).getByText("3")).toBeInTheDocument();
    expect(within(row).getByTitle("2026-06-01T09:00:00Z")).toBeInTheDocument();
    expect(within(row).getByTitle("2026-06-10T09:00:00Z")).toBeInTheDocument();
    // Exact canonical identity access stays available.
    expect(within(row).getByRole("link", { name: "View" })).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/relationships?selected=${RELATIONSHIP}`,
    );
  });

  it("G31D-U07: null observed times render unavailable (never substituted)", async () => {
    const { neighborhood } = neighbors();
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      graphNeighborhoodHandler({
        neighborhood: {
          ...neighborhood,
          edges: [
            buildGraphEdge({
              relationship_id: RELATIONSHIP,
              source_entity_id: FOCAL,
              target_entity_id: B,
              first_observed_at: null,
              last_observed_at: null,
            }),
          ],
        },
        recorder,
      }),
    );
    renderAtPath(graphEntry());
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    expect(within(list).getAllByText("Unavailable")).toHaveLength(2);
    // No retrieved-time substitution anywhere in the loaded edge data.
    expect(within(list).queryByTitle(/retrieved/)).not.toBeInTheDocument();
  });

  it("G31D-U08: truncated=true shows the bounded-neighborhood notice", async () => {
    const { neighborhood } = neighbors();
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      graphNeighborhoodHandler({
        neighborhood: { ...neighborhood, truncated: true },
        recorder,
      }),
    );
    renderAtPath(graphEntry());
    expect(
      await screen.findByText(/Bounded neighborhood; additional relationships exist/),
    ).toBeInTheDocument();
  });

  it("G31D-U09: an isolated focal renders the focal node and an honest empty state", async () => {
    const { focal } = neighbors();
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood({ nodes: [focal], edges: [], truncated: false }),
        recorder,
      }),
    );
    renderAtPath(graphEntry());
    expect(
      await screen.findByText(/No stable relationships are known for this entity/),
    ).toBeInTheDocument();
    const focalNode = document.querySelector(`[data-testid="rf__node-${nodeId(FOCAL)}"]`);
    expect(focalNode).not.toBeNull();
  });

  it("G31D-U15: initial loading shows an explicit loading state", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      // A pending-until-abort handler keeps the query in-flight so the
      // explicit loading state is observable; cancellation stays clean.
      pendingGraphNeighborhoodHandler,
    );
    renderAtPath(graphEntry());
    expect(
      await screen.findByText("Loading the relationship graph…"),
    ).toBeInTheDocument();
    void recorder;
  });

  it("G31D-U16: a graph failure shows a typed Retry state with no Relationships fallback", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      graphNeighborhoodNetworkErrorHandler,
    );
    renderAtPath(graphEntry());
    expect(await screen.findByRole("alert")).toHaveTextContent(/Unable to load the relationship graph/);
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    // No graph data and no /relationships fallback request.
    expect(
      screen.queryByRole("table", { name: "Relationship list (this page)" }),
    ).not.toBeInTheDocument();
    void recorder;
  });

  it("G31D-U17: pane click clears the node selection", async () => {
    renderGraph();
    const focalNode = await screen.findByTestId(`rf__node-${nodeId(FOCAL)}`);
    fireEvent.click(focalNode);
    expect(
      await screen.findByText("Entity: Update Package Service"),
    ).toBeInTheDocument();
    const pane = document.querySelector(".react-flow__pane");
    expect(pane).not.toBeNull();
    fireEvent.click(pane as Element);
    await waitFor(() => {
      expect(
        screen.queryByText("Entity: Update Package Service"),
      ).not.toBeInTheDocument();
    });
  });

  it("G31D-U18: nodes are draggable through the controlled node-change path", async () => {
    renderGraph();
    const selector = `[data-testid="rf__node-${nodeId(FOCAL)}"]`;
    const nodeEl = await screen.findByTestId(`rf__node-${nodeId(FOCAL)}`);
    // Wired draggable behavior (nodesDraggable enabled).
    expect(nodeEl.classList.contains("draggable")).toBe(true);
    // Deterministic initial position.
    expect(nodeEl.style.transform).toContain("translate");
    // The controlled node-change path receives React Flow changes: clicking
    // the node fires a SELECT change through onNodesChange, and the applied
    // state round-trips into the rendered node. jsdom cannot run the real
    // pointer drag, so position retention is covered by the real-browser
    // drag smoke (G31D-E09).
    fireEvent.click(nodeEl);
    await waitFor(() => {
      expect(
        (document.querySelector(selector) as HTMLElement).classList.contains("selected"),
      ).toBe(true);
    });
  });
});

/**
 * Pending-until-abort graph handler.
 *
 * Holds the request in-flight for the loading-state test and rejects with
 * an AbortError on cancellation so the Query client treats it as
 * abandonment, never as a semantic graph failure.
 */
const pendingGraphNeighborhoodHandler = http.get(
  "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood",
  ({ request }) =>
    new Promise<never>((_resolve, reject) => {
      request.signal.addEventListener("abort", () =>
        reject(new DOMException("Aborted", "AbortError")),
      );
    }),
);

// PR 31E component tests (G31E-U01..U25): analyst-driven incremental
// expansion through the existing selected-node PivotMenu. Expansion reuses
// the same PR 31C one-hop endpoint, merges by canonical identity, preserves
// existing topology/positions, places only new nodes near the expanded
// anchor, tracks failure/retry and truncation, and never mutates the pivot
// URL. The deterministic fake world here guarantees second-hop growth.

/** The deterministic expansion fixture world for the graph component. */
function expansionNeighbors() {
  const focal = buildGraphNode({
    entity_id: FOCAL,
    entity_type: "domain",
    value: "update-package.test",
    display_name: "Update Package Service",
  });
  const b = buildGraphNode({
    entity_id: B,
    entity_type: "ip_address",
    value: "203.0.113.10",
    display_name: "203.0.113.10",
  });
  const root = buildGraphNeighborhood({
    nodes: [focal, b],
    edges: [
      buildGraphEdge({
        relationship_id: RELATIONSHIP,
        source_entity_id: FOCAL,
        target_entity_id: B,
        observation_count: 3,
      }),
    ],
  });
  const bHop = buildGraphNeighborhood({
    nodes: [
      b,
      buildGraphNode({
        entity_id: C,
        entity_type: "malware",
        value: "malware.test",
        display_name: "malware.test",
      }),
      buildGraphNode({
        entity_id: D,
        entity_type: "ip_address",
        value: "198.51.100.7",
        display_name: "198.51.100.7",
      }),
    ],
    edges: [
      buildGraphEdge({
        relationship_id: uuidAt(31),
        source_entity_id: B,
        target_entity_id: C,
        observation_count: 1,
      }),
      buildGraphEdge({
        relationship_id: uuidAt(32),
        source_entity_id: B,
        target_entity_id: D,
        observation_count: 2,
      }),
    ],
  });
  return { root, bHop, b };
}

interface ExpansionRecord {
  entity: string;
  direction: string | null;
  relationshipType: string | null;
  limit: string | null;
}

function renderExpansionGraph(
  handler: (
    recorder: ExpansionRecord[],
    params: { entity: string },
  ) => ReturnType<typeof jsonResponse> | Promise<ReturnType<typeof jsonResponse>>,
  params = "",
) {
  const recorder: ExpansionRecord[] = [];
  setHttpHandlers(
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
    http.get(
      "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood",
      ({ request, params: pathParams }) => {
        const url = new URL(request.url);
        const entity = String(pathParams.entityId);
        recorder.push({
          entity,
          direction: url.searchParams.get("direction"),
          relationshipType: url.searchParams.get("relationship_type"),
          limit: url.searchParams.get("limit"),
        });
        return handler(recorder, { entity });
      },
    ),
  );
  const rendered = renderAtPath(graphEntry(params));
  return { ...rendered, recorder };
}

function renderedNodeCount(): number {
  return document.querySelectorAll('[data-testid^="rf__node-"]').length;
}

function selectNode(entity: string): void {
  const node = document.querySelector(`[data-testid="rf__node-${nodeId(entity)}"]`);
  expect(node).not.toBeNull();
  fireEvent.click(node as Element);
}

/** Open the selected-node pivot menu by its accessible trigger name. */
async function userEventClickMenu(name: string): Promise<void> {
  const trigger = screen.getByRole("button", { name });
  fireEvent.click(trigger);
}

/** Flush a promise-resolved state update inside ``act``. */
function actAsync<T>(fn: () => Promise<T> | T): Promise<void> {
  return act(async () => {
    await Promise.resolve(fn());
  });
}

/** Parse the current RF node transform into view coordinates. */
function nodePosition(entity: string): { x: number; y: number } {
  const node = document.querySelector(`[data-testid="rf__node-${nodeId(entity)}"]`);
  expect(node).not.toBeNull();
  const transform = (node as HTMLElement).style.transform;
  const match = /translate\((-?[0-9.e+-]+)px,\s*(-?[0-9.e+-]+)px\)/.exec(transform);
  if (match === null) {
    return { x: 0, y: 0 };
  }
  return { x: Number(match[1]), y: Number(match[2]) };
}

describe("Relationship Graph expansion (PR 31E)", () => {
  it("G31E-U01/U02/U05/U06/U09: selecting a node exposes three expansion actions and expansion grows the graph by canonical merge", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    await waitFor(() => {
      expect(rendered.recorder.length).toBeGreaterThan(0);
    });
    // Select the non-focal counterparty (canonical B) -> detail + menu.
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    // No selection-time expansion request.
    const selectionRequestCount = rendered.recorder.length;
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    await screen.findByRole("menuitem", { name: "Expand known relationships" });
    expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Expand incoming relationships" })).toBeInTheDocument();
    // Existing navigation pivots remain (U20).
    expect(screen.getByRole("menuitem", { name: "Evidence for this entity" })).toBeInTheDocument();
    // Fire the local expansion action (U02: selected canonical B, either).
    fireEvent.click(screen.getByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(rendered.recorder.length).toBe(selectionRequestCount + 1);
    });
    const request = rendered.recorder[rendered.recorder.length - 1];
    expect(request.entity).toBe(B);
    expect(request.direction).toBe("either");
    expect(request.limit).toBe("25");
    // Accumulated topology: new nodes/edges render, originals remain once.
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    expect(document.querySelector(`[data-testid="rf__node-${nodeId(FOCAL)}"]`)).not.toBeNull();
    expect(document.querySelector(`[data-testid="rf__node-${nodeId(B)}"]`)).not.toBeNull();
    // Accessible list now includes the accumulated edges (3 rows + header).
    await waitFor(() => {
      expect(within(list).getByText("malware.test")).toBeInTheDocument();
      expect(within(list).getByText("198.51.100.7")).toBeInTheDocument();
    });
    expect(within(list).getAllByRole("row")).toHaveLength(4);
  });

  it("G31E-U03/U04: outgoing/incoming expansion map to source/target on the selected Entity", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand outgoing relationships" }));
    await waitFor(() => {
      expect(rendered.recorder.some((r) => r.entity === B && r.direction === "source")).toBe(true);
    });
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand incoming relationships" }));
    await waitFor(() => {
      expect(rendered.recorder.some((r) => r.entity === B && r.direction === "target")).toBe(true);
    });
  });

  it("G31E-U07/U25: expansion preserves existing edges exactly once and never auto-expands returned nodes", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    // One canonical Relationship stays one row: 3 edges total, originals once.
    await waitFor(() => {
      expect(within(list).getAllByRole("row")).toHaveLength(4);
    });
    expect(within(list).getByText("3")).toBeInTheDocument();
    // Exactly one explicit expansion request; returned nodes are not expanded.
    const expansionRequests = () =>
      rendered.recorder.filter((r) => r.entity === B && r.direction === "either");
    expect(expansionRequests()).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(expansionRequests()).toHaveLength(1);
  });

  it("G31E-U10/U11/U12: existing node positions survive expansion; only new nodes move near the anchor", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    const focalBefore = nodePosition(FOCAL);
    const bBefore = nodePosition(B);
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    // Existing nodes keep their exact positions (dragged or not).
    expect(nodePosition(FOCAL)).toEqual(focalBefore);
    expect(nodePosition(B)).toEqual(bBefore);
    // The new node lands deterministically near the expanded anchor (B),
    // not at the focal (which sits at the origin of the radial layout).
    const cPos = nodePosition(C);
    const distanceToAnchor = Math.hypot(cPos.x - bBefore.x, cPos.y - bBefore.y);
    const distanceToFocal = Math.hypot(cPos.x - focalBefore.x, cPos.y - focalBefore.y);
    expect(distanceToAnchor).toBeLessThanOrEqual(160);
    expect(distanceToAnchor).toBeLessThan(distanceToFocal);
    expect(rendered.recorder.filter((r) => r.entity === B && r.direction === "either")).toHaveLength(1);
  });

  it("G31E-U13: a completed expansion is disabled/marked in the menu without a normal refetch", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    // Re-open the menu on the same node: the exact expansion is disabled.
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    const completed = await screen.findByRole("menuitem", { name: "Expand known relationships" });
    expect(completed).toBeDisabled();
    // The other directions remain legal.
    expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).not.toBeDisabled();
    expect(screen.getByRole("menuitem", { name: "Expand incoming relationships" })).not.toBeDisabled();
    fireEvent.click(completed);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(rendered.recorder.filter((r) => r.entity === B && r.direction === "either")).toHaveLength(1);
  });

  it("G31E-U14/U16: expansion actions are disabled while in flight; a failed expansion keeps the graph and Retry merges", async () => {
    const { root, bHop } = expansionNeighbors();
    let release!: (value: ReturnType<typeof jsonResponse>) => void;
    const gate = new Promise<ReturnType<typeof jsonResponse>>((resolve) => {
      release = resolve;
    });
    renderExpansionGraph((_recorder, { entity }) => {
      if (entity === B) {
        return gate;
      }
      return jsonResponse(root);
    });
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    // In-flight: status shown and the three expansion actions are disabled.
    await screen.findByText(/Expanding known relationships/);
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    await waitFor(() => {
      expect(screen.getByRole("menuitem", { name: "Expand known relationships" })).toBeDisabled();
      expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).toBeDisabled();
      expect(screen.getByRole("menuitem", { name: "Expand incoming relationships" })).toBeDisabled();
    });
    // Release the gate: the expansion succeeds and merges.
    await actAsync(() => release(jsonResponse(bHop)));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    expect(within(list).getByText("malware.test")).toBeInTheDocument();
  });

  it("G31E-U15: a failed expansion leaves the graph intact and offers Retry", async () => {
    const { root, bHop } = expansionNeighbors();
    let failNext = true;
    const rendered = renderExpansionGraph((_recorder, { entity }) => {
      if (entity === B) {
        if (failNext) {
          failNext = false;
          return errorResponse(500, "server_error");
        }
        return jsonResponse(bHop);
      }
      return jsonResponse(root);
    });
    const list = await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    const nodeCountBefore = renderedNodeCount();
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    expect(await screen.findByText(/Unable to expand known relationships/)).toBeInTheDocument();
    expect(renderedNodeCount()).toBe(nodeCountBefore);
    // Retry repeats the exact expansion and merges on success (U16).
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    expect(within(list).getByText("malware.test")).toBeInTheDocument();
    expect(rendered.recorder.filter((r) => r.entity === B && r.direction === "either")).toHaveLength(2);
  });

  it("G31E-U17: a truncated expansion shows a bounded notice tied to the expanded Entity", async () => {
    const { root, bHop } = expansionNeighbors();
    const truncatedHop = { ...bHop, truncated: true };
    renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? truncatedHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    expect(
      await screen.findByText(/Additional known relationships exist for 203.0.113.10/),
    ).toBeInTheDocument();
  });

  it("G31E-U18/U19: a new root graph context renders only its own root topology", async () => {
    const { root, bHop } = expansionNeighbors();
    const otherFocal = uuidAt(201);
    const otherRoot = buildGraphNeighborhood({
      nodes: [
        buildGraphNode({
          entity_id: otherFocal,
          entity_type: "domain",
          value: "other.test",
          display_name: "other.test",
        }),
        buildGraphNode({
          entity_id: uuidAt(202),
          entity_type: "ip_address",
          value: "192.0.2.55",
          display_name: "192.0.2.55",
        }),
      ],
      edges: [
        buildGraphEdge({
          relationship_id: uuidAt(41),
          source_entity_id: otherFocal,
          target_entity_id: uuidAt(202),
        }),
      ],
    });
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    // A different root focal is a different graph context: no accumulation.
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      http.get(
        "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood",
        () => jsonResponse(otherRoot),
      ),
    );
    rendered.result.unmount();
    renderAtPath(graphEntry(`entity_id=${otherFocal}`));
    // The label appears in the canvas and in the accessible list rows.
    expect((await screen.findAllByText("other.test")).length).toBeGreaterThan(0);
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(2);
    });
    expect(screen.queryByText("malware.test")).toBeNull();
  });

  it("G31E-U21: local expansion never mutates the pivot URL", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    const searchBefore = new URLSearchParams(rendered.router.state.location.search);
    expect(searchBefore.has("pivot")).toBe(false);
    await userEventClickMenu("Pivot actions for 203.0.113.10");
    fireEvent.click(await screen.findByRole("menuitem", { name: "Expand known relationships" }));
    await waitFor(() => {
      expect(renderedNodeCount()).toBe(4);
    });
    const searchAfter = new URLSearchParams(rendered.router.state.location.search);
    expect(searchAfter.has("pivot")).toBe(false);
    expect(searchAfter.toString()).toBe(searchBefore.toString());
  });

  it("G31E-U23/U24: node or edge selection alone never triggers an expansion request", async () => {
    const { root, bHop } = expansionNeighbors();
    const rendered = renderExpansionGraph((_recorder, { entity }) =>
      jsonResponse(entity === B ? bHop : root));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    await waitFor(() => {
      expect(rendered.recorder.length).toBeGreaterThan(0);
    });
    const rootRequestCount = rendered.recorder.length;
    // Node selection only (U24).
    selectNode(B);
    await screen.findByText("Entity: 203.0.113.10");
    // Edge selection only (U23): the accessible row links are not the edge
    // canvas; select via pane interactions is covered by the canvas; here we
    // assert no request fires from selection at all.
    fireEvent.click(screen.getByRole("table", { name: "Relationship list (this page)" }));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(rendered.recorder.length).toBe(rootRequestCount);
  });
});
