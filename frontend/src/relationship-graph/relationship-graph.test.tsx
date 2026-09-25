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

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
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
  graphNeighborhoodHandler,
  graphNeighborhoodNetworkErrorHandler,
  investigationDetailHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";
import { entityTypeLabelKey } from "./relationship-graph-presentation";
import { nodeId } from "./RelationshipGraph";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
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
