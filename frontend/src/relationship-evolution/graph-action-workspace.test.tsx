// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31K graph-driven investigation action workspace tests (K-FE01..K-FE20).
//
// The Graph workspace derives a transient action selection from ONE
// canonical graph Entity clicked while path mode is OFF; the selection is
// browser-local (never URL-backed), path mode keeps click precedence, the
// committed graph context (including temporal frames) clears a stale
// selection deterministically, and submission reuses the existing
// Investigation create command / navigation rather than any graph-specific
// execution path. No optimistic graph data is ever inserted.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { CSRF_COOKIE_NAME } from "../api/csrf";
import {
  assessmentCurrentHandler,
  authMeSuccess,
  buildAssessment,
  buildGraphNeighborhood,
  buildReport,
  completedInvestigationFixture,
  createInvestigationHandler,
  graphNeighborhoodHandler,
  investigationDetailHandler,
  investigationsListHandler,
  reportCurrentHandler,
  resolveSupportPresentationsHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import { nodeId } from "../relationship-graph/RelationshipGraph";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const COUNTERPARTY = "40000000-0000-4000-8000-000000000102";
const EVOLUTION_BASE = `/investigations/${INVESTIGATION_ID}/relationships/evolution`;
const GRAPH_VIEW = (params: string) =>
  `${EVOLUTION_BASE}?entity_id=${FOCAL}&view=graph${params === "" ? "" : `&${params}`}`;
const NEW_INVESTIGATION_ID = "60000000-0000-4000-8000-000000000001";

function authHandlers() {
  return [
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
  ];
}

/** Simulate the real authenticated session: the CSRF cookie set at login. */
function installCsrfCookie(): void {
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
}

/** Click one rendered canvas node by its canonical Entity ID. */
function clickNode(entityId: string): void {
  const node = document.querySelector(
    `[data-testid="rf__node-${nodeId(entityId)}"]`,
  );
  expect(node).not.toBeNull();
  fireEvent.click(node as Element);
}

describe("PR 31K graph actions workspace", () => {
  it("K-FE01/K-FE18: path-mode-off node click selects the canonical Entity for the bounded action", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
    );
    renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    const panel = await screen.findByRole("region", {
      name: "Start investigation",
    });
    // Human-readable canonical presentation: exact Entity ID + type/value.
    expect(
      within(panel).getByText(
        /^Starts an ATI investigation for Domain update-package\.test\./,
      ),
    ).toBeInTheDocument();
    expect(
      within(panel).getByText(
        "Canonical Entity ID: 40000000-0000-4000-8000-000000000101",
      ),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^Objective/)).toHaveValue(
      "Investigate Domain update-package.test",
    );
    // K-FE14: re-selecting the same node is a harmless render/selection
    // change — exactly one panel stays mounted, the canonical identity is
    // preserved, and no second command surface is created.
    clickNode(FOCAL);
    expect(
      screen.getAllByRole("region", { name: "Start investigation" }),
    ).toHaveLength(1);
    expect(screen.getByLabelText(/^Objective/)).toHaveValue(
      "Investigate Domain update-package.test",
    );
  });

  it("K-FE02/K-FE19: path mode keeps node-click precedence; no action is selected", async () => {
    const recorder = resourceListRecorder();
    const create = createInvestigationHandler();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
      create.handler,
    );
    renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    await userEvent.click(screen.getByRole("button", { name: "Path mode" }));
    await screen.findByText(/Click two entities in the graph/);
    clickNode(FOCAL);
    // The click selected a path endpoint (source), not an action.
    await screen.findByText(/^Source: update-package\.test/);
    expect(
      screen.queryByRole("region", { name: "Start investigation" }),
    ).not.toBeInTheDocument();
    expect(create.requests).toHaveLength(0);
    // Exiting path mode restores the ordinary graph without a request.
    await userEvent.click(screen.getByRole("button", { name: "Exit path mode" }));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    expect(create.requests).toHaveLength(0);
  });

  it("K-FE03: entering path mode clears an existing action selection", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
    );
    renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    await screen.findByRole("region", { name: "Start investigation" });
    await userEvent.click(screen.getByRole("button", { name: "Path mode" }));
    await screen.findByText(/Click two entities in the graph/);
    expect(
      screen.queryByRole("region", { name: "Start investigation" }),
    ).not.toBeInTheDocument();
  });

  it("K-FE04: cancel clears the selection and closes the panel without any request", async () => {
    const recorder = resourceListRecorder();
    const create = createInvestigationHandler();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
      create.handler,
    );
    renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    await screen.findByRole("region", { name: "Start investigation" });
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("region", { name: "Start investigation" }),
      ).not.toBeInTheDocument(),
    );
    expect(create.requests).toHaveLength(0);
  });

  it("K-FE05/K-FE08: submitting the selected Entity reuses the existing create command and navigates to the new Investigation", async () => {
    const recorder = resourceListRecorder();
    const create = createInvestigationHandler();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
      assessmentCurrentHandler(buildAssessment()),
      reportCurrentHandler(buildReport()),
      resolveSupportPresentationsHandler(),
      investigationsListHandler([]),
      create.handler,
    );
    const { router } = renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(COUNTERPARTY);
    await screen.findByRole("region", { name: "Start investigation" });
    installCsrfCookie();
    await userEvent.click(
      screen.getByRole("button", { name: "Start investigation" }),
    );
    await waitFor(() => expect(create.requests.length).toBe(1));
    const body = create.requests[0].body as {
      objective: string;
      indicators: { type: string; value: string }[];
    };
    expect(body.objective).toBe("Investigate IP address 203.0.113.10");
    expect(body.indicators).toEqual([
      { type: "ip_address", value: "203.0.113.10" },
    ]);
    // The accepted 202 navigates through the EXISTING Investigation
    // workflow; the worker/Coordinator runs asynchronously.
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${NEW_INVESTIGATION_ID}/overview`,
      ),
    );
  });

  it("K-FE09: a typed validation failure surfaces a safe localized error and never navigates", async () => {
    const recorder = resourceListRecorder();
    const create = createInvestigationHandler({ failWith: "validation" });
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
      create.handler,
    );
    const { router } = renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    await screen.findByRole("region", { name: "Start investigation" });
    installCsrfCookie();
    await userEvent.click(
      screen.getByRole("button", { name: "Start investigation" }),
    );
    expect(
      await screen.findByText("Unable to start the investigation."),
    ).toBeInTheDocument();
    expect(create.requests).toHaveLength(1);
    expect(router.state.location.pathname).toContain("/relationships/evolution");
    // The typed failure does not clear the selection: the panel stays open.
    expect(
      screen.getByRole("region", { name: "Start investigation" }),
    ).toBeInTheDocument();
  });

  it("K-FE12/K-FE17: a committed graph-context change clears a stale action selection without URL corruption", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
    );
    const { router } = renderAtPath(GRAPH_VIEW("graph_scope=investigation"));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    await screen.findByRole("region", { name: "Start investigation" });
    // Commit a different graph scope through the existing filter form.
    await userEvent.click(screen.getByRole("button", { name: "Known graph" }));
    await userEvent.click(
      within(screen.getByRole("group", { name: "Graph context and filters" }))
        .getByRole("button", { name: "Apply" }),
    );
    await waitFor(() =>
      expect(router.state.location.search).toContain("graph_scope=known"),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("region", { name: "Start investigation" }),
      ).not.toBeInTheDocument(),
    );
    // The action never added its own URL parameters or disturbed the graph
    // context codec (only the committed scope parameter changed).
    expect(router.state.location.search).not.toContain("graph_action");
    expect(router.state.location.search).toContain("view=graph");
  });

  it("K-FE13/K-FE20: a committed temporal range change clears a stale action selection", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
    );
    const { router } = renderAtPath(
      GRAPH_VIEW(
        "graph_temporal=1&graph_time_start=2026-02-01T00:00:00Z&graph_time_end=2026-02-09T00:00:00Z",
      ),
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    clickNode(FOCAL);
    await screen.findByRole("region", { name: "Start investigation" });
    // Commit a different direct range through the existing temporal form.
    fireEvent.change(screen.getByLabelText("Range start date"), {
      target: { value: "2026-02-02" },
    });
    fireEvent.change(screen.getByLabelText(/Range start time/), {
      target: { value: "" },
    });
    fireEvent.change(screen.getByLabelText("Range end date"), {
      target: { value: "2026-02-03" },
    });
    fireEvent.change(screen.getByLabelText(/Range end time/), {
      target: { value: "" },
    });
    await userEvent.click(
      within(screen.getByRole("group", { name: "Temporal exploration" })).getByRole(
        "button",
        { name: "Apply temporal" },
      ),
    );
    await waitFor(() =>
      expect(router.state.location.search).toContain("graph_time_start=2026-02-02"),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("region", { name: "Start investigation" }),
      ).not.toBeInTheDocument(),
    );
    // The selection cannot be submitted against the new range.
    expect(
      screen.queryByRole("button", { name: "Start investigation" }),
    ).not.toBeInTheDocument();
  });

  it("K-FE15: an accepted action adds no optimistic graph data and never re-queries the graph", async () => {
    const recorder = resourceListRecorder();
    const create = createInvestigationHandler();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
      assessmentCurrentHandler(buildAssessment()),
      reportCurrentHandler(buildReport()),
      resolveSupportPresentationsHandler(),
      investigationsListHandler([]),
      create.handler,
    );
    const { router } = renderAtPath(GRAPH_VIEW(""));
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    const graphRequestsBefore = recorder.requests.length;
    expect(graphRequestsBefore).toBe(1);
    clickNode(COUNTERPARTY);
    await screen.findByRole("region", { name: "Start investigation" });
    installCsrfCookie();
    await userEvent.click(
      screen.getByRole("button", { name: "Start investigation" }),
    );
    await waitFor(() =>
      expect(router.state.location.pathname).toBe(
        `/investigations/${NEW_INVESTIGATION_ID}/overview`,
      ),
    );
    // No graph refetch or optimistic node/edge was injected by the action.
    expect(recorder.requests).toHaveLength(graphRequestsBefore);
  });
});
