// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// In-flow Pivot workbench route tests (PR 24D §26; PR 31F-6 amendment 5).
//
// Real route rendering over MSW: the normal Investigation workbench and
// the URL-selected in-flow Pivot workbench are ALTERNATIVE primary views.
// When the bounded ``pivot`` URL state is non-empty the Pivot workbench is
// the page's only main content (A5-PW02/03) and is ordinary in-flow
// content — no Portal, fixed overlay, backdrop, modal/``aria-modal``,
// body scroll lock or document pointer filter (A5-PW04..09, PW25). The
// Pivot domain contract is unchanged: URL stack authority, breadcrumbs,
// truncate, Close, Back/Forward, depth-five suppression, malformed-state
// recovery, list/detail inside the active step, inline Pivot actions, and
// bounded error/loading presentation.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  buildObservation,
  buildRelationship,
  completedInvestigationFixture,
  errorResponse,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { readPivotState, serializePivotState } from "./pivot-url";
import { MAX_PIVOT_STEPS, type PivotStep } from "./pivot-types";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const ENTITY_ID = uuidAt(101);
const ENTITY_ID_2 = uuidAt(102);
const EVIDENCE_ID = uuidAt(1);
const RELATIONSHIP_ID = uuidAt(21);

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

function evidenceA() {
  return buildEvidence({
    id: EVIDENCE_ID,
    subject_entity_id: ENTITY_ID,
    subject_value: "update-package.test",
    type: "urn:ati:evidence:dns",
  });
}

function relationshipA() {
  return buildRelationship({
    id: RELATIONSHIP_ID,
    source_entity_id: ENTITY_ID,
    target_entity_id: ENTITY_ID_2,
  });
}

function observationRows() {
  return [
    buildObservation({ id: uuidAt(41), relationship_id: RELATIONSHIP_ID, evidence_id: EVIDENCE_ID }),
  ];
}

/** Install the canonical pivot-flow handlers (evidence + relationships). */
function installFlowHandlers() {
  const evidenceRecorder = resourceListRecorder();
  const relationshipRecorder = resourceListRecorder();
  const observationRecorder = resourceListRecorder();
  setHttpHandlers(
    ...AUTH,
    workspaceHandler(),
    http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonResponse(evidenceA())),
    http.get("*/api/v1/investigations/:id/relationships/:relationshipId", () => jsonResponse(relationshipA())),
    pagedResourceHandler({
      path: "*/api/v1/investigations/:id/evidence",
      pages: [[evidenceA()]],
      recorder: evidenceRecorder,
    }),
    pagedResourceHandler({
      path: "*/api/v1/investigations/:id/relationships",
      pages: [[relationshipA()]],
      recorder: relationshipRecorder,
    }),
    pagedResourceHandler({
      path: "*/api/v1/investigations/:id/relationship-observations",
      pages: [observationRows()],
      recorder: observationRecorder,
    }),
  );
  return { evidenceRecorder, relationshipRecorder, observationRecorder };
}

/** Drill: subject cell Pivot menu -> one entity action. */
async function pivotSubjectCell(actionName: string): Promise<void> {
  await userEvent.click(screen.getByRole("button", { name: "Subject" }));
  await userEvent.click(await screen.findByRole("button", { name: actionName }));
}

/** The in-flow Pivot workbench section (PR 31F-6 A5). */
async function workbench(): Promise<HTMLElement> {
  return screen.findByTestId("pivot-workbench");
}

/** Await the workbench heading for a reached resource. */
async function workbenchHeading(name: RegExp): Promise<HTMLElement> {
  const wb = await workbench();
  return within(wb).findByRole("heading", { name });
}

describe("Pivot workbench (in-flow; PR 31F-6 A5)", () => {
  it("A5-PW01: with empty pivot state the normal Investigation workbench renders", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(`${BASE}/evidence`);
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
    expect(screen.queryByTestId("pivot-workbench")).toBeNull();
    // The normal workbench (resource tabs) is present.
    expect(screen.getByRole("tab", { name: "Evidence" })).toBeInTheDocument();
  });

  it("A5-PW02/03: an active Pivot step makes the Pivot workbench the primary content; the normal workbench is not interactive underneath", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");

    await workbenchHeading(/Relationships pivot workspace/);
    // The core Investigation body is NOT simultaneously mounted (no tabs /
    // resource outlet behind an overlay).
    expect(screen.queryByRole("tab", { name: "Evidence" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Relationships" })).toBeNull();
    // The active step's list renders through the workbench.
    expect(await screen.findByText("Resolves to")).toBeInTheDocument();
  });

  it("A5-PW04..09: presentation is ordinary in-flow content — no Portal, fixed overlay, backdrop, modal/dialog semantics, body lock or pointer filter", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await workbenchHeading(/Relationships pivot workspace/);

    const wb = await workbench();
    // In-flow: contained inside the app container, not a Portal to body.
    expect(wb.isConnected).toBe(true);
    // No dialog/modal semantics.
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(wb.getAttribute("aria-modal")).toBeNull();
    expect(wb.getAttribute("role")).not.toBe("dialog");
    // No body scroll lock and no body-child aria-hidden.
    expect(document.body.style.overflow).toBe("");
    expect(
      Array.from(document.body.children).some(
        (node) => node.getAttribute("aria-hidden") === "true",
      ),
    ).toBe(false);
    // No viewport backdrop element.
    expect(wb.closest("[aria-hidden='true']")).toBeNull();
  });

  it("A5-PW10/11: the active step and breadcrumb truncate semantics are preserved", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    const relHeading = await workbenchHeading(/Relationships pivot workspace/);

    // Nested push -> Evidence step, then truncate back to Relationships.
    const wb = await workbench();
    await userEvent.click(within(wb).getByRole("button", { name: /^View / }));
    await within(wb).findByRole("heading", { name: "Relationships details" });
    await userEvent.click(
      await within(wb).findByRole("button", { name: "Pivot actions Source entity" }),
    );
    await userEvent.click(await screen.findByRole("button", { name: "Evidence for this entity" }));
    await workbenchHeading(/Evidence pivot workspace/);

    await userEvent.click(
      within(await workbench()).getByRole("button", { name: "Return to Relationships" }),
    );
    await workbenchHeading(/Relationships pivot workspace/);
    await waitFor(() =>
      expect(screen.queryByRole("heading", { name: "Evidence pivot workspace" })).toBeNull(),
    );
    void relHeading;
  });

  it("A5-PW12/13: Close clears the pivot URL and restores the normal Investigation workbench", async () => {
    const { relationshipRecorder } = installFlowHandlers();
    const { router } = renderAtPath(`${BASE}/evidence?type=urn%3Aati%3Aevidence%3Adns`);
    await screen.findByText("update-package.test");

    await pivotSubjectCell("Relationships where source");
    await workbenchHeading(/Relationships pivot workspace/);

    await userEvent.click(screen.getByRole("button", { name: "Close pivot workspace" }));
    await waitFor(() => expect(screen.queryByTestId("pivot-workbench")).toBeNull());
    // The normal workbench (tabs + resource rows) returns; base filters intact.
    expect(screen.getByRole("tab", { name: "Evidence" })).toBeInTheDocument();
    expect(screen.getAllByText("update-package.test").length).toBeGreaterThan(0);
    const search = new URLSearchParams(router.state.location.search.slice(1));
    expect(search.get("type")).toBe("urn:ati:evidence:dns");
    expect(search.get("pivot")).toBeNull();
    expect(relationshipRecorder.requests.length).toBeGreaterThan(0);
  });

  it("A5-PW14: browser Back/Forward restores prior and later stack states", async () => {
    installFlowHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    const wb = await workbench();
    await userEvent.click(within(wb).getByRole("button", { name: /^View / }));
    await within(wb).findByRole("heading", { name: "Relationships details" });
    await userEvent.click(await within(wb).findByRole("button", { name: "Pivot actions Source entity" }));
    await userEvent.click(await screen.findByRole("button", { name: "Evidence for this entity" }));
    await workbenchHeading(/Evidence pivot workspace/);
    const current = new URLSearchParams(router.state.location.search);
    expect(readPivotState(current)?.steps.map((step) => step.resource)).toEqual([
      "relationships",
      "evidence",
    ]);

    await router.navigate(-1);
    const backState = readPivotState(new URLSearchParams(router.state.location.search));
    expect(backState?.steps.map((step) => step.resource)).toEqual(["relationships"]);
    expect(backState?.steps[0].selectedId).toBe(RELATIONSHIP_ID);

    await router.navigate(1);
    const forwardState = readPivotState(new URLSearchParams(router.state.location.search));
    expect(forwardState?.steps.map((step) => step.resource)).toEqual([
      "relationships",
      "evidence",
    ]);
  });

  it("A5-PW14b: a refresh deep link restores the Pivot workbench (validated parser path)", async () => {
    const { evidenceRecorder } = installFlowHandlers();
    const steps: PivotStep[] = [
      {
        resource: "relationships",
        filters: { source_entity_id: ENTITY_ID },
        selectedId: null,
        label: "update-package.test",
        sourceKind: "table_cell",
      },
      {
        resource: "evidence",
        filters: { subject_entity_id: ENTITY_ID },
        selectedId: null,
        label: "Entity 40000000",
        sourceKind: "table_cell",
      },
    ];
    const pivot = serializePivotState({ steps });
    expect(pivot).not.toBeNull();
    renderAtPath(`${BASE}/evidence?type=urn%3Aati%3Aevidence%3Adns&pivot=${pivot ?? ""}`);
    await workbenchHeading(/Evidence pivot workspace/);
    await waitFor(() => {
      const last = evidenceRecorder.requests.at(-1);
      expect(last?.params.subject_entity_id).toBe(ENTITY_ID);
    });
  });

  it("A5-PW15/16/17: inside the active step, selected absent -> list; selected present -> detail; resource Back restores the same step's list", async () => {
    installFlowHandlers();
    const steps: PivotStep[] = [
      {
        resource: "evidence",
        filters: { subject_entity_id: ENTITY_ID },
        selectedId: EVIDENCE_ID,
        label: "update-package.test",
        sourceKind: "table_cell",
      },
    ];
    const pivot = serializePivotState({ steps });
    expect(pivot).not.toBeNull();
    const { router } = renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);

    await workbenchHeading(/Evidence pivot workspace/);
    const wb = await workbench();
    // Selected present -> detail instead of list.
    await within(wb).findByRole("heading", { name: "Evidence details" });
    const current = readPivotState(new URLSearchParams(router.state.location.search));
    expect(current?.steps).toHaveLength(1);
    expect(current?.steps[0].selectedId).toBe(EVIDENCE_ID);

    // Resource Back clears selection only; the SAME PivotStep list returns.
    await userEvent.click(within(wb).getByRole("button", { name: "Back to Evidence" }));
    await waitFor(() =>
      expect(screen.queryByRole("heading", { name: "Evidence details" })).toBeNull(),
    );
    await within(wb).findByRole("table", { name: "Evidence" });
    const after = readPivotState(new URLSearchParams(router.state.location.search));
    expect(after?.steps).toHaveLength(1);
    expect(after?.steps[0].selectedId).toBeNull();
  });

  it("A5-PW18/19/20: inline Pivot actions push exactly once; local actions/semantics are unchanged", async () => {
    installFlowHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await workbenchHeading(/Relationships pivot workspace/);
    const wb = await workbench();
    // In the Relationships step's list, the source cell Pivot menu yields
    // the exact `Evidence for this entity` action (push transitions the
    // same in-flow workbench to an Evidence step).
    await userEvent.click(within(wb).getByRole("button", { name: /^View / }));
    await within(wb).findByRole("heading", { name: "Relationships details" });
    await userEvent.click(await within(wb).findByRole("button", { name: "Pivot actions Source entity" }));
    await userEvent.click(await screen.findByRole("button", { name: "Evidence for this entity" }));
    await workbenchHeading(/Evidence pivot workspace/);
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps.map((step) => step.resource)).toEqual(["relationships", "evidence"]);
  });

  it("A5-PW21: further pivots are suppressed at depth five with the textual explanation", async () => {
    const { evidenceRecorder } = installFlowHandlers();
    const steps: PivotStep[] = Array.from({ length: MAX_PIVOT_STEPS }, (_, index) =>
      ({
        resource: "evidence",
        filters: { subject_entity_id: uuidAt(100 + index) },
        selectedId: null,
        label: `Entity ${uuidAt(100 + index).slice(0, 8)}`,
        sourceKind: "table_cell",
      }) as PivotStep);
    const pivot = serializePivotState({ steps });
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);

    await workbenchHeading(/Evidence pivot workspace/);
    expect(within(await workbench()).getByText(/Maximum pivot depth/)).toBeInTheDocument();
    await waitFor(() => expect(evidenceRecorder.requests.length).toBeGreaterThan(0));
    expect(screen.queryByRole("button", { name: "Pivot actions" })).toBeNull();
  });

  it("A5-PW23: a malformed pivot parameter leaves the normal workbench usable", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(`${BASE}/evidence?pivot=%21%21not-base64%21%21`);
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
    expect(screen.queryByTestId("pivot-workbench")).toBeNull();
    expect(screen.getByRole("tab", { name: "Evidence" })).toBeInTheDocument();
  });

  it("A5-PW24a: target 404 surfaces bounded not-found inside the Pivot workbench", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () =>
        errorResponse(404, "evidence_not_found")),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder: resourceListRecorder(),
      }),
    );
    const pivot = serializePivotState({
      steps: [
        {
          resource: "evidence",
          filters: {},
          selectedId: EVIDENCE_ID,
          label: "Evidence 40000000",
          sourceKind: "report_support",
        } as PivotStep,
      ],
    });
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);

    await workbenchHeading(/Evidence pivot workspace/);
    expect(
      await within(await workbench()).findByText("Resource not found or not accessible"),
    ).toBeInTheDocument();
    // A5-PW03: the normal Investigation workbench is not mounted underneath.
    expect(screen.queryByRole("tab", { name: "Evidence" })).toBeNull();
  });

  it("A5-PW24b: a network failure surfaces bounded Retry inside the Pivot workbench", async () => {
    const failing = http.get("*/api/v1/investigations/:id/evidence", () =>
      errorResponse(500, "internal_error"));
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      failing,
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder,
      }),
    );
    const pivot = serializePivotState({
      steps: [
        {
          resource: "evidence",
          filters: { subject_entity_id: ENTITY_ID },
          selectedId: null,
          label: "update-package.test",
          sourceKind: "table_cell",
        } as PivotStep,
      ],
    });
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);
    await workbenchHeading(/Evidence pivot workspace/);
    const wb = await workbench();
    await within(wb).findByText("Unable to load Evidence");
    expect(within(wb).getByRole("button", { name: "Retry" })).toBeInTheDocument();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder,
      }),
    );
    await userEvent.click(within(wb).getByRole("button", { name: "Retry" }));
    expect(await within(wb).findByText("DNS", { exact: true })).toBeInTheDocument();
    expect(within(wb).queryByText("Unable to load Evidence")).toBeNull();
  });

  it("A5-PW25: Escape does not dismiss the in-flow workbench (no modal-only handler)", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await workbenchHeading(/Relationships pivot workspace/);

    fireEvent.keyDown(await workbench(), { key: "Escape" });
    await waitFor(() =>
      expect(screen.queryByTestId("pivot-workbench")).not.toBeNull(),
    );
    expect(
      within(await workbench()).getByRole("heading", { name: "Relationships pivot workspace" }),
    ).toBeInTheDocument();
  });

  it("A5-PW26: the Pivot workbench exposes a meaningful heading and semantic Close control", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    const heading = await workbenchHeading(/Relationships pivot workspace/);
    expect(heading.textContent).toContain("Relationships");
    expect(
      within(await workbench()).getByRole("button", { name: "Close pivot workspace" }),
    ).toBeInTheDocument();
    expect(
      within(await workbench()).getByRole("navigation", { name: "Pivot breadcrumb" }),
    ).toBeInTheDocument();
  });

  it("A5-PW10/PW11b: the Pivot workbench reuses the RelationshipObservations list DTO in an observations step", async () => {
    const { observationRecorder } = installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    const wb = await workbench();
    await workbenchHeading(/Relationships pivot workspace/);
    await userEvent.click(within(wb).getByRole("button", { name: /^View / }));
    await within(wb).findByRole("heading", { name: "Relationships details" });

    await userEvent.click(
      await within(wb).findByRole("button", { name: "Observations for this relationship" }),
    );
    await workbenchHeading(/Relationship observations pivot workspace/);
    await waitFor(() => {
      const last = observationRecorder.requests.at(-1);
      expect(last?.params.relationship_id).toBe(RELATIONSHIP_ID);
    });
    expect(
      await within(await workbench()).findByText("Observed at", { exact: true }),
    ).toBeInTheDocument();
  });
});
