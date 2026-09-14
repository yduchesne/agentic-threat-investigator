// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot modal workspace route tests (PR 24D §26).
//
// Real route rendering over MSW: open, breadcrumbs, pre-applied exact
// server filters, PR 24C table reuse inside the modal, detail drawer in
// the modal, nested pivots in one dialog, breadcrumb truncation, Close
// preserving the base route state, depth-five suppression, target 404 and
// network retry inside the modal, malformed pivot state, browser
// Back/Forward, and refresh/deep-link restoration.

import { screen, waitFor, within } from "@testing-library/react";
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

/** Install the canonical modal-flow handlers (evidence + relationships). */
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
  await userEvent.click(await screen.findByRole("menuitem", { name: actionName }));
}

describe("pivot modal workspace", () => {
  it("opens the modal with breadcrumbs and pre-applied exact server filters", async () => {
    const { relationshipRecorder } = installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");

    await pivotSubjectCell("Relationships where source");

    const dialog = await screen.findByRole("dialog", { name: /pivot workspace/i });
    expect(within(dialog).getByText("Relationships")).toBeInTheDocument();
    expect(
      within(dialog).getByRole("navigation", { name: "Pivot breadcrumb" }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("update-package.test")).toBeInTheDocument();
    // The breadcrumb ends at the reached resource; the base Investigation
    // segment anchors the path.
    expect(within(dialog).getByText("Investigation")).toBeInTheDocument();

    // The PR 24C table is reused: the row renders through the same table.
    expect(await screen.findByText("Resolves to")).toBeInTheDocument();

    await waitFor(() => {
      const last = relationshipRecorder.requests.at(-1);
      expect(last?.params.source_entity_id).toBe(ENTITY_ID);
    });
  });

  it("opens the Evidence detail drawer inside the modal and pivots again in one dialog", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });

    // Open the relationship row detail drawer inside the modal.
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    const drawer = await screen.findByRole("dialog", { name: "Relationships" });
    expect(within(drawer).getByText("Resolves to")).toBeInTheDocument();

    // Pivot the drawer's source entity: the same dialog hosts the new step.
    await userEvent.click(
      within(drawer).getByRole("button", { name: "Pivot actions Source entity" }),
    );
    await userEvent.click(
      await screen.findByRole("menuitem", { name: "Evidence for this entity" }),
    );

    const evidenceDialog = await screen.findByRole("dialog", {
      name: /Evidence pivot workspace/i,
    });
    expect(evidenceDialog).toBeInTheDocument();
    // At most one modal dialog exists for the nested stack.
    expect(screen.getAllByRole("dialog", { name: /pivot workspace/i })).toHaveLength(1);
    await within(evidenceDialog).findByText("DNS", { exact: true });
  });

  it("truncates the stack from an earlier breadcrumb and restores that step", async () => {
    installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    await screen.findByRole("dialog", { name: "Relationships" });

    // Nested push from the drawer, then truncate back through the first
    // resource segment of the first step.
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions Source entity" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Evidence for this entity" }));
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });

    const dialog = await screen.findByRole("dialog", { name: /pivot workspace/i });
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Return to Relationships" }),
    );
    await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });
    // Later steps are gone; the restored step keeps its selection drawer.
    expect(screen.queryByRole("dialog", { name: /Evidence pivot workspace/i })).toBeNull();
  });

  it("keeps the base route filters and closes to the same base state", async () => {
    const { relationshipRecorder } = installFlowHandlers();
    const { router } = renderAtPath(`${BASE}/evidence?type=urn%3Aati%3Aevidence%3Adns`);
    await screen.findByText("update-package.test");

    await pivotSubjectCell("Relationships where source");
    const dialog = await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });
    await within(dialog).findByText("Resolves to");

    await userEvent.click(screen.getByRole("button", { name: "Close pivot workspace" }));
    expect(screen.queryByRole("dialog", { name: /pivot workspace/i })).toBeNull();
    // The base evidence rows and URL filter state survived untouched
    // (cursor preservation is a unit-level property of the pivot helpers,
    // which never touch non-pivot parameters).
    expect(screen.getAllByText("update-package.test").length).toBeGreaterThan(0);
    const search = new URLSearchParams(router.state.location.search.slice(1));
    expect(search.get("type")).toBe("urn:ati:evidence:dns");
    expect(search.get("pivot")).toBeNull();
    expect(relationshipRecorder.requests.length).toBeGreaterThan(0);
  });

  it("restores prior and later stacks through browser Back/Forward (URL state)", async () => {
    // The URL is the authoritative pivot state (PR 24D §1.7): browser Back
    // and Forward must restore the exact prior/later stacks. The memory
    // router restores the committed search; the rendered restoration of a
    // parsed URL is covered by the deep-link test and by the real-browser
    // E2E (POP re-rendering happens in the browser via popstate).
    installFlowHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    await screen.findByRole("dialog", { name: "Relationships" });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions Source entity" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Evidence for this entity" }));
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
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

  it("restores the modal from a refresh deep link (validated parser path)", async () => {
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
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    await waitFor(() => {
      const last = evidenceRecorder.requests.at(-1);
      expect(last?.params.subject_entity_id).toBe(ENTITY_ID);
    });
  });

  it("suppresses further pivots at depth five and explains the limit textually", async () => {
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

    const dialog = await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    expect(within(dialog).getByText(/Maximum pivot depth/)).toBeInTheDocument();
    // The active evidence step renders its table and no pivot triggers.
    await waitFor(() => expect(evidenceRecorder.requests.length).toBeGreaterThan(0));
    expect(screen.queryByRole("button", { name: "Pivot actions" })).toBeNull();
  });

  it("keeps the modal context on a target 404 (bounded not-found)", async () => {
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

    const dialog = await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    expect(dialog).toBeInTheDocument();
    expect(
      await within(dialog).findByText("Resource not found or not accessible"),
    ).toBeInTheDocument();
    // The modal and its list stay intact.
    expect(await within(dialog).findByText("update-package.test")).toBeInTheDocument();
  });

  it("keeps modal context on a network failure and allows Retry inside it", async () => {
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
    // NOTE: two identical-path evidence handlers would be ambiguous; the
    // failing handler stays first and is replaced before the Retry click.
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
    const dialog = await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    await within(dialog).findByText("Unable to load Evidence");
    expect(within(dialog).getByRole("button", { name: "Retry" })).toBeInTheDocument();
    // Replace the failing surface, then retry inside the modal.
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder,
      }),
    );
    await userEvent.click(within(dialog).getByRole("button", { name: "Retry" }));
    expect(await within(dialog).findByText("DNS", { exact: true })).toBeInTheDocument();
    expect(within(dialog).queryByText("Unable to load Evidence")).toBeNull();
  });

  it("leaves the base page usable with a malformed pivot parameter", async () => {
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
    expect(screen.queryByRole("dialog", { name: /pivot workspace/i })).toBeNull();
  });

  it("keeps the modal open and reuses the list DTO inside RelationshipObservations pivots", async () => {
    const { observationRecorder } = installFlowHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await pivotSubjectCell("Relationships where source");
    await screen.findByRole("dialog", { name: /Relationships pivot workspace/i });
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    const drawer = await screen.findByRole("dialog", { name: "Relationships" });

    // The drawer's in-modal observation affordance pushes an observations
    // step inside the same dialog.
    await userEvent.click(
      within(drawer).getByRole("button", { name: "Observations for this relationship" }),
    );
    const obsDialog = await screen.findByRole("dialog", {
      name: /Relationship observations pivot workspace/i,
    });
    expect(obsDialog).toBeInTheDocument();
    await waitFor(() => {
      const last = observationRecorder.requests.at(-1);
      expect(last?.params.relationship_id).toBe(RELATIONSHIP_ID);
    });
    expect(
      await within(obsDialog).findByText("Observed at", { exact: true }),
    ).toBeInTheDocument();
  });
});
