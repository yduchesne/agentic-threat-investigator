// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PivotMenu behavior tests (PR 24D §8, §22, §24-§25; PR 31E §13;
// PR 31F-6 amendment 2 A2-PM01..14).
//
// The trigger renders a direct accessible action for one legal target and
// a compact in-flow action bar for several; no-op actions against the
// active step are suppressed; at the maximum pivot depth URL-backed
// navigation pivots are omitted; and the action pushes a valid URL-backed
// step that opens the modal. Expanding choices changes only transient
// local presentation state — no Portal/Menu/Popover/backdrop/document
// pointer listener exists, and Cancel collapses without navigating.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  buildObservation,
  completedInvestigationFixture,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { decodeBase64Url, readPivotState, serializePivotState } from "./pivot-url";
import { MAX_PIVOT_STEPS, type PivotStep } from "./pivot-types";
import {
  entityActions,
  type PivotAction,
} from "./pivot-capabilities";
import { PivotMenu, type PivotLocalAction } from "./PivotMenu";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const ENTITY_ID = uuidAt(101);
const RELATIONSHIP_ID = uuidAt(21);
const EVIDENCE_ID = uuidAt(1);

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

function installHandlers() {
  const recorder = resourceListRecorder();
  setHttpHandlers(
    ...AUTH,
    workspaceHandler(),
    http
      .get("*/api/v1/investigations/:id/evidence", () =>
        jsonResponse({ items: [evidenceFixture()], next_cursor: null })),
    pagedResourceHandler({
      path: "*/api/v1/investigations/:id/relationship-observations",
      pages: [[buildObservation({ relationship_id: RELATIONSHIP_ID, evidence_id: EVIDENCE_ID })]],
      recorder,
    }),
  );
  return recorder;
}

function evidenceFixture() {
  return buildEvidence({
    id: EVIDENCE_ID,
    subject_entity_id: ENTITY_ID,
    subject_value: "update-package.test",
  });
}

// The single-action surface: one observation-rendered trigger inside the
// relationship-observations route cell (evidence id cell; single action).
function observationRowRoute(): string {
  return `${BASE}/relationships/observations`;
}

/** The expanded in-flow action region. */
function actionBar(): HTMLElement {
  return screen.getByRole("group", { name: "Pivot actions" });
}

describe("PivotMenu", () => {
  it("A2-PM01/02: the trigger starts collapsed and expands an in-flow bar", async () => {
    installHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    const trigger = screen.getByRole("button", { name: "Subject" });
    expect(screen.queryByRole("group", { name: "Pivot actions" })).toBeNull();
    await userEvent.click(trigger);
    const bar = actionBar();
    expect(bar).toBeInTheDocument();
    // Ordinary buttons, not menu items.
    expect(screen.getByRole("button", { name: "Evidence for this entity" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Research for this entity" })).toBeInTheDocument();
  });

  it("A2-PM04/PM05: selecting a URL action pushes the exact PivotStep and collapses", async () => {
    installHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "Subject" }));
    await userEvent.click(await screen.findByRole("button", { name: "Relationships where source" }));
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(decodeBase64Url(new URLSearchParams(router.state.location.search).get("pivot") ?? ""))
      .toContain('"source_entity_id"');
    // The bar collapses after the action handoff.
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: "Pivot actions" })).toBeNull();
    });
  });

  it("A2-PM12: no-op targets matching the active step context are suppressed", async () => {
    const evidenceStep: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "update-package.test",
      sourceKind: "table_cell",
    };
    const pivot = serializePivotState({ steps: [evidenceStep] });
    installHandlers();
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);
    await screen.findByTestId("pivot-workbench");
    // The active evidence step renders its table; the same-resource no-op
    // actions are suppressed, so no pivot trigger is present at all.
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Pivot" })).toBeNull();
    });
  });

  it("A2-PM13: the trigger is omitted entirely at the maximum pivot depth", async () => {
    const steps: PivotStep[] = Array.from({ length: MAX_PIVOT_STEPS }, (_, index) =>
      ({
        resource: "evidence",
        filters: { subject_entity_id: uuidAt(100 + index) },
        selectedId: null,
        label: `Entity ${uuidAt(100 + index).slice(0, 8)}`,
        sourceKind: "table_cell",
      }) as PivotStep);
    const pivot = serializePivotState({ steps });
    installHandlers();
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);
    await screen.findByTestId("pivot-workbench");
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
    });
  });

  it("A2-PM03: a single observation target renders a direct action label", async () => {
    installHandlers();
    renderAtPath(observationRowRoute());
    await waitFor(() => {
      expect(screen.queryAllByRole("button", { name: "Evidence" }).length).toBeGreaterThan(0);
    });
    const evidenceCellButton = screen.getAllByRole("button", { name: "Evidence" })[0];
    await userEvent.click(evidenceCellButton);
    expect(await screen.findByRole("button", { name: "Observations for this relationship" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Open evidence" }));
    await screen.findByTestId("pivot-workbench");
  });
});

// PR 31E §13 + PR 31F-6 amendment 2: PivotMenu regression matrix for
// explicit local/context actions and the in-flow action bar.
describe("PivotMenu action bar (PR 31E + amendment 2)", () => {
  const LOCAL = {
    key: "graph-expand-either",
    label: "Expand known relationships",
  };

  function localActions(
    overrides: Array<Partial<PivotLocalAction>> = [],
  ): PivotLocalAction[] {
    return [
      { ...LOCAL, onSelect: vi.fn(), ...overrides[0] },
      {
        key: "graph-expand-source",
        label: "Expand outgoing relationships",
        onSelect: vi.fn(),
        ...overrides[1],
      },
    ];
  }

  /** Render one PivotMenu directly through the production providers. */
  function renderMenu(
    initialSearch: string,
    props: {
      actions: readonly PivotAction[];
      localActions?: readonly PivotLocalAction[];
    },
  ) {
    const router = createMemoryRouter(
      [{ path: "/", element: <PivotMenu actions={props.actions} localActions={props.localActions} /> }],
      { initialEntries: [initialSearch] },
    );
    const result = render(
      <AppProviders queryClient={freshQueryClient()}>
        <RouterProvider router={router} />
      </AppProviders>,
    );
    return { result, router };
  }

  it("A2-PM06: a single local action renders as a direct action and executes without a PivotStep", async () => {
    const local = localActions()[0];
    renderMenu("/", { actions: [], localActions: [local] });
    const button = screen.getByRole("button", { name: "Expand known relationships" });
    await userEvent.click(button);
    expect(local.onSelect).toHaveBeenCalledTimes(1);
  });

  it("A2-PM03/PM06: local + PivotActions expand one combined in-flow bar; a local selection changes no URL or pivot state", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    expect(bar).toBeInTheDocument();
    // Local command + the four URL navigation pivots in one ordinary bar.
    expect(screen.getByRole("button", { name: "Expand known relationships" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Evidence for this entity" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Research for this entity" })).toBeInTheDocument();
    const before = router.state.location.search;
    await userEvent.click(screen.getByRole("button", { name: "Expand known relationships" }));
    expect(local.onSelect).toHaveBeenCalledTimes(1);
    // No PivotStep, no pivot= URL mutation.
    expect(router.state.location.search).toBe(before);
    expect(readPivotState(new URLSearchParams(router.state.location.search))).toBeNull();
  });

  it("A2-PM05: selecting a navigation Pivot next to locals still pushes the exact PivotStep", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    await userEvent.click(await screen.findByRole("button", { name: "Research for this entity" }));
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(state?.steps[0].resource).toBe("research");
    if (state !== null && state.steps[0].resource === "research") {
      expect(state.steps[0].filters.subject_entity_id).toBe(ENTITY_ID);
    }
    expect(local.onSelect).not.toHaveBeenCalled();
  });

  it("A2-PM13: at MAX_PIVOT_STEPS navigation pivots disappear but local actions remain", async () => {
    const steps: PivotStep[] = Array.from({ length: MAX_PIVOT_STEPS }, (_, index) =>
      ({
        resource: "evidence",
        filters: { subject_entity_id: uuidAt(100 + index) },
        selectedId: null,
        label: `Entity ${uuidAt(100 + index).slice(0, 8)}`,
        sourceKind: "table_cell",
      }) as PivotStep);
    const pivot = serializePivotState({ steps });
    const locals = localActions();
    renderMenu(`/?pivot=${pivot ?? ""}`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: locals,
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    actionBar();
    expect(screen.getByRole("button", { name: "Expand known relationships" })).toBeInTheDocument();
    // Navigation pivots are depth-suppressed at the maximum depth.
    expect(screen.queryByRole("button", { name: "Evidence for this entity" })).toBeNull();
  });

  it("A2-PM12: a URL no-op pivot is suppressed but local actions remain", async () => {
    const step: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "update-package.test",
      sourceKind: "table_cell",
    };
    const pivot = serializePivotState({ steps: [step] });
    const local = localActions()[0];
    renderMenu(`/?pivot=${pivot ?? ""}`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    actionBar();
    // Evidence-for-this-entity is the no-op here; relationships/research remain.
    expect(screen.queryByRole("button", { name: "Evidence for this entity" })).toBeNull();
    expect(screen.getByRole("button", { name: "Relationships where source" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Expand known relationships" })).toBeInTheDocument();
  });

  it("A2-PM05: a disabled local action can never execute", async () => {
    const local = localActions([{ disabled: true }]);
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: local,
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const item = await screen.findByRole("button", { name: "Expand known relationships" });
    expect(item).toBeDisabled();
    // The disabled item is inert: a raw click event never reaches onClick.
    fireEvent.click(item);
    expect(local[0].onSelect).not.toHaveBeenCalled();
  });

  it("A2-PM10: ordinary buttons keep natural Tab order and Enter/Space activation", async () => {
    const local = localActions()[0];
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    const buttons = Array.from(bar.querySelectorAll("button")).filter(
      (b) => (b as HTMLButtonElement).disabled === false,
    );
    expect(buttons.length).toBeGreaterThanOrEqual(2);
    // Natural document order; keyboard activation on the first action runs it.
    (buttons[0] as HTMLButtonElement).focus();
    await userEvent.keyboard("{Enter}");
    expect(local.onSelect).toHaveBeenCalledTimes(1);
  });

  it("A2-PM04: Cancel collapses the bar without navigating", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    actionBar();
    const before = router.state.location.search;
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: "Pivot actions" })).toBeNull();
    });
    expect(local.onSelect).not.toHaveBeenCalled();
    expect(router.state.location.search).toBe(before);
  });

  it("A2-PM08: stale expansion resets when the hosting Pivot context changes", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    actionBar();
    // A navigation push (any PivotStep) resets the presentation-only bar.
    await userEvent.click(screen.getByRole("button", { name: "Relationships where source" }));
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: "Pivot actions" })).toBeNull();
    });
    expect(router.state.location.search).toContain("pivot=");
  });

  it("A2-PM09/A2-PM14: the bar is ordinary in-flow DOM — no Portal/Menu/Popover/separator", async () => {
    const local = localActions()[0];
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    expect(bar).toHaveAttribute("role", "group");
    expect(bar.closest("body")).not.toBeNull();
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.queryByRole("menuitem")).toBeNull();
    expect(screen.queryByRole("separator")).toBeNull();
    // Graph local actions remain local and never serialize into the URL.
    expect(new URLSearchParams(window.location.search).has("pivot")).toBe(false);
    expect(local.onSelect).not.toHaveBeenCalled();
  });

  it("A2-PM13: no actions and no local actions produces no trigger", () => {
    renderMenu("/", { actions: [] });
    expect(screen.queryByRole("button", { name: "Pivot" })).toBeNull();
  });
});
