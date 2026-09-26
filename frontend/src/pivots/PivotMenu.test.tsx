// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PivotMenu behavior tests (PR 24D §8, §22, §24-§25).
//
// The trigger renders a direct accessible action for one legal target and
// an accessible menu for several; no-op actions against the active step
// are suppressed; at the maximum pivot depth the trigger is omitted; and
// the action pushes a valid URL-backed step that opens the modal.

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

describe("PivotMenu", () => {
  it("renders a direct accessible action for a single legal target", async () => {
    installHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    // Evidence subject exposes four actions -> a menu trigger.
    const trigger = screen.getByRole("button", { name: "Subject" });
    expect(trigger).toHaveAttribute("aria-haspopup", "menu");
    await userEvent.click(trigger);
    expect(await screen.findByRole("menuitem", { name: "Evidence for this entity" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Research for this entity" }));
    const dialog = await screen.findByRole("dialog", { name: /Research pivot workspace/i });
    expect(dialog).toBeInTheDocument();
  });

  it("pushes the exact target filters and keeps them reachable in the URL", async () => {
    installHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "Subject" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Relationships where source" }));
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(decodeBase64Url(new URLSearchParams(router.state.location.search).get("pivot") ?? ""))
      .toContain('"source_entity_id"');
  });

  it("suppresses no-op targets matching the active step context", async () => {
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
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    // The active evidence step renders its table; the same-resource no-op
    // actions are suppressed, so no pivot trigger is present at all.
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Pivot actions" })).toBeNull();
    });
  });

  it("omits the trigger entirely at the maximum pivot depth", async () => {
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
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
    });
  });

  it("renders a direct action label for a single observation target", async () => {
    installHandlers();
    renderAtPath(observationRowRoute());
    // Each row cell exposes the two observation actions through an
    // accessible menu trigger; wait for the loaded row first.
    await waitFor(() => {
      expect(screen.queryAllByRole("button", { name: "Evidence" }).length).toBeGreaterThan(0);
    });
    const evidenceCellButton = screen.getAllByRole("button", { name: "Evidence" })[0];
    await userEvent.click(evidenceCellButton);
    expect(await screen.findByRole("menuitem", { name: "Observations for this relationship" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Open evidence" }));
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
  });
});

// PR 31E §13: PivotMenu regression matrix for explicit local/context actions.
//
// Local actions are UI commands (graph expansion in 31E), not Pivot
// resources: they never become PivotSteps, never mutate ``pivot=``, are
// never no-op suppressed, and are never blocked by Pivot depth. URL-backed
// PivotActions keep their exact semantics alongside them.

describe("PivotMenu local actions (PR 31E)", () => {
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

  it("G31E-P02: a single local action renders as a direct action and executes", async () => {
    const local = localActions()[0];
    renderMenu("/", { actions: [], localActions: [local] });
    const button = screen.getByRole("button", { name: "Expand known relationships" });
    expect(button).not.toHaveAttribute("aria-haspopup");
    await userEvent.click(button);
    expect(local.onSelect).toHaveBeenCalledTimes(1);
  });

  it("G31E-P03/P04: local + PivotActions render one combined accessible menu; a local selection changes no URL or pivot state", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    const menu = await screen.findByRole("menu");
    expect(menu).toBeInTheDocument();
    // Local command + the four URL navigation pivots, one accessible menu.
    expect(screen.getByRole("menuitem", { name: "Expand known relationships" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Evidence for this entity" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Research for this entity" })).toBeInTheDocument();
    // Locals first, grouped from navigation pivots by a separator.
    expect(screen.getByRole("separator")).toBeInTheDocument();
    const before = router.state.location.search;
    await userEvent.click(screen.getByRole("menuitem", { name: "Expand known relationships" }));
    expect(local.onSelect).toHaveBeenCalledTimes(1);
    // No PivotStep, no pivot= URL mutation.
    expect(router.state.location.search).toBe(before);
    expect(readPivotState(new URLSearchParams(router.state.location.search))).toBeNull();
  });

  it("G31E-P05: selecting a navigation Pivot next to locals still pushes the exact PivotStep", async () => {
    const local = localActions()[0];
    const { router } = renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Research for this entity" }));
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(state?.steps[0].resource).toBe("research");
    if (state !== null && state.steps[0].resource === "research") {
      expect(state.steps[0].filters.subject_entity_id).toBe(ENTITY_ID);
    }
    expect(local.onSelect).not.toHaveBeenCalled();
  });

  it("G31E-P06: at MAX_PIVOT_STEPS navigation pivots disappear but local actions remain", async () => {
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
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    await screen.findByRole("menu");
    expect(screen.getByRole("menuitem", { name: "Expand known relationships" })).toBeInTheDocument();
    // Navigation pivots are depth-suppressed at the maximum depth.
    expect(screen.queryByRole("menuitem", { name: "Evidence for this entity" })).toBeNull();
  });

  it("G31E-P07: a URL no-op pivot is suppressed but local actions remain", async () => {
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
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    await screen.findByRole("menu");
    // Evidence-for-this-entity is the no-op here; relationships/research remain.
    expect(screen.queryByRole("menuitem", { name: "Evidence for this entity" })).toBeNull();
    expect(screen.getByRole("menuitem", { name: "Relationships where source" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Expand known relationships" })).toBeInTheDocument();
  });

  it("G31E-P08: a disabled local action can never execute", async () => {
    const local = localActions([{ disabled: true }]);
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: local,
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    const item = await screen.findByRole("menuitem", { name: "Expand known relationships" });
    expect(item).toBeDisabled();
    // The disabled item is inert: a raw click event never reaches onClick.
    fireEvent.click(item);
    expect(local[0].onSelect).not.toHaveBeenCalled();
  });

  it("G31E-P09: ArrowDown/ArrowUp navigate only the legal enabled items, skipping disabled ones", async () => {
    const locals = localActions([{ disabled: true }]);
    renderMenu("/", {
      actions: [],
      localActions: locals,
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    await screen.findByRole("menu");
    // The second (enabled) item receives focus on open; disabled must be skipped.
    await waitFor(() => {
      expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).toHaveFocus();
    });
    await userEvent.keyboard("{ArrowDown}");
    // Wraps back to the only enabled item.
    expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).toHaveFocus();
    await userEvent.keyboard("{ArrowUp}");
    expect(screen.getByRole("menuitem", { name: "Expand outgoing relationships" })).toHaveFocus();
  });

  it("G31E-P10: Escape closes the menu and returns focus to the trigger", async () => {
    const local = localActions()[0];
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    const trigger = screen.getByRole("button", { name: "Pivot actions" });
    await userEvent.click(trigger);
    await screen.findByRole("menu");
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("menu")).toBeNull();
    });
    expect(trigger).toHaveFocus();
  });

  it("G31E-P11: an outside pointer press closes the menu", async () => {
    const local = localActions()[0];
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    await screen.findByRole("menu");
    await userEvent.click(document.body);
    await waitFor(() => {
      expect(screen.queryByRole("menu")).toBeNull();
    });
  });

  it("G31E-P12: the combined menu keeps the non-modal Portal/Paper architecture", async () => {
    const local = localActions()[0];
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot actions" }));
    const menu = await screen.findByRole("menu");
    // The menu lives in a Portal (document.body), not in a MUI Modal/Menu.
    expect(document.body.contains(menu)).toBe(true);
    expect(menu).toHaveAttribute("role", "menu");
  });

  it("G31E-P13: no actions and no local actions produces no trigger", () => {
    renderMenu("/", { actions: [] });
    expect(screen.queryByRole("button", { name: "Pivot actions" })).toBeNull();
  });
});
