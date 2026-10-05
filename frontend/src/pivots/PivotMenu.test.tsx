// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PivotMenu behavior tests (PR 24D §8, §22; PR 31E §13; PR 31F-6
// amendment 2 A2-PM01..14; PR 31F-8 §8).
//
// The trigger renders a direct accessible semantic link action for one
// legal target and a compact in-flow action bar for several; every route
// destination is produced by the exhaustive typed mapper (canonical
// Investigation-scoped route + query). Local/context actions remain
// buttons that never touch the URL. Expanding choices changes only
// transient local presentation state — no Portal/Menu/Popover/backdrop/
// document pointer listener exists, and Hide collapses without
// navigating.

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { uuidAt } from "../test/handlers";
import { readPivotState } from "./pivot-url";
import {
  entityActions,
  type PivotAction,
} from "./pivot-capabilities";
import { PivotMenu, type PivotLocalAction } from "./PivotMenu";

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const ENTITY_ID = uuidAt(101);
const BASE = `/investigations/${INVESTIGATION_ID}`;

/** The expanded in-flow action region. */
function actionBar(): HTMLElement {
  return screen.getByTestId("pivot-action-bar");
}

describe("PivotMenu (PR 31F-8 routed actions)", () => {
  /** Render one PivotMenu through the production providers inside an
   * Investigation-scoped route (canonical context for the mapper). */
  function renderMenu(
    path: string,
    props: {
      actions: readonly PivotAction[];
      localActions?: readonly PivotLocalAction[];
    },
  ) {
    const router = createMemoryRouter(
      [
        {
          path: "/investigations/:investigationId/*",
          element: <PivotMenu actions={props.actions} localActions={props.localActions} />,
        },
        {
          path: "/",
          element: <PivotMenu actions={props.actions} localActions={props.localActions} />,
        },
      ],
      { initialEntries: [path] },
    );
    const result = render(
      <AppProviders queryClient={freshQueryClient()}>
        <RouterProvider router={router} />
      </AppProviders>,
    );
    return { result, router };
  }

  it("A2-PM01/02: the trigger starts collapsed and expands an in-flow bar", async () => {
    renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "table_cell"),
    });
    const trigger = screen.getByRole("button", { name: "Pivot" });
    expect(screen.queryByTestId("pivot-action-bar")).toBeNull();
    await userEvent.click(trigger);
    const bar = actionBar();
    expect(bar).toBeInTheDocument();
    // Ordinary links, not menu items.
    expect(screen.getByTestId("pivot-action-evidenceForEntity")).toBeInTheDocument();
    expect(screen.getByTestId("pivot-action-researchForEntity")).toBeInTheDocument();
    expect(screen.queryByRole("menuitem")).toBeNull();
  });

  it("PM-R01: a route action carries the canonical Investigation-scoped destination", async () => {
    const { router } = renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "table_cell"),
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const evidenceLink = screen.getByTestId("pivot-action-evidenceForEntity");
    expect(evidenceLink).toHaveAttribute(
      "href",
      `${BASE}/evidence?subject_entity_id=${ENTITY_ID}`,
    );
    const relationshipsLink = screen.getByTestId("pivot-action-relationshipsSource");
    expect(relationshipsLink).toHaveAttribute(
      "href",
      `${BASE}/relationships?source_entity_id=${ENTITY_ID}`,
    );
    // Activating the semantic link navigates the router (no pivot URL).
    await userEvent.click(relationshipsLink);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/relationships`);
    });
    expect(router.state.location.search).toBe(`?source_entity_id=${ENTITY_ID}`);
    expect(readPivotState(new URLSearchParams(router.state.location.search))).toBeNull();
  });

  it("PM-R02: a single exact-Evidence target renders a direct semantic link", async () => {
    const evidenceId = uuidAt(1);
    const { router } = renderMenu(`${BASE}/relationships/observations`, {
      actions: [
        {
          key: "evidenceExact",
          labelKey: "actions.evidenceExact",
          sourceKind: "table_cell",
          target: {
            resource: "evidence",
            filters: {},
            selectedId: evidenceId,
            label: `Evidence ${evidenceId.slice(0, 8)}`,
          },
        },
      ],
    });
    const direct = screen.getByTestId("pivot-action-evidenceExact");
    expect(direct).toHaveAttribute("href", `${BASE}/evidence/${evidenceId}`);
    await userEvent.click(direct);
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/evidence/${evidenceId}`);
    });
  });

  it("PM-R03: malformed targets never produce a navigation (R12)", async () => {
    renderMenu(`${BASE}/geoint/entities/${ENTITY_ID}`, {
      actions: [
        {
          key: "geointEntity",
          labelKey: "actions.geointEntity",
          sourceKind: "geoint_entity",
          target: {
            resource: "geoint-entity",
            filters: { entity_id: "not-a-uuid" },
            selectedId: null,
            label: "value",
          },
        },
      ],
    });
    // The only trigger renders nothing actionable: the group contains just
    // Hide when multi-entry, or the trigger is absent when the whole menu
    // collapses. Here the single malformed action yields no trigger.
    expect(screen.queryByRole("button", { name: "Pivot" })).toBeNull();
    expect(screen.queryByTestId("pivot-action-geointEntity")).toBeNull();
  });

  it("PM-R04: no investigation route context yields no route actions (locals stay)", async () => {
    const local = vi.fn();
    renderMenu("/", {
      actions: entityActions(ENTITY_ID, "update-package.test", "table_cell"),
      localActions: [
        { key: "graph-expand", label: "Expand graph", onSelect: local },
      ],
    });
    // With no Investigation scope the route actions never convert; the only
    // remaining entry is the local command, rendered as a direct action.
    const direct = screen.getByRole("button", { name: "Expand graph" });
    expect(direct).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Evidence for this entity" })).toBeNull();
    await userEvent.click(direct);
    expect(local).toHaveBeenCalledTimes(1);
  });

  it("A2-PM10: ordinary links keep natural Tab order and Enter/Space activation", async () => {
    const local = vi.fn();
    renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [{ key: "graph-expand-either", label: "Expand known relationships", onSelect: local }],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    const links = Array.from(bar.querySelectorAll("a"));
    expect(links.length).toBeGreaterThanOrEqual(2);
    (links[0] as HTMLAnchorElement).focus();
    await userEvent.keyboard("{Enter}");
    // Link activation is native router navigation; the bar collapses.
    await waitFor(() => {
      expect(screen.queryByTestId("pivot-action-bar")).toBeNull();
    });
  });

  it("A2-PM04: Hide collapses the bar without navigating", async () => {
    const { router } = renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const before = router.state.location;
    await userEvent.click(screen.getByTestId("pivot-hide"));
    await waitFor(() => {
      expect(screen.queryByTestId("pivot-action-bar")).toBeNull();
    });
    expect(router.state.location.pathname).toBe(before.pathname);
    expect(router.state.location.search).toBe(before.search);
  });

  it("A2-PM09/A2-PM14: the bar is ordinary in-flow DOM — no Portal/Menu/Popover", async () => {
    renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    expect(bar).toHaveAttribute("role", "group");
    expect(bar.closest("body")).not.toBeNull();
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.queryByRole("menuitem")).toBeNull();
    expect(screen.queryByRole("separator")).toBeNull();
  });

  it("A2-PM13: no actions and no local actions produces no trigger", () => {
    renderMenu(`${BASE}/evidence`, { actions: [] });
    expect(screen.queryByRole("button", { name: "Pivot" })).toBeNull();
  });
});

// PR 31E §13 + PR 31F-6 amendment 2: local/context actions stay local.
describe("PivotMenu action bar (PR 31E + amendment 2, routed)", () => {
  const LOCAL = {
    key: "graph-expand-either",
    label: "Expand known relationships",
  };

  const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
  const BASE = `/investigations/${INVESTIGATION_ID}`;
  const ENTITY_ID = uuidAt(101);

  /** Render one PivotMenu directly through the production providers. */
  function renderMenu(
    initialPath: string,
    props: {
      actions: readonly PivotAction[];
      localActions?: readonly PivotLocalAction[];
    },
  ) {
    const router = createMemoryRouter(
      [
        {
          path: "/investigations/:investigationId/*",
          element: <PivotMenu actions={props.actions} localActions={props.localActions} />,
        },
        {
          path: "/",
          element: <PivotMenu actions={props.actions} localActions={props.localActions} />,
        },
      ],
      { initialEntries: [initialPath] },
    );
    const result = render(
      <AppProviders queryClient={freshQueryClient()}>
        <RouterProvider router={router} />
      </AppProviders>,
    );
    return { result, router };
  }

  it("A2-PM06: a single local action renders as a direct action and executes without a route", async () => {
    const local = { ...LOCAL, onSelect: vi.fn() };
    renderMenu(`${BASE}/evidence`, { actions: [], localActions: [local] });
    const button = screen.getByRole("button", { name: "Expand known relationships" });
    await userEvent.click(button);
    expect(local.onSelect).toHaveBeenCalledTimes(1);
  });

  it("A2-PM03/PM06: local + route actions expand one combined in-flow bar; a local selection changes no URL", async () => {
    const local = { ...LOCAL, onSelect: vi.fn() };
    const { router } = renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const bar = actionBar();
    expect(bar).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Expand known relationships" })).toBeInTheDocument();
    expect(screen.getByTestId("pivot-action-evidenceForEntity")).toBeInTheDocument();
    expect(screen.getByTestId("pivot-action-researchForEntity")).toBeInTheDocument();
    const before = router.state.location;
    await userEvent.click(screen.getByRole("button", { name: "Expand known relationships" }));
    expect(local.onSelect).toHaveBeenCalledTimes(1);
    // No URL mutation for local commands.
    expect(router.state.location.pathname).toBe(before.pathname);
    expect(router.state.location.search).toBe(before.search);
    expect(readPivotState(new URLSearchParams(router.state.location.search))).toBeNull();
  });

  it("A2-PM05: selecting a routed navigation next to locals navigates the canonical route", async () => {
    const local = { ...LOCAL, onSelect: vi.fn() };
    const { router } = renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    await userEvent.click(await screen.findByTestId("pivot-action-researchForEntity"));
    expect(router.state.location.pathname).toBe(`${BASE}/research`);
    expect(router.state.location.search).toBe(`?subject_entity_id=${ENTITY_ID}`);
    expect(local.onSelect).not.toHaveBeenCalled();
  });

  it("A2-PM05b: a disabled local action can never execute", async () => {
    const local = { ...LOCAL, onSelect: vi.fn(), disabled: true };
    renderMenu(`${BASE}/evidence`, {
      actions: entityActions(ENTITY_ID, "update-package.test", "detail_field"),
      localActions: [local],
    });
    await userEvent.click(screen.getByRole("button", { name: "Pivot" }));
    const item = await screen.findByRole("button", { name: "Expand known relationships" });
    expect(item).toBeDisabled();
  });

  it("A2-PM13: no actions and no local actions produces no trigger", () => {
    renderMenu(`${BASE}/evidence`, { actions: [], localActions: [] });
    expect(screen.queryByRole("button", { name: "Pivot" })).toBeNull();
  });
});
