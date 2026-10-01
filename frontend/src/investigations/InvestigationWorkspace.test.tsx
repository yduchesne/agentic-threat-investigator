// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace tests: polling policy, terminality, cancellation,
// analyst-table routes, the secondary History access and scoped 404
// (PR 24B U20-U27, U43-U49; PR 24C workspace integration).

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import {
  authMeSuccess,
  buildEvidence,
  buildInvestigation,
  completedInvestigationFixture,
  investigationDetail404Handler,
  investigationDetailHandler,
  investigationDetailNetworkErrorHandler,
  investigationLifecycleHandler,
  jsonResponse,
  listRequestRecorder,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import { serializePivotState } from "../pivots/pivot-url";
import type { PivotStep } from "../pivots/pivot-types";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

describe("Investigation workspace routes", () => {
  it("redirects /investigations/:id to the Overview (U43)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}`);
    // The index route redirected to the Overview surface: wait for the
    // substantive Overview content (stable after the redirect), then the
    // now-active Overview tab (PR 31F-8: the active tab is inert).
    expect(
      await screen.findByText("Investigation in progress"),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders the real Evidence route with one bounded collection query (U44)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
      http.get("*/api/v1/investigations/:id/evidence", ({ request }) => {
        const url = new URL(request.url);
        recorder.requests.push({
          status: null,
          cursor: url.searchParams.get("cursor"),
          limit: url.searchParams.get("limit"),
        });
        return jsonResponse({ items: [], next_cursor: null });
      }),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/evidence`);
    expect(
      await screen.findByRole("heading", { name: "Evidence" }),
    ).toBeInTheDocument();
    // The placeholder is gone and the real page rendered its empty state.
    await screen.findByText("No evidence");
    // Exactly one bounded page request, never polling.
    expect(recorder.requests).toHaveLength(1);
    expect(recorder.requests[0].limit).toBe("25");
  });

  it("renders the real Relationships route (U45)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
      http.get("*/api/v1/investigations/:id/relationships", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/relationships`);
    expect(
      await screen.findByRole("heading", { name: "Relationships" }),
    ).toBeInTheDocument();
    await screen.findByText("No relationships");
  });

  it("renders the real Research route (U46)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
      http.get("*/api/v1/investigations/:id/research", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/research`);
    expect(
      await screen.findByRole("heading", { name: "Research context" }),
    ).toBeInTheDocument();
    await screen.findByText("No research results");
  });

  it("renders the real Timeline route (U47)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
      http.get("*/api/v1/investigations/:id/timeline", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/timeline`);
    expect(
      await screen.findByRole("heading", { name: "Timeline" }),
    ).toBeInTheDocument();
    await screen.findByText("No timeline events");
  });

  it("exposes secondary History through More -> History (U49)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
      ),
      http.get("*/api/v1/investigations/:id/history", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    await screen.findByRole("heading", { name: "assess the update-package delivery domain" });
    await userEvent.click(screen.getByRole("button", { name: "More" }));
    const nav = await screen.findByRole("navigation", {
      name: "More investigation navigation",
    });
    await userEvent.click(within(nav).getByRole("link", { name: "History" }));
    expect(
      await screen.findByRole("heading", { name: "History" }),
    ).toBeInTheDocument();
    await screen.findByText("No history rows");
  });

  it("renders a scoped not-found UI on detail 404 (U48)", async () => {
    setHttpHandlers(...AUTH, investigationDetail404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(
      await screen.findByText("Investigation not found or not accessible"),
    ).toBeInTheDocument();
  });

  it("renders a bounded error surface on detail transport failure (U48b)", async () => {
    setHttpHandlers(...AUTH, investigationDetailNetworkErrorHandler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(
      await screen.findByText("Unable to load the Investigation"),
    ).toBeInTheDocument();
    // No invented partial state is rendered.
    expect(screen.queryByText("Investigation in progress")).not.toBeInTheDocument();
  });

  it("keeps the persistent header visible across analyst-table routes (U44b)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "running",
          objective: "assess the update-package delivery domain",
        }),
      ]),
      // Pending/running explains why a fresh route navigation issues once.
      http.get("*/api/v1/investigations/:id/timeline", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/timeline`);
    expect(
      await screen.findByRole("heading", {
        name: "assess the update-package delivery domain",
      }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Running").length).toBeGreaterThan(0);
    // Running notice with a bounded Refresh is visible (no polling).
    expect(
      await screen.findByText(/Investigation still running; the timeline may change/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });
});
describe("Investigation workspace More navigation + legacy pivot policy (PR 31F-7 M01..M11; PR 31F-8 N03/N04)", () => {
  function renderOverview(): { navigate: (url: string) => void } {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "completed",
          completed_at: "2026-06-01T12:00:00Z",
          stop_reason: "fatal_error",
        }),
      ),
      http.get("*/api/v1/investigations/:id/history", () =>
        jsonResponse({ items: [], next_cursor: null })),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[]],
        recorder: resourceListRecorder(),
      }),
    );
    const { router } = renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    return { navigate: (url: string) => void router.navigate(url) };
  }

  const MORE_REGION_LABEL = "More investigation navigation";

  it("M01: starts collapsed with no in-flow region", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(trigger).not.toHaveAttribute("aria-controls");
    expect(
      screen.queryByRole("navigation", { name: MORE_REGION_LABEL }),
    ).not.toBeInTheDocument();
  });

  it("M02: activating More expands an ordinary in-flow disclosure region", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(trigger).toHaveAttribute("aria-controls", "investigation-more-region");
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    expect(nav).toBeInTheDocument();
    expect(nav.id).toBe("investigation-more-region");
    // The region is a sibling of the trigger in the ordinary workspace
    // layout (in place, never portaled to the end of <body>).
    expect(trigger.parentElement).toBe(nav.parentElement);
  });

  it("M03: Close and the trigger toggle both collapse the disclosure", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    await userEvent.click(within(nav).getByRole("button", { name: "Close" }));
    expect(
      screen.queryByRole("navigation", { name: MORE_REGION_LABEL }),
    ).not.toBeInTheDocument();
    expect(trigger).toHaveAttribute("aria-expanded", "false");

    // Toggling the trigger again expands and collapses without navigating.
    await userEvent.click(trigger);
    expect(
      screen.getByRole("navigation", { name: MORE_REGION_LABEL }),
    ).toBeInTheDocument();
    await userEvent.click(trigger);
    expect(
      screen.queryByRole("navigation", { name: MORE_REGION_LABEL }),
    ).not.toBeInTheDocument();
  });

  it("M04/M05: the History destination is preserved with its exact route", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    const historyLink = within(nav).getByRole("link", { name: "History" });
    expect(historyLink).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/history`,
    );
  });

  it("M06: activating History causes exactly one navigation", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    const historyLink = within(nav).getByRole("link", { name: "History" });
    await userEvent.click(historyLink);
    expect(
      await screen.findByRole("heading", { name: "History" }),
    ).toBeInTheDocument();
    await screen.findByText("No history rows");
  });

  it("M07: the Close action collapses without navigating", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    await userEvent.click(within(nav).getByRole("button", { name: "Close" }));
    // Still on the Overview route: no navigation happened.
    expect(
      screen.queryByRole("heading", { name: "History" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "assess the update-package delivery domain" }),
    ).toBeInTheDocument();
  });

  it("M08: Tab reaches the trigger and the region entries and can leave (no focus trap)", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    trigger.focus();
    await userEvent.keyboard("{Enter}");
    const nav = screen.getByRole("navigation", { name: MORE_REGION_LABEL });
    const historyLink = within(nav).getByRole("link", { name: "History" });
    const close = within(nav).getByRole("button", { name: "Close" });

    await userEvent.tab();
    expect(historyLink).toHaveFocus();
    await userEvent.tab();
    expect(close).toHaveFocus();
    // Tab can leave the region entirely (no focus trap).
    await userEvent.tab();
    expect(close).not.toHaveFocus();
    expect(historyLink).not.toHaveFocus();
  });

  it("M09: native Enter and Space toggle the trigger", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    trigger.focus();
    await userEvent.keyboard("{Enter}");
    expect(
      screen.getByRole("navigation", { name: MORE_REGION_LABEL }),
    ).toBeInTheDocument();
    await userEvent.keyboard(" ");
    expect(
      screen.queryByRole("navigation", { name: MORE_REGION_LABEL }),
    ).not.toBeInTheDocument();
  });

  it("M10: the expanded disclosure keeps no menu/Portal/modal contract", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    expect(screen.getByRole("navigation", { name: MORE_REGION_LABEL })).toBeInTheDocument();
    // No ARIA menu/menuitem, no modal, no MUI Popover/Menu Portal anywhere.
    expect(document.querySelector('[role="menu"]')).toBeNull();
    expect(document.querySelector('[role="menuitem"]')).toBeNull();
    expect(document.querySelector('[aria-modal="true"]')).toBeNull();
    expect(document.querySelector(".MuiPopover-root")).toBeNull();
  });

  it("M11: the normal workbench stays usable with no body masking", async () => {
    renderOverview();
    const trigger = await screen.findByRole("button", { name: "More" });
    await userEvent.click(trigger);
    expect(screen.getByRole("navigation", { name: MORE_REGION_LABEL })).toBeInTheDocument();
    // No body lock / aria-hidden masking while the disclosure is open.
    expect(document.body.getAttribute("aria-hidden")).toBeNull();
    // A primary tab remains operable beside the open disclosure.
    await userEvent.click(screen.getByRole("tab", { name: "Evidence" }));
    expect(
      await screen.findByRole("heading", { name: "Evidence" }),
    ).toBeInTheDocument();
  });

  it("N03: a valid legacy pivot URL redirects once to its canonical route and drops the parameter", async () => {
    const recorder = resourceListRecorder();
    const entityId = uuidAt(101);
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [
          [
            buildEvidence({
              id: uuidAt(1),
              subject_entity_id: entityId,
              subject_value: "update-package.test",
            }),
          ],
        ],
        recorder,
      }),
    );
    const steps: PivotStep[] = [
      {
        resource: "relationships",
        filters: { source_entity_id: entityId },
        selectedId: null,
        label: "update-package.test",
        sourceKind: "table_cell",
      },
    ];
    const pivot = serializePivotState({ steps });
    expect(pivot).not.toBeNull();
    const { router } = renderAtPath(
      `/investigations/${INVESTIGATION_ID}?pivot=${pivot ?? ""}`,
    );
    // The workspace redirects (replace) to the active step's canonical
    // route; the legacy pivot parameter never survives (N03).
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/relationships`,
      );
    });
    expect(router.state.location.search).toBe(`?source_entity_id=${entityId}`);
    expect(router.state.location.search).not.toContain("pivot=");
  });

  it("N04: malformed legacy pivot state is removed safely without navigation or crash", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[]],
        recorder: resourceListRecorder(),
      }),
    );
    const { router } = renderAtPath(
      `/investigations/${INVESTIGATION_ID}/overview?pivot=!!!not-an-envelope!!!`,
    );
    // Malformed pivot state is dropped in place; the canonical route stays
    // and the router never crashes.
    await waitFor(() => {
      expect(router.state.location.search).toBe("");
    });
    expect(router.state.location.pathname).toBe(
      `/investigations/${INVESTIGATION_ID}/overview`,
    );
    // The normal Investigation shell is mounted and usable.
    expect(
      await screen.findByRole("tab", { name: "Overview" }),
    ).toBeInTheDocument();
  });
});

describe("Investigation header stop reason (PR 31F-1 U32/U33)", () => {
  it("shows the human label for a known stop reason and the raw value for unknown", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "completed",
          completed_at: "2026-06-01T12:00:00Z",
          stop_reason: "fatal_error",
        }),
      ),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect((await screen.findAllByText("Stop reason: Fatal error")).length).toBeGreaterThan(0);
    expect(screen.queryByText(/Stop reason: fatal_error/)).not.toBeInTheDocument();

    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "completed",
          completed_at: "2026-06-01T12:00:00Z",
          stop_reason: "future_unknown_reason",
        }),
      ),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(
      (await screen.findAllByText("Stop reason: future_unknown_reason")).length,
    ).toBeGreaterThan(0);
  });
});
