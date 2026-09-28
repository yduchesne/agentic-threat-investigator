// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace tests: polling policy, terminality, cancellation,
// analyst-table routes, the secondary History access and scoped 404
// (PR 24B U20-U27, U43-U49; PR 24C workspace integration).

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import {
  authMeSuccess,
  buildInvestigation,
  investigationDetail404Handler,
  investigationDetailHandler,
  investigationDetailNetworkErrorHandler,
  investigationLifecycleHandler,
  jsonResponse,
  listRequestRecorder,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

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
    expect(
      await screen.findByRole("tab", { name: "Overview" }),
    ).toBeInTheDocument();
    // The index route redirected to the Overview surface.
    expect(
      await screen.findByText("Investigation in progress"),
    ).toBeInTheDocument();
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
    await userEvent.click(await screen.findByRole("menuitem", { name: "History" }));
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
describe("Investigation workspace More menu (PR 31F-1 U34..U37)", () => {
  function renderOverview(stopReason: string | null): { navigate: (url: string) => void } {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "completed",
          completed_at: "2026-06-01T12:00:00Z",
          stop_reason: stopReason,
        }),
      ),
      http.get("*/api/v1/investigations/:id/history", () =>
        jsonResponse({ items: [], next_cursor: null })),
    );
    const { router } = renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    return { navigate: (url: string) => void router.navigate(url) };
  }

  it("opens an anchored menu at the trigger and closes on Escape without navigation (U34/U36)", async () => {
    renderOverview("fatal_error");
    const trigger = await screen.findByRole("button", { name: "More" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(trigger);
    const menu = await screen.findByRole("menu", {}, { timeout: 3000 });
    expect(menu).toBeInTheDocument();
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(await screen.findByRole("menuitem", { name: "History" })).toBeInTheDocument();
    // Escape closes the menu without navigating.
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });

  it("History closes the menu and navigates (U35)", async () => {
    renderOverview("fatal_error");
    await userEvent.click(await screen.findByRole("button", { name: "More" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "History" }));
    expect(
      await screen.findByRole("heading", { name: "History" }),
    ).toBeInTheDocument();
    await screen.findByText("No history rows");
  });

  it("is keyboard-operable through the trigger button (U37)", async () => {
    renderOverview("fatal_error");
    const trigger = await screen.findByRole("button", { name: "More" });
    trigger.focus();
    await userEvent.keyboard("{Enter}");
    await screen.findByRole("menuitem", { name: "History" });
    await userEvent.keyboard("{Escape}");
    expect(document.querySelector('[role="menu"]')).toBeNull();
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
