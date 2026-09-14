// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace tests: polling policy, terminality, cancellation,
// analyst-table routes, the secondary History access and scoped 404
// (PR 24B U20-U27, U43-U49; PR 24C workspace integration).

import { screen } from "@testing-library/react";
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