// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace tests: polling policy, terminality, cancellation,
// placeholders and scoped 404 (PR 24B U20-U27, U43-U49).

import { screen } from "@testing-library/react";
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

  it("renders Evidence as a bounded placeholder without collection queries (U44)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
      // If the browser asked the Evidence collection, this unhandled state
      // would fail; the placeholder must not fetch anything.
      http.get("*/api/v1/investigations/:id/evidence", () => {
        recorder.requests.push({ status: null, cursor: null, limit: null });
        return jsonResponse({ items: [], next_cursor: null });
      }),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/evidence`);
    expect(
      await screen.findByText(
        /The evidence workspace arrives in a later release/,
      ),
    ).toBeInTheDocument();
    expect(recorder.requests).toHaveLength(0);
  });

  it("renders Relationships as a bounded placeholder (U45)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/relationships`);
    expect(
      await screen.findByText(
        /The relationships workspace arrives in a later release/,
      ),
    ).toBeInTheDocument();
  });

  it("renders Research as a bounded placeholder (U46)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/research`);
    expect(
      await screen.findByText(
        /The research workspace arrives in a later release/,
      ),
    ).toBeInTheDocument();
  });

  it("renders Timeline as a bounded placeholder (U47)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/timeline`);
    expect(
      await screen.findByText(
        /The timeline workspace arrives in a later release/,
      ),
    ).toBeInTheDocument();
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

  it("keeps the persistent header visible across placeholder routes (U44b)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationDetailHandler(
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "running",
          objective: "assess the update-package delivery domain",
        }),
      ),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/timeline`);
    expect(
      await screen.findByRole("heading", {
        name: "assess the update-package delivery domain",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
  });
});