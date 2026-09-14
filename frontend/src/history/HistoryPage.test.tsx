// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History page tests (PR 24C H01-H08).
//
// Generic History surfaces only allowlisted public rows; exact-version
// detail renders redacted state/diff as escaped data; non-allowlisted
// object types are never sent. RelationshipObservation never appears as
// generic history.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildHistoryRecord,
  completedInvestigationFixture,
  errorResponse,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/history`;

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

describe("History page", () => {
  it("renders object/type/op/version/time/actor columns (H01)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[buildHistoryRecord()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("Updated")).toBeInTheDocument();
    expect(screen.getByText("investigation")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T09:00:02Z")).toBeInTheDocument();
  });

  it("applies exact operation and occurred filters (H02)", { timeout: 15_000 }, async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[buildHistoryRecord()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Updated");
    await userEvent.click(screen.getByRole("combobox", { name: "Operation" }));
    await userEvent.click(await screen.findByRole("option", { name: "Created" }));
    await userEvent.type(screen.getByLabelText("Occurred from"), "2026-06-01T00:00");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await screen.findByText("Updated");
    const last = recorder.requests.at(-1);
    expect(last?.params.operation).toBe("CREATE");
    expect(last?.params.occurred_from).toMatch(/2026-06-01T\d{2}:\d{2}:\d{2}Z/);
  });

  it("only offers backend-public object types (H03)", { timeout: 15_000 }, async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[buildHistoryRecord()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Updated");
    await userEvent.click(screen.getByRole("combobox", { name: "Object type" }));
    const options = screen.getAllByRole("option");
    const values = options.map((option) => option.getAttribute("data-value") ?? "");
    expect(values).not.toContain("credential");
    expect(values).not.toContain("session");
    expect(values).toContain("investigation");
    expect(values).toContain("entity");
    expect(values).toContain("relationship");
    expect(values).toContain("assessment");
    expect(values).toContain("investigation_report");
    await userEvent.click(await screen.findByRole("option", { name: "Entity" }));
    await userEvent.click(screen.getAllByRole("button", { name: "Apply" })[0]);
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.object_type).toBe("entity");
    });
  });

  it("renders exact-version state/diff as escaped data (H04, H05)", async () => {
    const record = buildHistoryRecord({
      state: { status: "running", version: 2 },
      diff: { status: { before: "pending", after: "running" } },
    });
    const detail = buildHistoryRecord({
      id: "40000000-0000-4000-8000-000000000141",
      state: { status: "completed", "<script>" : "x" },
      diff: { status: { before: "running", after: "completed" } },
    });
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[record]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/history/:objectType/:objectId/:version", () =>
        jsonResponse(detail)),
    );
    renderAtPath(`${BASE}?selected=${record.id}`);
    expect(await screen.findByText("State")).toBeInTheDocument();
    expect(screen.getByText("Diff")).toBeInTheDocument();
    expect(screen.getByText(/running/)).toBeInTheDocument();
    // The malicious key stays escaped text, never markup.
    expect(screen.queryByRole("script")).not.toBeInTheDocument();
    expect(screen.getByText(/<script>/)).toBeInTheDocument();
  });

  it("browses bounded object versions inside the drawer (H06)", async () => {
    const record = buildHistoryRecord();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[record]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/history/:objectType/:objectId/:version", () =>
        jsonResponse(record)),
      // Object-scoped browsing returns one bounded page.
      http.get("*/api/v1/investigations/:id/history/:objectType/:objectId", ({ request }) => {
        const url = new URL(request.url);
        expect(url.searchParams.get("limit")).toBe("25");
        return jsonResponse({
          items: [
            buildHistoryRecord({ version: 1, operation: "CREATE" }),
            buildHistoryRecord({ version: 2, operation: "UPDATE" }),
          ],
          next_cursor: null,
        });
      }),
    );
    renderAtPath(`${BASE}?selected=${record.id}`);
    await userEvent.click(
      await screen.findByRole("button", { name: "View versions of this object" }),
    );
    expect(await screen.findByText(/v1/)).toBeInTheDocument();
    expect(screen.getByText(/v2/)).toBeInTheDocument();
    // The object-scoped request is History-internal and bounded.
    expect(screen.queryByText("No history rows")).not.toBeInTheDocument();
  });

  it("rejects non-allowlisted object types in the URL before sending them (H03b)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[buildHistoryRecord()]],
        recorder,
      }),
    );
    renderAtPath(`${BASE}?object_type=credential`);
    await screen.findByText("Updated");
    await waitFor(() => {
      for (const request of recorder.requests) {
        expect(request.params.object_type).not.toBe("credential");
      }
    });
  });

  it("never fetches relationship_observation through generic history (H08)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[buildHistoryRecord()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Updated");
    for (const request of recorder.requests) {
      expect(request.params.object_type).not.toBe("relationship_observation");
    }
  });

  it("renders a scoped 404 inside the drawer for a missing exact version (H05b)", async () => {
    const record = buildHistoryRecord();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/history",
        pages: [[record]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/history/:objectType/:objectId/:version", () =>
        errorResponse(404, "not_found")),
    );
    renderAtPath(`${BASE}?selected=${record.id}`);
    expect(
      await screen.findByText("Version not found or not accessible"),
    ).toBeInTheDocument();
  });
});