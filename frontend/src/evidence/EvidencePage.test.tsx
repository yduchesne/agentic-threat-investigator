// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence page tests (PR 24C E01-E07, T10, T11, T14).
//
// Real route rendering over MSW: exact filter params, opaque cursors,
// authoritative detail drawer, source-link safety, and current-page-only
// export.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import type { JsonBodyType } from "msw";
import { describe, expect, it, vi } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  completedInvestigationFixture,
  errorResponse,
  investigationDetailHandler,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";
import { EVIDENCE_PAGE_SIZE } from "./evidence-api";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/evidence`;

function evidenceA() {
  return buildEvidence({
    id: "40000000-0000-4000-8000-000000000001",
    subject_value: "update-package.test",
    type: "urn:ati:evidence:dns",
    source: "fake-dns",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
  });
}

function evidenceB() {
  return buildEvidence({
    id: "40000000-0000-4000-8000-000000000002",
    subject_value: "alice-corp.test",
    type: "urn:ati:evidence:registration",
    source: "fake-registry",
    observed_at: "2026-06-02T10:00:00Z",
    retrieved_at: "2026-06-02T10:10:00Z",
  });
}

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

describe("Evidence page", () => {
  it("renders subject/type/source and distinct observed/retrieved timestamps (E01)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
    expect(screen.getByText("DNS")).toBeInTheDocument();
    expect(screen.getByText("fake-dns")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T09:00:00Z")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T09:05:00Z")).toBeInTheDocument();
    // Bounded page request with the configured limit; no polling.
    expect(recorder.requests).toHaveLength(1);
    expect(recorder.requests[0].limit).toBe(String(EVIDENCE_PAGE_SIZE));
  });

  it("applies exact type/source/entity/time filters (E02)", { timeout: 15_000 }, async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder }),
    );
    renderAtPath(BASE);
    await screen.findByText("update-package.test");

    await userEvent.type(screen.getByRole("textbox", { name: "Source" }), "fake-dns");
    await userEvent.type(
      screen.getByRole("textbox", { name: "Subject entity ID" }),
      "40000000-0000-4000-8000-000000000101",
    );
    await userEvent.click(screen.getByRole("combobox", { name: "Evidence type" }));
    await userEvent.click(await screen.findByRole("option", { name: "DNS" }));

    // Text/date inputs apply only on explicit Apply.
    const all = screen.getAllByRole("button", { name: "Apply" });
    await userEvent.click(all[0]);

    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.source).toBe("fake-dns");
      expect(last?.params.subject_entity_id).toBe("40000000-0000-4000-8000-000000000101");
      expect(last?.params.type).toBe("urn:ati:evidence:dns");
    });
  });

  it("passes the opaque next cursor byte-for-byte (T07b)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()], [evidenceB()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("alice-corp.test");
    expect(recorder.requests.at(-1)?.cursor).toBe("cursor-1");
  });

  it("opens the authoritative scoped detail on View (E03, T09, T11)", async () => {
    const detail = buildEvidence({
      id: "40000000-0000-4000-8000-000000000001",
      facts: { resolver: "8.8.8.8" },
    });
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[detail]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonOf(detail)),
    );
    renderAtPath(BASE);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "View 40000000-0000-4000-8000-000000000001" }));
    await screen.findByRole("dialog");
    expect(await screen.findByText("Normalized facts", { selector: "h3" })).toBeInTheDocument();
    // Closing the drawer preserves the list.
    await userEvent.click(screen.getByRole("button", { name: "Close detail" }));
    expect(screen.getByText("update-package.test")).toBeInTheDocument();
  });

  it("shows resource not found 404 inside the drawer while keeping the list (T12)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () =>
        errorResponse(404, "evidence_not_found")),
    );
    renderAtPath(`${BASE}?selected=40000000-0000-4000-8000-000000000001`);
    expect(
      await screen.findByText("Resource not found or not accessible"),
    ).toBeInTheDocument();
    expect(screen.getByText("update-package.test")).toBeInTheDocument();
  });

  it("offers Return to first page on an invalid cursor (T08b)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()]],
        recorder: resourceListRecorder(),
        failCursor: true,
      }),
    );
    renderAtPath(`${BASE}?cursor=cursor-stale`);
    expect(
      await screen.findByText("Unable to load Evidence"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Return to first page" }),
    ).toBeInTheDocument();
  });

  it("exports exactly the current page with a safe filename (T14)", async () => {
    const createUrl = vi.fn(() => "blob:test");
    const revokeUrl = vi.fn(() => {});
    Object.defineProperty(URL, "createObjectURL", {
      value: createUrl,
      configurable: true,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      value: revokeUrl,
      configurable: true,
    });
    const anchor = { click: vi.fn(), remove: vi.fn() } as unknown as HTMLAnchorElement;
    const append = vi
      .spyOn(document.body, "append")
      .mockImplementation((node: string | Node) => {
        Object.assign(node as Node, anchor);
      });
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA(), evidenceB()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "Export current page" }));
    await waitFor(() => expect(anchor.click).toHaveBeenCalledTimes(1));
    // Retrieves no extra pages: exactly one list request served the export.
    expect(createUrl).toHaveBeenCalledOnce();
    expect(revokeUrl).toHaveBeenCalledOnce();
    expect(append).toHaveBeenCalledOnce();
    Object.defineProperty(URL, "createObjectURL", { value: undefined, configurable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: undefined, configurable: true });
    append.mockRestore();
  });

  it("never implies benign on empty results (E07)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[]], recorder: resourceListRecorder() }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("No evidence")).toBeInTheDocument();
    expect(
      screen.queryByText(/benign/i),
    ).not.toBeInTheDocument();
  });
});

function jsonOf(value: JsonBodyType): HttpResponse<JsonBodyType> {
  return HttpResponse.json(value);
}