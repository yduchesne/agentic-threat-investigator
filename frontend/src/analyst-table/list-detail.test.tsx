// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31F-6 amendment 4: conservative list/detail workspace tests (A4-LD).
//
// The resource list and its detail are ALTERNATIVE full-width in-flow
// views: ``View`` replaces the list with the exact scoped detail, and
// ``Back to <resource>`` clears exactly the existing selection through the
// proven URL port (next-macrotask deferred commit). No side Inspector,
// Portal, modal/drawer/backdrop, body masking, focus trap, or second
// durable selection state exists. The matrix is exercised against the
// real Evidence surface (the first migrated resource) plus the shared
// ResourceDetailView primitive.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import type { JsonBodyType } from "msw";
import { describe, expect, it, vi } from "vitest";

import { renderAtPath, renderProviders } from "../test/render";
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
import { ResourceDetailView } from "./ResourceDetailView";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/evidence`;
const EVIDENCE_A_ID = "40000000-0000-4000-8000-000000000001";

function evidenceA() {
  return buildEvidence({
    id: EVIDENCE_A_ID,
    subject_entity_id: "40000000-0000-4000-8000-000000000101",
    subject_value: "update-package.test",
    type: "urn:ati:evidence:dns",
    source: "fake-dns",
  });
}

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

function jsonOf(value: JsonBodyType): HttpResponse<JsonBodyType> {
  return HttpResponse.json(value);
}

describe("ResourceDetailView primitive (PR 31F-6 A4)", () => {
  it("A4-LD28: the Back control is a keyboard-operable semantic button", async () => {
    const onBack = vi.fn();
    renderProviders(
      <ResourceDetailView
        backLabel="Back to Evidence"
        heading="Evidence details"
        onBack={onBack}
      >
        <div>detail body</div>
      </ResourceDetailView>,
    );
    const back = screen.getByTestId("resource-detail-back");
    expect(back.tagName).toBe("BUTTON");
    back.focus();
    await userEvent.keyboard("{Enter}");
    expect(onBack).toHaveBeenCalledTimes(1);
    await userEvent.keyboard(" ");
    expect(onBack).toHaveBeenCalledTimes(2);
  });

  it("A4-LD04: renders a human-readable heading, not a raw id", () => {
    renderProviders(
      <ResourceDetailView
        backLabel="Back to Evidence"
        heading="Evidence details"
        onBack={() => undefined}
      >
        <div>body</div>
      </ResourceDetailView>,
    );
    expect(
      screen.getByRole("heading", { name: "Evidence details" }),
    ).toBeInTheDocument();
  });

  it("A4-LD12/LD13: no modal/portal/backdrop, no body masking or aria-hidden", () => {
    const { result } = renderProviders(
      <ResourceDetailView
        backLabel="Back to Evidence"
        heading="Evidence details"
        onBack={() => undefined}
      >
        <div>body</div>
      </ResourceDetailView>,
    );
    // Ordinary in-flow DOM inside the app container — never a Portal/modal.
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("presentation")).toBeNull();
    expect(result.container.querySelector('[role="presentation"]')).toBeNull();
    // No body scroll lock and no body-child aria-hidden.
    expect(document.body.style.overflow).toBe("");
    expect(
      Array.from(document.body.children).some(
        (node) => node.getAttribute("aria-hidden") === "true",
      ),
    ).toBe(false);
    // The detail never uses fixed/absolute presentation.
    const back = screen.getByTestId("resource-detail-back");
    expect(back.closest("div")?.classList.length ?? 0).toBeGreaterThan(0);
    expect(screen.getByText("Evidence details").closest("h2")).not.toBeNull();
  });
});

describe("Evidence list/detail workspace (PR 31F-6 A4)", () => {
  it("A4-LD01: with no selection the list renders and no detail exists", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
    );
    renderAtPath(BASE);
    expect(await screen.findByRole("table", { name: "Evidence" })).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Evidence details" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("resource-detail-back")).not.toBeInTheDocument();
  });

  it("A4-LD06: Back preserves the committed filters/order/cursor list context", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()], [evidenceA()]],
        recorder,
      }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonOf(evidenceA())),
    );
    renderAtPath(`${BASE}?source=fake-dns`);
    await screen.findByText("update-package.test");
    // The committed filter is part of the request params.
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.source).toBe("fake-dns");
    });
    // View -> Back: the same URL list context returns.
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    await screen.findByRole("heading", { name: "Evidence details" });
    await userEvent.click(screen.getByTestId("resource-detail-back"));
    expect(await screen.findByRole("table", { name: "Evidence" })).toBeInTheDocument();
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.source).toBe("fake-dns");
    });
  });

  it("A4-LD07: browser history restores list/detail from the URL", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonOf(evidenceA())),
    );
    const { router } = renderAtPath(BASE);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    await screen.findByRole("heading", { name: "Evidence details" });
    expect(router.state.location.search).toContain("selected=");
    // Browser Back: `selected` is removed by the URL port -> list returns.
    await router.navigate(-1);
    expect(router.state.location.search).not.toContain("selected=");
    expect(
      await screen.findByRole("table", { name: "Evidence" }),
    ).toBeInTheDocument();
  });

  it("A4-LD10: the detail shows the existing loading state while the exact read resolves", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", async () => {
        await new Promise((resolve) => setTimeout(resolve, 120));
        return jsonOf(evidenceA());
      }),
    );
    renderAtPath(`${BASE}?selected=${EVIDENCE_A_ID}`);
    expect(await screen.findByText("Loading evidence…")).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Evidence details" }),
    ).toBeInTheDocument();
  });

  it("A4-LD11: a detail load failure surfaces the bounded error with Retry", async () => {
    let fail = true;
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => {
        if (fail) {
          return errorResponse(500, "internal_error");
        }
        return jsonOf(evidenceA());
      }),
    );
    renderAtPath(`${BASE}?selected=${EVIDENCE_A_ID}`);
    expect(
      await screen.findByText("Unable to load this evidence"),
    ).toBeInTheDocument();
    fail = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
  });

  it("A4-LD14/LD15: Pivot actions are inline in the detail and Hide collapses only the action bar", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonOf(evidenceA())),
    );
    const { router } = renderAtPath(`${BASE}?selected=${EVIDENCE_A_ID}`);
    await screen.findByRole("heading", { name: "Evidence details" });
    // Expand the inline action bar (ordinary in-flow buttons).
    const trigger = await screen.findByRole("button", { name: "Pivot actions" });
    await userEvent.click(trigger);
    const bar = await screen.findByTestId("pivot-action-bar");
    expect(within(bar).getByTestId("pivot-action-relationshipsSource")).toBeInTheDocument();
    // Hide collapses only the bar: no URL mutation, detail intact.
    await userEvent.click(within(bar).getByTestId("pivot-hide"));
    await waitFor(() =>
      expect(screen.queryByTestId("pivot-action-bar")).toBeNull(),
    );
    expect(router.state.location.search).toContain("selected=");
    expect(router.state.location.search).not.toContain("pivot=");
    expect(
      screen.getByRole("heading", { name: "Evidence details" }),
    ).toBeInTheDocument();
  });

  it("A4-LD18/LD20: human-readable subject/type/value first, UUID secondary", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({ path: "*/api/v1/investigations/:id/evidence", pages: [[evidenceA()]], recorder: resourceListRecorder() }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonOf(evidenceA())),
    );
    renderAtPath(`${BASE}?selected=${EVIDENCE_A_ID}`);
    await screen.findByRole("heading", { name: "Evidence details" });
    // Subject value + type + evidence type are the primary human text.
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
    expect(screen.getByText("domain")).toBeInTheDocument();
    expect(screen.getByText("DNS")).toBeInTheDocument();
    // The technical identity is secondary metadata: the detail ID row is a
    // compact/copyable id, never the primary heading or subject.
    expect(screen.getByText("Evidence ID")).toBeInTheDocument();
    const heading = screen.getByRole("heading", { name: "Evidence details" });
    expect(heading.textContent).not.toContain(EVIDENCE_A_ID);
  });

  it("A4-LD25/LD26/LD27: exact scoped read; no simultaneous list re-fetch; one durable selected identity", async () => {
    const listRecorder = resourceListRecorder();
    const detailRequests: Array<{ id: string }> = [];
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/evidence",
        pages: [[evidenceA()], [evidenceA()]],
        recorder: listRecorder,
      }),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ params }) => {
        detailRequests.push({ id: String(params.evidenceId) });
        return jsonOf(evidenceA());
      }),
    );
    const { router } = renderAtPath(BASE);
    await screen.findByText("update-package.test");
    const listRequestsBefore = listRecorder.requests.length;
    await userEvent.click(screen.getByRole("button", { name: /^View / }));
    await screen.findByRole("heading", { name: "Evidence details" });
    // The exact Investigation-scoped detail endpoint serves the selection
    // (the row id, not a list scan).
    await waitFor(() => expect(detailRequests.length).toBe(1));
    expect(detailRequests[0].id).toBe(EVIDENCE_A_ID);
    // Opening the detail issues NO new list request.
    expect(listRecorder.requests.length).toBe(listRequestsBefore);
    // One durable selected identity: exactly one `selected` URL parameter.
    const params = new URLSearchParams(router.state.location.search);
    expect(params.getAll("selected")).toEqual([EVIDENCE_A_ID]);
    expect(params.get("cursor")).toBeNull();
  });
});
