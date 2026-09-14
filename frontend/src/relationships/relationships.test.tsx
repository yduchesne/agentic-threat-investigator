// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships + RelationshipObservations tests (PR 24C R01-R09, O01-O04).
//
// Stable edge browsing, exact filters, Investigation-scoped detail, and
// the first-class observations route preserving observed/retrieved
// independence.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildObservation,
  buildRelationship,
  completedInvestigationFixture,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const REL_BASE = `/investigations/${INVESTIGATION_ID}/relationships`;
const OBS_BASE = `${REL_BASE}/observations`;

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

function relA() {
  return buildRelationship({
    id: "40000000-0000-4000-8000-000000000021",
    source_entity_id: "40000000-0000-4000-8000-000000000101",
    target_entity_id: "40000000-0000-4000-8000-000000000102",
    type: "urn:ati:relationship:dns:resolves_to",
  });
}

function obsA() {
  return buildObservation({
    id: "40000000-0000-4000-8000-000000000041",
    relationship_id: "40000000-0000-4000-8000-000000000021",
    source: "fake-dns",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
  });
}

describe("Relationships page", () => {
  it("renders source/type/target with analyst labels (R01)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(REL_BASE);
    await screen.findByText("Resolves to");
    // Compact entity ids with the full value in the tooltip.
    expect(screen.getByTitle("40000000-0000-4000-8000-000000000101")).toBeInTheDocument();
    expect(screen.getByTitle("40000000-0000-4000-8000-000000000102")).toBeInTheDocument();
  });

  it("applies exact source/target/type filters (R02)", { timeout: 15_000 }, async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder,
      }),
    );
    renderAtPath(REL_BASE);
    await screen.findByText("Resolves to");
    await userEvent.type(
      screen.getByRole("textbox", { name: "Source entity ID" }),
      "40000000-0000-4000-8000-000000000101",
    );
    await userEvent.click(screen.getByRole("combobox", { name: "Relationship type" }));
    await userEvent.click(await screen.findByRole("option", { name: "Resolves to" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.source_entity_id).toBe("40000000-0000-4000-8000-000000000101");
      expect(last?.params.relationship_type).toBe("urn:ati:relationship:dns:resolves_to");
    });
  });

  it("shows the stable edge plus a bounded observation preview (R03, R04)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder: resourceListRecorder(),
      }),
      // The preview is bounded: relationship_id filter + limit 5.
      http.get("*/api/v1/investigations/:id/relationship-observations", ({ request }) => {
        const url = new URL(request.url);
        expect(url.searchParams.get("relationship_id")).toBe(relA().id);
        expect(url.searchParams.get("limit")).toBe("5");
        return jsonResponse({ items: [obsA()], next_cursor: "cursor-1" });
      }),
      http.get("*/api/v1/investigations/:id/relationships/:relationshipId", () =>
        jsonResponse(relA())),
    );
    renderAtPath(REL_BASE);
    await screen.findByText("Resolves to");
    await userEvent.click(screen.getByRole("button", { name: /View 40000000/ }));
    expect(await screen.findByText(/Observations \(first page\)/)).toBeInTheDocument();
    expect(
      screen.getByTitle("2026-06-01T09:00:00Z"),
    ).toBeInTheDocument();
    expect(
      screen.getByTitle("2026-06-01T09:05:00Z"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View all observations/ })).toBeInTheDocument();
  });
});

describe("Relationship observations page", () => {
  it("browses through URL filters with distinct observed/retrieved (R05, R06)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder,
      }),
    );
    renderAtPath(`${OBS_BASE}?relationship_id=40000000-0000-4000-8000-000000000021`);
    expect(await screen.findByText("fake-dns")).toBeInTheDocument();
    // Both timestamps visible and distinct.
    expect(screen.getByTitle("2026-06-01T09:00:00Z")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T09:05:00Z")).toBeInTheDocument();
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.relationship_id)
        .toBe("40000000-0000-4000-8000-000000000021");
    });
  });

  it("keeps observed and retrieved ranges independent (R07)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder,
      }),
    );
    renderAtPath(OBS_BASE);
    await screen.findByText("fake-dns");
    const [observedFrom, observedTo] = [
      screen.getByLabelText("Observed from"),
      screen.getByLabelText("Observed to"),
    ];
    await userEvent.type(observedFrom, "2026-06-01T00:00");
    await userEvent.type(observedTo, "2026-06-02T00:00");
    // Only the observed range is committed; retrieved stays absent.
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.observed_from).toMatch(/2026-06-01T\d{2}:\d{2}:\d{2}Z/);
      expect(last?.params.observed_to).toMatch(/2026-06-02T\d{2}:\d{2}:\d{2}Z/);
      expect(last?.params.retrieved_from).toBeUndefined();
      expect(last?.params.retrieved_to).toBeUndefined();
    });
  });

  it("never infers ended/removed semantics (R08)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(OBS_BASE);
    await screen.findByText("fake-dns");
    // The observation view never infers ended/removed/started semantics.
    expect(screen.queryByText(/ended|removed/i)).not.toBeInTheDocument();
  });

  it("never routes observations through generic History (R09)", async () => {
    let historyCalls = 0;
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/history/*", () => {
        historyCalls += 1;
        return jsonResponse({ items: [], next_cursor: null });
      }),
    );
    renderAtPath(OBS_BASE);
    await screen.findByText("fake-dns");
    expect(historyCalls).toBe(0);
  });
});