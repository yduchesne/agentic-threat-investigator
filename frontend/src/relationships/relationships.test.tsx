// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships + RelationshipObservations tests (PR 24C R01-R09, O01-O04).
//
// Stable edge browsing, exact filters, Investigation-scoped detail, and
// the first-class observations route preserving observed/retrieved
// independence.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildGraphNeighborhood,
  buildObservation,
  buildRelationship,
  completedInvestigationFixture,
  graphNeighborhoodHandler,
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
    // PR 31F-5 EP03: source/target show value + translated type before the
    // compact UUID; both ends use identical organization.
    expect(screen.getByText("update-package.test")).toBeInTheDocument();
    expect(screen.getByText("Domain")).toBeInTheDocument();
    expect(screen.getByText("malware.badloader_v2")).toBeInTheDocument();
    expect(screen.getByText("Malware")).toBeInTheDocument();
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
    await waitFor(
      () => {
        const last = recorder.requests.at(-1);
        expect(last?.params.source_entity_id).toBe("40000000-0000-4000-8000-000000000101");
        expect(last?.params.relationship_type).toBe("urn:ati:relationship:dns:resolves_to");
      },
      { timeout: 5000 },
    );
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
    // PR 31F-5 EP04: detail presents value/type before the canonical IDs.
    expect(await screen.findByRole("heading", { name: "Source entity" })).toBeInTheDocument();
    expect(screen.getAllByText("update-package.test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Malware").length).toBeGreaterThan(0);
    expect(await screen.findByText(/Recent relationship history/)).toBeInTheDocument();
    expect(
      screen.getByTitle("2026-06-01T09:00:00Z"),
    ).toBeInTheDocument();
    expect(
      screen.getByTitle("2026-06-01T09:05:00Z"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View all history/ })).toBeInTheDocument();
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

  it("resolves a selection not on the loaded page through the exact scoped GET (F-P04)", async () => {
    const selected = "40000000-0000-4000-8000-000000000099";
    const detailRequests: string[] = [];
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        // The loaded page contains a different observation: the open
        // selection must be fetched by exact persisted id, never scanned.
        pages: [[obsA()]],
        recorder: resourceListRecorder(),
      }),
      http.get(
        "*/api/v1/investigations/:id/relationship-observations/:observationId",
        ({ request }) => {
          const url = new URL(request.url);
          detailRequests.push(url.pathname);
          return jsonResponse(
            buildObservation({
              id: selected,
              relationship_id: "40000000-0000-4000-8000-000000000021",
              source: "exact-dns",
              observed_at: "2026-06-01T08:00:00Z",
              retrieved_at: "2026-06-01T08:30:00Z",
            }),
          );
        },
      ),
    );
    renderAtPath(`${OBS_BASE}?selected=${selected}`);
    // The drawer renders the exact observation resolved by the scoped GET
    // (its source differs from the loaded page row).
    expect(await screen.findByText("exact-dns")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T08:00:00Z")).toBeInTheDocument();
    expect(screen.getByTitle("2026-06-01T08:30:00Z")).toBeInTheDocument();
    await waitFor(() => {
      expect(detailRequests).toHaveLength(1);
      expect(detailRequests[0]).toContain(`/relationship-observations/${selected}`);
    });
  });

  it("N3 (amendment): History -> Current relationship snapshots -> Back preserves context", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder: resourceListRecorder(),
      }),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder: resourceListRecorder(),
      }),
    );
    const { router } = renderAtPath({
      pathname: OBS_BASE,
      state: { navigation: { returns: [{ pathname: REL_BASE, search: "", hash: "" }] } },
    });
    await screen.findByText("fake-dns");
    // History -> Current relationship snapshots is a drill-down that pushes
    // the exact history location.
    await userEvent.click(
      screen.getByRole("link", { name: "Current relationship snapshots" }),
    );
    await waitFor(() => expect(router.state.location.pathname).toBe(REL_BASE));
    // Relationships shows a contextual Back to the exact history origin.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(OBS_BASE));
    // The history workspace retains its own ancestor context.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(REL_BASE));
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

  it("L01/L02/L03: the observation row Evidence ID is one linked compact ID (PR 35-1)", async () => {
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
    const link = await screen.findByRole("link", { name: "Evidence" });
    expect(link).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/evidence/40000000-0000-4000-8000-000000000001`,
    );
    // The visible short ID appears exactly once in the evidence cell and the
    // full UUID remains copyable.
    const cell = link.parentElement as HTMLElement;
    expect(within(cell).getAllByText("40000000")).toHaveLength(1);
    expect(
      within(cell).getByRole("button", { name: "Copy ID 40000000" }),
    ).toBeInTheDocument();
  });

  it("B01/B04: a valid returnTo renders Back and restores the exact origin (PR 35-1)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[obsA()]],
        recorder: resourceListRecorder(),
      }),
    );
    const origin = `/investigations/${INVESTIGATION_ID}/relationships?selected=40000000-0000-4000-8000-000000000021#top`;
    const { router } = renderAtPath({
      pathname: OBS_BASE,
      state: { returnTo: origin },
    });
    await screen.findByText("fake-dns");
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(
        `${router.state.location.pathname}${router.state.location.search}${router.state.location.hash}`,
      ).toBe(origin);
    });
  });

  it("B02: a direct link with no returnTo renders no Back control (PR 35-1)", async () => {
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
    expect(screen.queryByRole("button", { name: "< Back" })).not.toBeInTheDocument();
  });
});

describe("PR 35-8 focal Relationships indicator", () => {
  const FOCAL = "40000000-0000-4000-8000-000000000101";

  function entityReadHandler() {
    return graphNeighborhoodHandler({
      neighborhood: buildGraphNeighborhood(),
      recorder: resourceListRecorder(),
    });
  }

  it("U31/U32: entity_id filters the server request and shows the canonical focal value", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder,
      }),
      entityReadHandler(),
    );
    renderAtPath(`${REL_BASE}?entity_id=${FOCAL}`);
    const value = await screen.findByTestId("focal-entity-value");
    expect(value).toHaveTextContent("update-package.test");
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.entity_id).toBe(FOCAL);
    });
  });

  it("U33: a source-only filter shows no focal indicator", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/relationships",
        pages: [[relA()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(`${REL_BASE}?source_entity_id=${FOCAL}`);
    await screen.findByText("Resolves to");
    expect(
      document.querySelector('[data-ati-id="relationship.focal-entity"]'),
    ).toBeNull();
  });
});
