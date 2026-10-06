// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deferred navigation boundary tests (PR 31F-6 amendment 2 A2-DC01..03;
// PR 31F-8 §8, §9).
//
// The progressive composition bisect proved that synchronously committing
// router/search-parameter navigation while the live query/table
// composition rerenders in the same native pointer event dispatch wedges
// Chromium and Firefox. The PR therefore schedules affected navigation
// commits for the next macrotask — after the originating native event
// completes. These tests pin that boundary: a synchronous (raw)
// activation must not mutate the URL inside the handler stack, and the
// commit must apply exactly once on the next macrotask with unchanged
// URL semantics.
//
// PR 31F-8 removes the encoded Pivot stack from navigation: route-known
// actions are semantic react-router links, and the router transition
// (unlike the table controller's search-param commit) is owned by React
// Router. The former pivot push/close tests are replaced by the canonical
// route-navigation equivalents below.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  completedInvestigationFixture,
  investigationDetailHandler,
  jsonResponse,
  runtimeFake,
  uuidAt,
} from "../test/handlers";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const EVIDENCE_ID = uuidAt(1);

const AUTH = [authMeSuccess, runtimeFake];

function evidenceHandlers() {
  setHttpHandlers(
    ...AUTH,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
    http.get("*/api/v1/investigations/:id/evidence", () =>
      jsonResponse({
        items: [
          buildEvidence({
            id: EVIDENCE_ID,
            subject_value: "update-package.test",
          }),
        ],
        next_cursor: null,
      })),
  );
}

describe("deferred navigation boundary (A2-DC)", () => {
  it("A2-DC01/DC02: resource selection commits on the next macrotask, not in the handler stack", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    // Raw synchronous activation: the click handler must not commit the
    // URL synchronously inside its own stack.
    fireEvent.click(screen.getByRole("button", { name: /^View / }));
    expect(router.state.location.search).not.toContain("selected=");
    // The commit applies exactly once on the next macrotask.
    await waitFor(() => {
      expect(router.state.location.search).toContain("selected=");
    });
    const params = new URLSearchParams(router.state.location.search);
    expect(params.getAll("selected")).toHaveLength(1);
    expect(params.get("selected")).toBe(EVIDENCE_ID);
  });

  it("A2-DC03: selection close yields the same URL result as before (only the selection removed)", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    fireEvent.click(screen.getByRole("button", { name: /^View / }));
    await waitFor(() => {
      expect(router.state.location.search).toContain("selected=");
    });
    fireEvent.click(screen.getByTestId("resource-detail-back"));
    // The close selection commit is also deferred one macrotask.
    expect(router.state.location.search).toContain("selected=");
    await waitFor(() => {
      expect(router.state.location.search).not.toContain("selected=");
    });
    // Nothing else was touched (no cursor/filter params introduced).
    const params = new URLSearchParams(router.state.location.search);
    expect(params.get("selected")).toBeNull();
    expect(params.get("cursor")).toBeNull();
  });

  it("A2-DC04 (PR 31F-8): a semantic route action navigates the canonical route without any pivot URL", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await screen.findByRole("button", { name: "Subject" });
    fireEvent.click(screen.getByRole("button", { name: "Subject" }));
    // Expansion is transient presentation only — no URL mutation.
    expect(router.state.location.search).not.toContain("pivot=");
    fireEvent.click(await screen.findByTestId("pivot-action-relationshipsSource"));
    // The router transition lands the canonical route with the exact
    // filter query; no legacy pivot envelope is ever produced.
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/relationships`);
    });
    const params = new URLSearchParams(router.state.location.search);
    expect(params.get("source_entity_id")).toBe(uuidAt(101));
    expect(params.has("pivot")).toBe(false);
  });

  it("A2-DC05 (PR 31F-8): the canonical route never retains pivot state after navigation", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await screen.findByRole("button", { name: "Subject" });
    fireEvent.click(screen.getByRole("button", { name: "Subject" }));
    fireEvent.click(await screen.findByTestId("pivot-action-researchForEntity"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/research`);
    });
    expect(router.state.location.search).toBe(`?subject_entity_id=${uuidAt(101)}`);
    expect(router.state.location.search).not.toContain("pivot=");
  });

  it("amendment 1: a drill-down pivot carries the bounded navigation context", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await screen.findByRole("button", { name: "Subject" });
    fireEvent.click(screen.getByRole("button", { name: "Subject" }));
    fireEvent.click(await screen.findByTestId("pivot-action-relationshipsSource"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/relationships`);
    });
    const state = router.state.location.state as {
      navigation?: { returns?: { pathname: string }[] };
    };
    expect(state.navigation?.returns?.length).toBe(1);
    expect(state.navigation?.returns?.[0]?.pathname).toBe(`${BASE}/evidence`);
  });

  it("amendment 1: Apply with an unchanged draft issues no equivalent-URL commit", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    const keyBefore = router.state.location.key;
    const searchBefore = router.state.location.search;
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    // Give the deferred commit a macrotask to (not) run.
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(router.state.location.search).toBe(searchBefore);
    expect(router.state.location.key).toBe(keyBefore);
  });
});
