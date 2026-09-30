// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deferred navigation boundary tests (PR 31F-6 amendment 2 A2-DC01..05).
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
import { readPivotState } from "./pivot-url";

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
    fireEvent.click(screen.getByRole("button", { name: "Back to Evidence" }));
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

  it("A2-DC04: the Pivot push lands the exact PivotStep on the next macrotask", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await screen.findByRole("button", { name: "Subject" });
    fireEvent.click(screen.getByRole("button", { name: "Subject" }));
    // Expansion is transient presentation only — no URL mutation.
    expect(router.state.location.search).not.toContain("pivot=");
    fireEvent.click(await screen.findByRole("button", { name: "Relationships where source" }));
    // The push commit is deferred one macrotask.
    expect(router.state.location.search).not.toContain("pivot=");
    await waitFor(() => {
      expect(router.state.location.search).toContain("pivot=");
    });
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(state?.steps[0].resource).toBe("relationships");
  });

  it("A2-DC05: close/truncate workspace stack results are unchanged by the deferred commit", async () => {
    evidenceHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await screen.findByRole("button", { name: "Subject" });
    fireEvent.click(screen.getByRole("button", { name: "Subject" }));
    fireEvent.click(await screen.findByRole("button", { name: "Relationships where source" }));
    await waitFor(() => {
      expect(router.state.location.search).toContain("pivot=");
    });
    // Close the workspace: the stack clears on the next macrotask.
    fireEvent.click(screen.getByRole("button", { name: "Close pivot workspace" }));
    await waitFor(() => {
      expect(router.state.location.search).not.toContain("pivot=");
    });
    expect(readPivotState(new URLSearchParams(router.state.location.search))).toBeNull();
  });
});
