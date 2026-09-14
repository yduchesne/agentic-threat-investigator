// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline page tests (PR 24C L01-L05).
//
// Canonical chronological ordering is preserved, exact filters apply, known
// event enums map to labels, unknown values fall back safely, and the
// surface never claims Relationship Evolution.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import type { TimelineEventTypeName } from "../api/schema-types";
import {
  authMeSuccess,
  buildTimelineEvent,
  completedInvestigationFixture,
  investigationDetailHandler,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/timeline`;

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

describe("Timeline page", () => {
  it("preserves canonical order and maps event labels (L01, L03)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [
          [
            buildTimelineEvent({
              id: "40000000-0000-4000-8000-000000000111",
              type: "investigation_started",
              occurred_at: "2026-06-01T09:00:01Z",
            }),
            buildTimelineEvent({
              id: "40000000-0000-4000-8000-000000000112",
              type: "provider_work_failed",
              occurred_at: "2026-06-01T09:01:00Z",
              provider: "fake-dns",
              error_code: "provider_unreachable",
            }),
          ],
        ],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("Investigation started")).toBeInTheDocument();
    expect(screen.getByText("Provider work failed")).toBeInTheDocument();
    // The API order is the display order: the rows are index-ordered rows.
    const timestamps = Array.from(screen.getByRole("table").querySelectorAll("time"))
      .map((node) => node.getAttribute("datetime"));
    expect(timestamps).toEqual(["2026-06-01T09:00:01Z", "2026-06-01T09:01:00Z"]);
    // Failure summary includes the safe public error code.
    expect(screen.getByText(/error provider_unreachable/)).toBeInTheDocument();
  });

  it("fills the exact event type and occurred range filters (L02)", { timeout: 15_000 }, async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [[buildTimelineEvent()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Provider work completed");
    await userEvent.click(screen.getByRole("combobox", { name: "Event type" }));
    await userEvent.click(await screen.findByRole("option", { name: "Evidence persisted" }));
    await userEvent.type(screen.getByLabelText("Occurred from"), "2026-06-01T00:00");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await screen.findByText("Provider work completed");
    const last = recorder.requests.at(-1);
    expect(last?.params.event_type).toBe("evidence_persisted");
    expect(last?.params.occurred_from).toMatch(/2026-06-01T\d{2}:\d{2}:\d{2}Z/);
  });

  it("falls back safely on an unknown future event type (L04)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [
          [
            buildTimelineEvent({
              id: "40000000-0000-4000-8000-000000000113",
              type: "unknown_future_event" as unknown as TimelineEventTypeName,
            }),
          ],
        ],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("unknown_future_event")).toBeInTheDocument();
  });

  it("never describes itself as Relationship Evolution (L05)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [[buildTimelineEvent()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Provider work completed");
    expect(screen.queryByText(/relationship evolution/i)).not.toBeInTheDocument();
  });
});