// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline page tests (PR 24C L01-L05).
//
// Canonical chronological ordering is preserved, exact filters apply, known
// event enums map to labels, unknown values fall back safely, and the
// surface never claims Relationship Evolution.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
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

  it("closes the detail drawer by close button, Escape and backdrop (F1-U01..U05)", { timeout: 15_000 }, async () => {
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
    const { router } = renderAtPath(BASE);
    await screen.findByText("Provider work completed");
    const requestsBefore = recorder.requests.length;
    const open = (): void => {
      // Plain DOM click (the repository E2E convention): the full pointer
      // sequence can wedge jsdom after a fixed-overlay drawer unmounts.
      fireEvent.click(screen.getByRole("button", { name: /view/i }));
    };

    // Open once (URL-addressable selection), then close via the ✕ control.
    open();
    const dialog = await screen.findByRole("dialog", { name: "Timeline event" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Close detail" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Timeline event" })).not.toBeInTheDocument();
    }, { timeout: 3000 });
    expect(router.state.location.search).not.toContain("selected=");

    // Reopen (reopening works) and close via Escape.
    open();
    const dialog2 = await screen.findByRole("dialog", { name: "Timeline event" });
    fireEvent.keyDown(dialog2, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Timeline event" })).not.toBeInTheDocument();
    }, { timeout: 3000 });
    expect(router.state.location.search).not.toContain("selected=");

    // Reopen and close via the backdrop.
    open();
    await screen.findByRole("dialog", { name: "Timeline event" });
    const dialog3 = screen.getByRole("dialog", { name: "Timeline event" });
    const backdrop = dialog3.parentElement?.firstElementChild;
    expect(backdrop).not.toBeNull();
    fireEvent.click(backdrop as Element);
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Timeline event" })).not.toBeInTheDocument();
    }, { timeout: 3000 });
    expect(router.state.location.search).not.toContain("selected=");

    // Drawer open/close never re-fetches the list (no extra Timeline fetch).
    expect(recorder.requests.length).toBe(requestsBefore);

    // Filters + cursor are preserved across a close.
    await userEvent.type(screen.getByLabelText("Occurred from"), "2026-06-01T00:00");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    open();
    await screen.findByRole("dialog", { name: "Timeline event" });
    fireEvent.keyDown(screen.getByRole("dialog", { name: "Timeline event" }), {
      key: "Escape",
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Timeline event" })).not.toBeInTheDocument();
    }, { timeout: 3000 });
    expect(router.state.location.search).toContain("occurred_from");
  });

  it("shrinks the native datetime labels empty and populated (F1-U06/U07)", async () => {
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
    const from = screen.getByLabelText("Occurred from").closest(".MuiFormControl-root");
    expect(from).not.toBeNull();
    const fromLabel = from?.querySelector(".MuiInputLabel-root");
    expect(fromLabel?.classList.contains("MuiInputLabel-shrink")).toBe(true);
    // Populated: label stays separated from the native input value.
    await userEvent.type(screen.getByLabelText("Occurred to"), "2026-06-02T00:00");
    const to = screen.getByLabelText("Occurred to").closest(".MuiFormControl-root");
    expect(
      to?.querySelector(".MuiInputLabel-root")?.classList.contains("MuiInputLabel-shrink"),
    ).toBe(true);
  });

  it("maps known reason codes to human labels and keeps the raw code in detail (F1-U08/U09)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [
          [
            buildTimelineEvent({
              id: "40000000-0000-4000-8000-000000000114",
              type: "investigation_stopped",
              reason_code: "fatal_error",
            }),
          ],
        ],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    // Table summary uses the translated label, not the raw enum.
    expect(await screen.findByText(/reason Fatal error/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /view/i }));
    const dialog = await screen.findByRole("dialog", { name: "Timeline event" });
    expect(within(dialog).getByText("Fatal error (fatal_error)")).toBeInTheDocument();
  });

  it("falls back to the raw code for unknown codes without crashing (F1-U10)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/timeline",
        pages: [
          [
            buildTimelineEvent({
              id: "40000000-0000-4000-8000-000000000115",
              type: "provider_work_failed",
              error_code: "future_error_code_42",
            }),
          ],
        ],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText(/error future_error_code_42/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /view/i }));
    const dialog = await screen.findByRole("dialog", { name: "Timeline event" });
    expect(within(dialog).getByText("future_error_code_42")).toBeInTheDocument();
  });
});
