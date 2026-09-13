// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigations landing page tests (PR 24B U01-U07).

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ANALYST_USER,
  authMeSuccess,
  buildInvestigation,
  investigationsListErrorHandler,
  investigationsListHandler,
  investigationsPagedHandler,
  listRequestRecorder,
  runtimeFake,
} from "../test/handlers";
import type { Investigation } from "../api/schema-types";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];

function rowA(): Investigation {
  return buildInvestigation({
    id: "20000000-0000-4000-8000-000000000001",
    objective: "assess the update-package delivery domain",
    status: "completed",
    completed_at: "2026-06-01T10:06:00Z",
    assessment_id: "30000000-0000-4000-8000-000000000001",
    report_id: "50000000-0000-4000-8000-000000000001",
  });
}

function rowB(): Investigation {
  return buildInvestigation({
    id: "20000000-0000-4000-8000-000000000002",
    objective: "assess the alice-corp domain",
    status: "pending",
    created_at: "2026-06-02T10:00:00Z",
    started_at: "2026-06-02T10:00:01Z",
  });
}

describe("Investigations landing", () => {
  it("renders the first bounded page (U01)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationsPagedHandler({ pages: [[rowA(), rowB()]], recorder }),
    );
    renderAtPath("/investigations");
    expect(
      await screen.findByText("assess the update-package delivery domain"),
    ).toBeInTheDocument();
    expect(screen.getByText("assess the alice-corp domain")).toBeInTheDocument();
    // Bounded list request with the default page size.
    expect(recorder.requests).toHaveLength(1);
    expect(recorder.requests[0].limit).toBe("25");
    // Timestamps render through the shared formatter with ISO in title.
    expect(screen.getAllByTitle("2026-06-01T10:00:01Z").length).toBeGreaterThan(0);
    expect(screen.getByTitle("2026-06-01T10:06:00Z")).toBeInTheDocument();
    // Status text and artifact availability are visible for the completed row.
    expect(screen.getAllByText("Completed").length).toBeGreaterThan(1);
    expect(screen.getAllByLabelText("Assessment")[0]).toHaveTextContent("available");
    expect(screen.getAllByLabelText("Report")[0]).toHaveTextContent("available");
  });

  it("passes the exact status enum to the backend (U02)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationsPagedHandler({ pages: [[rowA()]], recorder }),
    );
    renderAtPath("/investigations");
    await screen.findByText("assess the update-package delivery domain");

    await userEvent.click(screen.getByRole("combobox"));
    await userEvent.click(await screen.findByRole("option", { name: "Completed" }));

    await screen.findByText("assess the update-package delivery domain");
    const request = recorder.requests.at(-1);
    expect(request?.status).toBe("completed");
    expect(request?.cursor).toBeNull();
  });

  it("passes the opaque next cursor unchanged (U03)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationsPagedHandler({ pages: [[rowA()], [rowB()]], recorder }),
    );
    renderAtPath("/investigations");
    await screen.findByText("assess the update-package delivery domain");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("assess the alice-corp domain");
    const request = recorder.requests.at(-1);
    expect(request?.cursor).toBe("cursor-1");
  });

  it("restores the prior cursor on Previous without decoding (U04)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationsPagedHandler({ pages: [[rowA()], [rowB()]], recorder }),
    );
    renderAtPath("/investigations");
    await screen.findByText("assess the update-package delivery domain");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("assess the alice-corp domain");
    const forward = recorder.requests.at(-1);
    expect(forward?.cursor).toBe("cursor-1");

    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("assess the update-package delivery domain");
    // First page restored through the browser-local cursor stack; Previous
    // is disabled again because no earlier page exists.
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
  });

  it("disables Next when no next cursor exists (U05)", async () => {
    const recorder = listRequestRecorder();
    setHttpHandlers(
      ...AUTH,
      investigationsPagedHandler({ pages: [[rowA()]], recorder }),
    );
    renderAtPath("/investigations");
    await screen.findByText("assess the update-package delivery domain");
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("renders an explicit empty state (U06)", async () => {
    setHttpHandlers(...AUTH, investigationsListHandler([]));
    renderAtPath("/investigations");
    expect(await screen.findByText("No investigations yet")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows a bounded error with retry (U07)", async () => {
    setHttpHandlers(...AUTH, investigationsListErrorHandler);
    renderAtPath("/investigations");
    expect(
      await screen.findByText("Unable to load Investigations"),
    ).toBeInTheDocument();

    setHttpHandlers(...AUTH, investigationsListHandler([rowA()]));
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(
      await screen.findByText("assess the update-package delivery domain"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Unable to load Investigations"),
    ).not.toBeInTheDocument();
  });

  it("renders user identity inside the authenticated shell (24A regression)", async () => {
    setHttpHandlers(...AUTH, investigationsListHandler([]));
    renderAtPath("/investigations");
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    const main = screen.getByRole("main");
    expect(within(main).getByRole("heading", { name: "Investigations" })).toBeInTheDocument();
  });
});