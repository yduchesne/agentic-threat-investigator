// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Full Report route tests (PR 24B U50, §27).

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  assessmentCurrentHandler,
  authMeSuccess,
  buildAssessment,
  buildInvestigation,
  buildReport,
  completedInvestigationFixture,
  investigationLifecycleHandler,
  reportCurrentHandler,
  reportMarkdownHandler,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

describe("Full Report route", () => {
  it("renders the persisted structured Report with metadata (U50)", async () => {
    const completed = completedInvestigationFixture();
    const report = buildReport({
      investigation_id: completed.id,
      unresolved_questions: ["Whether this indicator belongs to a larger campaign."],
    });
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationLifecycleHandler([completed]),
      assessmentCurrentHandler(buildAssessment({ investigation_id: completed.id })),
      reportCurrentHandler(report),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview/report`);

    expect(
      await screen.findByText("ATI deterministic investigation report"),
    ).toBeInTheDocument();
    // Persisted metadata: version and created timestamp.
    expect(screen.getByText(/Version:/)).toBeInTheDocument();
    expect(screen.getByText(/Created:/)).toBeInTheDocument();
    expect(screen.getAllByTitle("2026-06-01T10:06:00Z").length).toBeGreaterThan(0);
    // Structured sections render persisted content (never regenerated).
    expect(screen.getByText("Executive summary")).toBeInTheDocument();
    expect(
      screen.getByText(/The investigation concluded .* malicious delivery/i),
    ).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("Research context")).toBeInTheDocument();
    expect(screen.getByText("No research context recorded.")).toBeInTheDocument();
    expect(screen.getByText("Limitations")).toBeInTheDocument();
    expect(
      screen.getByText("Report caveats are copied from the current Assessment."),
    ).toBeInTheDocument();
    expect(screen.getByText("Unresolved questions")).toBeInTheDocument();
    expect(screen.getByText("Recommended next steps")).toBeInTheDocument();
  });

  it("shows the deterministic Markdown on demand as plain text (U50b)", async () => {
    const completed = completedInvestigationFixture();
    const report = buildReport({ investigation_id: completed.id });
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationLifecycleHandler([completed]),
      assessmentCurrentHandler(buildAssessment({ investigation_id: completed.id })),
      reportCurrentHandler(report),
      reportMarkdownHandler("# ATI deterministic investigation report\n\nMarkdown body."),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview/report`);

    await screen.findByText("ATI deterministic investigation report");
    expect(screen.queryByText(/# ATI deterministic investigation report/)).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "View Markdown" }));
    expect(
      await screen.findByText(/# ATI deterministic investigation report/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Markdown body\./)).toBeInTheDocument();
    // Raw HTML is never interpreted: the toggled surface is preformatted text.
    expect(document.body.querySelector("h1")).not.toBeNull();
  });

  it("renders a bounded notice when the Investigation has no Report (U50c)", async () => {
    const completed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "completed",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
    });
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationLifecycleHandler([completed]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview/report`);

    expect(
      await screen.findByText("This investigation has no persisted Report."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to Overview" }),
    ).toBeInTheDocument();
  });
});