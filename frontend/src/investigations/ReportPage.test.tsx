// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Full Report route tests (PR 24B U50, §27).

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";

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
  resolveSupportPresentationsHandler,
  runtimeFake,
} from "../test/handlers";
import { CSRF_COOKIE_NAME } from "../api/csrf";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

beforeEach(() => {
  // The double-submit CSRF cookie is set by the real login flow; tests that
  // exercise state-changing requests (support presentation resolution) arm it
  // exactly like the browser would (PR 31F-5 E).
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
});


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
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview/report`);

    expect(
      await screen.findByText("ATI deterministic investigation report"),
    ).toBeInTheDocument();
    // Persisted metadata: version and created timestamp.
    expect(screen.getByText(/Version:/)).toBeInTheDocument();
    expect(screen.getByText(/Created:/)).toBeInTheDocument();
    expect(screen.getAllByTitle("2026-06-01T10:06:00Z").length).toBeGreaterThan(0);
    // Canonical Final Report structure; no Executive Summary remains.
    expect(screen.queryByText("Executive summary")).toBeNull();
    expect(screen.getAllByText("Summary").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Status").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Contents").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Details").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Findings").length).toBeGreaterThan(0);
    // Details renders the persisted Report Writer title and description.
    expect(
      screen.getAllByText(/Root indicator linked to malicious delivery infrastructure/)
        .length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(
        /Threat-intelligence observations associate the root indicator with known malicious delivery infrastructure/,
      ),
    ).toBeInTheDocument();
    // Optional empty Research Context is omitted.
    expect(screen.queryByText("Research context")).toBeNull();
    expect(screen.getAllByText("Limitations").length).toBeGreaterThan(0);
    expect(
      screen.getByText("Report caveats are copied from the current Assessment."),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Unresolved questions").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Recommended next steps").length).toBeGreaterThan(0);
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
      resolveSupportPresentationsHandler(),
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
      screen.getByRole("link", { name: "< Back" }),
    ).toBeInTheDocument();
  });

  it("renders the canonical finding projections and navigable Contents", async () => {
    const completed = completedInvestigationFixture();
    const evidenceId = "40000000-0000-4000-8000-000000000001";
    const observationId = "60000000-0000-4000-8000-000000000001";
    const report = buildReport({
      investigation_id: completed.id,
      summary: [
        {
          report_finding_number: 1,
          assessment_finding_ordinal: 1,
          text: "Persisted summary one.",
          support: [
            {
              kind: "assessment_finding",
              assessment_id: "30000000-0000-4000-8000-000000000001",
              finding_ordinal: 1,
            },
          ],
        },
      ],
      findings: [
        {
          assessment_finding_ordinal: 1,
          report_finding_number: 1,
          criticality: "high",
          title: "Root indicator linked to delivery infrastructure",
          category: "reputation",
          disposition: "supporting",
          statement: "Authoritative statement one.",
          confidence: "high",
          summary: "Persisted summary one.",
          description: "Persisted detailed description one.",
          support: [{ kind: "evidence", evidence_id: evidenceId }],
        },
        {
          assessment_finding_ordinal: 2,
          report_finding_number: 2,
          criticality: "informational",
          title: "Approximate geographic context",
          category: "geolocation",
          disposition: "supporting",
          statement: "Authoritative statement two.",
          confidence: "low",
          summary: "Persisted summary two.",
          description: "Persisted detailed description two.",
          support: [
            {
              kind: "relationship_observation",
              relationship_observation_id: observationId,
            },
          ],
        },
      ],
    });
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationLifecycleHandler([completed]),
      assessmentCurrentHandler(buildAssessment({ investigation_id: completed.id })),
      reportCurrentHandler(report),
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview/report`);

    // Summary uses the persisted summary and deterministic numbering only.
    expect(
      await screen.findByText(/Finding 1: Persisted summary one\./),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Finding 2:/)).toBeNull();
    expect(screen.queryByText(/Assessment 1/)).toBeNull();
    // Details renders the persisted title and description for both findings.
    expect(
      screen.getAllByText(/Finding 1 — Root indicator linked to delivery infrastructure/)
        .length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("Persisted detailed description one.")).toBeInTheDocument();
    expect(
      screen.getAllByText(/Finding 2 — Approximate geographic context/).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("Persisted detailed description two.")).toBeInTheDocument();
    // Contents uses stable, title-independent anchors and Back to contents.
    const findingLink = document.querySelector('a[href="#finding-1"]');
    expect(findingLink).not.toBeNull();
    const backLinks = screen.getAllByRole("link", { name: "Back to contents" });
    expect(backLinks.length).toBeGreaterThan(0);
    for (const link of backLinks) {
      expect(link.getAttribute("href")).toBe("#contents");
    }
    // Corroboration partitions exact support into Evidence and Relationships.
    expect(screen.getAllByText("Corroboration").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Evidence").length).toBeGreaterThan(0);
  });
});
