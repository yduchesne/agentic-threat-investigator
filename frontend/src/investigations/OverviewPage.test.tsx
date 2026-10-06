// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Overview route tests (PR 24B; PR 35-5).
//
// PR 35-5 removes the abbreviated terminal report from the Overview: the
// Overview keeps lifecycle/running/failed/navigation behavior and links to
// the one canonical Final Report. It never renders a second copy of the
// Summary, findings, recommendations, or report-only at-a-glance counts.

import { screen } from "@testing-library/react";
import { http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

import type { Assessment, Investigation, Report } from "../api/schema-types";
import {
  assessmentCurrentHandler,
  authMeSuccess,
  buildAssessment,
  buildInvestigation,
  buildReport,
  completedInvestigationFixture,
  investigationLifecycleHandler,
  jsonResponse,
  reportCurrent404Handler,
  reportCurrentHandler,
  resolveSupportPresentationsHandler,
  runtimeFake,
} from "../test/handlers";
import { CSRF_COOKIE_NAME } from "../api/csrf";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";

useHttp();

beforeEach(() => {
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
});

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

/** Installs handlers that record every current-resource/collection call. */
function countingCurrentHandlers(assessment: Assessment, report: Report) {
  const calls: string[] = [];
  const assessmentCurrent = http.get(
    `*/api/v1/investigations/${INVESTIGATION_ID}/assessments/current`,
    () => {
      calls.push("assessment-current");
      return jsonResponse(assessment);
    },
  );
  const reportCurrent = http.get(
    `*/api/v1/investigations/${INVESTIGATION_ID}/reports/current`,
    () => {
      calls.push("report-current");
      return jsonResponse(report);
    },
  );
  const assessmentsList = http.get(
    `*/api/v1/investigations/${INVESTIGATION_ID}/assessments`,
    () => {
      calls.push("assessments-list");
      return jsonResponse({ items: [], next_cursor: null });
    },
  );
  const reportsList = http.get(
    `*/api/v1/investigations/${INVESTIGATION_ID}/reports`,
    () => {
      calls.push("reports-list");
      return jsonResponse({ items: [], next_cursor: null });
    },
  );
  const supportResolve = resolveSupportPresentationsHandler({ calls });
  return {
    calls,
    handlers: [
      assessmentCurrent,
      reportCurrent,
      assessmentsList,
      reportsList,
      supportResolve,
    ],
  };
}

function detailHandler(investigation: Investigation) {
  return investigationLifecycleHandler([investigation]);
}

describe("Overview route", () => {
  it("links to the one Final Report for completed + Report", async () => {
    const completed = completedInvestigationFixture();
    const { calls, handlers } = countingCurrentHandlers(
      buildAssessment({ investigation_id: completed.id }),
      buildReport({ investigation_id: completed.id }),
    );
    setHttpHandlers(...AUTH, detailHandler(completed), ...handlers);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByRole("link", { name: "View report" }),
    ).toBeInTheDocument();
    // No abbreviated terminal report content on the Overview.
    expect(screen.queryByText("View full report")).toBeNull();
    expect(screen.queryByText("At a glance")).toBeNull();
    expect(screen.queryByText(/Threat-intelligence and reputation sources/)).toBeNull();
    expect(
      screen.queryByText("ATI deterministic investigation report"),
    ).toBeNull();

    expect(calls).toContain("assessment-current");
    expect(calls).toContain("report-current");
    expect(calls).not.toContain("assessments-list");
    expect(calls).not.toContain("reports-list");
  });

  it("renders the Assessment fallback when no Report exists", async () => {
    const completed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "completed",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
    });
    const assessment = buildAssessment({ investigation_id: completed.id });
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(assessment),
      reportCurrent404Handler,
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText(
        "A Report is not available for this investigation; the current Assessment is shown.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Correlated multi-source evidence is sufficient/),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("ATI deterministic investigation report"),
    ).not.toBeInTheDocument();
  });

  it("renders the failed state without Report errors when no artifacts exist", async () => {
    const failed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "failed",
      completed_at: "2026-06-01T10:06:00Z",
      stop_reason: "budget_exhausted",
    });
    setHttpHandlers(...AUTH, detailHandler(failed), reportCurrent404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(await screen.findByText("This investigation failed.")).toBeInTheDocument();
    expect(
      screen.getAllByText("Stop reason: budget_exhausted").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("No conclusion is available")).toBeInTheDocument();
    expect(
      screen.queryByText("Unable to load the current Report"),
    ).not.toBeInTheDocument();
  });

  it("maps a known stop reason to its human label", async () => {
    const failed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "failed",
      completed_at: "2026-06-01T10:06:00Z",
      stop_reason: "fatal_error",
    });
    setHttpHandlers(...AUTH, detailHandler(failed), reportCurrent404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    await screen.findByText("This investigation failed.");
    expect(
      screen.getAllByText("Stop reason: Fatal error").length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/Stop reason: fatal_error/)).not.toBeInTheDocument();
  });

  it("renders a visible partial warning plus the Final Report link", async () => {
    const partial = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "partial",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
      report_id: "50000000-0000-4000-8000-000000000001",
    });
    setHttpHandlers(
      ...AUTH,
      detailHandler(partial),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: partial.id }),
      ),
      reportCurrentHandler(buildReport({ investigation_id: partial.id })),
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText("This investigation completed partially."),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("link", { name: "View report" }),
    ).toBeInTheDocument();
  });

  it("never invents progress percentages or ETAs while running", async () => {
    const running = buildInvestigation({ id: INVESTIGATION_ID, status: "running" });
    setHttpHandlers(...AUTH, detailHandler(running));
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText("Investigation in progress"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    expect(screen.queryByText(/ETA/i)).not.toBeInTheDocument();
  });

  it("queries neither current endpoint while pointers are null", async () => {
    const pending = buildInvestigation({ id: INVESTIGATION_ID, status: "pending" });
    const { calls, handlers } = countingCurrentHandlers(
      buildAssessment({ investigation_id: pending.id }),
      buildReport({ investigation_id: pending.id }),
    );
    setHttpHandlers(...AUTH, detailHandler(pending), ...handlers);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    await screen.findByText("Investigation in progress");
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(calls).toEqual([]);
  });

  it("surfaces the Report/Assessment consistency warning", async () => {
    const completed = completedInvestigationFixture();
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id, verdict: "suspicious" }),
      ),
      reportCurrentHandler(
        buildReport({
          investigation_id: completed.id,
          verdict: "suspicious",
          confidence: "medium",
        }),
      ),
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText(
        "The Report and the current Assessment disagree on verdict or confidence. The persisted Report is authoritative; re-run the assessment pipeline for a consistent pair.",
      ),
    ).toBeInTheDocument();
  });

  it("treats a 404 with a durable pointer as a bounded report error", async () => {
    const completed = completedInvestigationFixture();
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id }),
      ),
      reportCurrent404Handler,
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText("Unable to load the current Report"),
    ).toBeInTheDocument();
    expect(screen.getByText("FAKE DATA")).toBeInTheDocument();
  });

  it("renders analytical text escaped, never as raw HTML", async () => {
    const completed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "completed",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
    });
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({
          investigation_id: completed.id,
          summary: "<script>alert('xss')</script>",
        }),
      ),
      reportCurrent404Handler,
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    const text = await screen.findByText(/<script>alert\('xss'\)<\/script>/);
    expect(text).toBeInTheDocument();
    expect(document.body.querySelector("script")).toBeNull();
  });

  it("never passes analytical content through translation lookup", async () => {
    const completed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "completed",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
    });
    const summary = "{{not.a.translation.key}} and plain text";
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id, summary }),
      ),
      reportCurrent404Handler,
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(await screen.findByText(summary)).toBeInTheDocument();
  });

  it("activates the current-resource queries when pointers transition", async () => {
    const running = buildInvestigation({ id: INVESTIGATION_ID, status: "running" });
    const completed = completedInvestigationFixture();
    const assessment = buildAssessment({ investigation_id: completed.id });
    const report = buildReport({ investigation_id: completed.id });
    let stage = 0;
    const handler = http.get(`*/api/v1/investigations/${INVESTIGATION_ID}`, () => {
      stage += 1;
      return jsonResponse(stage >= 2 ? completed : running);
    });
    const { calls, handlers } = countingCurrentHandlers(assessment, report);
    setHttpHandlers(...AUTH, handler, ...handlers);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    await screen.findByText("Investigation in progress");
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(calls).toEqual([]);

    expect(
      await screen.findByRole("link", { name: "View report" }, { timeout: 10_000 }),
    ).toBeInTheDocument();
    expect(calls).toEqual(
      expect.arrayContaining(["assessment-current", "report-current"]),
    );
  });
});
