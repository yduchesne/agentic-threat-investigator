// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Overview route tests (PR 24B U28-U42, U52-U55).

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
  // The double-submit CSRF cookie is set by the real login flow; tests that
  // exercise state-changing requests (support presentation resolution) arm it
  // exactly like the browser would (PR 31F-5 E).
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
  it("renders the Report-based Overview for completed + Report (U33, U55)", async () => {
    const completed = completedInvestigationFixture();
    const { calls, handlers } = countingCurrentHandlers(
      buildAssessment({ investigation_id: completed.id }),
      buildReport({ investigation_id: completed.id }),
    );
    setHttpHandlers(...AUTH, detailHandler(completed), ...handlers);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    // Verdict/confidence + executive summary + title.
    expect(await screen.findByText("Malicious")).toBeInTheDocument();
    expect(screen.getAllByText("High").length).toBeGreaterThan(0);
    expect(
      screen.getByText("ATI deterministic investigation report"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/The investigation concluded .* malicious delivery/i),
    ).toBeInTheDocument();

    // Findings with statement/category/disposition/confidence + support.
    expect(
      screen.getByText(/Threat-intelligence and reputation sources/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Reputation • High confidence • Supporting/),
    ).toBeInTheDocument();
    expect(screen.getByText("Supports")).toBeInTheDocument();
    // PR 31F-5 SP01: the support reference is the semantic description
    // (source · type · subject value/type) with the ID secondary.
    expect(
      await screen.findByText(/urn:ati:source:google_public_dns · DNS · update-package\.test · Domain/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Evidence ID:/)).toBeInTheDocument();
    expect(screen.getByTitle("40000000-0000-4000-8000-000000000001")).toBeInTheDocument();

    // At a glance counts derive from the loaded artifact arrays only.
    expect(await screen.findByText("At a glance")).toBeInTheDocument();
    expect(screen.getByText(/Findings: 1/)).toBeInTheDocument();
    expect(screen.getByText(/Recommended next steps: 1/)).toBeInTheDocument();

    // Full Report action + FAKE DATA.
    expect(screen.getByRole("link", { name: "View full report" })).toBeInTheDocument();
    expect(screen.getByText("FAKE DATA")).toBeInTheDocument();

    // Only the /current endpoints and one bounded support resolution ran.
    expect(calls).toContain("assessment-current");
    expect(calls).toContain("report-current");
    expect(calls).toContain("support-resolve");
    expect(calls).not.toContain("assessments-list");
    expect(calls).not.toContain("reports-list");
  });

  it("renders the Assessment fallback when no Report exists (U34)", async () => {
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
        "A full Report is not available for this investigation; the current Assessment is shown.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(
      screen.getByText(/Correlated multi-source evidence is sufficient/),
    ).toBeInTheDocument();
    // The assessment fallback must not synthesize Report content.
    expect(
      screen.queryByText("ATI deterministic investigation report"),
    ).not.toBeInTheDocument();
  });

  it("bounds the Overview to the first 3 findings and next steps and links to the full Report (OV02/OV03)", async () => {
    const completed = completedInvestigationFixture();
    const manyFindings = Array.from({ length: 5 }, (_, index) => ({
      assessment_finding_ordinal: index + 1,
      category: "network" as const,
      disposition: "supporting" as const,
      confidence: "medium" as const,
      statement: `Bounded finding number ${index + 1}.`,
      support: [],
    }));
    const manySteps = Array.from({ length: 4 }, (_, index) => `Next step ${index + 1}.`);
    const report = buildReport({
      investigation_id: completed.id,
      findings: manyFindings,
      recommended_next_steps: manySteps,
    });
    const { calls, handlers } = countingCurrentHandlers(
      buildAssessment({ investigation_id: completed.id }),
      report,
    );
    setHttpHandlers(...AUTH, detailHandler(completed), ...handlers);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    await screen.findByText("Bounded finding number 1.");
    expect(screen.getByText("Bounded finding number 3.")).toBeInTheDocument();
    expect(screen.queryByText("Bounded finding number 4.")).toBeNull();
    // The remainder links to the full Report.
    expect(
      screen.getByRole("link", { name: "+2 more findings in full report" }),
    ).toBeInTheDocument();
    // Next steps bounded to the first 3.
    expect(screen.getByText("Next step 1.")).toBeInTheDocument();
    expect(screen.getByText("Next step 3.")).toBeInTheDocument();
    expect(screen.queryByText("Next step 4.")).toBeNull();
    // Counts reflect the loaded artifact arrays (not the rendered subset).
    expect(screen.getByText(/Findings: 5/)).toBeInTheDocument();
    expect(screen.getByText(/Recommended next steps: 4/)).toBeInTheDocument();
    void calls;
  });

  it("renders the failed state without Report errors when no artifacts exist (U35)", async () => {
    const failed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "failed",
      completed_at: "2026-06-01T10:06:00Z",
      stop_reason: "budget_exhausted",
    });
    setHttpHandlers(...AUTH, detailHandler(failed), reportCurrent404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(await screen.findByText("This investigation failed.")).toBeInTheDocument();
    // Unknown stop reasons still fall back to the raw value (never prettified).
    expect(
      screen.getAllByText("Stop reason: budget_exhausted").length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("No conclusion is available")).toBeInTheDocument();
    expect(
      screen.queryByText("Unable to load the current Report"),
    ).not.toBeInTheDocument();
  });

  it("maps a known stop reason to its human label (F1-U32/U33)", async () => {
    const failed = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "failed",
      completed_at: "2026-06-01T10:06:00Z",
      stop_reason: "fatal_error",
    });
    setHttpHandlers(...AUTH, detailHandler(failed), reportCurrent404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    await screen.findByText("This investigation failed.");
    // The lifecycle line shows the translated label, not the raw enum.
    expect(
      screen.getAllByText("Stop reason: Fatal error").length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/Stop reason: fatal_error/)).not.toBeInTheDocument();

    // Unknown values fail safe with the raw value.
    const unknown = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "failed",
      completed_at: "2026-06-01T10:06:00Z",
      stop_reason: "future_reason_9",
    });
    setHttpHandlers(...AUTH, detailHandler(unknown), reportCurrent404Handler);
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(
      (await screen.findAllByText("Stop reason: future_reason_9")).length,
    ).toBeGreaterThan(0);
  });

  it("renders a visible partial warning plus the Report (U36)", async () => {
    const partial = buildInvestigation({
      id: INVESTIGATION_ID,
      status: "partial",
      completed_at: "2026-06-01T10:06:00Z",
      assessment_id: "30000000-0000-4000-8000-000000000001",
      report_id: "50000000-0000-4000-8000-000000000001",
    });
    const assessment = buildAssessment({ investigation_id: partial.id });
    const report = buildReport({ investigation_id: partial.id });
    setHttpHandlers(
      ...AUTH,
      detailHandler(partial),
      assessmentCurrentHandler(assessment),
      reportCurrentHandler(report),
    );
      resolveSupportPresentationsHandler(),
      resolveSupportPresentationsHandler(),
      resolveSupportPresentationsHandler(),
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText("This investigation completed partially."),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("ATI deterministic investigation report"),
    ).toBeInTheDocument();
  });

  it("never invents progress percentages or ETAs while running (U37)", async () => {
    const running = buildInvestigation({ id: INVESTIGATION_ID, status: "running" });
    setHttpHandlers(...AUTH, detailHandler(running));
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText("Investigation in progress"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
    expect(screen.queryByText(/ETA/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("progressbar", { name: /eta/i })).not.toBeInTheDocument();
  });

  it("queries neither current endpoint while pointers are null (U28, U30)", async () => {
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

  it("disagreement between Report and Assessment surfaces a consistency warning (U19 §19)", async () => {
    const completed = completedInvestigationFixture();
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id, verdict: "suspicious" }),
      ),
      reportCurrentHandler(
        buildReport({ investigation_id: completed.id, verdict: "suspicious", confidence: "medium" }),
      ),
    );
      resolveSupportPresentationsHandler(),
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(
      await screen.findByText(
        "The Report and the current Assessment disagree on verdict or confidence. The persisted Report is authoritative; re-run the assessment pipeline for a consistent pair.",
      ),
    ).toBeInTheDocument();
  });

  it("treats a 404 with a durable pointer as a bounded report error, not a crash (U28b)", async () => {
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
    // The workspace remains usable around the isolated section error.
    expect(screen.getByText("FAKE DATA")).toBeInTheDocument();
  });

  it("labels research claims as Research context, never Evidence (U40)", async () => {
    const completed = completedInvestigationFixture();
    const report = buildReport({
      investigation_id: completed.id,
      research_context: [
        {
          research_claim_id: "70000000-0000-4000-8000-000000000001",
          research_result_id: "70000000-0000-4000-8000-000000000002",
          subject_entity_id: "20000000-0000-4000-8000-000000000003",
          claim_text: "Research claim about the malware delivery association.",
          citation_ids: ["70000000-0000-4000-8000-000000000004"],
          citations: [],
        },
      ],
    });
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id }),
      ),
      reportCurrentHandler(report),
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    // PR 31F-5 §3.4: the Overview is concise — Research context (part of
    // the full Report) no longer renders below the navigation/action row.
    await screen.findByText("At a glance");
    expect(screen.queryByText("Research context")).toBeNull();
    expect(
      screen.queryByText("Research claim about the malware delivery association."),
    ).toBeNull();
  });

  it("renders analytical text escaped, never as raw HTML (U52)", async () => {
    const completed = completedInvestigationFixture();
    const report = buildReport({
      investigation_id: completed.id,
      executive_summary: [
        {
          text: "<script>alert('xss')</script>",
          support: [
            {
              kind: "assessment_finding",
              assessment_id: "30000000-0000-4000-8000-000000000001",
              finding_ordinal: 1,
            },
          ],
        },
      ],
    });
    setHttpHandlers(
      ...AUTH,
      detailHandler(completed),
      assessmentCurrentHandler(
        buildAssessment({ investigation_id: completed.id }),
      ),
      reportCurrentHandler(report),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    const text = await screen.findByText(/<script>alert\('xss'\)<\/script>/);
    expect(text).toBeInTheDocument();
    expect(document.body.querySelector("script")).toBeNull();
  });

  it("never passes analytical content through translation lookup (U54)", async () => {
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
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);

    expect(await screen.findByText(summary)).toBeInTheDocument();
  });

  it("activates the current-resource queries when pointers transition (U29, U31, U32)", async () => {
    // suspended -> completed through the lifecycle; the completed stage
    // carries the durable pointers.
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

    // Running first: no current-resource fetches yet.
    await screen.findByText("Investigation in progress");
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(calls).toEqual([]);

    // After the 2s poll flips the detail to completed with pointers, the
    // /current endpoints activate.
    expect(await screen.findByText("ATI deterministic investigation report", undefined, { timeout: 10_000 })).toBeInTheDocument();
    expect(calls).toEqual(
      expect.arrayContaining(["assessment-current", "report-current"]),
    );
  });
});
