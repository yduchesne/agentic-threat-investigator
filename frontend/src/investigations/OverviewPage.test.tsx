// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// REPORT workspace surface tests (PR 35-5 amendment).
//
// The primary `/overview` route renders the one canonical persisted Final
// Report directly. There is no `View report` indirection, no separate
// Lifecycle Overview, no Corroboration wrapper, no Details Back to contents,
// and relationship-observation support is presented as `Graph Analysis`.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

import type { Report, ReportFinding } from "../api/schema-types";
import {
  EVIDENCE_ID,
  OBSERVATION_ID,
  authMeSuccess,
  buildInvestigation,
  buildReport,
  completedInvestigationFixture,
  investigationLifecycleHandler,
  jsonResponse,
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
const ASSESSMENT_ID = "30000000-0000-4000-8000-000000000001";

function finding(
  ordinal: number,
  overrides: Partial<ReportFinding> = {},
): ReportFinding {
  return {
    assessment_finding_ordinal: ordinal,
    report_finding_number: ordinal,
    criticality: ordinal === 1 ? "high" : "informational",
    title: `Finding ${ordinal} title`,
    category: ordinal === 1 ? "reputation" : "geolocation",
    disposition: "supporting",
    statement: `Authoritative statement ${ordinal}.`,
    confidence: ordinal === 1 ? "high" : "low",
    summary: `Summary sentence ${ordinal}.`,
    description: `Reader-facing description ${ordinal}.`,
    support:
      ordinal === 1
        ? [{ kind: "evidence", evidence_id: EVIDENCE_ID }]
        : [
            {
              kind: "relationship_observation",
              relationship_observation_id: OBSERVATION_ID,
            },
          ],
    ...overrides,
  };
}

function twoFindingReport(overrides: Partial<Report> = {}): Report {
  return buildReport({
    investigation_id: INVESTIGATION_ID,
    assessment_id: ASSESSMENT_ID,
    summary: [
      {
        report_finding_number: 1,
        assessment_finding_ordinal: 1,
        text: "Summary sentence 1.",
        support: [
          { kind: "assessment_finding", assessment_id: ASSESSMENT_ID, finding_ordinal: 1 },
        ],
      },
      {
        report_finding_number: 2,
        assessment_finding_ordinal: 2,
        text: "Summary sentence 2.",
        support: [
          { kind: "assessment_finding", assessment_id: ASSESSMENT_ID, finding_ordinal: 2 },
        ],
      },
    ],
    findings: [finding(1), finding(2)],
    ...overrides,
  });
}

function renderReport(report: Report, path = "overview"): void {
  setHttpHandlers(
    ...AUTH,
    investigationLifecycleHandler([completedInvestigationFixture()]),
    reportCurrentHandler(report),
    resolveSupportPresentationsHandler(),
  );
  renderAtPath(`/investigations/${INVESTIGATION_ID}/${path}`);
}

describe("REPORT workspace surface", () => {
  it("renders the canonical persisted Report directly with no View report or Lifecycle", async () => {
    renderReport(twoFindingReport());
    await screen.findByRole("heading", {
      name: "ATI deterministic investigation report",
    });
    expect(screen.queryByRole("link", { name: "View report" })).toBeNull();
    expect(screen.queryByText("Lifecycle")).toBeNull();
  });

  it("renders Status before Summary in DOM order", async () => {
    renderReport(twoFindingReport());
    const status = await screen.findByRole("heading", { name: "Status" });
    const summary = screen.getByRole("heading", { name: "Summary" });
    // Node.DOCUMENT_POSITION_FOLLOWING === 4: summary follows status.
    expect(status.compareDocumentPosition(summary)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
  });

  it("retains every canonical Finding in Summary and Details", async () => {
    renderReport(twoFindingReport());
    await screen.findByText(/Finding 1: Summary sentence 1\./);
    expect(screen.getByText(/Finding 2: Summary sentence 2\./)).toBeInTheDocument();
    expect(
      screen.getAllByText(/Finding 1 — Finding 1 title/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByText(/Finding 2 — Finding 2 title/).length,
    ).toBeGreaterThan(0);
  });

  it("renders Evidence and Graph Analysis directly with no Corroboration", async () => {
    renderReport(twoFindingReport());
    await screen.findByRole("heading", { name: "Status" });
    expect(
      screen.getByRole("heading", { name: "Evidence" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Graph Analysis" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Corroboration")).toBeNull();
    expect(
      screen.queryByRole("heading", { name: "Relationship observation" }),
    ).toBeNull();
  });

  it("omits Graph Analysis when only Evidence support exists", async () => {
    renderReport(
      twoFindingReport({
        summary: [],
        findings: [finding(1)],
      }),
    );
    await screen.findByRole("heading", { name: "Status" });
    expect(
      screen.getByRole("heading", { name: "Evidence" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Graph Analysis" }),
    ).toBeNull();
  });

  it("omits Evidence when only relationship support exists", async () => {
    renderReport(
      twoFindingReport({
        summary: [],
        findings: [finding(2)],
      }),
    );
    await screen.findByRole("heading", { name: "Status" });
    expect(
      screen.getByRole("heading", { name: "Graph Analysis" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Evidence" })).toBeNull();
  });

  it("omits empty support headings", async () => {
    renderReport(
      twoFindingReport({
        summary: [],
        findings: [finding(1, { support: [] })],
      }),
    );
    await screen.findByRole("heading", {
      name: "ATI deterministic investigation report",
    });
    expect(screen.queryByRole("heading", { name: "Evidence" })).toBeNull();
    expect(
      screen.queryByRole("heading", { name: "Graph Analysis" }),
    ).toBeNull();
  });

  it("renders no Back to contents in Details", async () => {
    renderReport(twoFindingReport());
    await screen.findByText(/Reader-facing description 1\./);
    expect(screen.queryByText("Back to contents")).toBeNull();
  });

  it("keeps Contents with stable finding anchors", async () => {
    renderReport(twoFindingReport());
    await screen.findByRole("heading", { name: "Contents" });
    const link = document.querySelector('a[href="#finding-1"]');
    expect(link).not.toBeNull();
    expect(document.querySelector("#finding-1")).not.toBeNull();
  });

  it("resolves a direct #finding-N fragment independent of the title", async () => {
    renderReport(twoFindingReport(), "overview#finding-2");
    await screen.findByRole("heading", { name: "Status" });
    expect(document.querySelector("#finding-2")).not.toBeNull();
  });

  it("preserves exact Evidence and relationship drill-down identities", async () => {
    renderReport(twoFindingReport());
    await screen.findByRole("heading", { name: "Status" });
    expect(screen.getByTestId("pivot-action-evidenceExact")).toBeInTheDocument();
    expect(
      screen.getByTestId("pivot-action-observationExact"),
    ).toBeInTheDocument();
  });

  it("renders untrusted report text as escaped React text", async () => {
    renderReport(
      twoFindingReport({
        findings: [
          finding(1, {
            title: "Safe title",
            description: "<script>alert('xss')</script>",
          }),
        ],
        summary: [],
      }),
    );
    const text = await screen.findByText(/<script>alert\('xss'\)<\/script>/);
    expect(text).toBeInTheDocument();
    expect(document.body.querySelector("script")).toBeNull();
  });

  it("retains the persisted Markdown surface", async () => {
    const report = twoFindingReport();
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completedInvestigationFixture()]),
      reportCurrentHandler(report),
      http.get(
        `*/api/v1/investigations/${INVESTIGATION_ID}/reports/${report.id}/markdown`,
        () => new Response("# Markdown report body", { headers: { "Content-Type": "text/markdown" } }),
      ),
      resolveSupportPresentationsHandler(),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    await userEvent.click(await screen.findByRole("button", { name: "View Markdown" }));
    expect(await screen.findByText(/Markdown report body/)).toBeInTheDocument();
  });

  it("shows a bounded in-progress state for a nonterminal Investigation", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({ id: INVESTIGATION_ID, status: "running" }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(
      await screen.findByText("Investigation in progress"),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("ATI deterministic investigation report"),
    ).toBeNull();
  });

  it("shows the Report loading state while the current Report resolves", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completedInvestigationFixture()]),
      http.get(
        `*/api/v1/investigations/${INVESTIGATION_ID}/reports/current`,
        () => new Promise(() => {}),
      ),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(await screen.findByText("Loading current Report…")).toBeInTheDocument();
  });

  it("shows a bounded retry on current Report failure", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completedInvestigationFixture()]),
      http.get(
        `*/api/v1/investigations/${INVESTIGATION_ID}/reports/current`,
        () =>
          jsonResponse(
            { error: { code: "internal_error", message: "boom", request_id: "r" } },
            500,
          ),
      ),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    await screen.findByText("Unable to load the current Report");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows an explicit unavailable state for a terminal Investigation without a Report", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([
        buildInvestigation({
          id: INVESTIGATION_ID,
          status: "completed",
          completed_at: "2026-06-01T12:00:00Z",
        }),
      ]),
    );
    renderAtPath(`/investigations/${INVESTIGATION_ID}/overview`);
    expect(await screen.findByText("No conclusion is available")).toBeInTheDocument();
  });
});
