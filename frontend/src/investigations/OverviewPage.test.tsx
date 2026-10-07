// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// REPORT workspace surface tests (PR 35-5 amendment).
//
// The primary `/overview` route renders the one canonical persisted Final
// Report directly. There is no `View report` indirection, no separate
// Lifecycle Overview, no Corroboration wrapper, no Details Back to contents,
// and relationship-observation support is presented as `Graph Analysis`.

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

import type { Report, ReportFinding, ReportResearchClaim } from "../api/schema-types";
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
import { REPORT_TYPOGRAPHY } from "./report-typography";
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

  it("uses the readable Final Report typography hierarchy (PR 35-7)", async () => {
    renderReport(twoFindingReport());
    await screen.findByText(/Reader-facing description 1\./);

    // Stable report anchors, not mutable English labels, identify the tree.
    const status = document.querySelector("#status");
    const detailsSection = document.querySelector("#details") as HTMLElement;
    const findingsSection = document.querySelector("#findings") as HTMLElement;
    const finding = document.querySelector("#finding-1") as HTMLElement;
    expect(status?.parentElement).not.toBeNull();
    const reportRoot = status?.parentElement as HTMLElement;

    const title = within(reportRoot).getByRole("heading", { level: 1 });
    const details = within(detailsSection).getByRole("heading", { level: 2 });
    const findings = within(findingsSection).getByRole("heading", { level: 3 });
    const findingHeading = within(finding).getByRole("heading", { level: 4 });
    const supportHeading = within(finding).getByRole("heading", { level: 5 });

    // Semantic nesting: every child heading sits inside its parent.
    expect(detailsSection).toContainElement(findingsSection);
    expect(findingsSection).toContainElement(finding);
    expect(finding).toContainElement(findingHeading);
    expect(finding).toContainElement(supportHeading);

    // Rendered readable scale: every report element resolves to the
    // centralized contract (jsdom preserves the authored rem value).
    const fontSize = (element: HTMLElement): string =>
      window.getComputedStyle(element).fontSize;
    expect(fontSize(title)).toBe(REPORT_TYPOGRAPHY.h1.fontSize);
    expect(fontSize(details)).toBe(REPORT_TYPOGRAPHY.h2.fontSize);
    expect(fontSize(findings)).toBe(REPORT_TYPOGRAPHY.h3.fontSize);
    expect(fontSize(findingHeading)).toBe(REPORT_TYPOGRAPHY.h4.fontSize);
    expect(fontSize(supportHeading)).toBe(REPORT_TYPOGRAPHY.h5.fontSize);
    // The support line itself uses the readable support role, not ``caption``.
    const supportList = supportHeading.nextElementSibling as HTMLElement;
    const supportLine = supportList.querySelector("li span") as HTMLElement;
    expect(supportLine).not.toBeNull();
    expect(fontSize(supportLine)).toBe(REPORT_TYPOGRAPHY.support.fontSize);
    expect(
      fontSize(within(finding).getByText(/Reader-facing description 1\./)),
    ).toBe(REPORT_TYPOGRAPHY.body.fontSize);
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
      screen.getByRole("heading", { name: "Evidence", level: 5 }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Graph Analysis", level: 5 }),
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

/** One persisted research claim with an encoded citation title (PR 38-10). */
function encodedResearchClaim(): ReportResearchClaim {
  return {
    research_result_id: "60000000-0000-4000-8000-000000000001",
    research_claim_id: "60000000-0000-4000-8000-000000000002",
    subject_entity_id: "40000000-0000-4000-8000-000000000101",
    claim_text: "Context &#39;claim&#39; &amp; detail",
    citation_ids: ["60000000-0000-4000-8000-000000000003"],
    citations: [
      {
        chunk_sequence: 0,
        citation_id: "60000000-0000-4000-8000-000000000003",
        document_id: "60000000-0000-4000-8000-000000000004",
        document_type: "report",
        published_at: null,
        similarity_score: null,
        source_id: "source",
        source_record_id: "record",
        source_url: null,
        text: "citation text",
        title: "Title &amp; &quot;quoted&quot;",
      },
    ],
  };
}

describe("Final Report HTML entity decoding (PR 38-10 R-C01..R-C15)", () => {
  function encodedReport(overrides: Partial<Report> = {}): Report {
    return twoFindingReport({
      title: "Report &amp; &#39;title&#39;",
      summary: [
        {
          report_finding_number: 1,
          assessment_finding_ordinal: 1,
          text: "Summary &amp; &#39;quoted&#39;",
          support: [
            {
              kind: "assessment_finding",
              assessment_id: ASSESSMENT_ID,
              finding_ordinal: 1,
            },
          ],
        },
      ],
      findings: [
        finding(1, {
          title: "Finding &amp; &#39;title&#39;",
          description:
            "C&amp;C (threat_type botnet_cc, described as &#39;C&amp;C server&#39;)",
        }),
      ],
      research_context: [encodedResearchClaim()],
      limitations: ["Limit &amp; &#39;one&#39;"],
      unresolved_questions: ["Question &amp; &#39;two&#39;"],
      recommended_next_steps: ["Step &amp; &#39;three&#39;"],
      ...overrides,
    });
  }

  it("R-C01/R-C02/R-C03: decodes the observed C&C regression and encoded quotes", async () => {
    renderReport(encodedReport());
    expect(
      await screen.findByText(
        "C&C (threat_type botnet_cc, described as 'C&C server')",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/&amp;|&#39;/)).toBeNull();
  });

  it("R-C04/R-C05: encoded markup stays literal text and creates no element", async () => {
    renderReport(
      encodedReport({
        findings: [
          finding(1, {
            description:
              "&lt;script&gt;alert(1)&lt;/script&gt; &lt;img src=x onerror=alert(2)&gt;",
          }),
        ],
      }),
    );
    expect(
      await screen.findByText(/<script>alert\(1\)<\/script>/),
    ).toBeInTheDocument();
    expect(screen.getByText(/<img src=x onerror=alert\(2\)>/)).toBeInTheDocument();
    const findingElement = document.querySelector("#finding-1") as HTMLElement;
    expect(findingElement.querySelector("script")).toBeNull();
    expect(findingElement.querySelector("img")).toBeNull();
  });

  it("R-C06: double-encoded content is decoded exactly one layer", async () => {
    renderReport(
      encodedReport({
        findings: [finding(1, { description: "&amp;lt;script&amp;gt;" })],
      }),
    );
    expect(await screen.findByText("&lt;script&gt;")).toBeInTheDocument();
    expect(
      (document.querySelector("#finding-1") as HTMLElement).querySelector("script"),
    ).toBeNull();
  });

  it("R-C07/R-C08: ordinary ampersands and Unicode are unchanged", async () => {
    renderReport(
      encodedReport({
        findings: [finding(1, { description: "AT&T café — 日本語" })],
      }),
    );
    expect(await screen.findByText("AT&T café — 日本語")).toBeInTheDocument();
  });

  it("R-C09/R-C10/R-C11: title, summary and finding prose are decoded safely", async () => {
    renderReport(encodedReport());
    await screen.findByRole("heading", { name: "Status" });
    expect(
      screen.getByRole("heading", { name: "Report & 'title'" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Finding 1: Summary & 'quoted'/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/Finding 1 — Finding & 'title'/).length,
    ).toBeGreaterThan(0);
  });

  it("R-C12: research claim and citation title prose are decoded", async () => {
    renderReport(encodedReport());
    expect(
      await screen.findByText("Context 'claim' & detail"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Title & "quoted"/)).toBeInTheDocument();
  });

  it("R-C13: optional sections are decoded", async () => {
    renderReport(encodedReport());
    await screen.findByRole("heading", { name: "Status" });
    expect(await screen.findByText("Limit & 'one'")).toBeInTheDocument();
    expect(screen.getByText("Question & 'two'")).toBeInTheDocument();
    expect(screen.getByText("Step & 'three'")).toBeInTheDocument();
  });

  it("R-C14: stable finding anchors are independent of the decoded title", async () => {
    renderReport(encodedReport());
    await screen.findByRole("heading", { name: "Status" });
    expect(document.querySelector('a[href="#finding-1"]')).not.toBeNull();
    expect(document.querySelector("#finding-1")).not.toBeNull();
  });
});
