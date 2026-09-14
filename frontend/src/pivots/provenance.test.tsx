// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Report/Assessment provenance navigation tests (PR 24D §7, §27; PR 24F §15).
//
// Finding support references navigate by exact persisted identity only:
// Evidence support opens the exact scoped Evidence selection, Research
// claim support opens the exact Research result, and RelationshipObservation
// support opens the exact Investigation-scoped observation read (never a
// list scan, never a substitute observation). A scoped 404 keeps the pivot
// workspace open and states the not-found without a fallback. Report/
// Research free text never enters the pivot URL and navigation never
// mutates Assessment/Report requests.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import type { Report } from "../api/schema-types";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  assessmentCurrentHandler,
  authMeSuccess,
  buildEvidence,
  buildObservation,
  buildReport,
  buildResearchResult,
  completedInvestigationFixture,
  errorResponse,
  investigationLifecycleHandler,
  jsonResponse,
  reportCurrentHandler,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { decodeBase64Url, readPivotState } from "./pivot-url";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const EVIDENCE_ID = uuidAt(1);
const OBSERVATION_ID = uuidAt(41);
const RESEARCH_ID = uuidAt(61);
const REPORT_STATEMENT =
  "Threat-intelligence sources associate the root indicator with known malicious delivery infrastructure.";

function completed() {
  return completedInvestigationFixture({ id: INVESTIGATION_ID });
}

function evidenceFixture() {
  return buildEvidence({
    id: EVIDENCE_ID,
    subject_entity_id: uuidAt(101),
    subject_value: "update-package.test",
  });
}

function reportWithEvidenceSupport(): Report {
  return buildReport({
    investigation_id: INVESTIGATION_ID,
    findings: [
      {
        assessment_finding_ordinal: 1,
        category: "reputation",
        disposition: "supporting",
        statement: REPORT_STATEMENT,
        confidence: "high",
        support: [{ kind: "evidence", evidence_id: EVIDENCE_ID }],
      },
    ],
  });
}

function reportWithObservationSupport(): Report {
  return buildReport({
    investigation_id: INVESTIGATION_ID,
    findings: [
      {
        assessment_finding_ordinal: 1,
        category: "reputation",
        disposition: "supporting",
        statement: "Reported by two independent observation sources.",
        confidence: "high",
        support: [
          { kind: "relationship_observation", relationship_observation_id: OBSERVATION_ID },
        ],
      },
    ],
  });
}

function reportWithResearchContext(): Report {
  return buildReport({
    investigation_id: INVESTIGATION_ID,
    research_context: [
      {
        research_claim_id: uuidAt(71),
        research_result_id: RESEARCH_ID,
        subject_entity_id: uuidAt(101),
        claim_text: "Contextual research claim about the delivery infrastructure.",
        citation_ids: [],
        citations: [],
      },
    ],
  });
}

function assessmentLike() {
  return {
    id: "30000000-0000-4000-8000-000000000001",
    investigation_id: INVESTIGATION_ID,
    verdict: "malicious" as const,
    confidence: "high" as const,
    summary: "summary",
    analyzed_evidence_ids: [EVIDENCE_ID],
    findings: [],
    limitations: [],
    unresolved_questions: [],
    recommended_next_steps: [],
    created_at: "2026-06-01T10:05:00Z",
    version: 1,
  };
}

/** Shared handlers: Overview current-resource + pivot target resources. */
function baseOverviewHandlers(
  report: Report,
  capture: { reports: number; assessments: number },
  observationDetail: { requests: string[] } = { requests: [] },
) {
  return [
    ...AUTH,
    investigationLifecycleHandler([completed()]),
    assessmentCurrentHandler(assessmentLike()),
    reportCurrentHandler(report),
    http.get("*/api/v1/investigations/:id/reports", () => {
      capture.reports += 1;
      return jsonResponse({ items: [], next_cursor: null });
    }),
    http.get("*/api/v1/investigations/:id/assessments", () => {
      capture.assessments += 1;
      return jsonResponse({ items: [], next_cursor: null });
    }),
    http.get("*/api/v1/investigations/:id/evidence/:evidenceId", ({ request }) => {
      const url = new URL(request.url);
      expect(url.pathname).toContain(`/evidence/${EVIDENCE_ID}`);
      return jsonResponse(evidenceFixture());
    }),
    http.get("*/api/v1/investigations/:id/evidence", () =>
      jsonResponse({ items: [evidenceFixture()], next_cursor: null })),
    http.get("*/api/v1/investigations/:id/research/:researchId", ({ request }) => {
      const url = new URL(request.url);
      expect(url.pathname).toContain(`/research/${RESEARCH_ID}`);
      return jsonResponse(buildResearchResult({ id: RESEARCH_ID }));
    }),
    http.get("*/api/v1/investigations/:id/research", () =>
      jsonResponse({ items: [], next_cursor: null })),
    // Observation list serves a *different* row: the exact provenance
    // selection must resolve through the scoped GET, never a list scan.
    http.get("*/api/v1/investigations/:id/relationship-observations", () =>
      jsonResponse({
        items: [
          buildObservation({
            id: uuidAt(42),
            evidence_id: uuidAt(2),
            source: "fake-list-row",
          }),
        ],
        next_cursor: null,
      })),
    http.get(
      "*/api/v1/investigations/:id/relationship-observations/:observationId",
      ({ request }) => {
        const url = new URL(request.url);
        observationDetail.requests.push(url.pathname);
        return jsonResponse(exactObservationFixture());
      },
    ),
  ];
}

/** The exact immutable observation resolved by the support id. */
function exactObservationFixture() {
  return buildObservation({
    id: OBSERVATION_ID,
    evidence_id: EVIDENCE_ID,
    source: "exact-dns",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
  });
}

describe("Report/Assessment provenance pivots", () => {
  it("Evidence support opens the exact scoped Evidence selection", async () => {
    const capture = { reports: 0, assessments: 0 };
    setHttpHandlers(...baseOverviewHandlers(reportWithEvidenceSupport(), capture));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Supports");
    await screen.findByText(REPORT_STATEMENT);

    await userEvent.click(screen.getByRole("button", { name: "Open evidence" }));
    const dialog = await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    expect(dialog).toBeInTheDocument();
    // The exact selection opens the scoped detail drawer with the value
    // (the detail handler above also asserts the exact id in the URL).
    await waitFor(() => {
      expect(within(dialog).getAllByText("update-package.test").length).toBeGreaterThan(1);
    });

    // Report free text never enters the pivot URL; the step carries the
    // exact selection identity.
    const pivotParam = new URLSearchParams(router.state.location.search).get("pivot");
    const decoded = decodeBase64Url(pivotParam ?? "");
    expect(decoded).not.toBeNull();
    expect(decoded).not.toContain(REPORT_STATEMENT);
    expect(decoded).not.toContain("Threat-intelligence");
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps[0].resource).toBe("evidence");
    expect(state?.steps[0].selectedId).toBe(EVIDENCE_ID);
  });

  it("RelationshipObservation support opens the exact scoped observation (F-P03/F-P04/F-P08/F-P09)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByRole("button", { name: "View relationship observation" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: /Relationship observations pivot workspace/i,
    });
    expect(dialog).toBeInTheDocument();

    // The exact persisted observation id drives the scoped GET (never a
    // list scan): the list page above serves a different row, yet the
    // drawer renders the exact observation's source from the GET response.
    const drawer = await screen.findByRole("dialog", {
      name: "Relationship observation detail",
    });
    await within(drawer).findByText("exact-dns");
    await expect(observationDetail.requests).toHaveLength(1);
    expect(observationDetail.requests[0]).toContain(
      `/relationship-observations/${OBSERVATION_ID}`,
    );
    // The drawer keeps exact Evidence identity and distinct times.
    await within(drawer).findByText("Observed at");
    await within(drawer).findByText("Retrieved at");
    expect(within(drawer).getAllByText("Evidence ID").length).toBeGreaterThan(0);

    // Bounded breadcrumb label: the compact observation id, never raw text.
    const breadcrumb = within(dialog).getByRole("navigation", {
      name: "Pivot breadcrumb",
    });
    await within(breadcrumb).findByText(/^RelationshipObservation 40000000$/);

    // Report free text never enters the pivot URL; the step carries the
    // exact selection identity only.
    const pivotParam = new URLSearchParams(router.state.location.search).get("pivot");
    const decoded = decodeBase64Url(pivotParam ?? "");
    expect(decoded).not.toBeNull();
    expect(decoded).not.toContain("independent observation sources");
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps[0].resource).toBe("relationship-observations");
    expect(state?.steps[0].selectedId).toBe(OBSERVATION_ID);
    expect(state?.steps[0].filters).toEqual({});
  });

  it("a scoped observation 404 keeps the pivot open with an honest not-found (F-P05/F-P06)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completed()]),
      assessmentCurrentHandler(assessmentLike()),
      reportCurrentHandler(reportWithObservationSupport()),
      http.get("*/api/v1/investigations/:id/reports", () =>
        jsonResponse({ items: [], next_cursor: null })),
      http.get("*/api/v1/investigations/:id/assessments", () =>
        jsonResponse({ items: [], next_cursor: null })),
      http.get("*/api/v1/investigations/:id/relationship-observations", () =>
        jsonResponse({ items: [], next_cursor: null })),
      // The exact read reports the observation is not visible here — both
      // for missing and cross-Investigation ids (one safe scoped 404).
      http.get(
        "*/api/v1/investigations/:id/relationship-observations/:observationId",
        () => errorResponse(404, "relationship_not_found"),
      ),
    );
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByRole("button", { name: "View relationship observation" }),
    );
    const dialog = await screen.findByRole("dialog", {
      name: /Relationship observations pivot workspace/i,
    });
    // The pivot workspace stays open; the drawer states the scoped
    // not-found without inventing a substitute observation.
    await within(dialog).findByText("Resource not found or not accessible");
    const pivotParam = new URLSearchParams(router.state.location.search).get("pivot");
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps[0].selectedId).toBe(OBSERVATION_ID);
    expect(pivotParam).not.toBeNull();
  });

  it("observation detail pivots to exact Evidence by evidence_id (F-P07)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByRole("button", { name: "View relationship observation" }),
    );
    const drawer = await screen.findByRole("dialog", {
      name: "Relationship observation detail",
    });
    await within(drawer).findByText("exact-dns");

    // The drawer's provenance menu carries the exact Evidence target.
    await userEvent.click(
      within(drawer).getByRole("button", {
        name: "Observation provenance actions",
      }),
    );
    await userEvent.click(await screen.findByRole("menuitem", { name: "Open evidence" }));
    const evidenceDialog = await screen.findByRole("dialog", {
      name: /Evidence pivot workspace/i,
    });
    // The exact Evidence detail opens with its subject value.
    await waitFor(() => {
      expect(
        within(evidenceDialog).getAllByText("update-package.test").length,
      ).toBeGreaterThan(0);
    });
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps[1].resource).toBe("evidence");
    expect(state?.steps[1].selectedId).toBe(EVIDENCE_ID);
  });

  it("Close restores the base Overview state (F-P10)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByRole("button", { name: "View relationship observation" }),
    );
    await screen.findByRole("dialog", {
      name: /Relationship observations pivot workspace/i,
    });
    await userEvent.click(screen.getByRole("button", { name: "Close pivot workspace" }));
    await screen.findByText("Reported by two independent observation sources.");
    expect(
      screen.queryByRole("dialog", { name: /pivot workspace/i }),
    ).toBeNull();
  });

  it("Research claim support opens the exact Research result selection", async () => {
    const capture = { reports: 0, assessments: 0 };
    setHttpHandlers(...baseOverviewHandlers(reportWithResearchContext(), capture));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Contextual research claim about the delivery infrastructure.");

    await userEvent.click(screen.getByRole("button", { name: "Open research result" }));
    const dialog = await screen.findByRole("dialog", {
      name: /Research pivot workspace/i,
    });
    expect(dialog).toBeInTheDocument();
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps[0].resource).toBe("research");
    expect(state?.steps[0].selectedId).toBe(RESEARCH_ID);
    // Research claim text never enters the pivot URL.
    const decoded = decodeBase64Url(new URLSearchParams(router.state.location.search).get("pivot") ?? "");
    expect(decoded).not.toContain("Contextual research claim");
  });

  it("insufficient support metadata yields no inferred action", async () => {
    const capture = { reports: 0, assessments: 0 };
    const withoutIdentity = buildReport({
      investigation_id: INVESTIGATION_ID,
      findings: [
        {
          assessment_finding_ordinal: 1,
          category: "reputation",
          disposition: "supporting",
          statement: "Reference without usable identity.",
          confidence: "medium",
          support: [{ kind: "evidence", evidence_id: null }],
        },
      ],
    });
    setHttpHandlers(...baseOverviewHandlers(withoutIdentity, capture));
    renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reference without usable identity.");
    // The unknown reference renders as text only; no action exists.
    expect(screen.queryAllByRole("button", { name: "Open evidence" })).toHaveLength(0);
  });

  it("navigation does not mutate Assessment/Report (single current fetches)", async () => {
    const current = { reports: 0, assessments: 0 };
    const report = reportWithEvidenceSupport();
    const assessment = assessmentLike();
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completed()]),
      http.get("*/api/v1/investigations/:id/assessments/current", () => {
        current.assessments += 1;
        return jsonResponse(assessment);
      }),
      http.get("*/api/v1/investigations/:id/reports/current", () => {
        current.reports += 1;
        return jsonResponse(report);
      }),
      http.get("*/api/v1/investigations/:id/reports", () => jsonResponse({ items: [], next_cursor: null })),
      http.get("*/api/v1/investigations/:id/assessments", () => jsonResponse({ items: [], next_cursor: null })),
      http.get("*/api/v1/investigations/:id/evidence/:evidenceId", () => jsonResponse(evidenceFixture())),
      http.get("*/api/v1/investigations/:id/evidence", () =>
        jsonResponse({ items: [evidenceFixture()], next_cursor: null })),
    );
    renderAtPath(`${BASE}/overview`);
    await screen.findByText("Supports");
    await userEvent.click(screen.getByRole("button", { name: "Open evidence" }));
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    await userEvent.click(screen.getByRole("button", { name: "Close pivot workspace" }));
    await screen.findByText("Supports");
    // The current Report/Assessment queries were fetched exactly once each;
    // pivoting neither mutates nor refetches the artifacts.
    expect(current.reports).toBe(1);
    expect(current.assessments).toBe(1);
  });
});