// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Report/Assessment provenance navigation tests (PR 24D §7, §27; PR 24F §15;
// PR 31F-8 §8).
//
// Finding support references navigate by exact persisted identity only:
// Evidence support opens the exact scoped Evidence route, Research claim
// support opens the exact Research result selection, and
// RelationshipObservation support opens the exact Investigation-scoped
// observation route (never a list scan, never a substitute observation).
// A scoped 404 states the not-found without a fallback. Report/Research
// free text never enters any URL and navigation never mutates
// Assessment/Report requests.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { beforeEach, describe, expect, it } from "vitest";

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
  resolveSupportPresentationsHandler,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { CSRF_COOKIE_NAME } from "../api/csrf";

useHttp();

beforeEach(() => {
  // The double-submit CSRF cookie is set by the real login flow; tests that
  // exercise state-changing requests (support presentation resolution) arm it
  // exactly like the browser would (PR 31F-5 E).
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
});

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

/** Shared handlers: Overview current-resource + routed target resources. */
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
    resolveSupportPresentationsHandler(),
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
    // navigation must resolve through the scoped GET, never a list scan.
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

describe("Report/Assessment provenance navigation (PR 31F-8 routed)", () => {
  it("Evidence support navigates to the exact scoped Evidence route", async () => {
    const capture = { reports: 0, assessments: 0 };
    setHttpHandlers(...baseOverviewHandlers(reportWithEvidenceSupport(), capture));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Supports");
    await screen.findByText(REPORT_STATEMENT);

    await userEvent.click(screen.getByTestId("pivot-action-evidenceExact"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/evidence/${EVIDENCE_ID}`);
    });
    // The exact Evidence route renders the scoped detail as the main
    // content (the detail handler above also asserts the exact id).
    const heading = await screen.findByRole("heading", { name: "Evidence details" });
    expect(heading).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText("update-package.test").length).toBeGreaterThan(0);
    });
    // Canonical URL: no pivot envelope, no Report free text anywhere.
    expect(router.state.location.search).toBe("");
    expect(router.state.location.search).not.toContain("pivot=");
    expect(router.state.location.pathname).not.toContain(encodeURIComponent(REPORT_STATEMENT));
  });

  it("RelationshipObservation support opens the exact scoped observation (F-P03/F-P04/F-P08/F-P09)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByTestId("pivot-action-observationExact"),
    );
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `${BASE}/relationships/observations/${OBSERVATION_ID}`,
      );
    });
    const dialogHeading = await screen.findByRole("heading", {
      name: "Relationship observation detail",
    });
    expect(dialogHeading).toBeInTheDocument();
    // The exact persisted observation id drives the scoped GET (never a
    // list scan): the list page above serves a different row, yet the
    // detail renders the exact observation's source from the GET response.
    await within(dialogHeading.parentNode as HTMLElement).findByText("exact-dns");
    await expect(observationDetail.requests).toHaveLength(1);
    expect(observationDetail.requests[0]).toContain(
      `/relationship-observations/${OBSERVATION_ID}`,
    );
    // The detail keeps exact Evidence identity and distinct times.
    const drawer = dialogHeading.parentNode as HTMLElement;
    await within(drawer).findByText("Observed at");
    await within(drawer).findByText("Retrieved at");
    expect(within(drawer).getAllByText("Evidence ID").length).toBeGreaterThan(0);
    // No pivot envelope; Report text never enters the URL.
    expect(router.state.location.search).not.toContain("pivot=");
    expect(router.state.location.pathname).not.toContain("independent");
  });

  it("a scoped observation 404 renders the safe not-found without a substitute (F-P05/F-P06)", async () => {
    setHttpHandlers(
      ...AUTH,
      investigationLifecycleHandler([completed()]),
      assessmentCurrentHandler(assessmentLike()),
      reportCurrentHandler(reportWithObservationSupport()),
      resolveSupportPresentationsHandler(),
      http.get("*/api/v1/investigations/:id/reports", () =>
        jsonResponse({ items: [], next_cursor: null })),
      http.get("*/api/v1/investigations/:id/assessments", () =>
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
      screen.getByTestId("pivot-action-observationExact"),
    );
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `${BASE}/relationships/observations/${OBSERVATION_ID}`,
      );
    });
    // The exact observation route states the scoped not-found without
    // inventing a substitute observation; the route stays intact.
    await screen.findByText("Resource not found or not accessible");
    expect(router.state.location.pathname).toContain(OBSERVATION_ID);
  });

  it("observation detail pivots to exact Evidence by evidence_id (F-P07)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByTestId("pivot-action-observationExact"),
    );
    const dialogHeading = await screen.findByRole("heading", {
      name: "Relationship observation detail",
    });
    const drawer = dialogHeading.parentNode as HTMLElement;
    await within(drawer).findByText("exact-dns");

    // The observation detail's provenance menu carries the exact Evidence
    // destination (route link).
    await userEvent.click(
      within(drawer).getByRole("button", {
        name: "Observation provenance actions",
      }),
    );
    await userEvent.click(await within(drawer).findByTestId("pivot-action-evidenceExact"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/evidence/${EVIDENCE_ID}`);
    });
    // The exact Evidence detail opens with its subject value.
    await screen.findByRole("heading", { name: "Evidence details" });
    await waitFor(() => {
      expect(screen.getAllByText("update-package.test").length).toBeGreaterThan(0);
    });
  });

  it("browser Back restores the previous surfaced route (F-P10)", async () => {
    const capture = { reports: 0, assessments: 0 };
    const observationDetail = { requests: [] as string[] };
    setHttpHandlers(...baseOverviewHandlers(reportWithObservationSupport(), capture, observationDetail));
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Reported by two independent observation sources.");

    await userEvent.click(
      screen.getByTestId("pivot-action-observationExact"),
    );
    await screen.findByRole("heading", { name: "Relationship observation detail" });

    // Browser Back walks the entry: the Overview surface returns and the
    // Report support reference stays visible.
    await router.navigate(-1);
    await screen.findByText("Reported by two independent observation sources.");
    expect(router.state.location.pathname).toBe(`${BASE}/overview`);
  });

  it("Research claim support opens the exact Research result selection", async () => {
    const capture = { reports: 0, assessments: 0 };
    setHttpHandlers(...baseOverviewHandlers(reportWithResearchContext(), capture));
    // PR 31F-5 C: Research context is part of the full Report (the Overview
    // is the concise surface), so the assertion starts on the Report route.
    const { router } = renderAtPath(`${BASE}/overview/report`);
    await screen.findByText("Contextual research claim about the delivery infrastructure.");

    await userEvent.click(screen.getByTestId("pivot-action-researchExact"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/research`);
    });
    expect(router.state.location.search).toBe(`?selected=${RESEARCH_ID}`);
    // The exact Research detail renders as the workspace content.
    await screen.findByRole("heading", { name: "Research context details" });
    // Research claim text never enters the URL.
    expect(router.state.location.search).not.toContain("Contextual");
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
    expect(screen.queryAllByTestId("pivot-action-evidenceExact")).toHaveLength(0);
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
    const { router } = renderAtPath(`${BASE}/overview`);
    await screen.findByText("Supports");
    await userEvent.click(screen.getByTestId("pivot-action-evidenceExact"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${BASE}/evidence/${EVIDENCE_ID}`);
    });
    await screen.findByRole("heading", { name: "Evidence details" });
    // The current Report/Assessment queries were fetched exactly once each;
    // navigation neither mutates nor refetches the artifacts.
    expect(current.reports).toBe(1);
    expect(current.assessments).toBe(1);
  });
});
