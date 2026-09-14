// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central MSW handlers (PR 24A).
//
// Budget the deterministic HTTP surface for /auth/me, /auth/login,
// /auth/logout and /runtime. Tests compose the handlers they need; the
// harness (see server.ts) rejects unhandled requests loudly.

import type { HttpHandler } from "msw";
import { http, HttpResponse } from "msw";
import type { JsonBodyType } from "msw";

import type { PublicUser } from "../api/schema-types";
import type {
  Assessment,
  CreateInvestigationResult,
  Evidence,
  EvidenceTypeName,
  HistoryOperationName,
  HistoryRecord,
  Investigation,
  Relationship,
  RelationshipObservation,
  RelationshipTypeName,
  Report,
  ResearchResult,
  TimelineEvent,
  TimelineEventTypeName,
} from "../api/schema-types";

export const ANALYST_USER: PublicUser = {
  id: "10000000-0000-4000-8000-000000000001",
  alias: "analyst-a",
  role: "analyst",
};

export const ADMIN_USER: PublicUser = {
  id: "10000000-0000-4000-8000-000000000002",
  alias: "admin-a",
  role: "admin",
};

/** Build a stable public API error envelope response. */
export function errorResponse(
  status: number,
  code: string,
  requestId: string = "test-request-id",
): HttpResponse<JsonBodyType> {
  return HttpResponse.json(
    { error: { code, message: `${code} (test message)`, request_id: requestId } },
    { status },
  );
}

/** Build a JSON success response. */
export function jsonResponse<T extends JsonBodyType>(body: T, status: number = 200): HttpResponse<JsonBodyType> {
  return HttpResponse.json(body, { status });
}

// /auth/me ---------------------------------------------------------------

export const authMeSuccess = http.get("*/api/v1/auth/me", () => jsonResponse(ANALYST_USER));
export const authMe401 = http.get("*/api/v1/auth/me", () => errorResponse(401, "authentication_required"));
export const authMe500 = http.get("*/api/v1/auth/me", () => errorResponse(500, "internal_error"));
export const authMeNetworkError = http.get("*/api/v1/auth/me", () => HttpResponse.error());

// /auth/login ------------------------------------------------------------

export const loginSuccess = http.post("*/api/v1/auth/login", () => jsonResponse(ANALYST_USER));
export const loginInvalid = http.post("*/api/v1/auth/login", () => errorResponse(401, "invalid_credentials"));
export const loginRateLimited = http.post("*/api/v1/auth/login", () => errorResponse(429, "rate_limited"));
export const loginUnavailable = http.post("*/api/v1/auth/login", () => errorResponse(503, "dependency_unavailable"));
export const loginNetworkError = http.post("*/api/v1/auth/login", () => HttpResponse.error());

// /auth/logout -----------------------------------------------------------

export const logoutSuccess = http.post("*/api/v1/auth/logout", () => new HttpResponse(null, { status: 204 }));

// /runtime ---------------------------------------------------------------

export const runtimeFake = http.get("*/api/v1/runtime", () => jsonResponse({ operating_mode: "fake" }));
export const runtimeProduction = http.get("*/api/v1/runtime", () => jsonResponse({ operating_mode: "production" }));
export const runtimeFailure = http.get("*/api/v1/runtime", () => errorResponse(503, "dependency_unavailable"));
export const runtimeNetworkError = http.get("*/api/v1/runtime", () => HttpResponse.error());

/**
 * Stateful login-flow handlers mirroring the real session lifecycle:
 * `/auth/me` returns 401 until a successful login turns it into 200, and
 * login sets the double-submit CSRF cookie the way the real server does.
 */
export function loginFlowHandlers(
  user: PublicUser = ANALYST_USER,
): HttpHandler[] {
  let authenticated = false;
  return [
    http.get("*/api/v1/auth/me", () =>
      authenticated ? jsonResponse(user) : errorResponse(401, "authentication_required")),
    http.post("*/api/v1/auth/login", () => {
      authenticated = true;
      document.cookie = "ati_csrf=test-csrf-token";
      return jsonResponse(user);
    }),
    http.post("*/api/v1/auth/logout", () => {
      // Mirror the real server: revoke the session and expire the CSRF cookie.
      authenticated = false;
      document.cookie = "ati_csrf=; Max-Age=0";
      return new HttpResponse(null, { status: 204 });
    }),
    runtimeFake,
  ];
}
// /investigations -- PR 24B ---------------------------------------------

// One bounded synthetic Investigation fixture (opaque IDs only).
export function buildInvestigation(
  overrides: Partial<Investigation> = {},
): Investigation {
  const id = overrides.id ?? "20000000-0000-4000-8000-000000000001";
  return {
    id,
    objective: "assess the update-package delivery domain",
    status: "pending",
    created_at: "2026-06-01T10:00:00Z",
    started_at: "2026-06-01T10:00:01Z",
    completed_at: null,
    stop_reason: null,
    root_entity_ids: [],
    discovered_entity_ids: [],
    evidence_ids: [],
    relationship_ids: [],
    assessment_id: null,
    report_id: null,
    version: 1,
    ...overrides,
  };
}

export const EVIDENCE_ID = "40000000-0000-4000-8000-000000000001";
export const OBSERVATION_ID = "40000000-0000-4000-8000-000000000002";

export function buildAssessment(
  overrides: Partial<Assessment> = {},
): Assessment {
  const investigationId = overrides.investigation_id ?? "20000000-0000-4000-8000-000000000001";
  return {
    id: "30000000-0000-4000-8000-000000000001",
    investigation_id: investigationId,
    verdict: "malicious",
    confidence: "high",
    summary: "Correlated multi-source evidence is sufficient to conclude that the root indicator is part of malicious delivery infrastructure.",
    analyzed_evidence_ids: [EVIDENCE_ID],
    findings: [
      {
        category: "reputation",
        disposition: "supporting",
        statement: "Threat-intelligence and reputation sources associate the root indicator with known malicious delivery infrastructure.",
        confidence: "high",
        support: [{ kind: "evidence", evidence_id: EVIDENCE_ID }],
      },
    ],
    limitations: ["Assessment limits are bounded to the supplied evidence."],
    unresolved_questions: [],
    recommended_next_steps: ["Monitor the resolved delivery infrastructure."],
    created_at: "2026-06-01T10:05:00Z",
    version: 1,
    ...overrides,
  };
}

export function buildReport(overrides: Partial<Report> = {}): Report {
  const investigationId = overrides.investigation_id ?? "20000000-0000-4000-8000-000000000001";
  const assessmentId = overrides.assessment_id ?? "30000000-0000-4000-8000-000000000001";
  return {
    id: "50000000-0000-4000-8000-000000000001",
    investigation_id: investigationId,
    assessment_id: assessmentId,
    verdict: "malicious",
    confidence: "high",
    title: "ATI deterministic investigation report",
    executive_summary: [
      {
        text: "The investigation concluded that the root indicator participates in malicious delivery infrastructure with high confidence.",
        support: [
          {
            kind: "assessment_finding",
            assessment_id: assessmentId,
            finding_ordinal: 1,
          },
        ],
      },
    ],
    findings: [
      {
        assessment_finding_ordinal: 1,
        category: "reputation",
        disposition: "supporting",
        statement: "Threat-intelligence and reputation sources associate the root indicator with known malicious delivery infrastructure.",
        confidence: "high",
        support: [{ kind: "evidence", evidence_id: EVIDENCE_ID }],
      },
    ],
    research_context: [],
    source_evidence_ids: [EVIDENCE_ID],
    source_relationship_observation_ids: [],
    source_research_result_ids: [],
    limitations: ["Report caveats are copied from the current Assessment."],
    unresolved_questions: [],
    recommended_next_steps: ["Monitor the resolved delivery infrastructure."],
    created_at: "2026-06-01T10:06:00Z",
    version: 1,
    ...overrides,
  };
}

/** A completed Investigation with current Assessment + Report pointers. */
export function completedInvestigationFixture(
  overrides: Partial<Investigation> = {},
): Investigation {
  return buildInvestigation({
    status: "completed",
    completed_at: "2026-06-01T10:06:00Z",
    assessment_id: "30000000-0000-4000-8000-000000000001",
    report_id: "50000000-0000-4000-8000-000000000001",
    version: 5,
    ...overrides,
  });
}

/** Record every list request's exact query parameters (never decoded). */
export interface ListRequestRecord {
  status: string | null;
  cursor: string | null;
  limit: string | null;
}

export function listRequestRecorder() {
  const requests: ListRequestRecord[] = [];
  return { requests };
}

/**
 * Deterministic paged list handler over opaque cursors.
 *
 * `pages[i]` is served when the request cursor equals `cursors[i]`; the
 * returned `next_cursor` is the next opaque cursor (or null on the last
 * page). An unknown cursor fails closed with 422. `recorder` captures the
 * exact status/cursor/limit parameters for assertions.
 */
export function investigationsPagedHandler({
  pages,
  recorder,
  statusParam = null,
}: {
  pages: Investigation[][];
  recorder: { requests: ListRequestRecord[] };
  statusParam?: string | null;
}) {
  const cursors = ["", "cursor-1", "cursor-2", "cursor-3"];
  return http.get("*/api/v1/investigations", ({ request }) => {
    const url = new URL(request.url);
    recorder.requests.push({
      status: url.searchParams.get("status"),
      cursor: url.searchParams.get("cursor"),
      limit: url.searchParams.get("limit"),
    });
    if (statusParam !== null && url.searchParams.get("status") !== statusParam) {
      return jsonResponse({ items: [], next_cursor: null });
    }
    const cursor = url.searchParams.get("cursor") ?? "";
    const index = cursors.indexOf(cursor);
    if (index < 0 || index >= pages.length) {
      return errorResponse(422, "validation_error");
    }
    return jsonResponse({
      items: pages[index],
      next_cursor: index + 1 < pages.length ? cursors[index + 1] : null,
    });
  });
}

export function investigationsListHandler(items: Investigation[], nextCursor: string | null = null) {
  return http.get("*/api/v1/investigations", () =>
    jsonResponse({ items, next_cursor: nextCursor }));
}

export const investigationsListErrorHandler = http.get("*/api/v1/investigations", () =>
  errorResponse(500, "internal_error"));

export const investigationsListNetworkErrorHandler = http.get("*/api/v1/investigations", () =>
  HttpResponse.error());

export function investigationDetailHandler(investigation: Investigation) {
  return http.get("*/api/v1/investigations/:id", () => jsonResponse(investigation));
}

export const investigationDetail404Handler = http.get("*/api/v1/investigations/:id", () =>
  errorResponse(404, "investigation_not_found"));

export const investigationDetailNetworkErrorHandler = http.get("*/api/v1/investigations/:id", () =>
  HttpResponse.error());

/**
 * Stateful lifecycle handler: each GET returns the next stage, holding the
 * last stage forever. Mirrors `pending -> running -> completed` etc.
 */
export function investigationLifecycleHandler(stages: Investigation[]) {
  let calls = 0;
  return http.get("*/api/v1/investigations/:id", () => {
    const stage = stages[Math.min(calls, stages.length - 1)];
    calls += 1;
    return jsonResponse(stage);
  });
}

/** Record the last create request's exact headers/body (no secrets). */
export interface CreateRequestRecord {
  body: unknown;
  idempotencyKey: string | null;
  csrfToken: string | null;
}

/**
 * Stateful create handler: 202 with a durable identity, or a scripted
 * conflict/validation/transport failure. Records every request. `failWith`
 * lets a test switch modes mid-flow (e.g. transport -> ok for retry tests).
 */
export function createInvestigationHandler({
  result,
  failWith: initialFailWith = "ok",
}: {
  result?: CreateInvestigationResult;
  failWith?: "ok" | "conflict" | "validation" | "transport";
} = {}) {
  const requests: CreateRequestRecord[] = [];
  const state: { failWith: "ok" | "conflict" | "validation" | "transport" } = {
    failWith: initialFailWith,
  };
  const handler = http.post("*/api/v1/investigations", async ({ request }) => {
    const body = await request.json();
    requests.push({
      body,
      idempotencyKey: request.headers.get("Idempotency-Key"),
      csrfToken: request.headers.get("X-CSRF-Token"),
    });
    if (state.failWith === "conflict") {
      return errorResponse(409, "idempotency_conflict");
    }
    if (state.failWith === "validation") {
      return errorResponse(422, "validation_error");
    }
    if (state.failWith === "transport") {
      return HttpResponse.error();
    }
    return jsonResponse<CreateInvestigationResult>(
      result ?? {
        id: "60000000-0000-4000-8000-000000000001",
        status: "pending",
        created_at: "2026-06-01T10:00:00Z",
      },
      202,
    );
  });
  return { handler, requests, failWith: (mode: typeof state.failWith) => { state.failWith = mode; } };
}

export function assessmentCurrentHandler(assessment: Assessment) {
  return http.get("*/api/v1/investigations/:id/assessments/current", () =>
    jsonResponse(assessment));
}

export const assessmentCurrent404Handler = http.get("*/api/v1/investigations/:id/assessments/current", () =>
  errorResponse(404, "assessment_not_found"));

export function reportCurrentHandler(report: Report) {
  return http.get("*/api/v1/investigations/:id/reports/current", () =>
    jsonResponse(report));
}

export const reportCurrent404Handler = http.get("*/api/v1/investigations/:id/reports/current", () =>
  errorResponse(404, "report_not_found"));

export function reportMarkdownHandler(text: string) {
  return http.get("*/api/v1/investigations/:id/reports/:reportId/markdown", () =>
    new HttpResponse(text, {
      headers: { "Content-Type": "text/markdown; charset=utf-8" },
    }));
}

export const reportMarkdown404Handler = http.get("*/api/v1/investigations/:id/reports/:reportId/markdown", () =>
  errorResponse(404, "report_not_found"));

// PR 24C analyst resource fixtures + handlers ---------------------------------

/** Record exact list query parameters for one resource request. */
export interface ResourceListRequestRecord {
  cursor: string | null;
  limit: string | null;
  params: Record<string, string>;
}

export function resourceListRecorder() {
  const requests: ResourceListRequestRecord[] = [];
  return { requests };
}

/**
 * Deterministic paged resource handler over opaque cursors.
 *
 * `pages[i]` is served when the request cursor equals `cursors[i]`; an
 * unknown cursor fails closed with 422. Every exact query parameter is
 * recorded for filter assertions (never decoded).
 */
export function pagedResourceHandler<T>({
  path,
  pages,
  recorder,
  failCursor = false,
}: {
  path: string;
  pages: T[][];
  recorder: { requests: ResourceListRequestRecord[] };
  failCursor?: boolean;
}) {
  const cursors = ["", "cursor-1", "cursor-2", "cursor-3"];
  return http.get(path, ({ request }) => {
    const url = new URL(request.url);
    recorder.requests.push({
      cursor: url.searchParams.get("cursor"),
      limit: url.searchParams.get("limit"),
      params: Object.fromEntries(url.searchParams.entries()),
    });
    const cursor = url.searchParams.get("cursor") ?? "";
    const index = cursors.indexOf(cursor);
    if (index < 0 || index >= pages.length) {
      return failCursor
        ? errorResponse(422, "invalid_cursor")
        : errorResponse(422, "validation_error");
    }
    return jsonResponse({
      items: pages[index],
      next_cursor: index + 1 < pages.length ? cursors[index + 1] : null,
    });
  });
}

export const RESOURCE_UUID_BASE = "40000000-0000-4000-8000-";

export function uuidAt(ordinal: number): string {
  return `${RESOURCE_UUID_BASE}${String(ordinal).padStart(12, "0")}`;
}

export function buildEvidence(overrides: Partial<Evidence> = {}): Evidence {
  return {
    id: uuidAt(1),
    subject_entity_id: uuidAt(101),
    subject_value: "update-package.test",
    subject_type: "domain",
    type: "urn:ati:evidence:dns" as EvidenceTypeName,
    source: "fake-dns",
    source_record_id: "record-1",
    source_url: "https://example.invalid/dns/update-package.test",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
    facts: { resolver: "8.8.8.8" },
    ...overrides,
  };
}

export function buildRelationship(overrides: Partial<Relationship> = {}): Relationship {
  return {
    id: uuidAt(21),
    source_entity_id: uuidAt(101),
    target_entity_id: uuidAt(102),
    type: "urn:ati:relationship:dns:resolves_to" as RelationshipTypeName,
    ...overrides,
  };
}

export function buildObservation(overrides: Partial<RelationshipObservation> = {}): RelationshipObservation {
  return {
    id: uuidAt(41),
    relationship_id: uuidAt(21),
    evidence_id: uuidAt(1),
    investigation_id: "20000000-0000-4000-8000-000000000001",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
    source: "fake-dns",
    confidence: 0.9,
    ...overrides,
  };
}

export function buildResearchResult(overrides: Partial<ResearchResult> = {}): ResearchResult {
  return {
    id: uuidAt(61),
    investigation_id: "20000000-0000-4000-8000-000000000001",
    subject_entity_id: uuidAt(101),
    query: "context for update-package.test",
    created_at: "2026-06-01T09:10:00Z",
    claims: [
      {
        id: uuidAt(71),
        text: "Asserted sentence about the subject from persisted research.",
        citation_ids: [uuidAt(81)],
      },
    ],
    citations: [
      {
        citation_id: uuidAt(81),
        document_id: uuidAt(91),
        document_type: "report",
        source_id: "source-1",
        source_record_id: "record-9",
        source_url: "https://example.invalid/research/1",
        title: "Example research document",
        published_at: "2026-05-01T00:00:00Z",
        chunk_sequence: 3,
        similarity_score: 0.81,
        text: "Persisted chunk text with <markup> that must stay escaped.",
      },
    ],
    ...overrides,
  };
}

export function buildTimelineEvent(overrides: Partial<TimelineEvent> = {}): TimelineEvent {
  return {
    id: uuidAt(111),
    occurred_at: "2026-06-01T09:00:01Z",
    type: "provider_work_completed" as TimelineEventTypeName,
    provider: "fake-dns",
    target_entity_id: uuidAt(101),
    entity_ids: [uuidAt(101)],
    evidence_ids: [uuidAt(1)],
    relationship_ids: [],
    entity_count: 1,
    pivot_depth: null,
    provider_calls_used: 3,
    replans_used: 0,
    error_code: null,
    reason_code: null,
    ...overrides,
  };
}

export function buildHistoryRecord(overrides: Partial<HistoryRecord> = {}): HistoryRecord {
  return {
    id: uuidAt(131),
    object_type: "investigation",
    object_id: "20000000-0000-4000-8000-000000000001",
    operation: "UPDATE" as HistoryOperationName,
    version: 2,
    occurred_at: "2026-06-01T09:00:02Z",
    actor_id: "10000000-0000-4000-8000-000000000001",
    state: { status: "running", version: 2 },
    diff: { status: { before: "pending", after: "running" } },
    ...overrides,
  };
}
