// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Research page tests (PR 24C Q01-Q08).
//
// Research is visibly contextual knowledge, never Evidence; claims and
// citations render with inspectable closure; all external text is escaped
// and never fetched.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildResearchResult,
  completedInvestigationFixture,
  errorResponse,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}/research`;

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

describe("Research page", () => {
  it("renders list metadata and counts (Q01)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[buildResearchResult()]],
        recorder: resourceListRecorder(),
      }),
    );
    renderAtPath(BASE);
    expect(await screen.findByText("Research context")).toBeInTheDocument();
    expect(
      screen.getByText("Contextual retrieved/synthesized knowledge — not observed Evidence."),
    ).toBeInTheDocument();
    // Metadata/count headers from the exact DTO.
    expect(await screen.findByText("Claim count")).toBeInTheDocument();
    expect(screen.getByText("Citation count")).toBeInTheDocument();
    expect(screen.getByText("Research result ID")).toBeInTheDocument();
  });

  it("applies exact subject entity and created-time filters (Q02)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[buildResearchResult()]],
        recorder,
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Research context");
    await userEvent.type(screen.getByLabelText("Subject entity ID"), "40000000-0000-4000-8000-000000000101");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await screen.findByText("Research context");
    const last = recorder.requests.at(-1);
    expect(last?.params.subject_entity_id).toBe("40000000-0000-4000-8000-000000000101");
  });

  it("renders claims and citations with inspectable closure (Q03, Q04)", async () => {
    const research = buildResearchResult();
    const detail = buildResearchResult({
      claims: [
        {
          id: "40000000-0000-4000-8000-000000000071",
          text: "Asserted sentence about the subject.",
          citation_ids: ["40000000-0000-4000-8000-000000000081"],
        },
      ],
      citations: [
        {
          citation_id: "40000000-0000-4000-8000-000000000081",
          document_id: "40000000-0000-4000-8000-000000000091",
          document_type: "report",
          source_id: "source-1",
          source_record_id: "record-9",
          source_url: "https://example.invalid/research/1",
          title: "Example research document",
          published_at: "2026-05-01T00:00:00Z",
          chunk_sequence: 3,
          similarity_score: 0.81,
          text: "Persisted chunk text.",
        },
      ],
    });
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[research]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/research/:researchResultId", () =>
        jsonResponse(detail)),
    );
    renderAtPath(BASE);
    await userEvent.click(
      await screen.findByRole("button", { name: /View 40000000-0000-4000-8000-000000000061/ }),
    );
    expect(await screen.findByText("Asserted sentence about the subject.")).toBeInTheDocument();
    expect(screen.getByText("Example research document")).toBeInTheDocument();
    // Claim-to-citation closure is inspectable by citation reference.
    expect(screen.getByText(/citation 40000000/)).toBeInTheDocument();
    // Similarity is labeled as a retrieval score, never credibility.
    expect(screen.getByText("Retrieval score")).toBeInTheDocument();
    expect(screen.queryByText(/credibility|confidence|truth|malicious/i)).not.toBeInTheDocument();
  });

  it("escapes markup in external research text (Q06)", async () => {
    const detail = buildResearchResult({
      citations: [
        {
          ...buildResearchResult().citations[0],
          text: "<img src=x onerror=alert(1)> chunk text",
        },
      ],
    });
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[buildResearchResult()]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/research/:researchResultId", () =>
        jsonResponse(detail)),
    );
    renderAtPath(BASE);
    await userEvent.click(
      await screen.findByRole("button", { name: /View 40000000-0000-4000-8000-000000000061/ }),
    );
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)> chunk text/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("never fetches external sources from the browser (Q07)", async () => {
    let externalFetch = 0;
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[buildResearchResult()]],
        recorder: resourceListRecorder(),
      }),
      http.get("https://example.invalid/research/1", () => {
        externalFetch += 1;
        return jsonResponse({});
      }),
    );
    renderAtPath(BASE);
    await screen.findByText("Research context");
    expect(externalFetch).toBe(0);
  });

  it("renders a scoped 404 inside the drawer (Q05b)", async () => {
    setHttpHandlers(
      ...AUTH,
      workspaceHandler(),
      pagedResourceHandler({
        path: "*/api/v1/investigations/:id/research",
        pages: [[buildResearchResult()]],
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/research/:researchResultId", () =>
        errorResponse(404, "research_result_not_found")),
    );
    renderAtPath(`${BASE}?selected=40000000-0000-4000-8000-000000000061`);
    expect(
      await screen.findByText("Resource not found or not accessible"),
    ).toBeInTheDocument();
  });
});