// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GraphRelationshipProvenance component tests (PR 31F U01..U37).
//
// The graph-local provenance drill-down is a composition of the existing
// Investigation-scoped Relationship / RelationshipObservation / Evidence
// hooks and surfaces. Exact identity chain under test:
//
//   GraphEdge.relationship_id
//     -> Relationship (exact GET)
//     -> bounded RelationshipObservations filtered by relationship_id
//     -> exact RelationshipObservation (observation.id, page row or GET)
//     -> exact EvidenceObservation (observation.evidence_id, explicit action)
//
// Assertions cover: no identity reconstruction or global probes; bounded
// opaque-cursor pagination with a local back stack; observed_at /
// retrieved_at staying distinct with null observed_at never substituted;
// zero Evidence fan-out before the explicit action; per-level failures
// keeping the higher context and Retry; drill-down never issuing graph/
// topology requests (so graph expansion state and node positions cannot be
// touched); and reusable canonical surfaces (DetailRows, EvidenceDetail,
// observation Pivot actions). Edge canvas selection itself is not
// jsdom-renderable (see relationship-graph.test.tsx G31D-U06), so the
// graph-integration slice opens the provenance through the accessible edge
// list (the same non-spatial path real analysts always have).

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { HttpHandler } from "msw";
import { http } from "msw";
import { describe, expect, it } from "vitest";
import { useState } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";
import type { ReactElement } from "react";

import { renderAtPath } from "../test/render";
import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  buildGraphEdge,
  buildGraphNeighborhood,
  buildGraphNode,
  buildObservation,
  buildRelationship,
  completedInvestigationFixture,
  errorResponse,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
  type ResourceListRequestRecord,
} from "../test/handlers";
import type { RelationshipObservation } from "../api/schema-types";
import { nodeId } from "./RelationshipGraph";
import { GraphRelationshipProvenance } from "./GraphRelationshipProvenance";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const RELATIONSHIP = "40000000-0000-4000-8000-000000000021";
const OTHER_RELATIONSHIP = "40000000-0000-4000-8000-000000000022";
const EVIDENCE_A = "40000000-0000-4000-8000-000000000001";
const EVIDENCE_B = "40000000-0000-4000-8000-000000000002";
const OBS_A_ID = "40000000-0000-4000-8000-000000000041";
const OBS_B_ID = "40000000-0000-4000-8000-000000000042";

const OBS_A = buildObservation({
  id: OBS_A_ID,
  relationship_id: RELATIONSHIP,
  evidence_id: EVIDENCE_A,
  observed_at: "2026-06-01T09:00:00Z",
  retrieved_at: "2026-06-01T09:05:00Z",
  source: "fake-dns-a",
  confidence: 0.9,
});
const OBS_B = buildObservation({
  id: OBS_B_ID,
  relationship_id: RELATIONSHIP,
  evidence_id: EVIDENCE_B,
  observed_at: null,
  retrieved_at: "2026-06-02T09:00:00Z",
  source: "fake-dns-b",
  confidence: null,
});

/** A handler recording every exact relationship-detail path parameter. */
function relationshipDetailRecorder(
  relationship = buildRelationship({ id: RELATIONSHIP }),
) {
  const recorder = { requests: [] as string[] };
  const handler = http.get(
    "*/api/v1/investigations/:id/relationships/:relationshipId",
    ({ params }) => {
      recorder.requests.push(String(params.relationshipId));
      return jsonResponse(relationship);
    },
  );
  return { recorder, handler };
}

/**
 * A handler serving the exact OBS_A observation for any observation id and
 * recording every requested path parameter (recovery from an off-page
 * selection uses a different observation than the page row may have held).
 */
function recoverObservationRecorder() {
  const recorder = { requests: [] as string[] };
  const handler = http.get(
    "*/api/v1/investigations/:id/relationship-observations/:observationId",
    ({ params }) => {
      const id = String(params.observationId);
      recorder.requests.push(id);
      return jsonResponse({ ...OBS_A, id });
    },
  );
  return { recorder, handler };
}

/** A handler recording every exact Evidence-detail path parameter. */
function evidenceDetailRecorder(evidence = buildEvidence({ id: EVIDENCE_A })) {
  const recorder = { requests: [] as string[] };
  const handler = http.get(
    "*/api/v1/investigations/:id/evidence/:evidenceId",
    ({ params }) => {
      recorder.requests.push(String(params.evidenceId));
      return jsonResponse(evidence);
    },
  );
  return { recorder, handler };
}

/** Mount the provenance component under the production providers + a router. */
function renderInRouter(children: ReactElement): {
  result: ReturnType<typeof render>;
  router: ReturnType<typeof createMemoryRouter>;
} {
  const queryClient = freshQueryClient();
  const router = createMemoryRouter(
    [{ path: "*", element: children }],
    { initialEntries: ["/"] },
  );
  return {
    result: render(
      <AppProviders queryClient={queryClient}>
        <RouterProvider router={router} />
      </AppProviders>,
    ),
    router,
  };
}

/** Mount the provenance component directly under the production providers. */
function renderProvenance(relationshipId: string = RELATIONSHIP) {
  return renderInRouter(
    <GraphRelationshipProvenance
      investigationId={INVESTIGATION_ID}
      relationshipId={relationshipId}
      onClose={() => {}}
    />,
  );
}

/**
 * A live host that swaps the provenance ``relationshipId`` prop on demand,
 * so the prop-change reset (U15) runs on the same component instance.
 */
function ProvenanceHost(): ReactElement {
  const [relationshipId, setRelationshipId] = useState(RELATIONSHIP);
  return (
    <div>
      <button type="button" onClick={() => setRelationshipId(OTHER_RELATIONSHIP)}>
        switch relationship
      </button>
      <GraphRelationshipProvenance
        investigationId={INVESTIGATION_ID}
        relationshipId={relationshipId}
        onClose={() => {}}
      />
    </div>
  );
}

/** The standard happy-path handler set for one Relationship + a page. */
function happyHandlerSet({
  recorder,
  rows = [OBS_A],
  relationship = buildRelationship({ id: RELATIONSHIP }),
}: {
  recorder: { requests: ResourceListRequestRecord[] };
  rows?: RelationshipObservation[];
  relationship?: ReturnType<typeof buildRelationship>;
}): HttpHandler[] {
  return [
    http.get(
      "*/api/v1/investigations/:id/relationships/:relationshipId",
      () => jsonResponse(relationship),
    ),
    pagedResourceHandler<RelationshipObservation>({
      path: "*/api/v1/investigations/:id/relationship-observations",
      pages: [rows],
      recorder,
    }),
  ];
}

/** Wait until the graph-local provenance panel is visible. */
async function provenanceVisible(): Promise<void> {
  await screen.findByRole("region", { name: "Relationship provenance" });
}

/** The unique marker of the open observation detail surface. */
async function viewEvidenceButton(): Promise<HTMLElement> {
  return screen.findByRole("button", { name: "View supporting evidence" });
}

describe("GraphRelationshipProvenance relationship detail (PR 31F U01-U06)", () => {
  it("U01/U03: a mounted component reads the exact Investigation-scoped Relationship and shows canonical stable fields", async () => {
    const relation = relationshipDetailRecorder();
    const listRecorder = resourceListRecorder();
    setHttpHandlers(
      relation.handler,
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: listRecorder,
      }),
    );
    renderProvenance(RELATIONSHIP);
    await provenanceVisible();
    // Exact relationship_id path (never endpoints/type/edge label).
    await waitFor(() => {
      expect(relation.recorder.requests).toEqual([RELATIONSHIP]);
    });
    // Canonical stable fields: source/type/target/id.
    expect(
      screen.getByTitle("40000000-0000-4000-8000-000000000101"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Resolves to").length).toBeGreaterThan(0);
    expect(
      screen.getByTitle("40000000-0000-4000-8000-000000000102"),
    ).toBeInTheDocument();
    expect(
      screen.getByTitle(RELATIONSHIP),
    ).toBeInTheDocument();
    // The bounded observation page for the same relationship is loaded.
    expect(listRecorder.requests.at(-1)?.params.relationship_id).toBe(RELATIONSHIP);
  });

  it("U02: initial load shows an explicit bounded loading state", async () => {
    const pendingRelationship = http.get(
      "*/api/v1/investigations/:id/relationships/:relationshipId",
      ({ request }) =>
        new Promise<never>((_resolve, reject) => {
          request.signal.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        }),
    );
    const pendingList = http.get(
      "*/api/v1/investigations/:id/relationship-observations",
      ({ request }) =>
        new Promise<never>((_resolve, reject) => {
          request.signal.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          );
        }),
    );
    setHttpHandlers(pendingRelationship, pendingList);
    renderProvenance();
    await provenanceVisible();
    expect(screen.getByText("Loading relationship…")).toBeInTheDocument();
    expect(screen.getByText("Loading observations…")).toBeInTheDocument();
  });

  it("U04: a scoped 404 renders not-found instead of a global probe", async () => {
    const listRecorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => errorResponse(404, "relationship_not_found"),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: listRecorder,
      }),
    );
    renderProvenance();
    await provenanceVisible();
    expect(
      await screen.findByText("Relationship not found or not accessible."),
    ).toBeInTheDocument();
    // The observations page still loads (failure isolated by level).
    expect(listRecorder.requests.at(-1)?.params.relationship_id).toBe(RELATIONSHIP);
  });

  it("U05/U06: a Relationship failure offers Retry and Retry repeats the exact request", async () => {
    const relation = relationshipDetailRecorder();
    const listRecorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => errorResponse(500, "internal_error"),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: listRecorder,
      }),
    );
    renderProvenance();
    await provenanceVisible();
    expect(
      await screen.findByText("Unable to load relationship."),
    ).toBeInTheDocument();
    // The observations page loads independently (failure isolated by level).
    expect(listRecorder.requests.at(-1)?.params.relationship_id).toBe(RELATIONSHIP);
    // Retry repeats the exact Relationship request.
    setHttpHandlers(
      relation.handler,
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: listRecorder,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(relation.recorder.requests).toEqual([RELATIONSHIP]);
    });
    expect(
      await screen.findByTitle("40000000-0000-4000-8000-000000000101"),
    ).toBeInTheDocument();
  });
});

describe("GraphRelationshipProvenance observation page (PR 31F U07-U15)", () => {
  it("U07/U08/U09: the first page filters by exact relationship_id, stays bounded, and exposes every row field", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...happyHandlerSet({ recorder, rows: [OBS_A, OBS_B] }),
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    await waitFor(() => {
      expect(recorder.requests.length).toBeGreaterThan(0);
    });
    const request = recorder.requests.at(0);
    expect(request?.params.relationship_id).toBe(RELATIONSHIP);
    expect(request?.limit).toBe("25"); // existing bounded observation page size
    expect(request?.cursor).toBeNull(); // first page
    // Row fields: source, observed_at, retrieved_at, confidence, IDs.
    expect(within(table).getByText("fake-dns-a")).toBeInTheDocument();
    expect(
      within(table).getByTitle("2026-06-01T09:00:00Z"),
    ).toBeInTheDocument();
    expect(
      within(table).getByTitle("2026-06-01T09:05:00Z"),
    ).toBeInTheDocument();
    expect(within(table).getByText("0.9")).toBeInTheDocument();
    expect(
      within(table).getByTitle(OBS_A_ID),
    ).toBeInTheDocument(); // observation id
    expect(
      within(table).getByTitle(EVIDENCE_A),
    ).toBeInTheDocument(); // evidence id
  });

  it("U10: a null observed_at renders unavailable and is never replaced by retrieved time", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(...happyHandlerSet({ recorder, rows: [OBS_B] }));
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    // The null observed_at cell is explicitly unavailable; only retrieved
    // time renders as a timestamp, so no retrieved-derived observed time
    // can appear anywhere in the row.
    const row = within(table).getByRole("row", { name: /fake-dns-b/ });
    expect(within(row).getByText("Not observed")).toBeInTheDocument();
    expect(within(row).getByTitle("2026-06-02T09:00:00Z")).toBeInTheDocument();
    expect(within(row).getAllByTitle(/T/)).toHaveLength(1);
  });

  it("U11/U12: Next issues exactly one next-page request and Previous restores the prior cursor", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A], [OBS_B]],
        recorder,
      }),
    );
    renderProvenance();
    await provenanceVisible();
    let table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    expect(within(table).getByText("fake-dns-a")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    // Exactly one next-page request with the opaque cursor.
    await waitFor(() => {
      expect(recorder.requests.filter((r) => r.cursor === "cursor-1")).toHaveLength(1);
    });
    // The bounded loading state replaces the table while the next page
    // resolves; re-acquire it, then assert the next page rendered.
    table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    expect(await within(table).findByText("fake-dns-b")).toBeInTheDocument();
    expect(within(table).queryByText("fake-dns-a")).not.toBeInTheDocument();
    // Previous restores the prior cursor through the local back stack; the
    // first-page query reuses the TanStack cache (no extra request).
    const requestCountAfterNext = recorder.requests.length;
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    expect(await within(table).findByText("fake-dns-a")).toBeInTheDocument();
    expect(recorder.requests.length).toBe(requestCountAfterNext);
  });

  it("U13: Next is disabled when the page carries no next_cursor", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(...happyHandlerSet({ recorder, rows: [OBS_A] }));
    renderProvenance();
    await provenanceVisible();
    await screen.findByRole("table", { name: "Supporting observations" });
    await waitFor(() => {
      expect(recorder.requests.length).toBeGreaterThan(0);
    });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    });
    // Previous is disabled on the first page too (empty back stack).
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
  });

  it("U14: an observation-page error retains the Relationship context and offers Retry", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      http.get(
        "*/api/v1/investigations/:id/relationship-observations",
        () => errorResponse(500, "internal_error"),
      ),
    );
    renderProvenance();
    await provenanceVisible();
    expect(
      await screen.findByText("Unable to load observations."),
    ).toBeInTheDocument();
    // Relationship context retained (failure isolated by level).
    expect(screen.getByTitle(RELATIONSHIP)).toBeInTheDocument();
    const recorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder,
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(recorder.requests.length).toBe(1);
    });
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    expect(within(table).getByText("fake-dns-a")).toBeInTheDocument();
  });

  it("U15: a Relationship change resets cursor/back stack/observation/Evidence", async () => {
    const evidence = evidenceDetailRecorder();
    const recorder: { requests: ResourceListRequestRecord[] } = { requests: [] };
    const otherObservation = buildObservation({
      id: uuidAt(51),
      relationship_id: OTHER_RELATIONSHIP,
      evidence_id: EVIDENCE_B,
      source: "fake-other-source",
    });
    const observationsHandler = http.get(
      "*/api/v1/investigations/:id/relationship-observations",
      ({ request }) => {
        const url = new URL(request.url);
        recorder.requests.push({
          cursor: url.searchParams.get("cursor"),
          limit: url.searchParams.get("limit"),
          params: Object.fromEntries(url.searchParams.entries()),
        });
        const relationshipId = url.searchParams.get("relationship_id");
        if (relationshipId === OTHER_RELATIONSHIP) {
          // The other Relationship has its own distinct observation rows.
          return jsonResponse({
            items: [otherObservation],
            next_cursor: null,
          });
        }
        return jsonResponse({ items: [OBS_A], next_cursor: "cursor-1" });
      },
    );
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        ({ params }) =>
          jsonResponse(buildRelationship({ id: String(params.relationshipId) })),
      ),
      observationsHandler,
      evidence.handler,
    );
    renderInRouter(<ProvenanceHost />);
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    // Select OBS_A and open its Evidence (drill-down active).
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    await viewEvidenceButton();
    fireEvent.click(screen.getByRole("button", { name: "View supporting evidence" }));
    await waitFor(() => {
      expect(evidence.recorder.requests).toEqual([EVIDENCE_A]);
    });
    expect(
      await screen.findByRole("heading", { name: "Supporting evidence" }),
    ).toBeInTheDocument();
    // New Relationship on the same live host instance: full reset.
    fireEvent.click(screen.getByRole("button", { name: "switch relationship" }));
    const otherTable = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.relationship_id).toBe(OTHER_RELATIONSHIP);
      expect(last?.cursor).toBeNull(); // back to the first page
    });
    // No observation selection and no Evidence selection survive.
    expect(
      screen.queryByRole("button", { name: "View supporting evidence" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Supporting evidence" }),
    ).not.toBeInTheDocument();
    expect(
      within(otherTable).getByRole("button", { name: "View observation" }),
    ).toBeInTheDocument();
    // Never provenance from the prior edge: the other Relationship shows
    // its own observation rows.
    expect(within(otherTable).getByText("fake-other-source")).toBeInTheDocument();
    expect(within(otherTable).queryByText("fake-dns-a")).not.toBeInTheDocument();
  });
});

describe("GraphRelationshipProvenance exact observation selection (PR 31F U16-U21)", () => {
  it("U16/U17: a selection on the loaded page renders that exact row (observation.id, not evidence id)", async () => {
    const recorder = resourceListRecorder();
    const exact = recoverObservationRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder,
      }),
      exact.handler,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    // The observation detail opens from the loaded page row: the exact
    // observation GET is never issued for an on-page row.
    await viewEvidenceButton();
    expect(exact.recorder.requests).toEqual([]);
    // Selection identity is observation.id; the detail exposes it.
    expect(screen.getAllByTitle(OBS_A_ID).length).toBeGreaterThan(0);
  });

  it("U18: an off-page selection resolves through the exact observation GET by observation.id", async () => {
    const recorder = resourceListRecorder();
    const exact = recoverObservationRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A], [OBS_B]],
        recorder,
      }),
      exact.handler,
    );
    renderProvenance();
    await provenanceVisible();
    let table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    // Select OBS_A while it is on page 1, then paginate to page 2.
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    await viewEvidenceButton();
    expect(exact.recorder.requests).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    // Re-acquire the table: the bounded loading state replaced it.
    table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    await within(table).findByText("fake-dns-b");
    // OBS_A is no longer on the loaded page -> exactly one exact GET,
    // keyed by observation.id (never the evidence id, never a cursor scan).
    await waitFor(() => {
      expect(exact.recorder.requests).toEqual([OBS_A_ID]);
    });
    // The exact surface stays open with the recovered observation.
    await waitFor(() => {
      expect(
        screen.getAllByText("fake-dns-a").length,
      ).toBeGreaterThan(0);
    });
    const requestCount = exact.recorder.requests.length;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(exact.recorder.requests.length).toBe(requestCount);
  });

  it("U19: an exact observation 404 keeps the workspace with a scoped not-found", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A], [OBS_B]],
        recorder: resourceListRecorder(),
      }),
      http.get(
        "*/api/v1/investigations/:id/relationship-observations/:observationId",
        () => errorResponse(404, "observation_not_found"),
      ),
    );
    renderProvenance();
    await provenanceVisible();
    // Select OBS_A on page 1 (no GET); navigate to page 2 so the exact
    // GET must recover OBS_A and reports the scoped 404.
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(
      within(table).getAllByRole("button", { name: "View observation" })[0],
    );
    await viewEvidenceButton();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    const pageTwo = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    expect(
      await screen.findByText("Observation not found or not accessible."),
    ).toBeInTheDocument();
    // The Relationship + observation page stay intact.
    expect(screen.getByTitle(RELATIONSHIP)).toBeInTheDocument();
    expect(
      within(pageTwo).getByText("fake-dns-b"),
    ).toBeInTheDocument();
  });

  it("U20: an exact observation error offers Retry of the exact observation id", async () => {
    const bad = http.get(
      "*/api/v1/investigations/:id/relationship-observations/:observationId",
      () => errorResponse(500, "internal_error"),
    );
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A], [OBS_B]],
        recorder: resourceListRecorder(),
      }),
      bad,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(
      within(table).getAllByRole("button", { name: "View observation" })[0],
    );
    await viewEvidenceButton();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(
      await screen.findByText("Unable to load observation."),
    ).toBeInTheDocument();
    const exact = recoverObservationRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A, OBS_B]],
        recorder: resourceListRecorder(),
      }),
      exact.handler,
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(exact.recorder.requests).toEqual([OBS_A_ID]);
    });
    await waitFor(() => {
      expect(screen.getAllByText("fake-dns-a").length).toBeGreaterThan(0);
    });
  });

  it("U21: the observation detail keeps the existing provenance pivot actions", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(...happyHandlerSet({ recorder, rows: [OBS_A] }));
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    const trigger = await screen.findByRole("button", {
      name: "Observation provenance actions",
    });
    fireEvent.click(trigger);
    await screen.findByRole("menuitem", { name: "Open evidence" });
    expect(
      screen.getByRole("menuitem", { name: "Observations for this relationship" }),
    ).toBeInTheDocument();
  });
});

describe("GraphRelationshipProvenance exact Evidence drill-down (PR 31F U22-U31)", () => {
  it("U22/U23: no Evidence request before the explicit action (no fan-out)", async () => {
    const recorder = resourceListRecorder();
    const evidence = evidenceDetailRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A, OBS_B]],
        recorder,
      }),
      evidence.handler,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    await waitFor(() => {
      expect(
        within(table).getAllByRole("button", { name: "View observation" }).length,
      ).toBe(2);
    });
    // Two observation rows loaded -> still zero Evidence GETs.
    expect(evidence.recorder.requests).toEqual([]);
    // Selecting an observation still issues no Evidence request.
    fireEvent.click(within(table).getAllByRole("button", { name: "View observation" })[0]);
    await viewEvidenceButton();
    expect(evidence.recorder.requests).toEqual([]);
  });

  it("U24/U25/U26: the explicit action requests observation.evidence_id and renders canonical EvidenceDetail with distinct times", async () => {
    const recorder = resourceListRecorder();
    const evidence = evidenceDetailRecorder(
      buildEvidence({
        id: EVIDENCE_A,
        subject_value: "update-package.test",
        observed_at: "2026-06-01T09:00:00Z",
        retrieved_at: "2026-06-01T09:05:00Z",
      }),
    );
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder,
      }),
      evidence.handler,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    fireEvent.click(await viewEvidenceButton());
    // Exact evidence_id requested (never reconstructed or scanned).
    await waitFor(() => {
      expect(evidence.recorder.requests).toEqual([EVIDENCE_A]);
    });
    // Canonical EvidenceDetail with observed/retrieved kept distinct.
    expect(
      await screen.findByText("update-package.test"),
    ).toBeInTheDocument();
    expect(screen.getAllByTitle("2026-06-01T09:00:00Z").length).toBeGreaterThan(0);
    expect(screen.getAllByTitle("2026-06-01T09:05:00Z").length).toBeGreaterThan(0);
  });

  it("U27: Evidence 404 is scoped and keeps the selected observation", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: resourceListRecorder(),
      }),
      http.get(
        "*/api/v1/investigations/:id/evidence/:evidenceId",
        () => errorResponse(404, "evidence_not_found"),
      ),
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    fireEvent.click(await viewEvidenceButton());
    expect(
      await screen.findByText("Evidence not found or not accessible."),
    ).toBeInTheDocument();
    // Selected observation retained under the scoped 404.
    expect(
      screen.getByRole("button", { name: "View supporting evidence" }),
    ).toBeInTheDocument();
  });

  it("U28: an Evidence error offers Retry of the exact evidence_id", async () => {
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: resourceListRecorder(),
      }),
      http.get(
        "*/api/v1/investigations/:id/evidence/:evidenceId",
        () => errorResponse(500, "internal_error"),
      ),
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    fireEvent.click(await viewEvidenceButton());
    expect(
      await screen.findByText("Unable to load supporting evidence."),
    ).toBeInTheDocument();
    const evidence = evidenceDetailRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder: resourceListRecorder(),
      }),
      evidence.handler,
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(evidence.recorder.requests).toEqual([EVIDENCE_A]);
    });
    expect(
      await screen.findByText("update-package.test"),
    ).toBeInTheDocument();
  });

  it("U29: closing Evidence retains the selected observation", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder,
      }),
      evidenceDetailRecorder().handler,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    fireEvent.click(await viewEvidenceButton());
    // Wait for the Evidence detail itself (not just its heading) before
    // closing it back to the observation.
    await screen.findByText("update-package.test");
    const backToObservation = await screen.findByRole("button", {
      name: "Back to observation",
    });
    fireEvent.click(backToObservation);
    await waitFor(() => {
      expect(
        screen.queryByRole("heading", { name: "Supporting evidence" }),
      ).not.toBeInTheDocument();
    });
    // The selected observation stays rendered with its Evidence action.
    expect(
      screen.getAllByText("fake-dns-a").length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: "View supporting evidence" }),
    ).toBeInTheDocument();
  });

  it("U30: a new observation clears the prior Evidence selection", async () => {
    const recorder = resourceListRecorder();
    const evidence = evidenceDetailRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A, OBS_B]],
        recorder,
      }),
      evidence.handler,
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    const rowButtons = within(table).getAllByRole("button", { name: "View observation" });
    fireEvent.click(rowButtons[0]);
    fireEvent.click(await viewEvidenceButton());
    await waitFor(() => {
      expect(evidence.recorder.requests).toEqual([EVIDENCE_A]);
    });
    await screen.findByRole("heading", { name: "Supporting evidence" });
    // Select the other observation: Evidence closes, nothing refetches.
    fireEvent.click(rowButtons[1]);
    await waitFor(() => {
      expect(
        screen.queryByRole("heading", { name: "Supporting evidence" }),
      ).not.toBeInTheDocument();
    });
    expect(evidence.recorder.requests).toEqual([EVIDENCE_A]);
    expect(
      screen.getByRole("button", { name: "View supporting evidence" }),
    ).toBeInTheDocument();
  });

  it("U31: the Evidence surface exposes public DTO fields only (no raw/internal payload)", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        () => jsonResponse(buildRelationship({ id: RELATIONSHIP })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A]],
        recorder,
      }),
      http.get(
        "*/api/v1/investigations/:id/evidence/:evidenceId",
        () =>
          jsonResponse(
            buildEvidence({
              id: EVIDENCE_A,
              // A hostile extra field must never surface.
              ...({ raw_payload: "secret-canary", internal_hash: "deadbeef" } as object),
            }),
          ),
      ),
    );
    renderProvenance();
    await provenanceVisible();
    const table = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(within(table).getByRole("button", { name: "View observation" }));
    fireEvent.click(await viewEvidenceButton());
    // Canonical safe fields render.
    expect(
      await screen.findByText("update-package.test"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("fake-dns").length).toBeGreaterThan(0);
    // Never the raw provider payload or internal hashes.
    expect(screen.queryByText(/secret-canary/)).not.toBeInTheDocument();
    expect(screen.queryByText(/deadbeef/)).not.toBeInTheDocument();
    expect(screen.queryByText(/raw_payload/i)).not.toBeInTheDocument();
  });
});

describe("GraphRelationshipProvenance graph isolation (PR 31F U32-U37, Q08)", () => {
  // The provenance opens through the always-available accessible edge list;
  // canvas edge selection itself is real-stack-covered (G31D-E04/E02).
  const FOCAL = "40000000-0000-4000-8000-000000000101";
  const B = "40000000-0000-4000-8000-000000000102";
  const C = "40000000-0000-4000-8000-000000000103";

  const ROOT = buildGraphNeighborhood({
    nodes: [
      buildGraphNode({
        entity_id: FOCAL,
        entity_type: "domain",
        value: "update-package.test",
        display_name: "Update Package Service",
      }),
      buildGraphNode({
        entity_id: B,
        entity_type: "ip_address",
        value: "203.0.113.10",
        display_name: "203.0.113.10",
      }),
    ],
    edges: [
      buildGraphEdge({
        relationship_id: RELATIONSHIP,
        source_entity_id: FOCAL,
        target_entity_id: B,
      }),
    ],
  });
  const B_HOP = buildGraphNeighborhood({
    nodes: [
      buildGraphNode({
        entity_id: B,
        entity_type: "ip_address",
        value: "203.0.113.10",
        display_name: "203.0.113.10",
      }),
      buildGraphNode({
        entity_id: C,
        entity_type: "malware",
        value: "malware.test",
        display_name: "malware.test",
      }),
    ],
    edges: [
      buildGraphEdge({
        relationship_id: "40000000-0000-4000-8000-000000000032",
        source_entity_id: B,
        target_entity_id: C,
      }),
    ],
  });

  interface GraphWorld {
    rendered: ReturnType<typeof renderAtPath>;
    graphRecorder: { requests: ResourceListRequestRecord[] };
    observationRecorder: { requests: ResourceListRequestRecord[] };
  }

  function renderGraphWithProvenance(): GraphWorld {
    const graphRecorder = resourceListRecorder();
    const observationRecorder = resourceListRecorder();
    const query = new URLSearchParams({ entity_id: FOCAL, view: "graph" });
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({ id: INVESTIGATION_ID }),
      ),
      http.get(
        "*/api/v1/investigations/:id/graph/entities/:entityId/neighborhood",
        ({ request, params }) => {
          const url = new URL(request.url);
          const entity = String(params.entityId);
          graphRecorder.requests.push({
            cursor: null,
            limit: url.searchParams.get("limit"),
            params: {
              entity_id: entity,
              ...Object.fromEntries(url.searchParams.entries()),
            },
          });
          return jsonResponse(entity === B ? B_HOP : ROOT);
        },
      ),
      http.get(
        "*/api/v1/investigations/:id/relationships/:relationshipId",
        ({ params }) =>
          jsonResponse(buildRelationship({ id: String(params.relationshipId) })),
      ),
      pagedResourceHandler<RelationshipObservation>({
        path: "*/api/v1/investigations/:id/relationship-observations",
        pages: [[OBS_A], [OBS_B]],
        recorder: observationRecorder,
      }),
      recoverObservationRecorder().handler,
      evidenceDetailRecorder().handler,
    );
    const rendered = renderAtPath(
      `/investigations/${INVESTIGATION_ID}/relationships/evolution?${query.toString()}`,
    );
    return { rendered, graphRecorder, observationRecorder };
  }

  function graphNodeCount(): number {
    return document.querySelectorAll('[data-testid^="rf__node-"]').length;
  }

  function nodePosition(entity: string): { x: number; y: number } {
    const node = document.querySelector(
      `[data-testid="rf__node-${nodeId(entity)}"]`,
    );
    expect(node).not.toBeNull();
    const transform = (node as HTMLElement).style.transform;
    const match = /translate\((-?[0-9.e+-]+)px,\s*(-?[0-9.e+-]+)px\)/.exec(transform);
    if (match === null) {
      return { x: 0, y: 0 };
    }
    return { x: Number(match[1]), y: Number(match[2]) };
  }

  async function expandCounterparty(): Promise<void> {
    const counterparty = document.querySelector(`[data-testid="rf__node-${nodeId(B)}"]`);
    expect(counterparty).not.toBeNull();
    fireEvent.click(counterparty as Element);
    await screen.findByText("Entity: 203.0.113.10");
    fireEvent.click(
      screen.getByRole("button", { name: "Pivot actions for 203.0.113.10" }),
    );
    fireEvent.click(
      await screen.findByRole("menuitem", { name: "Expand known relationships" }),
    );
    await waitFor(() => {
      expect(graphNodeCount()).toBe(3);
    });
  }

  async function openProvenanceFromList(): Promise<void> {
    const list = await screen.findByRole("table", {
      name: "Relationship list (this page)",
    });
    fireEvent.click(
      within(list).getAllByRole("button", { name: "Inspect observations" })[0],
    );
    await provenanceVisible();
  }

  it("U32/U35: opening the provenance issues no expansion/topology request and preserves the accumulated graph", async () => {
    const { graphRecorder } = renderGraphWithProvenance();
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    // PR 31E: expand the counterparty so accumulated topology exists.
    await expandCounterparty();
    const graphRequestsBefore = graphRecorder.requests.length;
    const focalBefore = nodePosition(FOCAL);
    const bBefore = nodePosition(B);
    // Open the provenance through the accessible edge list.
    await openProvenanceFromList();
    await waitFor(() => {
      expect(graphRecorder.requests.length).toBe(graphRequestsBefore);
    });
    // Accumulated topology + positions untouched.
    expect(graphNodeCount()).toBe(3);
    expect(nodePosition(FOCAL)).toEqual(focalBefore);
    expect(nodePosition(B)).toEqual(bBefore);
  });

  it("U33/U34: paginating the provenance and opening Evidence leave topology and positions unchanged", async () => {
    const { graphRecorder, observationRecorder } = renderGraphWithProvenance();
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    await openProvenanceFromList();
    await screen.findByRole("table", {
      name: "Supporting observations",
    });
    await waitFor(() => {
      expect(observationRecorder.requests.length).toBe(1);
    });
    const graphRequestsBefore = graphRecorder.requests.length;
    const nodeCountBefore = graphNodeCount();
    const focalBefore = nodePosition(FOCAL);
    // Paginate: exactly one observation list request, zero graph requests.
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => {
      expect(observationRecorder.requests.length).toBe(2);
    });
    expect(graphRecorder.requests.length).toBe(graphRequestsBefore);
    expect(graphNodeCount()).toBe(nodeCountBefore);
    // The bounded loading state replaced the table; re-acquire it and
    // select the observation on the current page.
    const pageTwo = await screen.findByRole("table", {
      name: "Supporting observations",
    });
    fireEvent.click(
      within(pageTwo).getByRole("button", { name: "View observation" }),
    );
    fireEvent.click(await viewEvidenceButton());
    await screen.findByRole("heading", { name: "Supporting evidence" });
    expect(graphRecorder.requests.length).toBe(graphRequestsBefore);
    expect(graphNodeCount()).toBe(nodeCountBefore);
    const focalAfter = nodePosition(FOCAL);
    expect(Math.abs(focalAfter.x - focalBefore.x)).toBeLessThanOrEqual(2);
    expect(Math.abs(focalAfter.y - focalBefore.y)).toBeLessThanOrEqual(2);
  });

  it("U36/U37: closing the provenance leaves the graph, positions and expansion state intact", async () => {
    const { graphRecorder } = renderGraphWithProvenance();
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    // Expand first so expansion + position state must survive the close.
    await expandCounterparty();
    const bBefore = nodePosition(B);
    await openProvenanceFromList();
    const graphRequestsBefore = graphRecorder.requests.length;
    fireEvent.click(screen.getByRole("button", { name: "Close provenance" }));
    await waitFor(() => {
      expect(
        screen.queryByRole("region", { name: "Relationship provenance" }),
      ).not.toBeInTheDocument();
    });
    // Graph intact: accumulated topology visible, no extra graph request.
    expect(graphNodeCount()).toBe(3);
    expect(nodePosition(B)).toEqual(bBefore);
    expect(graphRecorder.requests.length).toBe(graphRequestsBefore);
    // Expansion state intact: the completed expansion still shows disabled.
    fireEvent.click(document.querySelector(`[data-testid="rf__node-${nodeId(B)}"]`) as Element);
    await screen.findByText("Entity: 203.0.113.10");
    fireEvent.click(
      screen.getByRole("button", { name: "Pivot actions for 203.0.113.10" }),
    );
    expect(
      screen.getByRole("menuitem", { name: "Expand known relationships" }),
    ).toBeDisabled();
    expect(graphRecorder.requests.length).toBe(graphRequestsBefore);
  });
});
