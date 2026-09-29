// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Support presentation collection/indexing tests (PR 31F-5 E3).
//
// SP05: duplicate requested IDs resolve once (unique sets leave the hook).
// SP07: missing metadata renders the localized unavailable statement with
// the secondary ID (covered by FindingList rendering below).
// SP10: the full Report route resolves through the same hook/endpoint.

import { render, screen, type RenderResult } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router";

import type { Finding, ReportFinding } from "../api/schema-types";
import { AppProviders } from "../app/AppProviders";
import { freshQueryClient } from "../test/render";
import { FindingList } from "./FindingList";
import {
  collectSupportIds,
  indexSupportPresentations,
  type SupportPresentationLookup,
} from "./support-presentations-queries";

const EVIDENCE_ID = "40000000-0000-4000-8000-000000000001";
const OBSERVATION_ID = "40000000-0000-4000-8000-000000000002";

function findingLike(
  support: Finding["support"] | ReportFinding["support"],
): FindingLike {
  return {
    category: "reputation",
    disposition: "supporting",
    statement: "statement",
    confidence: "high",
    support,
  } as FindingLike;
}

type FindingLike = Finding | ReportFinding;

/** A mutable presentation map (the production lookup is read-only). */
function lookup(): {
  evidence?: SupportPresentationLookup;
  observation?: SupportPresentationLookup;
} {
  const evidence: Record<string, SupportPresentationLookup[string]> = {};
  const observation: Record<string, SupportPresentationLookup[string]> = {};
  return {
    evidence: evidence as SupportPresentationLookup,
    observation: observation as SupportPresentationLookup,
  };
}

/** Render a bounded FindingList under the production providers + router. */
function renderFindingList(options: {
  findings: readonly FindingLike[];
  presentation?: SupportPresentationLookup | null;
}): RenderResult {
  const router = createMemoryRouter(
    [
      {
        path: "/",
        element: (
          <FindingList
            findings={options.findings}
            presentation={options.presentation}
          />
        ),
      },
    ],
    { initialEntries: ["/"] },
  );
  return render(
    <AppProviders queryClient={freshQueryClient()}>
      <RouterProvider router={router} />
    </AppProviders>,
  );
}

describe("collectSupportIds", () => {
  it("collects unique support IDs across findings (SP05)", () => {
    const ids = collectSupportIds([
      findingLike([
        { kind: "evidence", evidence_id: EVIDENCE_ID },
        { kind: "evidence", evidence_id: EVIDENCE_ID },
        {
          kind: "relationship_observation",
          relationship_observation_id: OBSERVATION_ID,
        },
      ]),
      findingLike([
        { kind: "evidence", evidence_id: EVIDENCE_ID },
        {
          kind: "relationship_observation",
          relationship_observation_id: OBSERVATION_ID,
        },
      ]),
    ]);
    expect(ids.evidenceIds).toEqual([EVIDENCE_ID]);
    expect(ids.relationshipObservationIds).toEqual([OBSERVATION_ID]);
  });

  it("returns empty sets for findings without supports", () => {
    expect(collectSupportIds([findingLike([])])).toEqual({
      evidenceIds: [],
      relationshipObservationIds: [],
    });
  });
});

describe("indexSupportPresentations", () => {
  it("indexes evidence and observation projections by ID", () => {
    const indexed = indexSupportPresentations({
      evidence: [
        {
          evidence_observation_id: EVIDENCE_ID,
          evidence_type: "urn:ati:evidence:dns",
          source: "urn:ati:source:google_public_dns",
          subject_entity_id: "40000000-0000-4000-8000-000000000101",
          subject_entity_type: "domain",
          subject_entity_value: "update-package.test",
        },
      ],
      relationship_observations: [
        {
          relationship_observation_id: OBSERVATION_ID,
          relationship_id: "40000000-0000-4000-8000-000000000021",
          relationship_type: "urn:ati:relationship:dns:resolves_to",
          source_entity_id: "40000000-0000-4000-8000-000000000101",
          source_entity_type: "domain",
          source_entity_value: "update-package.test",
          target_entity_id: "40000000-0000-4000-8000-000000000102",
          target_entity_type: "malware",
          target_entity_value: "malware.badloader_v2",
          observed_at: "2026-06-01T09:00:00Z",
        },
      ],
    });
    expect((indexed[EVIDENCE_ID] as { evidence_observation_id?: string }).evidence_observation_id).toBe(EVIDENCE_ID);
    expect((indexed[OBSERVATION_ID] as { relationship_observation_id?: string }).relationship_observation_id).toBe(OBSERVATION_ID);
  });
});

describe("FindingList support presentation", () => {
  it("renders the semantic Evidence description with the ID secondary (SP01)", () => {
    const boxes = lookup();
    const presentation = boxes.evidence;
    (presentation as Record<string, unknown>)[EVIDENCE_ID] = {
      evidence_observation_id: EVIDENCE_ID,
      evidence_type: "urn:ati:evidence:dns",
      source: "urn:ati:source:google_public_dns",
      subject_entity_id: "40000000-0000-4000-8000-000000000101",
      subject_entity_type: "domain",
      subject_entity_value: "update-package.test",
    };
    renderFindingList({
      findings: [findingLike([{ kind: "evidence", evidence_id: EVIDENCE_ID }])],
      presentation,
    });
    expect(
      screen.getByText(/update-package\.test/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Evidence ID:/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open evidence" })).toBeInTheDocument();
  });

  it("renders the semantic RelationshipObservation edge (SP02/SP03)", () => {
    const boxes = lookup();
    const presentation = boxes.observation;
    (presentation as Record<string, unknown>)[OBSERVATION_ID] = {
      relationship_observation_id: OBSERVATION_ID,
      relationship_id: "40000000-0000-4000-8000-000000000021",
      relationship_type: "urn:ati:relationship:dns:resolves_to",
      source_entity_id: "40000000-0000-4000-8000-000000000101",
      source_entity_type: "domain",
      source_entity_value: "update-package.test",
      target_entity_id: "40000000-0000-4000-8000-000000000102",
      target_entity_type: "malware",
      target_entity_value: "malware.badloader_v2",
      observed_at: "2026-06-01T09:00:00Z",
    };
    renderFindingList({
      findings: [
        findingLike([
          {
            kind: "relationship_observation",
            relationship_observation_id: OBSERVATION_ID,
          },
        ]),
      ],
      presentation,
    });
    expect(
      screen.getByText(/update-package\.test · Domain → Resolves to → malware\.badloader_v2 · Malware/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Observation ID:/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "View relationship observation" }),
    ).toBeInTheDocument();
  });

  it("renders the localized unavailable statement with the secondary ID (SP07)", () => {
    renderFindingList({
      findings: [findingLike([{ kind: "evidence", evidence_id: EVIDENCE_ID }])],
      presentation: {},
    });
    expect(screen.getByText("Evidence details unavailable")).toBeInTheDocument();
    expect(screen.getByText(/Evidence ID:/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open evidence" })).toBeInTheDocument();
  });
});
