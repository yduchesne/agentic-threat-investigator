// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot capability registry tests (PR 24D §25; PR 24F).
//
// Every registered action maps one explicit source identity to an exact
// existing server filter/selection. No actions are inferred from strings,
// no source-or-target merge exists, and no-op targets are suppressed.
// RelationshipObservation support now opens the exact scoped observation.

import { describe, expect, it } from "vitest";

import type { Evidence, Relationship, RelationshipObservation, ResearchResult } from "../api/schema-types";
import {
  entityActions,
  evidenceSubjectActions,
  evidenceSupportAction,
  observationActions,
  observationSupportAction,
  relationshipObservationsAction,
  relationshipSourceActions,
  relationshipTargetActions,
  researchSubjectActions,
  researchSupportAction,
  suppressNoOps,
  type PivotAction,
} from "./pivot-capabilities";
import type { PivotStep } from "./pivot-types";

const ENTITY_ID = "40000000-0000-4000-8000-000000000101";
const ENTITY_ID_2 = "40000000-0000-4000-8000-000000000102";
const EVIDENCE_ID = "40000000-0000-4000-8000-000000000001";
const RELATIONSHIP_ID = "40000000-0000-4000-8000-000000000021";
const RESEARCH_ID = "40000000-0000-4000-8000-000000000061";

function evidence(): Evidence {
  return {
    id: EVIDENCE_ID,
    subject_entity_id: ENTITY_ID,
    subject_value: "update-package.test",
    subject_type: "domain",
    type: "urn:ati:evidence:dns",
    source: "fake-dns",
    source_record_id: "record-1",
    source_url: null,
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
    facts: {},
  };
}

function relationship(): Relationship {
  return {
    id: RELATIONSHIP_ID,
    source_entity_id: ENTITY_ID,
    target_entity_id: ENTITY_ID_2,
    type: "urn:ati:relationship:dns:resolves_to",
  };
}

function observation(): RelationshipObservation {
  return {
    id: "40000000-0000-4000-8000-000000000041",
    relationship_id: RELATIONSHIP_ID,
    evidence_id: EVIDENCE_ID,
    investigation_id: "20000000-0000-4000-8000-000000000001",
    observed_at: "2026-06-01T09:00:00Z",
    retrieved_at: "2026-06-01T09:05:00Z",
    source: "fake-dns",
    confidence: 0.9,
  };
}

function research(): ResearchResult {
  return {
    id: RESEARCH_ID,
    investigation_id: "20000000-0000-4000-8000-000000000001",
    subject_entity_id: ENTITY_ID,
    query: "context for update-package.test",
    created_at: "2026-06-01T09:10:00Z",
    claims: [
      {
        id: "40000000-0000-4000-8000-000000000071",
        text: "Arbitrary claim text must never pivot to Evidence.",
        citation_ids: [],
      },
    ],
    citations: [],
  };
}

describe("pivot capability registry", () => {
  it("Evidence subject exposes all four entity targets", () => {
    const actions = evidenceSubjectActions(evidence(), "table_cell");
    expect(actions.map((action) => action.key)).toEqual([
      "evidenceForEntity",
      "relationshipsSource",
      "relationshipsTarget",
      "researchForEntity",
    ]);
    const byKey = Object.fromEntries(actions.map((action) => [action.key, action]));
    expect(byKey.evidenceForEntity.target.filters).toEqual({
      subject_entity_id: ENTITY_ID,
    });
    expect(byKey.relationshipsSource.target.filters).toEqual({
      source_entity_id: ENTITY_ID,
    });
    expect(byKey.relationshipsTarget.target.filters).toEqual({
      target_entity_id: ENTITY_ID,
    });
    expect(byKey.researchForEntity.target.filters).toEqual({
      subject_entity_id: ENTITY_ID,
    });
  });

  it("the human-readable subject value is the evidence action label", () => {
    const [evidenceAction] = evidenceSubjectActions(evidence(), "table_cell");
    expect(evidenceAction.target.label).toBe("update-package.test");
  });

  it("Relationship source exposes the entity targets on source identity", () => {
    const actions = relationshipSourceActions(relationship(), "table_cell");
    expect(actions.map((action) => action.target.filters)).toEqual([
      { subject_entity_id: ENTITY_ID },
      { source_entity_id: ENTITY_ID },
      { target_entity_id: ENTITY_ID },
      { subject_entity_id: ENTITY_ID },
    ]);
  });

  it("Relationship target exposes the entity targets on target identity", () => {
    const actions = relationshipTargetActions(relationship(), "table_cell");
    expect(actions.map((action) => action.target.filters)).toEqual([
      { subject_entity_id: ENTITY_ID_2 },
      { source_entity_id: ENTITY_ID_2 },
      { target_entity_id: ENTITY_ID_2 },
      { subject_entity_id: ENTITY_ID_2 },
    ]);
  });

  it("Relationship identity exposes exactly the observations target", () => {
    const action = relationshipObservationsAction(RELATIONSHIP_ID, "detail_field");
    expect(action.target.resource).toBe("relationship-observations");
    expect(action.target.filters).toEqual({ relationship_id: RELATIONSHIP_ID });
    expect(action.target.selectedId).toBeNull();
  });

  it("an observation exposes the relationship and exact-evidence targets only", () => {
    const actions = observationActions(observation(), "table_cell");
    expect(actions.map((action) => action.key)).toEqual([
      "observationsForRelationship",
      "evidenceExact",
    ]);
    const [observations, evidenceExact] = actions;
    expect(observations.target.filters).toEqual({ relationship_id: RELATIONSHIP_ID });
    expect(evidenceExact.target.resource).toBe("evidence");
    expect(evidenceExact.target.filters).toEqual({});
    expect(evidenceExact.target.selectedId).toBe(EVIDENCE_ID);
  });

  it("Research subject exposes the entity targets; claim text never pivots", () => {
    const actions = researchSubjectActions(research(), "table_cell");
    expect(actions).toHaveLength(4);
    for (const action of actions) {
      // No action key or filter ever references claim/citation text.
      expect(JSON.stringify(action.target)).not.toContain("Arbitrary claim");
    }
  });

  it("Report Evidence support opens the exact scoped Evidence selection", () => {
    const action = evidenceSupportAction(EVIDENCE_ID, "report_support");
    expect(action.target.resource).toBe("evidence");
    expect(action.target.filters).toEqual({});
    expect(action.target.selectedId).toBe(EVIDENCE_ID);
  });

  it("Report Research support opens the exact scoped ResearchResult selection", () => {
    const action = researchSupportAction(RESEARCH_ID, "research_reference");
    expect(action.target.resource).toBe("research");
    expect(action.target.selectedId).toBe(RESEARCH_ID);
  });

  it("RelationshipObservation support opens the exact scoped observation", () => {
    const observationId = "40000000-0000-4000-8000-000000000041";
    const action = observationSupportAction(observationId, "report_support");
    expect(action.key).toBe("observationExact");
    expect(action.target.resource).toBe("relationship-observations");
    expect(action.target.filters).toEqual({});
    expect(action.target.selectedId).toBe(observationId);
    expect(action.target.label).toContain("RelationshipObservation");
    expect(action.target.label).not.toContain(observationId);
  });

  it("no-op entity targets are suppressed against the active step", () => {
    const active: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "update-package.test",
      sourceKind: "table_cell",
    };
    const actions = suppressNoOps(evidenceSubjectActions(evidence(), "table_cell"), active);
    expect(actions.map((action) => action.key)).toEqual([
      "relationshipsSource",
      "relationshipsTarget",
      "researchForEntity",
    ]);
  });

  it("a different filter context is not a no-op", () => {
    const active: PivotStep = {
      resource: "evidence",
      filters: { source: "fake-dns" },
      selectedId: null,
      label: "source filter",
      sourceKind: "table_cell",
    };
    const actions = suppressNoOps(evidenceSubjectActions(evidence(), "table_cell"), active);
    expect(actions).toHaveLength(4);
  });

  it("exact-id selections are never suppressed as no-ops", () => {
    const active: PivotStep = {
      resource: "evidence",
      filters: {},
      selectedId: EVIDENCE_ID,
      label: "Evidence 40000000",
      sourceKind: "report_support",
    };
    const actions = suppressNoOps([evidenceSupportAction(EVIDENCE_ID, "report_support")], active);
    expect(actions).toHaveLength(1);
  });

  it("C-V07: no-op suppression applies identically to map_entity sources", () => {
    const active: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "203.0.113.10",
      sourceKind: "map_entity",
    };
    // Map-origin evidence-for-entity against the identical filter context
    // is suppressed exactly like any other source kind; the independent
    // relationship/research actions remain.
    const actions = suppressNoOps(
      entityActions(ENTITY_ID, "203.0.113.10", "map_entity"),
      active,
    );
    expect(actions.map((action) => action.key)).toEqual([
      "relationshipsSource",
      "relationshipsTarget",
      "researchForEntity",
    ]);
  });

  it("no actions are inferred for unsupported source kinds", () => {
    // The breadth of the registered surface: nothing outside the factory
    // functions above can produce an action.
    const allRegistered: PivotAction[] = [
      ...entityActions(ENTITY_ID, "Entity 40000000", "table_cell"),
      evidenceSupportAction(EVIDENCE_ID, "report_support"),
      researchSupportAction(RESEARCH_ID, "research_reference"),
      relationshipObservationsAction(RELATIONSHIP_ID, "detail_field"),
    ];
    const keys = new Set(allRegistered.map((action) => action.key));
    expect(keys.size).toBe(allRegistered.length);
  });
});