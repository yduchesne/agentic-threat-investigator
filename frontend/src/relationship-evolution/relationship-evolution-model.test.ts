// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution pure derived-model tests (PR 24E E-D01..E-D09).
//
// Lanes/points are converted deterministically from one loaded page: no
// validity inference, no cross-page first/frequency claims, null observed
// times stay in the explicit unavailable group, and retrieved time never
// substitutes on the temporal axis.

import { describe, expect, it } from "vitest";

import type { RelationshipObservation } from "../api/schema-types";
import { buildObservation } from "../test/handlers";
import {
  annotateLanes,
  earliestPagePoint,
} from "./relationship-evolution-derived";
import {
  buildEvolutionModel,
  edgeDirection,
} from "./relationship-evolution-model";

const FOCAL = "40000000-0000-4000-8000-000000000101";
const COUNTERPARTY = "40000000-0000-4000-8000-000000000102";
const NOISE = "40000000-0000-4000-8000-000000000103";

function outbound(
  overrides: Partial<RelationshipObservation> = {},
): RelationshipObservation {
  return buildObservation({
    relationship_source_entity_id: FOCAL,
    relationship_target_entity_id: COUNTERPARTY,
    ...overrides,
  });
}

function inbound(
  overrides: Partial<RelationshipObservation> = {},
): RelationshipObservation {
  return buildObservation({
    relationship_source_entity_id: COUNTERPARTY,
    relationship_target_entity_id: FOCAL,
    ...overrides,
  });
}

describe("Relationship Evolution derived model", () => {
  it("E-D01: a source-focal observation forms an outbound lane", () => {
    const model = buildEvolutionModel(FOCAL, [outbound()]);
    expect(model.lanes).toHaveLength(1);
    expect(model.lanes[0].direction).toBe("source");
    expect(model.lanes[0].counterpartyEntityId).toBe(COUNTERPARTY);
    expect(model.lanes[0].points).toHaveLength(1);
    expect(model.unavailable).toHaveLength(0);
  });

  it("E-D02: a target-focal observation forms an inbound lane", () => {
    const model = buildEvolutionModel(FOCAL, [inbound()]);
    expect(model.lanes[0].direction).toBe("target");
    expect(model.lanes[0].counterpartyEntityId).toBe(COUNTERPARTY);
  });

  it("E-D03: a self relationship yields exactly one deterministic lane", () => {
    const model = buildEvolutionModel(FOCAL, [
      buildObservation({
        relationship_source_entity_id: FOCAL,
        relationship_target_entity_id: FOCAL,
      }),
    ]);
    expect(model.lanes).toHaveLength(1);
    expect(model.lanes[0].direction).toBe("either");
    expect(model.lanes[0].counterpartyEntityId).toBe(FOCAL);
    expect(model.lanes[0].points).toHaveLength(1);
  });

  it("E-D04: null observed_at lands in the explicit unavailable group", () => {
    const model = buildEvolutionModel(FOCAL, [
      buildObservation({
        relationship_source_entity_id: FOCAL,
        relationship_target_entity_id: COUNTERPARTY,
        observed_at: null,
      }),
    ]);
    expect(model.lanes).toHaveLength(1);
    expect(model.lanes[0].points).toHaveLength(1);
    expect(model.unavailable).toHaveLength(1);
    // The retrieved time is preserved but never promoted to an x-axis value.
    expect(model.unavailable[0].retrievedAt).toBe("2026-06-01T09:05:00Z");
    expect(model.unavailable[0].observedAt).toBeNull();
  });

  it("E-D05: same-timestamp points break ties by stable observation id", () => {
    const first = outbound({
      id: "40000000-0000-4000-8000-000000000061",
      observed_at: "2026-06-01T09:00:00Z",
    });
    const second = outbound({
      id: "40000000-0000-4000-8000-000000000062",
      observed_at: "2026-06-01T09:00:00Z",
    });
    const model = buildEvolutionModel(FOCAL, [second, first]);
    expect(model.lanes[0].points.map((point) => point.observationId)).toEqual([
      first.id,
      second.id,
    ]);
  });

  it("E-D06: a differing retrieved time never alters the temporal axis", () => {
    const early = outbound({ observed_at: "2026-06-01T09:00:00Z" });
    const lateRetrieval = outbound({
      id: "40000000-0000-4000-8000-000000000063",
      observed_at: "2026-07-01T09:00:00Z",
      retrieved_at: "2026-09-01T09:00:00Z",
    });
    const model = buildEvolutionModel(FOCAL, [lateRetrieval, early]);
    // Ordering follows observed_at, not retrieved_at.
    expect(model.lanes[0].points[0].observationId).toBe(early.id);
    expect(model.lanes[0].points[1].observedAt).toBe("2026-07-01T09:00:00Z");
    expect(model.lanes[0].points[1].retrievedAt).toBe("2026-09-01T09:00:00Z");
  });

  it("E-D07: repeated observations of one relationship stay distinct points", () => {
    const model = buildEvolutionModel(FOCAL, [
      outbound({ observed_at: "2026-06-01T09:00:00Z" }),
      outbound({ observed_at: "2026-06-10T09:00:00Z" }),
    ]);
    expect(model.lanes).toHaveLength(1);
    expect(model.lanes[0].points).toHaveLength(2);
  });

  it("E-D08: two relationship types to the same counterparty stay separate lanes", () => {
    const model = buildEvolutionModel(FOCAL, [
      outbound({ relationship_type: "urn:ati:relationship:dns:resolves_to" }),
      outbound({
        relationship_id: "40000000-0000-4000-8000-000000000031",
        relationship_type: "urn:ati:relationship:dns:cname_of",
      }),
    ]);
    expect(model.lanes).toHaveLength(2);
    expect(new Set(model.lanes.map((lane) => lane.relationshipType))).toEqual(
      new Set([
        "urn:ati:relationship:dns:resolves_to",
        "urn:ati:relationship:dns:cname_of",
      ]),
    );
  });

  it("E-D09: annotations are page-scoped and never claim global first", () => {
    const first = outbound({ observed_at: "2026-06-01T09:00:00Z" });
    const model = buildEvolutionModel(FOCAL, [first]);
    const earliest = earliestPagePoint(model.lanes.flatMap((lane) => lane.points));
    expect(earliest?.observationId).toBe(first.id);
    const annotations = annotateLanes(model.lanes, earliest);
    // The label is deterministic and page-scoped ("earliest shown" only).
    expect(annotations.get(first.relationship_id)?.isEarliestShown).toBe(true);
    expect(annotations.get(first.relationship_id)?.pageObservationCount).toBe(1);
  });

  it("edge direction is deterministic for source/target/self", () => {
    expect(edgeDirection(FOCAL, FOCAL, COUNTERPARTY)).toBe("source");
    expect(edgeDirection(FOCAL, COUNTERPARTY, FOCAL)).toBe("target");
    expect(edgeDirection(FOCAL, FOCAL, FOCAL)).toBe("either");
    expect(edgeDirection(FOCAL, NOISE, COUNTERPARTY)).toBe("source");
  });
});