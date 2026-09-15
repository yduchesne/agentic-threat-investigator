// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot URL serializer/parser tests (PR 24D §24).
//
// Round-trip determinism and fail-closed validation: unknown versions,
// resources, filters, step fields, malformed UUIDs, label overflow, the
// sixth step, oversized parameters, and trailing/invalid payloads are all
// rejected without surfacing partial state. Navigation helpers preserve
// base search parameters exactly.

import { describe, expect, it } from "vitest";

import {
  clearPivotState,
  decodeBase64Url,
  encodeBase64Url,
  MAX_PIVOT_PARAM_BYTES,
  parsePivotState,
  PIVOT_VERSION,
  pushPivotStep,
  readPivotState,
  serializePivotState,
  truncatePivotSteps,
  withPivotState,
} from "./pivot-url";
import type { EvidenceTypeName } from "../api/schema-types";
import {
  MAX_PIVOT_STEPS,
  type PivotEvidenceStep,
  type PivotObservationStep,
  type PivotRelationshipStep,
  type PivotResearchStep,
  type PivotState,
  type PivotStep,
} from "./pivot-types";
import {
  MAX_PIVOT_LABEL_CHARS,
} from "./pivot-types";

const EVIDENCE_ID = "40000000-0000-4000-8000-000000000001";
const ENTITY_ID = "40000000-0000-4000-8000-000000000101";
const ENTITY_ID_2 = "40000000-0000-4000-8000-000000000102";
const RELATIONSHIP_ID = "40000000-0000-4000-8000-000000000021";

function evidenceStep(overrides: Partial<PivotEvidenceStep> = {}): PivotStep {
  return {
    resource: "evidence",
    filters: { subject_entity_id: ENTITY_ID },
    selectedId: null,
    label: "update-package.test",
    sourceKind: "table_cell",
    ...overrides,
  } as PivotStep;
}

function relationshipStep(overrides: Partial<PivotRelationshipStep> = {}): PivotStep {
  return {
    resource: "relationships",
    filters: { source_entity_id: ENTITY_ID },
    selectedId: null,
    label: "Entity 40000000",
    sourceKind: "table_cell",
    ...overrides,
  } as PivotStep;
}

function observationStep(overrides: Partial<PivotObservationStep> = {}): PivotStep {
  return {
    resource: "relationship-observations",
    filters: { relationship_id: RELATIONSHIP_ID },
    selectedId: null,
    label: "Relationship 40000000",
    sourceKind: "detail_field",
    ...overrides,
  } as PivotStep;
}

function researchStep(overrides: Partial<PivotResearchStep> = {}): PivotStep {
  return {
    resource: "research",
    filters: { subject_entity_id: ENTITY_ID_2 },
    selectedId: null,
    label: "Entity 40000000",
    sourceKind: "research_reference",
    ...overrides,
  } as PivotStep;
}

function steps(n: number): PivotStep[] {
  const base = [evidenceStep(), relationshipStep()];
  const out: PivotStep[] = [];
  for (let index = 0; index < n; index += 1) {
    out.push({ ...base[index % base.length] } as PivotStep);
  }
  return out;
}

describe("pivot URL serializer/parser", () => {
  it("base64url is the URL-safe unpadded RFC 4648 form", () => {
    const encoded = encodeBase64Url("hello world");
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(encoded).not.toContain("=");
    expect(decodeBase64Url(encoded)).toBe("hello world");
    expect(decodeBase64Url("!!not-base64!!")).toBeNull();
  });

  it("round-trips a valid single step deterministically (v1)", () => {
    const state = { steps: [evidenceStep()] };
    const serialized = serializePivotState(state);
    expect(serialized).not.toBeNull();
    expect(serialized).toBe(serializePivotState(state));
    const parsed = parsePivotState(serialized);
    expect(parsed).toEqual(state);
  });

  it("round-trips every resource and restores selection/cursor", () => {
    const states = [
      { steps: [evidenceStep({ selectedId: EVIDENCE_ID, cursor: "cursor-1" })] },
      { steps: [relationshipStep()] },
      { steps: [observationStep()] },
      { steps: [researchStep()] },
    ];
    for (const state of states) {
      const serialized = serializePivotState(state);
      expect(parsePivotState(serialized)).toEqual(state);
    }
  });

  it("round-trips filter enum and timestamp values", () => {
    const state: PivotState = {
      steps: [
        evidenceStep({
          filters: {
            source: "fake-dns",
            subject_entity_id: ENTITY_ID,
            type: "urn:ati:evidence:dns" as EvidenceTypeName,
            retrieved_from: "2026-06-01T09:00:00Z",
            retrieved_to: "2026-06-01T10:00:00Z",
          },
          cursor: "cursor-1",
        }),
      ],
    };
    expect(parsePivotState(serializePivotState(state))).toEqual(state);
  });

  it("rejects an unknown version", () => {
    const wire = `{"v":2,"steps":[{"r":"evidence","f":{},"s":null,"l":"l","k":"table_cell"}]}`;
    expect(parsePivotState(encodeBase64Url(wire))).toBeNull();
    expect(parsePivotState("garbage")).toBeNull();
  });

  it("rejects an unknown resource", () => {
    const steps = [{ ...evidenceStep(), resource: "timeline" }] as unknown as PivotStep[];
    expect(parseFromJson(steps)).toBeNull();
  });

  it("rejects an unsupported filter key per resource", () => {
    // The parser is exercised over the exact wire envelope: an invented
    // filter key must fail closed even if a serializer would drop it.
    const wire = `{"v":${PIVOT_VERSION},"steps":[{"r":"evidence","f":{"subject_entity_id":"${ENTITY_ID}","invented":"x"},"s":null,"l":"l","k":"table_cell"}]}`;
    expect(parsePivotState(encodeBase64Url(wire))).toBeNull();
  });

  it("rejects a malformed UUID filter value", () => {
    const state = { steps: [evidenceStep({ filters: { subject_entity_id: "not-a-uuid" } })] };
    expect(parseFromJson(state.steps)).toBeNull();
  });

  it("rejects an invalid enum filter value", () => {
    const steps = [
      {
        ...evidenceStep(),
        filters: { type: "urn:ati:evidence:invented" },
      },
    ] as unknown as PivotStep[];
    expect(parseFromJson(steps)).toBeNull();
  });

  it("rejects an invalid timestamp filter value", () => {
    const steps = [
      {
        ...evidenceStep(),
        filters: { retrieved_from: "yesterday" },
      },
    ] as unknown as PivotStep[];
    expect(parseFromJson(steps)).toBeNull();
  });

  it("rejects a malformed selected id", () => {
    expect(
      parseFromJson([{ ...evidenceStep(), selectedId: "123" }] as unknown as PivotStep[]),
    ).toBeNull();
    // Empty string selection is not a legal absent value.
    expect(
      parseFromJson([{ ...evidenceStep(), selectedId: "" }] as unknown as PivotStep[]),
    ).toBeNull();
  });

  it("rejects a sixth step but accepts the fifth", () => {
    expect(parseFromJson(steps(MAX_PIVOT_STEPS))).not.toBeNull();
    expect(parseFromJson(steps(MAX_PIVOT_STEPS + 1))).toBeNull();
  });

  it("rejects arbitrary extra envelope/step keys", () => {
    expect(
      parsePivotState(
        encodeBase64Url(`{"v":${PIVOT_VERSION},"steps":[],"extra":1}`),
      ),
    ).toBeNull();
    expect(
      parsePivotState(
        encodeBase64Url(
          `{"v":${PIVOT_VERSION},"steps":[{"r":"evidence","f":{},"s":null,"l":"l","k":"table_cell","oops":"x"}]}`,
        ),
      ),
    ).toBeNull();
  });

  it("rejects an oversized encoded parameter", () => {
    const oversized = "A".repeat(MAX_PIVOT_PARAM_BYTES + 1);
    expect(parsePivotState(oversized)).toBeNull();
    const state = {
      steps: [
        evidenceStep({
          filters: { subject_entity_id: ENTITY_ID, source: "s".repeat(200) },
        }),
      ],
    };
    expect(parsePivotState(serializePivotState(state))).not.toBeNull();
  });

  it("rejects a label over the bounded length and control characters", () => {
    const overlong = [
      { ...evidenceStep({ label: "x".repeat(129) }) },
    ] as unknown as PivotStep[];
    expect(parseFromJson(overlong)).toBeNull();
    const controlled = [
      { ...evidenceStep({ label: "ok\u0000bad" }) },
    ] as unknown as PivotStep[];
    expect(parseFromJson(controlled)).toBeNull();
  });

  it("rejects non-object envelopes and empty step arrays", () => {
    expect(parsePivotState(encodeBase64Url("[]"))).toBeNull();
    expect(parsePivotState(encodeBase64Url("[1,2,3]"))).toBeNull();
    expect(parsePivotState(encodeBase64Url(`{"v":${PIVOT_VERSION},"steps":[]}`))).toBeNull();
  });

  it("rejects prototype-bearing JSON keys", () => {
    const poisoned = JSON.parse(
      `{"v":${PIVOT_VERSION},"steps":[{"r":"evidence","f":{"__proto__":{"x":1}},"s":null,"l":"l","k":"table_cell"}]}`,
    );
    expect(parsePivotState(encodeBase64Url(JSON.stringify(poisoned)))).toBeNull();
  });

  it("push preserves previous steps and base params", () => {
    const params = new URLSearchParams("type=urn%3Aati%3Aevidence%3Adns&cursor=cursor-9");
    const params1 = pushPivotStep(params, evidenceStep());
    const state1 = readPivotState(params1);
    expect(state1?.steps).toHaveLength(1);
    expect(params1.get("type")).toBe("urn:ati:evidence:dns");
    expect(params1.get("cursor")).toBe("cursor-9");

    const params2 = pushPivotStep(params1, relationshipStep());
    const state2 = readPivotState(params2);
    expect(state2?.steps).toHaveLength(2);
    expect(state2?.steps[0]).toEqual(state1?.steps[0]);
    expect(params2.get("cursor")).toBe("cursor-9");
  });

  it("breadcrumb truncation keeps later steps only up to the target", () => {
    const params = withPivotState(new URLSearchParams(), {
      steps: [evidenceStep(), relationshipStep(), observationStep()],
    });
    const truncated = truncatePivotSteps(params, 1);
    const state = readPivotState(truncated);
    expect(state?.steps.map((step) => step.resource)).toEqual(["evidence"]);
  });

  it("breadcrumb truncation to zero clears the pivot parameter", () => {
    const params = withPivotState(new URLSearchParams("source=x"), {
      steps: [evidenceStep(), relationshipStep()],
    });
    const cleared = clearPivotState(params);
    expect(cleared.get("pivot")).toBeNull();
    expect(cleared.get("source")).toBe("x");
  });

  it("push refuses a step beyond the maximum depth", () => {
    const params = withPivotState(new URLSearchParams(), { steps: steps(MAX_PIVOT_STEPS) });
    const pushed = pushPivotStep(params, researchStep());
    expect(readPivotState(pushed)?.steps).toHaveLength(MAX_PIVOT_STEPS);
  });

  it("refuses to serialize states beyond the 4096-byte cap and keeps base params", () => {
    const huge = {
      steps: Array.from({ length: MAX_PIVOT_STEPS }, () =>
        ({
          resource: "evidence",
          filters: { source: "z".repeat(200), subject_entity_id: ENTITY_ID },
          selectedId: null,
          label: "y".repeat(128),
          sourceKind: "table_cell",
          cursor: "c".repeat(512),
        }) as PivotStep),
    };
    expect(serializePivotState(huge)).toBeNull();
    const params = withPivotState(new URLSearchParams("a=b"), huge);
    expect(params.get("pivot")).toBeNull();
    expect(params.get("a")).toBe("b");
  });

  it("C-V01/C-V02: accepts map_entity through the URL round-trip", () => {
    const mapStep = evidenceStep({
      sourceKind: "map_entity",
      label: "203.0.113.10",
    });
    const serialized = serializePivotState({ steps: [mapStep] });
    expect(serialized).not.toBeNull();
    expect(parsePivotState(serialized)).toEqual({ steps: [mapStep] });
    // The exact same wire value is deterministic.
    expect(serializePivotState({ steps: [mapStep] })).toBe(serialized);
  });

  it("C-V03: an unknown source kind is still rejected", () => {
    const wire = `{"v":${PIVOT_VERSION},"steps":[{"r":"evidence","f":{},"s":null,"l":"l","k":"map_marker"}]}`;
    expect(parsePivotState(encodeBase64Url(wire))).toBeNull();
    const wire2 = `{"v":${PIVOT_VERSION},"steps":[{"r":"evidence","f":{},"s":null,"l":"l","k":"map_row"}]}`;
    expect(parsePivotState(encodeBase64Url(wire2))).toBeNull();
  });

  it("C-V04: max pivot depth is unchanged at five", () => {
    expect(MAX_PIVOT_STEPS).toBe(5);
    expect(parseFromJson(steps(MAX_PIVOT_STEPS))).not.toBeNull();
    expect(parseFromJson(steps(MAX_PIVOT_STEPS + 1))).toBeNull();
  });

  it("C-V05: label bound is unchanged at 128 characters", () => {
    expect(MAX_PIVOT_LABEL_CHARS).toBe(128);
    const mapStep = evidenceStep({
      sourceKind: "map_entity",
      label: "x".repeat(128),
    });
    expect(parseFromJson([mapStep])).not.toBeNull();
    const overlong = [{ ...mapStep, label: "x".repeat(129) }] as unknown as PivotStep[];
    expect(parseFromJson(overlong)).toBeNull();
  });

  it("C-V06: UUID filter validation is unchanged for map-origin steps", () => {
    const bad = [
      {
        ...evidenceStep({
          sourceKind: "map_entity",
          filters: { subject_entity_id: "not-a-uuid" },
        }),
      },
    ] as unknown as PivotStep[];
    expect(parseFromJson(bad)).toBeNull();
    const good = [evidenceStep({ sourceKind: "map_entity" })];
    expect(parseFromJson(good)).not.toBeNull();
  });

  it("C-V08: close/back behavior is unchanged for map-origin stacks", () => {
    const params = withPivotState(new URLSearchParams("source=x"), {
      steps: [evidenceStep({ sourceKind: "map_entity", label: "203.0.113.10" })],
    });
    expect(readPivotState(params)?.steps[0].sourceKind).toBe("map_entity");
    const cleared = clearPivotState(params);
    expect(cleared.get("pivot")).toBeNull();
    expect(cleared.get("source")).toBe("x");
    // Truncation walks back exactly to the base route without residue.
    const truncated = truncatePivotSteps(params, 0);
    expect(truncated.get("pivot")).toBeNull();
    expect(truncated.get("source")).toBe("x");
  });
});

/** Map in-memory steps through the real serializer, then parse (fail closed). */
function parseFromJson(steps: readonly PivotStep[]): ReturnType<typeof parsePivotState> {
  const serialized = serializePivotState({ steps: [...steps] });
  return serialized === null ? null : parsePivotState(serialized);
}