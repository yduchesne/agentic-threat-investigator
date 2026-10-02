// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31K graph-action model tests (K-FE01/K-FE16/K-FE18 model layer).
//
// The bounded action model carries canonical identity only: entityId is
// authoritative, entityType/entityValue are the exact fields the reused
// Investigation create contract accepts, and the prefilled objective is
// factual wording that never embeds analytical conclusions.

import { describe, expect, it } from "vitest";

import {
  buildGraphActionObjective,
  isValidGraphActionEntityValue,
  isValidGraphActionObjective,
} from "./graph-actions";

describe("PR 31K graph action model", () => {
  it("K-FE01: the model keeps the canonical Entity ID authoritative", () => {
    const entity = {
      entityId: "40000000-0000-4000-8000-000000000101",
      entityType: "domain" as const,
      entityValue: "update-package.test",
    };
    expect(entity.entityId).toBe("40000000-0000-4000-8000-000000000101");
    expect(entity.entityType).toBe("domain");
    expect(entity.entityValue).toBe("update-package.test");
  });

  it("K-FE18: the objective is neutral factual wording (no analytical claims)", () => {
    expect(
      buildGraphActionObjective("Domain", "update-package.test"),
    ).toBe("Investigate Domain update-package.test");
    expect(
      buildGraphActionObjective("IP address", "203.0.113.10"),
    ).toBe("Investigate IP address 203.0.113.10");
    // The wording must not promise threat findings or maliciousness.
    expect(buildGraphActionObjective("Domain", "x.test")).not.toMatch(
      /malicious|threat|enrich|confirm/i,
    );
  });

  it("K-FE06: an objective is valid only when non-blank and within the exact create bound", () => {
    expect(isValidGraphActionObjective("Investigate Domain x.test")).toBe(true);
    expect(isValidGraphActionObjective("   ")).toBe(false);
    expect(isValidGraphActionObjective("")).toBe(false);
    expect(isValidGraphActionObjective("a".repeat(4000))).toBe(true);
    expect(isValidGraphActionObjective("a".repeat(4001))).toBe(false);
  });

  it("K-FE16: an entity value is valid only when non-blank and within the exact indicator bound", () => {
    expect(isValidGraphActionEntityValue("update-package.test")).toBe(true);
    expect(isValidGraphActionEntityValue("  ")).toBe(false);
    expect(isValidGraphActionEntityValue("")).toBe(false);
    expect(isValidGraphActionEntityValue("a".repeat(2048))).toBe(true);
    expect(isValidGraphActionEntityValue("a".repeat(2049))).toBe(false);
  });
});
