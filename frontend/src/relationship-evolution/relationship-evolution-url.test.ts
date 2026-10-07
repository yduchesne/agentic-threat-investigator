// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Focal-Entity URL codec tests (PR 35-8 Part 2, U01..U10).
//
// ``setEvolutionFocalEntity`` is the one pure focal transition: it must set
// the new canonical ``entity_id``, preserve ``view``/direction/type/source/
// time/graph/temporal context, clear the focal-relative transient state
// (cursor, selected detail, counterparty filter), and no-op for a malformed
// candidate or the current focal Entity.

import { describe, expect, it } from "vitest";

import { setEvolutionFocalEntity } from "./relationship-evolution-url";
import { SELECTED_PARAM } from "../analyst-table/url-params";

const A = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";
const COUNTERPARTY = "40000000-0000-4000-8000-000000000103";

function params(entries: Record<string, string>): URLSearchParams {
  return new URLSearchParams(entries);
}

describe("setEvolutionFocalEntity (PR 35-8)", () => {
  it("U01: Explore B replaces entity_id", () => {
    const next = setEvolutionFocalEntity(
      params({ entity_id: A }),
      B,
    );
    expect(next.get("entity_id")).toBe(B);
  });

  it("U02: view is preserved", () => {
    const next = setEvolutionFocalEntity(
      params({ entity_id: A, view: "graph" }),
      B,
    );
    expect(next.get("view")).toBe("graph");
  });

  it("U03: the observation cursor is cleared", () => {
    const next = setEvolutionFocalEntity(
      params({ entity_id: A, cursor: "opaque-cursor" }),
      B,
    );
    expect(next.get("cursor")).toBeNull();
  });

  it("U04: the selected observation detail is cleared", () => {
    const next = setEvolutionFocalEntity(
      params({ entity_id: A, [SELECTED_PARAM]: "40000000-0000-4000-8000-000000000099" }),
      B,
    );
    expect(next.get(SELECTED_PARAM)).toBeNull();
  });

  it("U05: the focal-relative counterparty filter is cleared", () => {
    const next = setEvolutionFocalEntity(
      params({ entity_id: A, counterparty_entity_id: COUNTERPARTY }),
      B,
    );
    expect(next.get("counterparty_entity_id")).toBeNull();
  });

  it("U06/U07/U08: direction, relationship type/source/time and graph context are preserved", () => {
    const next = setEvolutionFocalEntity(
      params({
        entity_id: A,
        direction: "source",
        relationship_type: "urn:ati:relationship:dns:cname_of",
        source: "rdap",
        observed_from: "2026-02-01T00:00:00Z",
        observed_to: "2026-02-09T00:00:00Z",
        graph_scope: "known",
        graph_entity_type: "ip_address",
        graph_relationship_type: "urn:ati:relationship:dns:resolves_to",
        graph_source: "fake-dns",
        graph_observed_from: "2026-02-01T00:00:00Z",
        graph_observed_to: "2026-02-02T00:00:00Z",
        graph_depth: "2",
      }),
      B,
    );
    expect(next.get("direction")).toBe("source");
    expect(next.get("relationship_type")).toBe("urn:ati:relationship:dns:cname_of");
    expect(next.get("source")).toBe("rdap");
    expect(next.get("observed_from")).toBe("2026-02-01T00:00:00Z");
    expect(next.get("observed_to")).toBe("2026-02-09T00:00:00Z");
    expect(next.get("graph_scope")).toBe("known");
    expect(next.get("graph_entity_type")).toBe("ip_address");
    expect(next.get("graph_relationship_type")).toBe("urn:ati:relationship:dns:resolves_to");
    expect(next.get("graph_source")).toBe("fake-dns");
    expect(next.get("graph_observed_from")).toBe("2026-02-01T00:00:00Z");
    expect(next.get("graph_observed_to")).toBe("2026-02-02T00:00:00Z");
    expect(next.get("graph_depth")).toBe("2");
  });

  it("U09: temporal context is preserved", () => {
    const next = setEvolutionFocalEntity(
      params({
        entity_id: A,
        graph_temporal: "1",
        graph_time_start: "2026-02-01T00:00:00Z",
        graph_time_end: "2026-02-09T00:00:00Z",
        graph_time_frame: "3",
      }),
      B,
    );
    expect(next.get("graph_temporal")).toBe("1");
    expect(next.get("graph_time_start")).toBe("2026-02-01T00:00:00Z");
    expect(next.get("graph_time_end")).toBe("2026-02-09T00:00:00Z");
    expect(next.get("graph_time_frame")).toBe("3");
  });

  it("U10: exploring the current focal Entity is a no-op", () => {
    const input = params({ entity_id: A, cursor: "opaque-cursor" });
    const next = setEvolutionFocalEntity(input, A);
    expect(next.toString()).toBe(input.toString());
  });

  it("F12: a malformed candidate ID never transitions", () => {
    const input = params({ entity_id: A, cursor: "opaque-cursor" });
    const next = setEvolutionFocalEntity(input, "not-a-uuid");
    expect(next.toString()).toBe(input.toString());
  });
});
