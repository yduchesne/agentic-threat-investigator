// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";
import {
  GRAPH_TEMPORAL_OBSOLETE_PARAMS,
  GRAPH_TEMPORAL_PARAMS,
  applyGraphTemporal,
  emptyGraphTemporalContext,
  graphTemporalActive,
  graphTemporalEffectiveBounds,
  graphTemporalEqual,
  graphTemporalKey,
  parseGraphTemporal,
} from "./graph-temporal";

function ps(query: string): URLSearchParams {
  return new URLSearchParams(query);
}

const START = "2026-02-01T00:00:00Z";
const END = "2026-02-09T00:00:00Z";

describe("PR 38-8 graph temporal direct range model", () => {
  it("T-U01: empty context is inactive with no bounds", () => {
    const temporal = parseGraphTemporal(ps(""));
    expect(temporal).toEqual({
      temporal: false,
      rangeStart: undefined,
      rangeEnd: undefined,
    });
    expect(graphTemporalActive(temporal)).toBe(false);
    expect(emptyGraphTemporalContext()).toEqual({
      temporal: false,
      rangeStart: undefined,
      rangeEnd: undefined,
    });
  });

  it("T-U02: a valid committed range is active", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    expect(temporal.temporal).toBe(true);
    expect(temporal.rangeStart).toBe(START);
    expect(temporal.rangeEnd).toBe(END);
    expect(graphTemporalActive(temporal)).toBe(true);
  });

  it("T-U03: a missing start fails the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_end=${END}`),
    );
    expect(temporal.temporal).toBe(false);
    expect(temporal.rangeStart).toBeUndefined();
    expect(temporal.rangeEnd).toBeUndefined();
  });

  it("T-U04: a missing end fails the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}`),
    );
    expect(temporal.temporal).toBe(false);
    expect(temporal.rangeStart).toBeUndefined();
    expect(temporal.rangeEnd).toBeUndefined();
  });

  it("T-U05: a malformed start fails the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps("graph_temporal=1&graph_time_start=not-a-time&graph_time_end=" + END),
    );
    expect(graphTemporalActive(temporal)).toBe(false);
  });

  it("T-U06: a malformed end fails the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps("graph_temporal=1&graph_time_start=" + START + "&graph_time_end=2026-13-99"),
    );
    expect(graphTemporalActive(temporal)).toBe(false);
  });

  it("T-U07: equal bounds fail the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${START}`),
    );
    expect(graphTemporalActive(temporal)).toBe(false);
  });

  it("T-U08: reversed bounds fail the tuple closed", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${END}&graph_time_end=${START}`),
    );
    expect(graphTemporalActive(temporal)).toBe(false);
  });

  it("T-U09: active effective bounds are the exact committed start/end", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const bounds = graphTemporalEffectiveBounds(temporal);
    expect(bounds.observedFrom).toBe(START);
    expect(bounds.observedTo).toBe(END);
  });

  it("T-U10/PR38-10 U01: inactive temporal state yields no effective bounds", () => {
    const bounds = graphTemporalEffectiveBounds(emptyGraphTemporalContext());
    expect(bounds.observedFrom).toBeUndefined();
    expect(bounds.observedTo).toBeUndefined();
  });

  it("PR38-10 U02/U08: inactive temporal state is unbounded even with a stale legacy context", () => {
    // The legacy graph-filter observed parameters are inert; the effective
    // bounds are derived solely from the temporal tuple.
    const legacy = parseGraphTemporal(
      ps(
        `graph_observed_from=2000-01-01T00:00:00Z&graph_observed_to=2099-01-01T00:00:00Z`,
      ),
    );
    expect(graphTemporalActive(legacy)).toBe(false);
    const bounds = graphTemporalEffectiveBounds(legacy);
    expect(bounds.observedFrom).toBeUndefined();
    expect(bounds.observedTo).toBeUndefined();
  });

  it("PR38-10 U08: Disable strips stale legacy graph observed keys too", () => {
    const disabled = applyGraphTemporal(
      ps(
        `graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}` +
          `&graph_observed_from=2000-01-01T00:00:00Z&graph_observed_to=2099-01-01T00:00:00Z`,
      ),
      emptyGraphTemporalContext(),
    );
    expect(disabled.get("graph_observed_from")).toBeNull();
    expect(disabled.get("graph_observed_to")).toBeNull();
  });

  it("T-U11: Apply writes only the switch and both instants", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const applied = applyGraphTemporal(ps(""), temporal);
    expect(applied.get("graph_temporal")).toBe("1");
    expect(applied.get("graph_time_start")).toBe(START);
    expect(applied.get("graph_time_end")).toBe(END);
    expect([...applied.keys()].sort()).toEqual([
      "graph_temporal",
      "graph_time_end",
      "graph_time_start",
    ]);
  });

  it("T-U12: Disable removes every temporal-owned parameter", () => {
    const applied = applyGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
      emptyGraphTemporalContext(),
    );
    expect(applied.get("graph_temporal")).toBeNull();
    expect(applied.get("graph_time_start")).toBeNull();
    expect(applied.get("graph_time_end")).toBeNull();
  });

  it("T-U13: unrelated URL parameters are preserved on Apply and Disable", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const applied = applyGraphTemporal(ps("cursor=abc&graph_scope=known"), temporal);
    expect(applied.get("cursor")).toBe("abc");
    expect(applied.get("graph_scope")).toBe("known");
    const disabled = applyGraphTemporal(applied, emptyGraphTemporalContext());
    expect(disabled.get("cursor")).toBe("abc");
    expect(disabled.get("graph_scope")).toBe("known");
  });

  it("T-U14: obsolete frame params are inert and stripped on canonical rewrite", () => {
    const obsolete = `graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}&graph_time_frames=24&graph_time_frame=7`;
    const parsed = parseGraphTemporal(ps(obsolete));
    expect(parsed.rangeStart).toBe(START);
    expect(parsed.rangeEnd).toBe(END);
    const rewritten = applyGraphTemporal(ps(obsolete), parsed);
    expect(rewritten.get("graph_time_frames")).toBeNull();
    expect(rewritten.get("graph_time_frame")).toBeNull();
    // A legacy frame-only URL never activates temporal mode.
    expect(
      graphTemporalActive(parseGraphTemporal(ps("graph_time_frames=12&graph_time_frame=3"))),
    ).toBe(false);
  });

  it("T-U15: the temporal key changes when the committed range changes", () => {
    const base = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const other = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=2026-02-10T00:00:00Z`),
    );
    expect(graphTemporalKey(base)).not.toBe(graphTemporalKey(other));
    expect(graphTemporalEqual(base, other)).toBe(false);
    expect(graphTemporalEqual(base, base)).toBe(true);
  });

  it("T-U16: only the canonical temporal parameter set remains owned", () => {
    expect([...GRAPH_TEMPORAL_PARAMS]).toEqual([
      "graph_temporal",
      "graph_time_start",
      "graph_time_end",
    ]);
    expect([...GRAPH_TEMPORAL_OBSOLETE_PARAMS]).toEqual([
      "graph_time_frames",
      "graph_time_frame",
    ]);
  });
});
