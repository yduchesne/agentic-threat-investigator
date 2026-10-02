// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from "vitest";
import { emptyGraphContext } from "./graph-context-url";
import {
  applyGraphTemporal,
  emptyGraphTemporalContext,
  graphTemporalActive,
  graphTemporalEffectiveBounds,
  graphTemporalEqual,
  graphTemporalFrameAt,
  graphTemporalFrames,
  graphTemporalHasNext,
  graphTemporalHasPrevious,
  graphTemporalKey,
  parseGraphTemporal,
  parseGraphTemporalFrameCount,
  shiftGraphTemporalFrame,
} from "./graph-temporal";

function ps(query: string): URLSearchParams {
  return new URLSearchParams(query);
}

const START = "2026-02-01T00:00:00Z";
const END = "2026-02-09T00:00:00Z";

describe("PR 31J graph temporal frame model", () => {
  it("FE01: absent params are mode off, default 8 frames, frame 0", () => {
    const temporal = parseGraphTemporal(ps(""));
    expect(temporal.temporal).toBe(false);
    expect(temporal.frameCount).toBe(8);
    expect(temporal.frameIndex).toBe(0);
    expect(temporal.rangeStart).toBeUndefined();
    expect(temporal.rangeEnd).toBeUndefined();
    expect(graphTemporalActive(temporal)).toBe(false);
    expect(emptyGraphTemporalContext().frameCount).toBe(8);
  });

  it("FE02: graph_time_frames=12 parses and empty URL canonicalizes to 8", () => {
    expect(parseGraphTemporal(ps("graph_time_frames=12")).frameCount).toBe(12);
    expect(parseGraphTemporal(ps("graph_time_frames=bogus")).frameCount).toBe(8);
    expect(parseGraphTemporal(ps("graph_time_frames=99")).frameCount).toBe(8);
    expect(parseGraphTemporalFrameCount(undefined)).toBe(8);
  });

  it("FE03: an active temporal tuple requires the switch AND a valid range", () => {
    const active = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    expect(active.temporal).toBe(true);
    expect(graphTemporalActive(active)).toBe(true);
    expect(
      graphTemporalActive(
        parseGraphTemporal(ps("graph_temporal=1")),
      ),
    ).toBe(false);
    expect(
      graphTemporalActive(
        parseGraphTemporal(ps(`graph_temporal=1&graph_time_start=${END}&graph_time_end=${START}`)),
      ),
    ).toBe(false);
  });

  it("FE04: eight frames evenly partition the committed range half-open intervals", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const frames = graphTemporalFrames(temporal);
    expect(frames).toHaveLength(8);
    expect(frames[0]!.observedFrom).toBe(START);
    expect(frames[7]!.observedTo).toBe(END);
    // Each frame is exactly one day wide over an eight-day range.
    for (const frame of frames) {
      const from = Date.parse(frame.observedFrom!);
      const to = Date.parse(frame.observedTo!);
      expect(to - from).toBe(24 * 60 * 60 * 1000);
    }
    // Half-open: adjacent frames share no boundary observation.
    expect(frames[1]!.observedFrom).toBe("2026-02-02T00:00:00Z");
    expect(frames[0]!.observedTo).toBe("2026-02-02T00:00:00Z");
    expect(frames[0]!.observedTo).toBe(frames[1]!.observedFrom);
  });

  it("FE05: frame navigation clamps to the committed index space", () => {
    const base = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const next = shiftGraphTemporalFrame(base, 1);
    expect(next.frameIndex).toBe(1);
    expect(graphTemporalHasPrevious(base)).toBe(false);
    expect(graphTemporalHasNext(base)).toBe(true);
    // Jump to the committed LAST frame (index 7 of 8) through Prev/Next
    // steps and prove clamping in both directions.
    let last = base;
    for (let step = 0; step < 7; step += 1) {
      last = shiftGraphTemporalFrame(last, 1);
    }
    expect(last.frameIndex).toBe(7);
    expect(graphTemporalHasNext(last)).toBe(false);
    expect(shiftGraphTemporalFrame(last, 1).frameIndex).toBe(7);
    expect(shiftGraphTemporalFrame(last, -1).frameIndex).toBe(6);
    // Previous before the FIRST frame stays clamped at frame 0.
    expect(shiftGraphTemporalFrame(base, -1).frameIndex).toBe(0);
    expect(graphTemporalHasPrevious(base)).toBe(false);
    // Frame identity changes per frame; stale frames never satisfy each other.
    expect(graphTemporalKey(base)).not.toBe(graphTemporalKey(next));
  });

  it("FE06: malformed range or out-of-range index fails the tuple closed", () => {
    expect(
      graphTemporalFrameAt(parseGraphTemporal(ps("graph_temporal=1"))),
    ).toBeUndefined();
    const outOfRange = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}&graph_time_frame=40`),
    );
    expect(outOfRange.frameIndex).toBe(0);
    expect(graphTemporalFrameAt(outOfRange)!.frameIndex).toBe(0);
    // 24-frame mode is a valid count.
    const twentyFour = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}&graph_time_frames=24&graph_time_frame=23`),
    );
    expect(twentyFour.frameCount).toBe(24);
    expect(graphTemporalFrameAt(twentyFour)!.frameIndex).toBe(23);
  });

  it("FE07: URL round-trip preserves unrelated params and drops owned ones when off", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}&graph_time_frames=4&graph_scope=known&cursor=abc`),
    );
    const applied = applyGraphTemporal(ps("cursor=abc"), temporal);
    expect(applied.get("graph_temporal")).toBe("1");
    expect(applied.get("graph_time_start")).toBe(START);
    expect(applied.get("graph_time_end")).toBe(END);
    expect(applied.get("graph_time_frames")).toBe("4");
    expect(applied.get("cursor")).toBe("abc");
    const reparsed = parseGraphTemporal(applied);
    expect(graphTemporalEqual(reparsed, temporal)).toBe(true);
    expect(
      applyGraphTemporal(applied, emptyGraphTemporalContext()).get("graph_temporal"),
    ).toBeNull();
  });

  it("FE08: canonical URL omits default frame count and first frame index", () => {
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const applied = applyGraphTemporal(ps(""), temporal);
    expect(applied.get("graph_time_frames")).toBeNull();
    expect(applied.get("graph_time_frame")).toBeNull();
    expect(applied.get("graph_temporal")).toBe("1");
  });

  it("FE09: effective bounds override GraphContext observed bounds per frame", () => {
    const context = { ...emptyGraphContext(), observedFrom: "2000-01-01T00:00:00Z", observedTo: "2099-01-01T00:00:00Z" };
    const temporal = parseGraphTemporal(
      ps(`graph_temporal=1&graph_time_start=${START}&graph_time_end=${END}`),
    );
    const frameBounds = graphTemporalEffectiveBounds(context, temporal);
    expect(frameBounds.observedFrom).toBe(START);
    expect(frameBounds.observedTo).toBe("2026-02-02T00:00:00Z");
    // Mode off passes the ordinary committed bounds through untouched.
    const passthrough = graphTemporalEffectiveBounds(context, emptyGraphTemporalContext());
    expect(passthrough.observedFrom).toBe("2000-01-01T00:00:00Z");
    expect(passthrough.observedTo).toBe("2099-01-01T00:00:00Z");
  });
});
