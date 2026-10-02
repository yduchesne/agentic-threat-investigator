// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph temporal-frame model + URL codec (PR 31J).
//
// Temporal graph exploration constrains one committed GraphContext to a
// deterministic half-open ``[observed_from, observed_to)`` observation
// window: the analyst supplies a bounded observed range, the app partitions
// it into exactly one of 4/8/12/24 equal contiguous frames over the
// ``RelationshipObservation.observed_at`` axis, and the active frame's
// bounds override ``GraphContext.observedFrom``/``observedTo`` only for
// that one graph request. Each frame is therefore its own committed
// identity — ``graphContextKey`` (which already includes observed bounds)
// and ``graphTemporalKey`` both change per frame, so frame navigation
// naturally yields a fresh neighborhood/traversal/path request and resets
// graph expansion with no extra machinery.
//
// The committed temporal tuple has exactly one authority, the Graph route's
// URL search parameters, so refresh and browser Back/Forward reproduce the
// same frame; no second durable temporal store exists. Draft UI state is
// never committed before Apply. The tuple lives in the graph-owned
// ``graph_time_*`` namespace so it never collides with the Evolution view's
// observation filters on the shared focused route.
//
//   graph_temporal=1                        (present/absent switch)
//   graph_time_start=<ISO>&graph_time_end=<ISO>
//   graph_time_frames=4|8|12|24             (absent = 8)
//   graph_time_frame=<zero-based index>     (absent = 0)
//
// Unrelated URL parameters are preserved; a malformed enum/timestamp/range
// is canonicalized away (never presented or sent to the API) and a
// reversed/empty range or out-of-range frame index fail the tuple closed.
// All arithmetic is exact epoch-milliseconds with ISO-second serialization
// matching the app format; no wall-clock, no ``Date.now()``, no formatted
// bucketing. A frame's absence never infers a Relationship lifetime.

import type { GraphContext } from "./graph-context-url";
import {
  applyFilterParams,
  parseTimestampParam,
} from "../analyst-table/filters";

/** The exactly-four supported frame counts (default 8). */
export const GRAPH_TEMPORAL_FRAME_COUNTS: readonly [4, 8, 12, 24] = [4, 8, 12, 24];

/** One committed frame count (4/8/12/24; 8 default). */
export type GraphTemporalFrameCount = (typeof GRAPH_TEMPORAL_FRAME_COUNTS)[number];

/** The default committed frame count when ``graph_time_frames`` is absent. */
export const GRAPH_TEMPORAL_FRAME_COUNT_DEFAULT: GraphTemporalFrameCount = 8;

/** The graph-owned temporal URL search parameters (all ``graph_time_*``). */
export const GRAPH_TEMPORAL_PARAMS = [
  "graph_temporal",
  "graph_time_start",
  "graph_time_end",
  "graph_time_frames",
  "graph_time_frame",
] as const;

/** The committed temporal tuple (absent = ordinary graph mode). */
export interface GraphTemporalContext {
  /** Whether temporal mode is committed (``graph_temporal=1``). */
  temporal: boolean;
  /** Inclusive overall observed-range start (ISO-8601 UTC seconds). */
  rangeStart: string | undefined;
  /** Exclusive overall observed-range end (ISO-8601 UTC seconds). */
  rangeEnd: string | undefined;
  /** The committed frame count (4/8/12/24; 8 default). */
  frameCount: GraphTemporalFrameCount;
  /** The committed zero-based frame index within ``[0, frameCount)``. */
  frameIndex: number;
}

/** One derived half-open observation frame ``[observedFrom, observedTo)``. */
export interface GraphTemporalFrame {
  /** Inclusive frame start (``rangeStart`` for frame 0). */
  observedFrom: string | undefined;
  /** Exclusive frame end (``rangeEnd`` for the final frame). */
  observedTo: string | undefined;
  /** The committed zero-based frame index this window covers. */
  frameIndex: number;
  /** The frame count this window was derived with. */
  frameCount: GraphTemporalFrameCount;
}

/** The neutral temporal tuple: mode off, default 8 frames, frame 0. */
export function emptyGraphTemporalContext(): GraphTemporalContext {
  return {
    temporal: false,
    rangeStart: undefined,
    rangeEnd: undefined,
    frameCount: GRAPH_TEMPORAL_FRAME_COUNT_DEFAULT,
    frameIndex: 0,
  };
}

/** Whether one committed temporal tuple is active (mode on + valid range). */
export function graphTemporalActive(context: GraphTemporalContext): boolean {
  return (
    context.temporal &&
    context.rangeStart !== undefined &&
    context.rangeEnd !== undefined &&
    context.rangeStart < context.rangeEnd
  );
}

/**
 * Partition ``[rangeStart, rangeEnd)`` into ``frameCount`` contiguous equal
 * half-open sub-windows with exact epoch-millisecond arithmetic.
 *
 * Frame ``i`` covers ``[start + i*inner, start + (i+1)*inner)`` where
 * ``inner = (end - start)/frameCount``; the final frame is clamped exactly
 * to ``rangeEnd``. Boundaries are derived from the same committed range with
 * no formatting round-trip, so adjacent frames never double-count a boundary
 * ``observed_at`` and every re-parse of the tuple yields identical frames.
 * An inactive tuple or non-finite range yields the empty array (fail closed).
 */
export function graphTemporalFrames(
  context: GraphTemporalContext,
): readonly GraphTemporalFrame[] {
  if (!graphTemporalActive(context)) {
    return [];
  }
  const rangeStart = context.rangeStart as string;
  const rangeEnd = context.rangeEnd as string;
  const startMs = Date.parse(rangeStart);
  const endMs = Date.parse(rangeEnd);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
    return [];
  }
  const inner = (endMs - startMs) / context.frameCount;
  const frames: GraphTemporalFrame[] = [];
  for (let index = 0; index < context.frameCount; index += 1) {
    const fromMs = startMs + index * inner;
    const toMs = index === context.frameCount - 1 ? endMs : startMs + (index + 1) * inner;
    frames.push({
      observedFrom: toIsoSeconds(fromMs),
      observedTo: toIsoSeconds(toMs),
      frameIndex: index,
      frameCount: context.frameCount,
    });
  }
  return frames;
}

/** Serialize exact epoch ms to app ISO-8601 UTC seconds. */
function toIsoSeconds(ms: number): string {
  return new Date(Math.round(ms)).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * The active frame window for the committed ``frameIndex``.
 *
 * Returns ``undefined`` when temporal mode is off or the range/frame is
 * malformed — failure is absence, never a synthesized interval.
 */
export function graphTemporalFrameAt(
  context: GraphTemporalContext,
): GraphTemporalFrame | undefined {
  if (!graphTemporalActive(context)) {
    return undefined;
  }
  const frames = graphTemporalFrames(context);
  const frame = frames[context.frameIndex];
  return frame === undefined ? undefined : frame;
}

/** Whether the committed frame has a Previous window (index > 0). */
export function graphTemporalHasPrevious(context: GraphTemporalContext): boolean {
  return graphTemporalActive(context) && context.frameIndex > 0;
}

/** Whether the committed frame has a Next window (index < frameCount - 1). */
export function graphTemporalHasNext(context: GraphTemporalContext): boolean {
  return (
    graphTemporalActive(context) && context.frameIndex < context.frameCount - 1
  );
}

/**
 * Move the committed frame index in ``delta`` steps, clamped to ``[0, frameCount)``.
 *
 * Returns a NEW tuple; the committed range and frame count are untouched.
 * Deterministic: Previous/Next always land on the same adjacent frame and can
 * never escape the committed index space.
 */
export function shiftGraphTemporalFrame(
  context: GraphTemporalContext,
  delta: -1 | 1,
): GraphTemporalContext {
  if (!graphTemporalActive(context)) {
    return context;
  }
  const nextIndex = context.frameIndex + delta;
  const clamped = Math.min(Math.max(nextIndex, 0), context.frameCount - 1);
  return { ...context, frameIndex: clamped };
}

/**
 * Derive the effective committed observed bounds for one graph request.
 *
 * With temporal mode active, the active frame window OVERRIDES the ordinary
 * committed ``GraphContext`` observed bounds — only the one active frame,
 * never the overall tuple, so each frame is its own graph request identity.
 * Otherwise the ordinary committed bounds pass through untouched.
 */
export function graphTemporalEffectiveBounds(
  context: GraphContext,
  temporal: GraphTemporalContext,
): { observedFrom: string | undefined; observedTo: string | undefined } {
  const frame = graphTemporalFrameAt(temporal);
  if (frame === undefined) {
    return { observedFrom: context.observedFrom, observedTo: context.observedTo };
  }
  return { observedFrom: frame.observedFrom, observedTo: frame.observedTo };
}

/** The canonical committed temporal-tuple identity (URL resync + frame key). */
export function graphTemporalKey(context: GraphTemporalContext): string {
  return JSON.stringify([
    context.temporal,
    context.rangeStart ?? null,
    context.rangeEnd ?? null,
    context.frameCount,
    context.frameIndex,
  ]);
}

/** Whether two committed temporal tuples are identical. */
export function graphTemporalEqual(a: GraphTemporalContext, b: GraphTemporalContext): boolean {
  return graphTemporalKey(a) === graphTemporalKey(b);
}

/** Parse one committed frame count; malformed/absent canonicalize to 8. */
export function parseGraphTemporalFrameCount(
  value: string | null | undefined,
): GraphTemporalFrameCount {
  if (value === undefined || value === null || value === "") {
    return GRAPH_TEMPORAL_FRAME_COUNT_DEFAULT;
  }
  const parsed = parseInt(value, 10);
  return (GRAPH_TEMPORAL_FRAME_COUNTS as readonly number[]).includes(parsed)
    ? (parsed as GraphTemporalFrameCount)
    : GRAPH_TEMPORAL_FRAME_COUNT_DEFAULT;
}

/** Parse one committed frame index; malformed/out-of-range values are 0. */
export function parseGraphTemporalFrameIndex(
  value: string | null | undefined,
  frameCount: GraphTemporalFrameCount,
): number {
  if (value === undefined || value === null || value === "") {
    return 0;
  }
  const parsed = parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed >= frameCount) {
    return 0;
  }
  return parsed;
}

/**
 * Parse the committed temporal tuple off one URL parameter set.
 *
 * ``graph_temporal=1`` commits temporal mode; any other/absent value
 * canonicalizes to mode off. A malformed/absent timestamp canonicalizes to
 * absence, and an absent/malformed/reversed range, or an out-of-range frame
 * count or index, fail the tuple closed (temporal never sends a half-valid
 * range and never resurrects a stale committed value).
 */
export function parseGraphTemporal(params: URLSearchParams): GraphTemporalContext {
  const temporal = params.get("graph_temporal") === "1";
  const rangeStart = parseTimestampParam(params.get("graph_time_start"));
  const rangeEnd = parseTimestampParam(params.get("graph_time_end"));
  const frameCount = parseGraphTemporalFrameCount(params.get("graph_time_frames"));
  const active =
    temporal &&
    rangeStart !== undefined &&
    rangeEnd !== undefined &&
    rangeStart < rangeEnd;
  return {
    temporal: active,
    rangeStart: active ? rangeStart : undefined,
    rangeEnd: active ? rangeEnd : undefined,
    frameCount: parseGraphTemporalFrameCount(params.get("graph_time_frames")),
    frameIndex: parseGraphTemporalFrameIndex(params.get("graph_time_frame"), frameCount),
  };
}

/**
 * Apply one committed temporal tuple over the URL parameter set.
 *
 * Only the current frame identity is committed: with temporal mode active the
 * switch, the overall observed range, and the frame count are written only
 * when they meaningfully differ from canonical defaults, and the frame index
 * only when it is not the first frame. Mode off removes all ``graph_time_*``
 * parameters (canonical ordinary graph mode). All unrelated URL parameters
 * are preserved untouched.
 */
export function applyGraphTemporal(
  params: URLSearchParams,
  temporal: GraphTemporalContext,
): URLSearchParams {
  return applyFilterParams(params, GRAPH_TEMPORAL_PARAMS, {
    graph_temporal: temporal.temporal ? "1" : undefined,
    graph_time_start: temporal.temporal ? temporal.rangeStart : undefined,
    graph_time_end: temporal.temporal ? temporal.rangeEnd : undefined,
    graph_time_frames:
      temporal.temporal && temporal.frameCount !== GRAPH_TEMPORAL_FRAME_COUNT_DEFAULT
        ? String(temporal.frameCount)
        : undefined,
    graph_time_frame:
      temporal.temporal && temporal.frameIndex !== 0
        ? String(temporal.frameIndex)
        : undefined,
  });
}
