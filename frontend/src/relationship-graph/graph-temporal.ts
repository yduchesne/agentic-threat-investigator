// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph temporal-range model + URL codec (PR 38-8, simplifying PR 31J).
//
// Temporal graph exploration constrains one committed GraphContext to a
// single deterministic half-open ``[observed_from, observed_to)``
// observation window: the analyst supplies one start instant and one end
// instant directly, and those bounds override
// ``GraphContext.observedFrom``/``observedTo`` only for that one graph
// request. The committed range is therefore its own committed identity —
// ``graphContextKey`` (which already includes observed bounds) and
// ``graphTemporalKey`` both change per range, so a range change naturally
// yields a fresh neighborhood/traversal/path request and resets graph
// expansion with no extra machinery.
//
// There is no temporal-frame concept: no frame count, no frame index, no
// partitioning, no Previous/Next navigation. PR 31J's
// ``graph_time_frames``/``graph_time_frame`` parameters are retired and are
// stripped whenever the canonical temporal URL is next written.
//
// The committed temporal tuple has exactly one authority, the Graph route's
// URL search parameters, so refresh and browser Back/Forward reproduce the
// same range; no second durable temporal store exists. Draft UI state is
// never committed before Apply. The tuple lives in the graph-owned
// ``graph_time_*`` namespace so it never collides with the Evolution view's
// observation filters on the shared focused route.
//
//   graph_temporal=1                        (present/absent switch)
//   graph_time_start=<ISO>&graph_time_end=<ISO>
//
// Unrelated URL parameters are preserved; a malformed timestamp, a missing
// bound, or a non-increasing range fails the tuple closed (temporal never
// sends a half-valid range and never resurrects a stale committed value).
// All arithmetic is exact epoch-milliseconds with ISO-second serialization
// matching the app format; no wall-clock and no ``Date.now()``. A range's
// absence never infers a Relationship lifetime.

import type { GraphContext } from "./graph-context-url";
import {
  applyFilterParams,
  parseTimestampParam,
} from "../analyst-table/filters";

/** The graph-owned canonical temporal URL search parameters. */
export const GRAPH_TEMPORAL_PARAMS = [
  "graph_temporal",
  "graph_time_start",
  "graph_time_end",
] as const;

/**
 * Retired PR 31J frame parameters.
 *
 * PR 38-8 removed the temporal-frame model, so these are never read as
 * state. They remain URL-temporal-owned so the next canonical temporal
 * write (Apply/Disable) strips them; an obsolete deep link can therefore
 * never resurrect a frame model.
 */
export const GRAPH_TEMPORAL_OBSOLETE_PARAMS = [
  "graph_time_frames",
  "graph_time_frame",
] as const;

/** The committed temporal tuple (absent = ordinary graph mode). */
export interface GraphTemporalContext {
  /** Whether temporal mode is committed (``graph_temporal=1``). */
  temporal: boolean;
  /** Inclusive observed-range start (ISO-8601 UTC seconds). */
  rangeStart: string | undefined;
  /** Exclusive observed-range end (ISO-8601 UTC seconds). */
  rangeEnd: string | undefined;
}

/** The neutral temporal tuple: mode off, no committed range. */
export function emptyGraphTemporalContext(): GraphTemporalContext {
  return {
    temporal: false,
    rangeStart: undefined,
    rangeEnd: undefined,
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
 * Derive the effective committed observed bounds for one graph request.
 *
 * With temporal mode active, the committed direct range OVERRIDES the
 * ordinary committed ``GraphContext`` observed bounds for that one request.
 * Otherwise the ordinary committed bounds pass through untouched.
 */
export function graphTemporalEffectiveBounds(
  context: GraphContext,
  temporal: GraphTemporalContext,
): { observedFrom: string | undefined; observedTo: string | undefined } {
  if (!graphTemporalActive(temporal)) {
    return { observedFrom: context.observedFrom, observedTo: context.observedTo };
  }
  return { observedFrom: temporal.rangeStart, observedTo: temporal.rangeEnd };
}

/** The canonical committed temporal-tuple identity (URL resync + graph key). */
export function graphTemporalKey(context: GraphTemporalContext): string {
  return JSON.stringify([
    context.temporal,
    context.rangeStart ?? null,
    context.rangeEnd ?? null,
  ]);
}

/** Whether two committed temporal tuples are identical. */
export function graphTemporalEqual(a: GraphTemporalContext, b: GraphTemporalContext): boolean {
  return graphTemporalKey(a) === graphTemporalKey(b);
}

/**
 * Parse the committed temporal tuple off one URL parameter set.
 *
 * ``graph_temporal=1`` commits temporal mode; any other/absent value
 * canonicalizes to mode off. Temporal mode is active only when the switch
 * is set AND both normalized bounds parse AND ``rangeStart < rangeEnd``.
 * Anything else fails closed: temporal never sends a half-valid range and
 * never synthesizes a missing committed instant. The retired frame
 * parameters are ignored entirely.
 */
export function parseGraphTemporal(params: URLSearchParams): GraphTemporalContext {
  const temporal = params.get("graph_temporal") === "1";
  const rangeStart = parseTimestampParam(params.get("graph_time_start"));
  const rangeEnd = parseTimestampParam(params.get("graph_time_end"));
  const active =
    temporal &&
    rangeStart !== undefined &&
    rangeEnd !== undefined &&
    rangeStart < rangeEnd;
  return {
    temporal: active,
    rangeStart: active ? rangeStart : undefined,
    rangeEnd: active ? rangeEnd : undefined,
  };
}

/**
 * Apply one committed temporal tuple over the URL parameter set.
 *
 * With temporal mode active the switch and both normalized instants are
 * written; mode off removes every temporal-owned parameter (canonical
 * ordinary graph mode), including the retired PR 31J frame parameters so
 * obsolete deep links are cleaned up. All unrelated URL parameters are
 * preserved untouched.
 */
export function applyGraphTemporal(
  params: URLSearchParams,
  temporal: GraphTemporalContext,
): URLSearchParams {
  return applyFilterParams(
    params,
    [...GRAPH_TEMPORAL_PARAMS, ...GRAPH_TEMPORAL_OBSOLETE_PARAMS],
    {
      graph_temporal: temporal.temporal ? "1" : undefined,
      graph_time_start: temporal.temporal ? temporal.rangeStart : undefined,
      graph_time_end: temporal.temporal ? temporal.rangeEnd : undefined,
    },
  );
}
