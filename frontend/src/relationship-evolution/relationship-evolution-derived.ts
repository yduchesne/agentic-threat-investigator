// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic page-scoped Evolution annotations (PR 24E §16).
//
// Only labels whose scope is explicit and whose computation is
// deterministic over the currently loaded page are produced. ATI never
// claims global "First observed" or cross-page frequency from one bounded
// cursor page: the earliest point on the page is labelled ``Earliest
// shown`` and per-lane counts are explicitly "on this page" counts.

import type { EvolutionLane, EvolutionPoint } from "./relationship-evolution-model";

/** The page-scoped marker attached to the earliest observed point. */
export const EARLIEST_SHOWN = "earliest_shown";

/** Page-scoped annotation of one lane. */
export interface LaneAnnotation {
  /** Observation count on this loaded page (never a global frequency). */
  pageObservationCount: number;
  /** True when the lane's first row is the earliest on the page. */
  isEarliestShown: boolean;
}

/**
 * Annotate every lane deterministically from the loaded page only.
 *
 * ``isEarliestShown`` compares lane points with the page minimum under the
 * canonical point ordering (observedAt, then id), so it is stable and
 * explicitly page-scoped: it is never presented as global first-observed.
 */
export function annotateLanes(
  lanes: readonly EvolutionLane[],
  earliestPagePoint: EvolutionPoint | null,
): ReadonlyMap<string, LaneAnnotation> {
  const annotated = new Map<string, LaneAnnotation>();
  for (const lane of lanes) {
    const first = lane.points[0] ?? null;
    annotated.set(lane.relationshipId, {
      pageObservationCount: lane.points.length,
      isEarliestShown:
        earliestPagePoint !== null &&
        first !== null &&
        first.observationId === earliestPagePoint.observationId,
    });
  }
  return annotated;
}

/**
 * The earliest observed point of one loaded page, or null.
 *
 * Uses the canonical page ordering (observedAt asc, then id asc) with null
 * observed times excluded — null-observed rows are not positioned on the
 * retrieved timestamp and never become the "earliest shown".
 */
export function earliestPagePoint(
  points: readonly EvolutionPoint[],
): EvolutionPoint | null {
  const candidate = points.find((point) => point.observedAt !== null) ?? null;
  return candidate;
}