// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution pure derived model (PR 24E §14, §16).
//
// Relationship Evolution is a deterministic read projection over the loaded
// RelationshipObservation page joined with its stable Relationship
// semantics: the browser never reconstructs unbounded history, never infers
// validity intervals (no started/ended/removed), and never claims
// cross-page first/frequency facts. Lanes group by the stable Relationship
// identity; points sort by ``observed_at`` with a stable observation-ID
// tie-breaker; rows without an observed time render in an explicit
// ``Observed time unavailable`` group and are never positioned on the
// ``retrieved_at`` timestamp.

import type {
  RelationshipDirectionName,
  RelationshipObservation,
  RelationshipTypeName,
} from "../api/schema-types";

/** A temporal point: one immutable observation on the loaded page. */
export interface EvolutionPoint {
  observationId: string;
  relationshipId: string;
  evidenceId: string;
  /** X-axis value; null means the source did not provide an observed time. */
  observedAt: string | null;
  /** Secondary metadata; never a temporal substitute for a null observedAt. */
  retrievedAt: string;
  source: string;
  /** Joined stable Relationship semantics from the same page row. */
  relationshipSourceEntityId: string | null;
  relationshipTargetEntityId: string | null;
  relationshipType: RelationshipTypeName | null;
}

/** One swimlane: a stable Relationship as observed on the loaded page. */
export interface EvolutionLane {
  /** Stable edge identity; lanes never merge different relationships. */
  relationshipId: string;
  relationshipType: RelationshipTypeName | null;
  counterpartyEntityId: string | null;
  /** Direction of the lane relative to the focal entity. */
  direction: RelationshipDirectionName;
  points: EvolutionPoint[];
}

/** The deterministic lane model of one loaded page. */
export interface EvolutionModel {
  /** Lanes with at least one observed-time point, deterministically sorted. */
  lanes: EvolutionLane[];
  /** Points whose observed time is unavailable, deterministically sorted. */
  unavailable: EvolutionPoint[];
}

/** Whether one observation row carries joined relationship semantics. */
export function hasJoinedRelationship(
  observation: RelationshipObservation,
): boolean {
  return (
    observation.relationship_type !== null &&
    observation.relationship_source_entity_id !== null &&
    observation.relationship_target_entity_id !== null
  );
}

/** Stable ISO timestamp comparison (both values are app-serialized). */
function compareIso(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** One observation row -> point (pure, no inference). */
export function toEvolutionPoint(
  observation: RelationshipObservation,
): EvolutionPoint {
  return {
    observationId: observation.id,
    relationshipId: observation.relationship_id,
    evidenceId: observation.evidence_id,
    observedAt: observation.observed_at,
    retrievedAt: observation.retrieved_at,
    source: observation.source,
    relationshipSourceEntityId: observation.relationship_source_entity_id ?? null,
    relationshipTargetEntityId: observation.relationship_target_entity_id ?? null,
    relationshipType: observation.relationship_type ?? null,
  };
}

/**
 * Sort points by ``observed_at`` ascending, then stable observation ID.
 *
 * The ID tie-breaker is deterministic within one loaded page; cross-page
 * first/last claims are never made from this ordering.
 */
export function sortPoints(points: readonly EvolutionPoint[]): EvolutionPoint[] {
  return [...points].sort((a, b) => {
    const aTime = a.observedAt ?? "";
    const bTime = b.observedAt ?? "";
    const timeOrder = compareIso(aTime, bTime);
    if (timeOrder !== 0) {
      return timeOrder;
    }
    return a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0;
  });
}

/** The direction of one edge relative to the focal entity. */
export function edgeDirection(
  focalEntityId: string,
  sourceEntityId: string | null,
  targetEntityId: string | null,
): RelationshipDirectionName {
  if (sourceEntityId === focalEntityId && targetEntityId === focalEntityId) {
    return "either";
  }
  if (targetEntityId === focalEntityId) {
    return "target";
  }
  return "source";
}

/**
 * Build the deterministic lane model of one loaded observation page.
 *
 * Lanes are keyed by stable ``relationship_id`` (unique per
 * source/type/target triple, so the focal-relative direction is
 * unambiguous); labels show counterparty/type/direction. Points without an
 * observed time form the explicit unavailable group in addition to their
 * lane so every observation stays reachable: the group is separately
 * declared on the model and rendered outside the time axis.
 */
export function buildEvolutionModel(
  focalEntityId: string,
  observations: readonly RelationshipObservation[],
): EvolutionModel {
  const lanes = new Map<string, EvolutionLane>();
  const unavailable: EvolutionPoint[] = [];

  for (const observation of observations) {
    const point = toEvolutionPoint(observation);
    if (point.observedAt === null) {
      unavailable.push(point);
    }
    let lane = lanes.get(observation.relationship_id);
    if (lane === undefined) {
      const counterparty = counterpartyFor(
        focalEntityId,
        point.relationshipSourceEntityId,
        point.relationshipTargetEntityId,
      );
      lane = {
        relationshipId: observation.relationship_id,
        relationshipType: observation.relationship_type ?? null,
        counterpartyEntityId: counterparty,
        direction: edgeDirection(
          focalEntityId,
          point.relationshipSourceEntityId,
          point.relationshipTargetEntityId,
        ),
        points: [],
      };
      lanes.set(observation.relationship_id, lane);
    }
    lane.points.push(point);
  }

  const sortedLanes = [...lanes.values()].sort((a, b) => {
    const counterpartyOrder = compareOptional(a.counterpartyEntityId, b.counterpartyEntityId);
    if (counterpartyOrder !== 0) {
      return counterpartyOrder;
    }
    const typeOrder = compareOptionalType(a.relationshipType, b.relationshipType);
    if (typeOrder !== 0) {
      return typeOrder;
    }
    return a.relationshipId < b.relationshipId ? -1 : a.relationshipId > b.relationshipId ? 1 : 0;
  });
  for (const lane of sortedLanes) {
    lane.points = sortPoints(lane.points);
  }
  return {
    lanes: sortedLanes,
    unavailable: sortPoints(unavailable),
  };
}

/** The other endpoint of one edge relative to the focal entity. */
function counterpartyFor(
  focalEntityId: string,
  source: string | null,
  target: string | null,
): string | null {
  if (source !== null && source !== focalEntityId) {
    return source;
  }
  if (target !== null && target !== focalEntityId) {
    return target;
  }
  // Self edge (or missing joined semantics): the only endpoint is the focal
  // entity itself — a deterministic single lane, never a synthesized value.
  return source ?? target;
}

/** Stable ordering of optional UUID strings (null sorts last). */
function compareOptional(a: string | null, b: string | null): number {
  if (a === null && b === null) {
    return 0;
  }
  if (a === null) {
    return 1;
  }
  if (b === null) {
    return -1;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Stable ordering of optional relationship type URNs (null sorts last). */
function compareOptionalType(
  a: RelationshipTypeName | null,
  b: RelationshipTypeName | null,
): number {
  return compareOptional(a, b);
}

/** The page-scoped observed-time extent used by the time axis. */
export interface EvolutionTimeSpan {
  minIso: string;
  maxIso: string;
  /** True when only a single distinct observed time exists on the page. */
  singleInstant: boolean;
}

/** Compute the observed-time span of one loaded page (page-scoped only). */
export function evolutionTimeSpan(
  points: readonly EvolutionPoint[],
): EvolutionTimeSpan | null {
  const withTime = points.filter(
    (point): point is EvolutionPoint & { observedAt: string } =>
      point.observedAt !== null,
  );
  if (withTime.length === 0) {
    return null;
  }
  let min = withTime[0].observedAt;
  let max = withTime[0].observedAt;
  for (const point of withTime) {
    if (compareIso(point.observedAt, min) < 0) {
      min = point.observedAt;
    }
    if (compareIso(point.observedAt, max) > 0) {
      max = point.observedAt;
    }
  }
  return { minIso: min, maxIso: max, singleInstant: min === max };
}