// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution URL codec (PR 24E §9, §13, §28).
//
// The Evolution route owns a first-class entity-centric state:
//
//   /investigations/:id/relationships/evolution
//     ?entity_id=<uuid>            (required to render Evolution)
//     &direction=source|target|either
//     &relationship_type=<urn>
//     &counterparty_entity_id=<uuid>
//     &source=<provider>
//     &observed_from=<ISO>&observed_to=<ISO>
//     &cursor=<opaque>
//     &view=evolution|graph
//
// The focal entity is URL-backed and required; without it the page renders
// an instructional empty state and never queries observations. Changing any
// semantic Evolution filter resets the cursor. The ``view`` parameter
// switches Evolution/Graph without losing focal entity/filter context, and
// temporal filters stay in the URL while Graph (correctly) ignores them.

import type {
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";
import {
  buildApiQuery,
  parseEnumParam,
  parseTimestampParam,
  parseUuidParam,
} from "../analyst-table/filters";
import { parseCursorParam } from "../analyst-table/cursor-stack";
import { RELATIONSHIP_DIRECTIONS } from "../relationships/relationships-filters";
import { RELATIONSHIP_TYPES } from "../relationships/labels";
import type { ObservationFilters } from "../relationships/relationships-filters";

/** The Evolution|Graph workspace view (URL-backed, no local tab state). */
export const EVOLUTION_VIEWS = ["evolution", "graph"] as const;

/** One committed Evolution/Graph workspace view. */
export type EvolutionWorkspaceView = (typeof EVOLUTION_VIEWS)[number];

/** The parameter switch for the workspace view. */
export const VIEW_PARAM = "view";

/** The parameter owning the focal entity (required for Evolution). */
export const ENTITY_PARAM = "entity_id";

/** The semantic Evolution filters (all reset cursor on change). */
export const EVOLUTION_FILTER_PARAMS = [
  "direction",
  "relationship_type",
  "counterparty_entity_id",
  "source",
  "observed_from",
  "observed_to",
] as const;

/** The validated URL-backed Evolution filter model. */
export interface RelationshipEvolutionFilters {
  entityId: string;
  direction: RelationshipDirectionName;
  relationshipType: RelationshipTypeName | undefined;
  counterpartyEntityId: string | undefined;
  source: string | undefined;
  observedFrom: string | undefined;
  observedTo: string | undefined;
}

/** Whether one value is an allowlisted workspace view. */
export function isEvolutionView(value: string | null | undefined): value is EvolutionWorkspaceView {
  return (EVOLUTION_VIEWS as readonly string[]).includes(value ?? "");
}

/** Read the workspace view parameter (defaults to Evolution). */
export function parseViewParam(params: URLSearchParams): EvolutionWorkspaceView {
  const value = params.get(VIEW_PARAM);
  return isEvolutionView(value) ? value : "evolution";
}

/**
 * Parse the Evolution workspace state off one URL parameter set.
 *
 * The focal entity is validated exactly; a missing/invalid entity yields a
 * null state (the page shows the instructional empty state and never
 * queries). A bare entity without ``direction`` normalizes to the
 * documented ``either`` semantics in the committed filter model.
 */
export function parseEvolutionParams(
  params: URLSearchParams,
): RelationshipEvolutionFilters | null {
  const entityId = parseUuidParam(params.get(ENTITY_PARAM));
  if (entityId === undefined) {
    return null;
  }
  return {
    entityId,
    direction:
      parseEnumParam(params.get("direction"), RELATIONSHIP_DIRECTIONS) ?? "either",
    relationshipType: parseEnumParam(
      params.get("relationship_type"),
      RELATIONSHIP_TYPES,
    ),
    counterpartyEntityId: parseUuidParam(params.get("counterparty_entity_id")),
    source: nonBlank(params.get("source")),
    observedFrom: parseTimestampParam(params.get("observed_from")),
    observedTo: parseTimestampParam(params.get("observed_to")),
  };
}

/** Apply one committed filter model over the parameter set (cursor reset). */
export function applyEvolutionFilters(
  params: URLSearchParams,
  filters: RelationshipEvolutionFilters,
): URLSearchParams {
  const next = new URLSearchParams(params);
  next.set(ENTITY_PARAM, filters.entityId);
  next.delete("cursor");
  for (const key of EVOLUTION_FILTER_PARAMS) {
    next.delete(key);
  }
  const values: Record<string, string | undefined> = {
    direction: filters.direction,
    relationship_type: filters.relationshipType,
    counterparty_entity_id: filters.counterpartyEntityId,
    source: filters.source,
    observed_from: filters.observedFrom,
    observed_to: filters.observedTo,
  };
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      next.set(key, value);
    }
  }
  return next;
}

/** Neutral committed filters for one focal entity (Either direction). */
export function emptyEvolutionFilters(entityId: string): RelationshipEvolutionFilters {
  return {
    entityId,
    direction: "either",
    relationshipType: undefined,
    counterpartyEntityId: undefined,
    source: undefined,
    observedFrom: undefined,
    observedTo: undefined,
  };
}

/** Switch the workspace view, preserving entity/filter context. */
export function setEvolutionView(
  params: URLSearchParams,
  view: EvolutionWorkspaceView,
): URLSearchParams {
  const next = new URLSearchParams(params);
  if (view === "evolution") {
    next.delete(VIEW_PARAM);
  } else {
    next.set(VIEW_PARAM, view);
  }
  return next;
}

/** Read the opaque bounded cursor off the parameter set. */
export function parseEvolutionCursor(params: URLSearchParams): string | undefined {
  return parseCursorParam(params.get("cursor"));
}

/** Set or clear the opaque cursor (never decoded). */
export function setEvolutionCursor(
  params: URLSearchParams,
  cursor: string | undefined,
): URLSearchParams {
  const next = new URLSearchParams(params);
  if (cursor === undefined || cursor === "") {
    next.delete("cursor");
  } else {
    next.set("cursor", cursor);
  }
  return next;
}

/** Convert the committed Evolution filters to the observation query model. */
export function evolutionFiltersToObservationFilters(
  filters: RelationshipEvolutionFilters,
): ObservationFilters {
  return {
    relationshipId: undefined,
    source: filters.source,
    observedFrom: filters.observedFrom,
    observedTo: filters.observedTo,
    retrievedFrom: undefined,
    retrievedTo: undefined,
    entityId: filters.entityId,
    direction: filters.direction,
    relationshipType: filters.relationshipType,
    counterpartyEntityId: filters.counterpartyEntityId,
  };
}

/** Build the exact API query parameters for the Evolution observation page. */
export function evolutionFiltersToApi(
  filters: RelationshipEvolutionFilters,
): URLSearchParams {
  return buildApiQuery({
    entity_id: filters.entityId,
    direction: filters.direction,
    relationship_type: filters.relationshipType,
    counterparty_entity_id: filters.counterpartyEntityId,
    source: filters.source,
    observed_from: filters.observedFrom,
    observed_to: filters.observedTo,
  });
}

/** Whether any semantic Evolution filter beyond entity/direction is active. */
export function evolutionFiltersActive(filters: RelationshipEvolutionFilters): boolean {
  return (
    filters.relationshipType !== undefined ||
    filters.counterpartyEntityId !== undefined ||
    filters.source !== undefined ||
    filters.observedFrom !== undefined ||
    filters.observedTo !== undefined
  );
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string | null): string | undefined {
  if (value === null) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}