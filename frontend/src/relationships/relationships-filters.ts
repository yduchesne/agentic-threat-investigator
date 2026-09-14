// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship and RelationshipObservation filter codecs (PR 24C §6, §9).
//
// Exact backend filter semantics only: source/target entity UUIDs and the
// relationship type URN for the stable edge; relationship id, exact
// source, and independent half-open observed/retrieved ranges for the
// immutable observations. Nothing here infers temporal validity.

import type {
  RelationshipObservation,
  RelationshipTypeName,
} from "../api/schema-types";
import {
  applyFilterParams,
  buildApiQuery,
  parseEnumParam,
  parseTimestampParam,
  parseUuidParam,
} from "../analyst-table/filters";
import { RELATIONSHIP_TYPES } from "./labels";

/** One validated Relationship list filter model. */
export interface RelationshipFilters {
  sourceEntityId: string | undefined;
  targetEntityId: string | undefined;
  relationshipType: RelationshipTypeName | undefined;
}

/** The URL parameter keys owned by the Relationship codec. */
export const RELATIONSHIP_FILTER_KEYS = [
  "source_entity_id",
  "target_entity_id",
  "relationship_type",
] as const;

/** The neutral Relationship filter state. */
export function emptyRelationshipFilters(): RelationshipFilters {
  return {
    sourceEntityId: undefined,
    targetEntityId: undefined,
    relationshipType: undefined,
  };
}

/** Parse one URL parameter set into a validated Relationship filter model. */
export function parseRelationshipFilters(params: URLSearchParams): RelationshipFilters {
  return {
    sourceEntityId: parseUuidParam(params.get("source_entity_id")),
    targetEntityId: parseUuidParam(params.get("target_entity_id")),
    relationshipType: parseEnumParam(params.get("relationship_type"), RELATIONSHIP_TYPES),
  };
}

/** Serialize a committed Relationship filter model over one URL set. */
export function relationshipFiltersToParams(
  params: URLSearchParams,
  filters: RelationshipFilters,
): URLSearchParams {
  return applyFilterParams(params, RELATIONSHIP_FILTER_KEYS, {
    source_entity_id: filters.sourceEntityId,
    target_entity_id: filters.targetEntityId,
    relationship_type: filters.relationshipType,
  });
}

/** Build API query parameters from a validated Relationship filter model. */
export function relationshipFiltersToApi(filters: RelationshipFilters): URLSearchParams {
  return buildApiQuery({
    source_entity_id: filters.sourceEntityId,
    target_entity_id: filters.targetEntityId,
    relationship_type: filters.relationshipType,
  });
}

/** Whether any Relationship filter value is active. */
export function relationshipFiltersActive(filters: RelationshipFilters): boolean {
  return (
    filters.sourceEntityId !== undefined ||
    filters.targetEntityId !== undefined ||
    filters.relationshipType !== undefined
  );
}

/** One validated RelationshipObservation list filter model. */
export interface ObservationFilters {
  relationshipId: string | undefined;
  source: string | undefined;
  observedFrom: string | undefined;
  observedTo: string | undefined;
  retrievedFrom: string | undefined;
  retrievedTo: string | undefined;
}

/** The URL parameter keys owned by the Observation codec. */
export const OBSERVATION_FILTER_KEYS = [
  "relationship_id",
  "source",
  "observed_from",
  "observed_to",
  "retrieved_from",
  "retrieved_to",
] as const;

/** The neutral Observation filter state. */
export function emptyObservationFilters(): ObservationFilters {
  return {
    relationshipId: undefined,
    source: undefined,
    observedFrom: undefined,
    observedTo: undefined,
    retrievedFrom: undefined,
    retrievedTo: undefined,
  };
}

/** Parse one URL parameter set into a validated Observation filter model. */
export function parseObservationFilters(params: URLSearchParams): ObservationFilters {
  return {
    relationshipId: parseUuidParam(params.get("relationship_id")),
    source: nonBlank(params.get("source")),
    observedFrom: parseTimestampParam(params.get("observed_from")),
    observedTo: parseTimestampParam(params.get("observed_to")),
    retrievedFrom: parseTimestampParam(params.get("retrieved_from")),
    retrievedTo: parseTimestampParam(params.get("retrieved_to")),
  };
}

/** Serialize a committed Observation filter model over one URL set. */
export function observationFiltersToParams(
  params: URLSearchParams,
  filters: ObservationFilters,
): URLSearchParams {
  return applyFilterParams(params, OBSERVATION_FILTER_KEYS, {
    relationship_id: filters.relationshipId,
    source: filters.source,
    observed_from: filters.observedFrom,
    observed_to: filters.observedTo,
    retrieved_from: filters.retrievedFrom,
    retrieved_to: filters.retrievedTo,
  });
}

/** Build API query parameters from a validated Observation filter model. */
export function observationFiltersToApi(filters: ObservationFilters): URLSearchParams {
  return buildApiQuery({
    relationship_id: filters.relationshipId,
    source: filters.source,
    observed_from: filters.observedFrom,
    observed_to: filters.observedTo,
    retrieved_from: filters.retrievedFrom,
    retrieved_to: filters.retrievedTo,
  });
}

/** Whether any Observation filter value is active. */
export function observationFiltersActive(filters: ObservationFilters): boolean {
  return (
    filters.relationshipId !== undefined ||
    filters.source !== undefined ||
    filters.observedFrom !== undefined ||
    filters.observedTo !== undefined ||
    filters.retrievedFrom !== undefined ||
    filters.retrievedTo !== undefined
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

/** One row type alias to keep the observation imports explicit. */
export type ObservationRow = RelationshipObservation;