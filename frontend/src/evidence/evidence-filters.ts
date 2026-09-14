// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence filter codec (PR 24C §6, §14).
//
// URL search params -> validated frontend filter model -> API params.
// Unknown/invalid enum and UUID values normalize to absence, empty values
// are never sent, and dates serialize as UTC ISO-8601. ``selected`` never
// alters the list query identity.

import type { EvidenceTypeName } from "../api/schema-types";
import {
  applyFilterParams,
  buildApiQuery,
  parseEnumParam,
  parseTimestampParam,
  parseUuidParam,
} from "../analyst-table/filters";
import { EVIDENCE_TYPES } from "./labels";

/** One validated Evidence list filter model. */
export interface EvidenceFilters {
  /** Exact source provider name (API semantics: exact, never contains). */
  source: string | undefined;
  subjectEntityId: string | undefined;
  type: EvidenceTypeName | undefined;
  /** Half-open UTC ISO start of the retrieval window (inclusive). */
  retrievedFrom: string | undefined;
  /** Half-open UTC ISO end of the retrieval window (exclusive). */
  retrievedTo: string | undefined;
}

/** The URL parameter keys owned by the Evidence codec. */
export const EVIDENCE_FILTER_KEYS = [
  "source",
  "subject_entity_id",
  "type",
  "retrieved_from",
  "retrieved_to",
] as const;

/** The empty/neutral filter state. */
export function emptyEvidenceFilters(): EvidenceFilters {
  return {
    source: undefined,
    subjectEntityId: undefined,
    type: undefined,
    retrievedFrom: undefined,
    retrievedTo: undefined,
  };
}

/** Parse one URL parameter set into a validated filter model. */
export function parseEvidenceFilters(params: URLSearchParams): EvidenceFilters {
  return {
    source: nonBlank(params.get("source")),
    subjectEntityId: parseUuidParam(params.get("subject_entity_id")),
    type: parseEnumParam(params.get("type"), EVIDENCE_TYPES),
    retrievedFrom: parseTimestampParam(params.get("retrieved_from")),
    retrievedTo: parseTimestampParam(params.get("retrieved_to")),
  };
}

/** Serialize a committed filter model over one URL parameter set. */
export function evidenceFiltersToParams(
  params: URLSearchParams,
  filters: EvidenceFilters,
): URLSearchParams {
  return applyFilterParams(params, EVIDENCE_FILTER_KEYS, {
    source: filters.source,
    subject_entity_id: filters.subjectEntityId,
    type: filters.type,
    retrieved_from: filters.retrievedFrom,
    retrieved_to: filters.retrievedTo,
  });
}

/** Build API query parameters from a validated filter model. */
export function evidenceFiltersToApi(filters: EvidenceFilters): URLSearchParams {
  return buildApiQuery({
    source: filters.source,
    subject_entity_id: filters.subjectEntityId,
    type: filters.type,
    retrieved_from: filters.retrievedFrom,
    retrieved_to: filters.retrievedTo,
  });
}

/** Whether any filter value is active (drives ``Clear filters``). */
export function evidenceFiltersActive(filters: EvidenceFilters): boolean {
  return (
    filters.source !== undefined ||
    filters.subjectEntityId !== undefined ||
    filters.type !== undefined ||
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