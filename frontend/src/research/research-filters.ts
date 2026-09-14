// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Research filter codec (PR 24C §6, §10).
//
// Research is contextual knowledge, never Evidence. Exact backend filters
// only: subject entity UUID and half-open created-time range.

import {
  applyFilterParams,
  buildApiQuery,
  parseTimestampParam,
  parseUuidParam,
} from "../analyst-table/filters";

/** One validated ResearchResult list filter model. */
export interface ResearchFilters {
  subjectEntityId: string | undefined;
  createdFrom: string | undefined;
  createdTo: string | undefined;
}

/** The URL parameter keys owned by the Research codec. */
export const RESEARCH_FILTER_KEYS = [
  "subject_entity_id",
  "created_from",
  "created_to",
] as const;

/** The neutral Research filter state. */
export function emptyResearchFilters(): ResearchFilters {
  return {
    subjectEntityId: undefined,
    createdFrom: undefined,
    createdTo: undefined,
  };
}

/** Parse one URL parameter set into a validated Research filter model. */
export function parseResearchFilters(params: URLSearchParams): ResearchFilters {
  return {
    subjectEntityId: parseUuidParam(params.get("subject_entity_id")),
    createdFrom: parseTimestampParam(params.get("created_from")),
    createdTo: parseTimestampParam(params.get("created_to")),
  };
}

/** Serialize a committed Research filter model over one URL set. */
export function researchFiltersToParams(
  params: URLSearchParams,
  filters: ResearchFilters,
): URLSearchParams {
  return applyFilterParams(params, RESEARCH_FILTER_KEYS, {
    subject_entity_id: filters.subjectEntityId,
    created_from: filters.createdFrom,
    created_to: filters.createdTo,
  });
}

/** Build API query parameters from a validated Research filter model. */
export function researchFiltersToApi(filters: ResearchFilters): URLSearchParams {
  return buildApiQuery({
    subject_entity_id: filters.subjectEntityId,
    created_from: filters.createdFrom,
    created_to: filters.createdTo,
  });
}

/** Whether any Research filter value is active. */
export function researchFiltersActive(filters: ResearchFilters): boolean {
  return (
    filters.subjectEntityId !== undefined ||
    filters.createdFrom !== undefined ||
    filters.createdTo !== undefined
  );
}