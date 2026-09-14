// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History filter codec (PR 24C §6, §12).
//
// Exact backend filters only: public-allowlisted object type, operation
// enum, and half-open occurred-time range. Unknown/invalid enum values
// normalize to absence; non-allowlisted object types are never sent.

import type { HistoryOperationName } from "../api/schema-types";
import {
  applyFilterParams,
  buildApiQuery,
  parseEnumParam,
  parseTimestampParam,
} from "../analyst-table/filters";
import { HISTORY_OPERATIONS, isPublicHistoryObjectType } from "./labels";

/** One validated History filter model. */
export interface HistoryFilters {
  objectType: string | undefined;
  operation: HistoryOperationName | undefined;
  occurredFrom: string | undefined;
  occurredTo: string | undefined;
}

/** The URL parameter keys owned by the History codec. */
export const HISTORY_FILTER_KEYS = [
  "object_type",
  "operation",
  "occurred_from",
  "occurred_to",
] as const;

/** The neutral History filter state. */
export function emptyHistoryFilters(): HistoryFilters {
  return {
    objectType: undefined,
    operation: undefined,
    occurredFrom: undefined,
    occurredTo: undefined,
  };
}

/** Parse one URL parameter set into a validated History filter model. */
export function parseHistoryFilters(params: URLSearchParams): HistoryFilters {
  return {
    objectType: parseObjectTypeParam(params.get("object_type")),
    operation: parseEnumParam(params.get("operation"), HISTORY_OPERATIONS),
    occurredFrom: parseTimestampParam(params.get("occurred_from")),
    occurredTo: parseTimestampParam(params.get("occurred_to")),
  };
}

/** Parse one object-type param against the backend public allowlist. */
export function parseObjectTypeParam(value: string | null | undefined): string | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  if (!isPublicHistoryObjectType(value)) {
    return undefined;
  }
  return value;
}

/** Serialize a committed History filter model over one URL set. */
export function historyFiltersToParams(
  params: URLSearchParams,
  filters: HistoryFilters,
): URLSearchParams {
  return applyFilterParams(params, HISTORY_FILTER_KEYS, {
    object_type: filters.objectType,
    operation: filters.operation,
    occurred_from: filters.occurredFrom,
    occurred_to: filters.occurredTo,
  });
}

/** Build API query parameters from a validated History filter model. */
export function historyFiltersToApi(filters: HistoryFilters): URLSearchParams {
  return buildApiQuery({
    object_type: filters.objectType,
    operation: filters.operation,
    occurred_from: filters.occurredFrom,
    occurred_to: filters.occurredTo,
  });
}

/** Whether any History filter value is active. */
export function historyFiltersActive(filters: HistoryFilters): boolean {
  return (
    filters.objectType !== undefined ||
    filters.operation !== undefined ||
    filters.occurredFrom !== undefined ||
    filters.occurredTo !== undefined
  );
}