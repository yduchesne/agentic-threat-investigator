// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline filter codec (PR 24C §6, §11).
//
// Exact backend filters only: event type enum and half-open occurred-time
// range. Timeline preserves the API's canonical chronological ordering.

import {
  applyFilterParams,
  buildApiQuery,
  parseEnumParam,
  parseTimestampParam,
} from "../analyst-table/filters";
import type { TimelineEventTypeName } from "../api/schema-types";
import { TIMELINE_EVENT_TYPES } from "./labels";

/** One validated Timeline filter model. */
export interface TimelineFilters {
  eventType: TimelineEventTypeName | undefined;
  occurredFrom: string | undefined;
  occurredTo: string | undefined;
}

/** The URL parameter keys owned by the Timeline codec. */
export const TIMELINE_FILTER_KEYS = [
  "event_type",
  "occurred_from",
  "occurred_to",
] as const;

/** The neutral Timeline filter state. */
export function emptyTimelineFilters(): TimelineFilters {
  return {
    eventType: undefined,
    occurredFrom: undefined,
    occurredTo: undefined,
  };
}

/** Parse one URL parameter set into a validated Timeline filter model. */
export function parseTimelineFilters(params: URLSearchParams): TimelineFilters {
  return {
    eventType: parseEnumParam(params.get("event_type"), TIMELINE_EVENT_TYPES),
    occurredFrom: parseTimestampParam(params.get("occurred_from")),
    occurredTo: parseTimestampParam(params.get("occurred_to")),
  };
}

/** Serialize a committed Timeline filter model over one URL set. */
export function timelineFiltersToParams(
  params: URLSearchParams,
  filters: TimelineFilters,
): URLSearchParams {
  return applyFilterParams(params, TIMELINE_FILTER_KEYS, {
    event_type: filters.eventType,
    occurred_from: filters.occurredFrom,
    occurred_to: filters.occurredTo,
  });
}

/** Build API query parameters from a validated Timeline filter model. */
export function timelineFiltersToApi(filters: TimelineFilters): URLSearchParams {
  return buildApiQuery({
    event_type: filters.eventType,
    occurred_from: filters.occurredFrom,
    occurred_to: filters.occurredTo,
  });
}

/** Whether any Timeline filter value is active. */
export function timelineFiltersActive(filters: TimelineFilters): boolean {
  return (
    filters.eventType !== undefined ||
    filters.occurredFrom !== undefined ||
    filters.occurredTo !== undefined
  );
}