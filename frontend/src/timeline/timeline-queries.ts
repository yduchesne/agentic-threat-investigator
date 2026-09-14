// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline API boundary + server-state hooks (PR 24C §7, §11).
//
// Timeline never polls and preserves the API's canonical chronological
// ordering; the cursor is opaque and passed through unchanged.

import { useQuery } from "@tanstack/react-query";

import { apiGet } from "../api/client";
import type { ApiError } from "../api/errors";
import type { TimelineEvent, TimelineEventPage } from "../api/schema-types";
import type { TimelineFilters } from "./timeline-filters";
import { timelineFiltersToApi } from "./timeline-filters";

/** Bounded browser page size (backend maximum is higher). */
export const TIMELINE_PAGE_SIZE = 25;

/** Load one bounded page of Timeline events through the keyset contract. */
export async function fetchTimelinePage(
  investigationId: string,
  filters: TimelineFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<TimelineEventPage> {
  const query = timelineFiltersToApi(filters);
  query.set("limit", String(TIMELINE_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<TimelineEventPage>(
    `/investigations/${investigationId}/timeline${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Query key for one bounded Timeline page. */
export function timelineListKey(
  investigationId: string,
  filters: TimelineFilters,
  cursor: string | undefined,
): unknown[] {
  return ["timeline", investigationId, "list", filters, cursor ?? ""];
}

/** Read one bounded Timeline page (never polls). */
export function useTimelinePage(
  investigationId: string,
  filters: TimelineFilters,
  cursor: string | undefined,
): {
  page: TimelineEventPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<TimelineEventPage, ApiError>({
    queryKey: timelineListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) => fetchTimelinePage(investigationId, filters, cursor, signal),
    staleTime: 30_000,
  });
  return {
    page: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** A narrow public DTO row alias for the timeline table. */
export type TimelineEventRow = TimelineEvent;