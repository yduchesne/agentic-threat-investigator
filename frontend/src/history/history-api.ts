// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History API boundary functions (PR 24C §7, §12).
//
// Three Investigation-scoped endpoints: list rows, object-scoped versions,
// and one exact version. All traffic funnels through the PR 24A
// centralized client; cursors stay opaque. State/diff arrive backend-
// redacted and are rendered only as data.

import { apiGet } from "../api/client";
import type { HistoryPage, HistoryRecord } from "../api/schema-types";
import type { HistoryFilters } from "./history-filters";
import { historyFiltersToApi } from "./history-filters";

/** Bounded browser page sizes (backend maxima are higher). */
export const HISTORY_PAGE_SIZE = 25;
export const OBJECT_HISTORY_PAGE_SIZE = 25;

/** Load one bounded page of History rows through the keyset contract. */
export async function fetchHistoryPage(
  investigationId: string,
  filters: HistoryFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<HistoryPage> {
  const query = historyFiltersToApi(filters);
  query.set("limit", String(HISTORY_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<HistoryPage>(
    `/investigations/${investigationId}/history${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Load the object-scoped version history of one object. */
export async function fetchObjectHistoryPage(
  investigationId: string,
  objectType: string,
  objectId: string,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<HistoryPage> {
  const query = new URLSearchParams();
  query.set("limit", String(OBJECT_HISTORY_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<HistoryPage>(
    `/investigations/${investigationId}/history/${encodeURIComponent(objectType)}/${objectId}${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Load the exact history row of one object version. */
export async function fetchHistoryVersion(
  investigationId: string,
  objectType: string,
  objectId: string,
  version: number,
  signal?: AbortSignal,
): Promise<HistoryRecord> {
  return apiGet<HistoryRecord>(
    `/investigations/${investigationId}/history/${encodeURIComponent(objectType)}/${objectId}/${version}`,
    signal,
  );
}