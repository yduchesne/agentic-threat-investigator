// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History server-state hooks + query keys (PR 24C §7, §12).
//
// History is secondary: list/detail load on demand, never poll, and never
// reconstruct unbounded chains. Object-scoped browsing stays inside the
// History surface (History-internal, not a PR 24D pivot).

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { HistoryPage, HistoryRecord } from "../api/schema-types";
import {
  fetchHistoryPage,
  fetchHistoryVersion,
  fetchObjectHistoryPage,
} from "./history-api";
import type { HistoryFilters } from "./history-filters";

/** Query key for one bounded History page. */
export function historyListKey(
  investigationId: string,
  filters: HistoryFilters,
  cursor: string | undefined,
): unknown[] {
  return ["history", investigationId, "list", filters, cursor ?? ""];
}

/** Query key for the object-scoped version browsing. */
export function objectHistoryListKey(
  investigationId: string,
  objectType: string,
  objectId: string,
  cursor: string | undefined,
): unknown[] {
  return ["history", investigationId, objectType, objectId, "list", cursor ?? ""];
}

/** Query key for one exact object version. */
export function historyVersionKey(
  investigationId: string,
  objectType: string,
  objectId: string,
  version: number,
): unknown[] {
  return ["history", investigationId, objectType, objectId, "version", version];
}

/** Read one bounded History page (never polls). */
export function useHistoryPage(
  investigationId: string,
  filters: HistoryFilters,
  cursor: string | undefined,
): {
  page: HistoryPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<HistoryPage, ApiError>({
    queryKey: historyListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) => fetchHistoryPage(investigationId, filters, cursor, signal),
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

/** Read the bounded object-scoped versions of one object. */
export function useObjectHistoryPage(
  investigationId: string,
  objectType: string | null,
  objectId: string | null,
): {
  page: HistoryPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const enabled = objectType !== null && objectId !== null;
  const result = useQuery<HistoryPage, ApiError>({
    queryKey: objectHistoryListKey(
      investigationId,
      objectType ?? "",
      objectId ?? "",
      undefined,
    ),
    queryFn: ({ signal }) =>
      fetchObjectHistoryPage(investigationId, objectType ?? "", objectId ?? "", undefined, signal),
    enabled,
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

/** Read the exact history row of one object version. */
export function useHistoryVersion(
  investigationId: string,
  objectType: string | null,
  objectId: string | null,
  version: number | null,
): {
  record: HistoryRecord | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const enabled = objectType !== null && objectId !== null && version !== null;
  const result = useQuery<HistoryRecord, ApiError>({
    queryKey: historyVersionKey(
      investigationId,
      objectType ?? "",
      objectId ?? "",
      version ?? 0,
    ),
    queryFn: ({ signal }) =>
      fetchHistoryVersion(investigationId, objectType ?? "", objectId ?? "", version ?? 0, signal),
    enabled,
    staleTime: 30_000,
  });
  return {
    record: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}