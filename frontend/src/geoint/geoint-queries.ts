// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT server-state hooks (PR 26E §2).
//
// Every GEOINT read is one bounded TanStack Query with the standard 30s
// stale time and no polling; refetch happens only through the explicit
// Retry/user flow. The AbortSignal from TanStack Query flows through the
// centralized client.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type {
  GeointEntityLocation,
  GeointLocationEntitiesPage,
  GeointLocationObservationsPage,
  GeointObservationDetail,
  GeointObservationPage,
  GeointSummary,
} from "../api/schema-types";
import {
  fetchGeointEntity,
  fetchGeointEntityHistory,
  fetchGeointLocationEntities,
  fetchGeointLocationObservations,
  fetchGeointObservation,
  fetchGeointSummary,
} from "./geoint-api";
import {
  geointEntityHistoryKey,
  geointEntityKey,
  geointLocationEntitiesKey,
  geointLocationObservationsKey,
  geointObservationKey,
  geointSummaryKey,
} from "./geoint-keys";

/** Read one Investigation's bounded geographic summary (never polls). */
export function useGeointSummary(investigationId: string): {
  summary: GeointSummary | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointSummary, ApiError>({
    queryKey: geointSummaryKey(investigationId),
    queryFn: ({ signal }) => fetchGeointSummary(investigationId, signal),
    staleTime: 30_000,
  });
  return {
    summary: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** Read one Entity's Investigation-relative current geographic context. */
export function useGeointEntity(
  investigationId: string,
  entityId: string | null,
): {
  entity: GeointEntityLocation | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointEntityLocation, ApiError>({
    queryKey: geointEntityKey(investigationId, entityId ?? ""),
    queryFn: ({ signal }) => fetchGeointEntity(investigationId, entityId ?? "", signal),
    enabled: entityId !== null,
    staleTime: 30_000,
  });
  return {
    entity: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** Read one page of an Entity's scoped observation history (never polls). */
export function useGeointEntityHistory(
  investigationId: string,
  entityId: string | null,
  cursor: string | undefined,
): {
  page: GeointObservationPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointObservationPage, ApiError>({
    queryKey: geointEntityHistoryKey(investigationId, entityId ?? "", cursor),
    queryFn: ({ signal }) =>
      fetchGeointEntityHistory(investigationId, entityId ?? "", cursor, signal),
    enabled: entityId !== null,
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

/** Read one Location-scoped page of Entities (exact or contained). */
export function useGeointLocationEntities(
  investigationId: string,
  locationId: string | null,
  includeContained: boolean,
  cursor: string | undefined,
): {
  page: GeointLocationEntitiesPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointLocationEntitiesPage, ApiError>({
    queryKey: geointLocationEntitiesKey(
      investigationId,
      locationId ?? "",
      includeContained,
      cursor,
    ),
    queryFn: ({ signal }) =>
      fetchGeointLocationEntities(
        investigationId,
        locationId ?? "",
        includeContained,
        cursor,
        signal,
      ),
    enabled: locationId !== null,
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

/** Read one Location-scoped page of observations (exact or contained). */
export function useGeointLocationObservations(
  investigationId: string,
  locationId: string | null,
  includeContained: boolean,
  cursor: string | undefined,
): {
  page: GeointLocationObservationsPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointLocationObservationsPage, ApiError>({
    queryKey: geointLocationObservationsKey(
      investigationId,
      locationId ?? "",
      includeContained,
      cursor,
    ),
    queryFn: ({ signal }) =>
      fetchGeointLocationObservations(
        investigationId,
        locationId ?? "",
        includeContained,
        cursor,
        signal,
      ),
    enabled: locationId !== null,
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

/** Read one exact Investigation-scoped geographic observation detail. */
export function useGeointObservation(
  investigationId: string,
  observationId: string | null,
): {
  detail: GeointObservationDetail | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<GeointObservationDetail, ApiError>({
    queryKey: geointObservationKey(investigationId, observationId ?? ""),
    queryFn: ({ signal }) =>
      fetchGeointObservation(investigationId, observationId ?? "", signal),
    enabled: observationId !== null,
    staleTime: 30_000,
  });
  return {
    detail: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}