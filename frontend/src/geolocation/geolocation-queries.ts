// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation geolocation server-state hook (PR 25B).
//
// The map dataset is an analytical resource: one bounded read per
// Investigation with the standard 30s stale time and no polling. Refetch
// happens only through the existing explicit Retry/user flow. The
// AbortSignal from TanStack Query flows through the centralized client.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { InvestigationGeolocationCollection } from "../api/schema-types";
import { fetchInvestigationGeolocations } from "./geolocation-api";
import { geolocationsKey } from "./geolocation-keys";

/** Read one Investigation's bounded geolocation projection (never polls). */
export function useInvestigationGeolocations(investigationId: string): {
  collection: InvestigationGeolocationCollection | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<InvestigationGeolocationCollection, ApiError>({
    queryKey: geolocationsKey(investigationId),
    queryFn: ({ signal }) =>
      fetchInvestigationGeolocations(investigationId, signal),
    staleTime: 30_000,
  });
  return {
    collection: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}