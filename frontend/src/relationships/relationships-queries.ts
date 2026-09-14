// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships + Observations server-state hooks (PR 24C §7, §9, §15).
//
// Tables never poll and observation previews are bounded (never recursive
// fetching of all history). AbortSignals flow through the centralized
// client.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type {
  Relationship,
  RelationshipObservationPage,
  RelationshipPage,
} from "../api/schema-types";
import {
  fetchObservationsPage,
  fetchRelationship,
  fetchRelationshipsPage,
} from "./relationships-api";
import type {
  ObservationFilters,
  RelationshipFilters,
} from "./relationships-filters";
import { emptyObservationFilters } from "./relationships-filters";
import {
  observationsListKey,
  relationshipDetailKey,
  relationshipObservationsPreviewKey,
  relationshipsListKey,
} from "./relationships-keys";

/** Bounded observation preview page size (never the full history). */
export const OBSERVATION_PREVIEW_LIMIT = 5;

/** Read one bounded Relationships page (never polls). */
export function useRelationshipsPage(
  investigationId: string,
  filters: RelationshipFilters,
  cursor: string | undefined,
): {
  page: RelationshipPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<RelationshipPage, ApiError>({
    queryKey: relationshipsListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) =>
      fetchRelationshipsPage(investigationId, filters, cursor, signal),
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

/** Read one authoritative Investigation-scoped Relationship edge. */
export function useRelationshipDetail(
  investigationId: string,
  relationshipId: string | null,
): {
  relationship: Relationship | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<Relationship, ApiError>({
    queryKey: relationshipDetailKey(investigationId, relationshipId ?? ""),
    queryFn: ({ signal }) =>
      fetchRelationship(investigationId, relationshipId ?? "", signal),
    enabled: relationshipId !== null,
    staleTime: 30_000,
  });
  return {
    relationship: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/**
 * Read the bounded observation preview of one Relationship.
 *
 * Always scoped by ``relationship_id`` and bounded to the first preview
 * page; never fetched through generic History and never iterated.
 */
export function useRelationshipObservationPreview(
  investigationId: string,
  relationshipId: string | null,
): {
  page: RelationshipObservationPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const filters: ObservationFilters = {
    ...emptyObservationFilters(),
    relationshipId: relationshipId ?? "",
  };
  const result = useQuery<RelationshipObservationPage, ApiError>({
    queryKey: relationshipObservationsPreviewKey(investigationId, relationshipId ?? ""),
    queryFn: ({ signal }) =>
      fetchObservationsPage(
        investigationId,
        filters,
        undefined,
        signal,
        OBSERVATION_PREVIEW_LIMIT,
      ),
    enabled: relationshipId !== null,
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

/** Read one bounded RelationshipObservations page (never polls). */
export function useObservationsPage(
  investigationId: string,
  filters: ObservationFilters,
  cursor: string | undefined,
): {
  page: RelationshipObservationPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<RelationshipObservationPage, ApiError>({
    queryKey: observationsListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) =>
      fetchObservationsPage(investigationId, filters, cursor, signal),
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