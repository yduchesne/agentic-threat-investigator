// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph-neighborhood server-state hook (PR 31D; PR 31G).
//
// The Graph view reads topology exclusively from the PR 31C neighborhood
// endpoint through this hook; it never reuses ``useRelationshipsPage`` for
// the canvas. The committed graph context (scope + every filter) is part of
// the query key, so any context change issues a new request. Queries are
// disabled without a valid focal Entity, never poll, use a standard
// analytical stale time, propagate AbortSignal, and surface a typed ApiError
// for the Retry path.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type {
  GraphNeighborhood,
  RelationshipDirectionName,
} from "../api/schema-types";
import {
  fetchGraphNeighborhood,
  GRAPH_NEIGHBORHOOD_LIMIT,
} from "./graph-api";
import type { GraphContext } from "./graph-context-url";
import { graphNeighborhoodKey } from "./graph-keys";

/** Read the bounded one-hop neighborhood of the focal Entity. */
export function useGraphNeighborhood(
  investigationId: string,
  entityId: string | undefined,
  direction: RelationshipDirectionName,
  context: GraphContext,
  enabled: boolean = true,
): {
  neighborhood: GraphNeighborhood | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const active = enabled && entityId !== undefined;
  const result = useQuery<GraphNeighborhood, ApiError>({
    queryKey: graphNeighborhoodKey(
      investigationId,
      entityId ?? "",
      direction,
      context,
      GRAPH_NEIGHBORHOOD_LIMIT,
    ),
    queryFn: ({ signal }) =>
      fetchGraphNeighborhood(
        investigationId,
        entityId ?? "",
        direction,
        context,
        GRAPH_NEIGHBORHOOD_LIMIT,
        signal,
      ),
    enabled: active,
    staleTime: 30_000,
  });
  return {
    neighborhood: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}
