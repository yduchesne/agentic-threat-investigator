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
  fetchGraphTraversal,
  GRAPH_NEIGHBORHOOD_LIMIT,
} from "./graph-api";
import type { GraphContext } from "./graph-context-url";
import { graphNeighborhoodKey, graphTraversalKey } from "./graph-keys";

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

/**
 * Read the bounded multi-hop traversal of the focal Entity (PR 31H).
 *
 * Only used for committed depth 2/3; the committed context (scope + every
 * filter + depth) is part of the distinct traversal query key, so any depth
 * or context change issues a new request and can never share an entry with
 * the one-hop neighborhood cache. Queries are disabled without a valid focal
 * Entity, never poll, use the standard analytical stale time, propagate
 * AbortSignal, and surface a typed ApiError for the Retry path.
 */
export function useGraphTraversal(
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
    queryKey: graphTraversalKey(
      investigationId,
      entityId ?? "",
      direction,
      context,
      GRAPH_NEIGHBORHOOD_LIMIT,
    ),
    queryFn: ({ signal }) =>
      fetchGraphTraversal(
        investigationId,
        entityId ?? "",
        direction,
        {
          scope: context.scope,
          entityType: context.entityType,
          relationshipType: context.relationshipType,
          source: context.source,
          observedFrom: context.observedFrom,
          observedTo: context.observedTo,
          maxDepth: context.depth,
        },
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
