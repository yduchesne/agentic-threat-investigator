// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical Investigation-scoped Entity exact-read hook (PR 35-8).
//
// The focal indicator (Relationship History/Graph and focal Relationships)
// and the generic Entity details route read the exact Entity projection
// through this hook. Its query key contains only Investigation + Entity
// identity (never any graph/observation filter), so the same canonical
// value/type is served regardless of which workspace view is active and
// regardless of graph/list result cardinality. Queries are disabled for a
// malformed UUID (fail closed), never poll, propagate AbortSignal and expose
// a typed ApiError for the Retry path.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import { isUuidValue } from "../analyst-table/filters";
import { fetchEntityDetail, type EntityDetail } from "./entity-api";

/** Query key for one exact Investigation-scoped Entity projection. */
export function entityDetailKey(investigationId: string, entityId: string): unknown[] {
  return ["entity", investigationId, entityId];
}

/** The exact Entity read state consumed by the focal/details surfaces. */
export interface EntityDetailState {
  entity: EntityDetail | null;
  isLoading: boolean;
  isError: boolean;
  /** The scoped read resolved to "not found/not accessible". */
  notFound: boolean;
  error: ApiError | null;
  refetch: () => void;
}

/** Read one exact Investigation-scoped Entity (value/type/display name). */
export function useEntityDetail(
  investigationId: string,
  entityId: string,
  enabled: boolean = true,
): EntityDetailState {
  const valid = enabled && entityId !== "" && isUuidValue(entityId);
  const result = useQuery<EntityDetail | null, ApiError>({
    queryKey: entityDetailKey(investigationId, entityId),
    queryFn: ({ signal }) => fetchEntityDetail(investigationId, entityId, signal),
    enabled: valid,
    staleTime: 30_000,
  });
  return {
    entity: result.data ?? null,
    isLoading: valid && result.isLoading,
    isError: valid && result.isError,
    notFound: !valid || (result.isSuccess && result.data === null),
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}
