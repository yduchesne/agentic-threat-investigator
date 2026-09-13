// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Runtime-mode server-state query (PR 24A / PR 23D contract).
//
// Runtime metadata is only ever requested from inside the authenticated
// shell, so it can never load before authentication.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { RuntimeInfo } from "../api/schema-types";
import { fetchRuntime } from "./runtime-api";

/** Central runtime feature query key. */
export const runtimeQueryKey = ["runtime"];

/** Read the authenticated runtime mode with bounded transient retry. */
export function useRuntimeQuery(): {
  runtime: RuntimeInfo | null;
  isLoading: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<RuntimeInfo, ApiError>({
    queryKey: runtimeQueryKey,
    queryFn: ({ signal }) => fetchRuntime(signal),
    staleTime: 60_000,
  });
  return {
    runtime: result.data ?? null,
    isLoading: result.isLoading,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}