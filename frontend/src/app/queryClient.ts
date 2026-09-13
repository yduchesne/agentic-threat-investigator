// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One QueryClient for all server state (PR 24A).
//
// Required policy (docs/PR_PLAN.md PR 24A):
// - no mutation retries;
// - no 401/403 retries;
// - at most one bounded transient GET/network retry;
// - `refetchOnWindowFocus: false` in the v0.1 foundation;
// - endpoint-specific stale times selected by each feature's query options.

import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "../api/errors";

/** Default transient-retry budget for GET/network failures. */
const MAX_TRANSIENT_RETRIES = 1;

/**
 * Default retry decision for GET queries.
 *
 * Exported for direct policy tests; the QueryClient defaultOptions wiring
 * is the production use. Public 401/403 failures are never retried, other
 * public 4xx failures are not transient, and transport/5xx failures get at
 * most one bounded retry.
 */
export function queryRetryPolicy(failureCount: number, error: Error): boolean {
  if (error instanceof ApiError) {
    if (error.kind === "api" && (error.status === 401 || error.status === 403)) {
      return false;
    }
    if (!error.isTransient) {
      return false;
    }
  }
  return failureCount < MAX_TRANSIENT_RETRIES;
}

export interface AppQueryClientOptions {
  /**
   * Override the transient retry backoff (production keeps the bounded
   * exponential default; tests use a zero delay for determinism).
   */
  retryDelay?: number | ((failureCount: number, error: Error) => number);
}

/** Mutations are never retried (no automatic mutation retry in 24A). */
export const MUTATION_RETRY_COUNT = 0;

/** Create the single application QueryClient. Tests create their own. */
export function createAppQueryClient(options: AppQueryClientOptions = {}): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        refetchOnWindowFocus: false,
        retry: queryRetryPolicy,
        retryDelay: options.retryDelay ?? 1000,
      },
      mutations: {
        retry: MUTATION_RETRY_COUNT,
      },
    },
  });
}