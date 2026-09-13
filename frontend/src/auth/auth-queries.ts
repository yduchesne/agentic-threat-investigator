// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Authentication server-state model and query/mutation hooks (PR 24A).
//
// `/auth/me` is the single authority for authentication state:
//   loading | authenticated(PublicUser) | unauthenticated | error
// Cookie presence is never treated as authentication. Successful login
// invalidates the cached `/auth/me` result; successful logout invalidates
// the auth and runtime server-state caches so the next `/auth/me` decides
// state from the server. Passwords and CSRF tokens never appear in query
// keys or cached state.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { LoginCredentials, PublicUser } from "../api/schema-types";
import { runtimeQueryKey } from "../runtime/runtime-queries";
import { fetchMe, loginCommand, logoutCommand } from "./auth-api";

/** Central feature query keys (never contain credentials or CSRF tokens). */
export const authQueryKeys = {
  me: ["auth", "me"],
};

/** Invalidate the auth and runtime server-state features after session change. */
export function invalidateAuthenticatedState(client: QueryClient): void {
  client.invalidateQueries({ queryKey: authQueryKeys.me });
  client.invalidateQueries({ queryKey: runtimeQueryKey });
}

/** Read the current authenticated user; `null` data while loading. */
export function useMeQuery(): {
  user: PublicUser | null;
  state: "loading" | "authenticated" | "unauthenticated" | "error";
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<PublicUser, ApiError>({
    queryKey: authQueryKeys.me,
    queryFn: ({ signal }) => fetchMe(signal),
    staleTime: 10_000,
  });
  // The query status (not cached data) is authoritative: on a refetch
  // failure TanStack keeps the previous successful data, which must never
  // be treated as an authenticated session.
  const unauthenticated =
    result.error !== null && result.error.kind === "api" && result.error.status === 401;
  const state =
    result.status === "success"
      ? "authenticated"
      : unauthenticated
        ? "unauthenticated"
        : result.status === "error"
          ? "error"
          : "loading";
  return {
    user: result.data ?? null,
    state,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

export interface LoginOutcome {
  /** Mutation trigger; `variables` carries the login credentials. */
  run: (variables: LoginCredentials) => void;
  isPending: boolean;
  error: ApiError | null;
}

/**
 * Login mutation hook (no automatic retry; see QueryClient defaults).
 *
 * On success the cached `/auth/me` result is invalidated so the server
 * session is the authority, then `onSuccess` runs (navigation lives in the
 * caller).
 */
export function useLoginMutation(onSuccess: (user: PublicUser) => void): LoginOutcome {
  const client = useQueryClient();
  const mutation = useMutation<PublicUser, ApiError, LoginCredentials, unknown>({
    mutationFn: (variables) => loginCommand(variables),
    onSuccess: (data) => {
      client.invalidateQueries({ queryKey: authQueryKeys.me });
      onSuccess(data);
    },
  });
  return {
    run: (variables) => void mutation.mutate(variables),
    isPending: mutation.isPending,
    error: mutation.error ?? null,
  };
}

export interface LogoutOutcome {
  run: () => void;
  isPending: boolean;
  error: ApiError | null;
}

/**
 * Logout mutation hook (no automatic retry; see QueryClient defaults).
 *
 * On success the auth and runtime caches are invalidated so `/auth/me`
 * re-decides state from the now-revoked server session, then `onSuccess`
 * runs (navigation lives in the caller).
 */
export function useLogoutMutation(onSuccess: () => void): LogoutOutcome {
  const client = useQueryClient();
  const mutation = useMutation<null, ApiError, void, unknown>({
    mutationFn: () => logoutCommand(),
    onSuccess: () => {
      invalidateAuthenticatedState(client);
      onSuccess();
    },
  });
  return {
    run: () => void mutation.mutate(),
    isPending: mutation.isPending,
    error: mutation.error ?? null,
  };
}