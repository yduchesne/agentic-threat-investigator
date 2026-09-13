// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation server-state hooks (PR 24B).
//
// Polling policy: while the authoritative detail reports `pending` or
// `running` the detail query refetches on a bounded interval; it stops on
// every terminal status (`completed`, `partial`, `failed`). `refetchIntervalInBackground`
// stays false, AbortSignals flow through the centralized client, and the
// current Assessment/Report queries are enabled only while their durable
// pointer exists — they never run on every poll tick.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";

import type { ApiError } from "../api/errors";
import { queryRetryPolicy } from "../app/queryClient";
import type {
  Assessment,
  CreateInvestigationInput,
  CreateInvestigationResult,
  Investigation,
  InvestigationPage,
  InvestigationStatusName,
  Report,
} from "../api/schema-types";
import { isTerminalStatus } from "./investigation-status";
import {
  createInvestigationCommand,
  fetchCurrentAssessment,
  fetchCurrentReport,
  fetchInvestigationsPage,
  fetchInvestigation,
  fetchReportMarkdown,
  type InvestigationListParams,
} from "./investigation-api";
import {
  currentAssessmentKey,
  currentReportKey,
  investigationDetailKey,
  investigationListKey,
  reportMarkdownKey,
} from "./investigation-keys";

/** Bounded detail polling interval; never below 1 second (PR 24B §15.3). */
export const DETAIL_POLL_INTERVAL_MS = 2000;

/** One bounded extra attempt for a current-resource 404 pointer/read race. */
export const POINTER_RACE_MAX_RETRIES = 1;

/** Whether one failure is the bounded pointer/read-race 404. */
export function isPointerRace404(error: ApiError): boolean {
  return error.kind === "api" && error.status === 404;
}

/**
 * Detail polling interval decision: poll only non-terminal statuses.
 *
 * Returns the bounded interval while `pending`/`running` (or while the
 * status is not yet known), `false` otherwise. Exported for direct policy
 * tests; `intervalMs` is the production constant by default. The workspace
 * never overrides it — tests use the parameter to avoid real sleeps.
 */
export function detailPollingInterval(
  status: InvestigationStatusName | undefined,
  intervalMs: number = DETAIL_POLL_INTERVAL_MS,
): number | false {
  if (status === undefined || !isTerminalStatus(status)) {
    return intervalMs;
  }
  return false;
}

/** Bounded current-resource retry policy (pointer race, then global policy). */
export function currentResourceRetryPolicy(
  failureCount: number,
  error: ApiError,
): boolean {
  if (failureCount < POINTER_RACE_MAX_RETRIES && isPointerRace404(error)) {
    return true;
  }
  return queryRetryPolicy(failureCount, error);
}

/** Read one bounded page of the Investigation list. */
export function useInvestigationsPage(params: InvestigationListParams): {
  page: InvestigationPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {  const result = useQuery<InvestigationPage, ApiError>({
    queryKey: investigationListKey(params),
    queryFn: ({ signal }) => fetchInvestigationsPage(params, signal),
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

/**
 * Read the authoritative Investigation detail with bounded polling.
 *
 * The AbortSignal from TanStack Query is passed to the API client so route
 * unmount and query cancellation reach the network layer. `pollIntervalMs`
 * is a test seam; production callers always use the bounded default.
 */
export function useInvestigationDetail(
  investigationId: string,
  options: { pollIntervalMs?: number } = {},
): {
  investigation: Investigation | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<Investigation, ApiError>({
    queryKey: investigationDetailKey(investigationId),
    queryFn: ({ signal }) => fetchInvestigation(investigationId, signal),
    refetchInterval: (query) =>
      detailPollingInterval(
        query.state.data?.status,
        options.pollIntervalMs,
      ),
    refetchIntervalInBackground: false,
    staleTime: 1_000,
    placeholderData: (previous) => previous,
  });
  return {
    investigation: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** Read the current Assessment only while its durable pointer exists. */
export function useCurrentAssessment(
  investigationId: string,
  enabled: boolean,
): {
  assessment: Assessment | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<Assessment, ApiError>({
    queryKey: currentAssessmentKey(investigationId),
    queryFn: ({ signal }) => fetchCurrentAssessment(investigationId, signal),
    enabled,
    retry: currentResourceRetryPolicy,
    staleTime: 30_000,
  });
  return {
    assessment: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** Read the current Report only while its durable pointer exists. */
export function useCurrentReport(
  investigationId: string,
  enabled: boolean,
): {
  report: Report | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<Report, ApiError>({
    queryKey: currentReportKey(investigationId),
    queryFn: ({ signal }) => fetchCurrentReport(investigationId, signal),
    enabled,
    retry: currentResourceRetryPolicy,
    staleTime: 30_000,
  });
  return {
    report: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

/** Read the deterministic Markdown of one persisted Report on demand. */
export function useReportMarkdown(
  investigationId: string,
  reportId: string,
  enabled: boolean,
): {
  markdown: string | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<string, ApiError>({
    queryKey: reportMarkdownKey(investigationId, reportId),
    queryFn: ({ signal }) => fetchReportMarkdown(investigationId, reportId, signal),
    enabled,
    staleTime: Infinity,
  });
  return {
    markdown: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}

export interface CreateInvestigationMutation {
  /** Trigger one logical submission; variables carry the attempt key. */
  run: (variables: {
    input: CreateInvestigationInput;
    idempotencyKey: string;
  }) => void;
  isPending: boolean;
  error: ApiError | null;
}

/**
 * Create mutation hook.
 *
 * No automatic mutation retry (QueryClient default). The caller retains
 * the attempt key for transport-uncertain retry; on success the
 * Investigation list caches are invalidated and navigation moves to the
 * new workspace immediately — the worker executes asynchronously and the
 * browser never waits inside the create mutation. `onError` lets the
 * caller settle its idempotency attempt store.
 */
export function useCreateInvestigation(
  onError?: (error: ApiError) => void,
): {
  run: CreateInvestigationMutation["run"];
  isPending: boolean;
  error: ApiError | null;
} {
  const client = useQueryClient();
  const navigate = useNavigate();
  const mutation = useMutation<
    CreateInvestigationResult,
    ApiError,
    { input: CreateInvestigationInput; idempotencyKey: string },
    unknown
  >({
    mutationFn: ({ input, idempotencyKey }) =>
      createInvestigationCommand(input, idempotencyKey),
    onError: (error) => onError?.(error),
    onSuccess: (result) => {
      client.invalidateQueries({ queryKey: ["investigations", "list"] });
      navigate(`/investigations/${result.id}/overview`, { replace: false });
    },
  });
  return {
    run: (variables) => void mutation.mutate(variables),
    isPending: mutation.isPending,
    error: mutation.error ?? null,
  };
}

/** Extract the bounded stable idempotency-conflict code. */
export function isIdempotencyConflict(error: ApiError): boolean {
  return error.kind === "api" && error.code === "idempotency_conflict";
}

/** Extract the bounded stable validation-error code. */
export function isValidationError(error: ApiError): boolean {
  return error.kind === "api" && error.code === "validation_error";
}