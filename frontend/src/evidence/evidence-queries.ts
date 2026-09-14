// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence server-state hooks (PR 24C §7, §15).
//
// Tables never poll: the list query loads once per committed filter/cursor
// and refreshes only on explicit user action. The AbortSignal from
// TanStack Query flows through the centralized client.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { Evidence, EvidencePage } from "../api/schema-types";
import { fetchEvidence, fetchEvidencePage } from "./evidence-api";
import type { EvidenceFilters } from "./evidence-filters";
import { evidenceDetailKey, evidenceListKey } from "./evidence-keys";

/** Read one bounded Evidence page (never polls). */
export function useEvidencePage(
  investigationId: string,
  filters: EvidenceFilters,
  cursor: string | undefined,
): {
  page: EvidencePage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<EvidencePage, ApiError>({
    queryKey: evidenceListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) => fetchEvidencePage(investigationId, filters, cursor, signal),
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

/** Read one authoritative Evidence observation on selection. */
export function useEvidenceDetail(
  investigationId: string,
  evidenceId: string | null,
): {
  evidence: Evidence | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<Evidence, ApiError>({
    queryKey: evidenceDetailKey(investigationId, evidenceId ?? ""),
    queryFn: ({ signal }) => fetchEvidence(investigationId, evidenceId ?? "", signal),
    enabled: evidenceId !== null,
    staleTime: 30_000,
  });
  return {
    evidence: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}