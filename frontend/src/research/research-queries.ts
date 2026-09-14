// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central Research query keys + server-state hooks (PR 24C §7).
//
// Research tables never poll; the detail query loads on selection and is
// strongly stale-cached because ResearchResults are immutable.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type { ResearchResult, ResearchResultPage } from "../api/schema-types";
import { fetchResearchResult, fetchResearchResultsPage } from "./research-api";
import type { ResearchFilters } from "./research-filters";

/** Query key for one bounded ResearchResults page. */
export function researchListKey(
  investigationId: string,
  filters: ResearchFilters,
  cursor: string | undefined,
): unknown[] {
  return ["research", investigationId, "list", filters, cursor ?? ""];
}

/** Query key for the authoritative detail of one ResearchResult. */
export function researchDetailKey(
  investigationId: string,
  researchResultId: string,
): unknown[] {
  return ["research", investigationId, "detail", researchResultId];
}

/** Read one bounded ResearchResults page (never polls). */
export function useResearchResultsPage(
  investigationId: string,
  filters: ResearchFilters,
  cursor: string | undefined,
): {
  page: ResearchResultPage | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<ResearchResultPage, ApiError>({
    queryKey: researchListKey(investigationId, filters, cursor),
    queryFn: ({ signal }) =>
      fetchResearchResultsPage(investigationId, filters, cursor, signal),
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

/** Read one authoritative Investigation-scoped ResearchResult. */
export function useResearchResultDetail(
  investigationId: string,
  researchResultId: string | null,
): {
  research: ResearchResult | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const result = useQuery<ResearchResult, ApiError>({
    queryKey: researchDetailKey(investigationId, researchResultId ?? ""),
    queryFn: ({ signal }) =>
      fetchResearchResult(investigationId, researchResultId ?? "", signal),
    enabled: researchResultId !== null,
    staleTime: 30_000,
  });
  return {
    research: result.data ?? null,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}