// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Research API boundary functions (PR 24C §7).
//
// All Research traffic funnels through the PR 24A centralized client and
// stays Investigation-scoped. The cursor is opaque; filters are exact.

import { apiGet } from "../api/client";
import type { ResearchResult, ResearchResultPage } from "../api/schema-types";
import type { ResearchFilters } from "./research-filters";
import { researchFiltersToApi } from "./research-filters";

/** Bounded browser page size (backend maximum is higher). */
export const RESEARCH_PAGE_SIZE = 25;

/** Load one bounded page of ResearchResults through the keyset contract. */
export async function fetchResearchResultsPage(
  investigationId: string,
  filters: ResearchFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<ResearchResultPage> {
  const query = researchFiltersToApi(filters);
  query.set("limit", String(RESEARCH_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<ResearchResultPage>(
    `/investigations/${investigationId}/research${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Load one Investigation-scoped ResearchResult. */
export async function fetchResearchResult(
  investigationId: string,
  researchResultId: string,
  signal?: AbortSignal,
): Promise<ResearchResult> {
  return apiGet<ResearchResult>(
    `/investigations/${investigationId}/research/${researchResultId}`,
    signal,
  );
}