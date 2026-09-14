// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence API boundary functions (PR 24C §7).
//
// All Evidence traffic funnels through the PR 24A centralized client and
// stays Investigation-scoped. The list request is bounded; the cursor is
// opaque and passed through unchanged. Filter semantics are the backend's
// — the browser never reconstructs query logic.

import { apiGet } from "../api/client";
import type { Evidence, EvidencePage } from "../api/schema-types";
import type { EvidenceFilters } from "./evidence-filters";
import { evidenceFiltersToApi } from "./evidence-filters";

/** Bounded browser page size (backend maximum is higher). */
export const EVIDENCE_PAGE_SIZE = 25;

/** Load one bounded page of Evidence through the keyset contract. */
export async function fetchEvidencePage(
  investigationId: string,
  filters: EvidenceFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<EvidencePage> {
  const query = evidenceFiltersToApi(filters);
  query.set("limit", String(EVIDENCE_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<EvidencePage>(
    `/investigations/${investigationId}/evidence${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Load one Investigation-scoped Evidence observation. */
export async function fetchEvidence(
  investigationId: string,
  evidenceId: string,
  signal?: AbortSignal,
): Promise<Evidence> {
  return apiGet<Evidence>(
    `/investigations/${investigationId}/evidence/${evidenceId}`,
    signal,
  );
}