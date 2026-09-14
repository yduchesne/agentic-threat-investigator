// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central Evidence query keys (PR 24C §7).
//
// Keys hold only stable resource identities and validated filter
// primitives; the cursor stays opaque and is never decoded.

import type { EvidenceFilters } from "./evidence-filters";

/** Query key for one bounded Evidence page. */
export function evidenceListKey(
  investigationId: string,
  filters: EvidenceFilters,
  cursor: string | undefined,
): unknown[] {
  return ["evidence", investigationId, "list", filters, cursor ?? ""];
}

/** Query key for the authoritative detail of one Evidence observation. */
export function evidenceDetailKey(
  investigationId: string,
  evidenceId: string,
): unknown[] {
  return ["evidence", investigationId, "detail", evidenceId];
}