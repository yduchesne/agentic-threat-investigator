// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central Investigation query keys (PR 24B).
//
// Keys hold only stable resource identities and normalized filter
// primitives. CSRF tokens, idempotency keys, passwords, error objects and
// unstable object identities never appear here.

import type { InvestigationStatusName } from "../api/schema-types";

/** Normalized list filters (all primitives, nothing unstable). */
export interface InvestigationListFilter {
  status: InvestigationStatusName | undefined;
  cursor: string | undefined;
}

/** Query key for one bounded list page. */
export function investigationListKey(filter: InvestigationListFilter): unknown[] {
  return ["investigations", "list", filter.status ?? "all", filter.cursor ?? ""];
}

/** Query key for the authoritative detail of one Investigation. */
export function investigationDetailKey(investigationId: string): unknown[] {
  return ["investigations", "detail", investigationId];
}

/** Query key for the current Assessment of one Investigation. */
export function currentAssessmentKey(investigationId: string): unknown[] {
  return ["investigations", "assessment", "current", investigationId];
}

/** Query key for the current Report of one Investigation. */
export function currentReportKey(investigationId: string): unknown[] {
  return ["investigations", "report", "current", investigationId];
}

/** Query key for the deterministic Markdown of one persisted Report. */
export function reportMarkdownKey(
  investigationId: string,
  reportId: string,
): unknown[] {
  return ["investigations", "report", "markdown", investigationId, reportId];
}