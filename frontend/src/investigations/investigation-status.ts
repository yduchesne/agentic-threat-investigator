// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation lifecycle status model (PR 24B).
//
// The five backend statuses are the only lifecycle states the frontend may
// use; nothing is invented client-side. Terminality is decided by status
// alone — never timestamps, Report presence, or guessed worker state.

import type { InvestigationStatusName } from "../api/schema-types";

/** The exact backend lifecycle statuses (PR 23C contract). */
export const INVESTIGATION_STATUSES: readonly InvestigationStatusName[] = [
  "pending",
  "running",
  "completed",
  "partial",
  "failed",
];

/** Whether one status is terminal (polling must stop). */
export function isTerminalStatus(status: InvestigationStatusName | undefined): boolean {
  return status === "completed" || status === "partial" || status === "failed";
}

/** i18n key for each status label, mapping exactly to the backend values. */
export const INVESTIGATION_STATUS_LABEL_KEYS: Record<
  InvestigationStatusName,
  string
> = {
  pending: "status.pending",
  running: "status.running",
  completed: "status.completed",
  partial: "status.partial",
  failed: "status.failed",
};

/** Return the i18n label key for one status. */
export function statusLabelKey(status: InvestigationStatusName): string {
  return INVESTIGATION_STATUS_LABEL_KEYS[status];
}