// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation stop-reason label mapping (PR 31F-1).
//
// Analyst-facing surfaces never prettify the raw ``stop_reason`` value by
// replacing underscores: known StopReason values map to explicit i18n keys
// inside the ``investigations`` namespace and unknown/future values return
// the raw value (i18next renders the key itself as the safe fallback).

/** i18n key per known Investigation ``stop_reason`` value. */
export const STOP_REASON_LABEL_KEYS: Readonly<Record<string, string>> = {
  sufficient_evidence: "stopReasons.sufficientEvidence",
  no_eligible_pivots: "stopReasons.noEligiblePivots",
  depth_limit_reached: "stopReasons.depthLimitReached",
  entity_budget_exhausted: "stopReasons.entityBudgetExhausted",
  provider_budget_exhausted: "stopReasons.providerBudgetExhausted",
  replan_limit_reached: "stopReasons.replanLimitReached",
  fatal_error: "stopReasons.fatalError",
};

/**
 * Resolve one Investigation stop reason to its i18n label key.
 *
 * Unknown values return the raw value (i18next renders the key itself as
 * the safe fallback, so no unknown reason is ever mapped to a false
 * semantic).
 */
export function stopReasonLabelKey(reason: string): string {
  return STOP_REASON_LABEL_KEYS[reason] ?? reason;
}
