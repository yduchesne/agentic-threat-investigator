// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline event type label mapping (PR 24C §11, §17).
//
// Timeline answers: what did ATI do during this Investigation? Known event
// enums map to translated labels; unknown/future values fall back to the
// raw value rather than crashing.

import type { TimelineEventTypeName } from "../api/schema-types";

/** i18n key per known InvestigationTimelineEventType. */
export const TIMELINE_EVENT_TYPE_KEYS: Readonly<Record<TimelineEventTypeName, string>> = {
  investigation_started: "types.investigationStarted",
  provider_work_started: "types.providerWorkStarted",
  provider_work_completed: "types.providerWorkCompleted",
  provider_work_failed: "types.providerWorkFailed",
  evidence_persisted: "types.evidencePersisted",
  entities_discovered: "types.entitiesDiscovered",
  pivot_enqueued: "types.pivotEnqueued",
  pivot_executed: "types.pivotExecuted",
  pivot_skipped: "types.pivotSkipped",
  research_requested: "types.researchRequested",
  assessment_requested: "types.assessmentRequested",
  investigation_stopped: "types.investigationStopped",
};

/**
 * Resolve one timeline event type to its i18n key.
 *
 * Unknown values return the raw enum (i18next renders the key itself as
 * the safe fallback).
 */
export function timelineEventTypeKey(type: TimelineEventTypeName | string): string {
  return TIMELINE_EVENT_TYPE_KEYS[type as TimelineEventTypeName] ?? type;
}

/** The exact v0.1 timeline event types accepted as list filters. */
export const TIMELINE_EVENT_TYPES: readonly TimelineEventTypeName[] = [
  "investigation_started",
  "provider_work_started",
  "provider_work_completed",
  "provider_work_failed",
  "evidence_persisted",
  "entities_discovered",
  "pivot_enqueued",
  "pivot_executed",
  "pivot_skipped",
  "research_requested",
  "assessment_requested",
  "investigation_stopped",
];

/**
 * i18n key per known timeline ``error_code`` value (PR 31F-1).
 *
 * ``PROVIDER_WORK_FAILED``/partial completion events expose the retained
 * provider error code (the stable ProviderErrorCode vocabulary). Unknown or
 * future codes return the raw value (i18next renders the key itself), so no
 * unknown code ever maps to a false semantic.
 */
export const TIMELINE_ERROR_CODE_KEYS: Readonly<Record<string, string>> = {
  timeout: "codes.error.timeout",
  rate_limited: "codes.error.rateLimited",
  authentication_failed: "codes.error.authenticationFailed",
  forbidden: "codes.error.forbidden",
  not_found: "codes.error.notFound",
  unsupported_indicator: "codes.error.unsupportedIndicator",
  invalid_response: "codes.error.invalidResponse",
  provider_unavailable: "codes.error.providerUnavailable",
};

/**
 * i18n key per known timeline ``reason_code`` value (PR 31F-1).
 *
 * ``investigation_stopped`` events carry the stable StopReason vocabulary;
 * ``pivot_skipped`` events carry the bounded PivotRejectionReason vocabulary.
 * The explicit maps share one key namespace; unknown/future values return the
 * raw value as a safe fallback.
 */
export const TIMELINE_REASON_CODE_KEYS: Readonly<Record<string, string>> = {
  // StopReason values (InvestigationStopped).
  sufficient_evidence: "codes.reason.sufficientEvidence",
  no_eligible_pivots: "codes.reason.noEligiblePivots",
  depth_limit_reached: "codes.reason.depthLimitReached",
  entity_budget_exhausted: "codes.reason.entityBudgetExhausted",
  provider_budget_exhausted: "codes.reason.providerBudgetExhausted",
  replan_limit_reached: "codes.reason.replanLimitReached",
  fatal_error: "codes.reason.fatalError",
  // PivotRejectionReason values (PivotSkipped).
  unknown_target: "codes.reason.unknownTarget",
  deleted_target: "codes.reason.deletedTarget",
  unsupported_class: "codes.reason.unsupportedClass",
  no_provider_path: "codes.reason.noProviderPath",
  duplicate_pivot: "codes.reason.duplicatePivot",
  duplicate_provider_work: "codes.reason.duplicateProviderWork",
  already_investigated: "codes.reason.alreadyInvestigated",
  depth_limit: "codes.reason.depthLimit",
  entity_budget: "codes.reason.entityBudget",
  provider_budget: "codes.reason.providerBudget",
};

/**
 * Resolve one timeline error code to its i18n key.
 *
 * Unknown values return the raw code (i18next renders the key itself as the
 * safe fallback).
 */
export function timelineErrorCodeKey(code: string): string {
  return TIMELINE_ERROR_CODE_KEYS[code] ?? code;
}

/**
 * Resolve one timeline reason code to its i18n key.
 *
 * Unknown values return the raw code (i18next renders the key itself as the
 * safe fallback).
 */
export function timelineReasonCodeKey(code: string): string {
  return TIMELINE_REASON_CODE_KEYS[code] ?? code;
}
