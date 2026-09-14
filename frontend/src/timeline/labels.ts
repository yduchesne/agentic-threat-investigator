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