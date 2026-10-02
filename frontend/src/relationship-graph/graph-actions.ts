// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31K: the bounded graph-driven investigation action model.
//
// One canonical graph Entity is the ONLY action target. The browser may
// display entity type/value for analyst confirmation, but the canonical
// persisted ``entity_id`` is authoritative: labels are presentation, and a
// free-form value is never an action target. This module owns no
// provider/transform/enum vocabulary and no orchestration semantics; the
// workspace routes the selected Entity through the existing Investigation
// creation command (the reused execution seam).

import type { EntityTypeName } from "../api/schema-types";
import {
  INDICATOR_VALUE_MAX_LENGTH,
  OBJECTIVE_MAX_LENGTH,
} from "../investigations/CreateInvestigationPage";

/** One canonical graph Entity selected for an ATI investigation action. */
export interface GraphActionEntity {
  /** The canonical persisted Entity identity (authoritative). */
  entityId: string;
  /** Exact canonical Entity type (same enum the create form submits). */
  entityType: EntityTypeName;
  /** The canonical Entity value (never synthesized from a UUID). */
  entityValue: string;
}

/**
 * Factual prefilled objective for a graph-originated Investigation.
 *
 * The wording is deliberately neutral and descriptive (`Investigate
 * <type> <value>`); it never embeds maliciousness, causality, or any
 * analytical conclusion ATI has not produced. The analyst may edit it
 * before submission.
 */
export function buildGraphActionObjective(
  entityTypeLabel: string,
  entityValue: string,
): string {
  return `Investigate ${entityTypeLabel} ${entityValue}`;
}

/** One non-blank objective within the exact backend bound. */
export function isValidGraphActionObjective(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= OBJECTIVE_MAX_LENGTH;
}

/** One graph Entity value within the exact backend indicator bound. */
export function isValidGraphActionEntityValue(value: string): boolean {
  return value.trim().length > 0 && value.trim().length <= INDICATOR_VALUE_MAX_LENGTH;
}
