// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central Relationships + Observations query keys (PR 24C §7).

import type {
  ObservationFilters,
  RelationshipFilters,
} from "./relationships-filters";

/** Query key for one bounded Relationships page. */
export function relationshipsListKey(
  investigationId: string,
  filters: RelationshipFilters,
  cursor: string | undefined,
): unknown[] {
  return ["relationships", investigationId, "list", filters, cursor ?? ""];
}

/** Query key for the authoritative detail of one Relationship edge. */
export function relationshipDetailKey(
  investigationId: string,
  relationshipId: string,
): unknown[] {
  return ["relationships", investigationId, "detail", relationshipId];
}

/** Query key for the bounded observation preview of one Relationship. */
export function relationshipObservationsPreviewKey(
  investigationId: string,
  relationshipId: string,
): unknown[] {
  return ["relationship-observations", investigationId, "preview", relationshipId];
}

/** Query key for the exact Investigation-scoped observation read. */
export function observationDetailKey(
  investigationId: string,
  observationId: string,
): unknown[] {
  return ["relationship-observations", investigationId, "detail", observationId];
}

/** Query key for one bounded RelationshipObservations page. */
export function observationsListKey(
  investigationId: string,
  filters: ObservationFilters,
  cursor: string | undefined,
): unknown[] {
  return ["relationship-observations", investigationId, "list", filters, cursor ?? ""];
}