// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT server-state query keys (PR 26E §2).
//
// Every key includes the Investigation plus every semantic identity/filter
// that changes the server result: Entity/Location/observation ID, the
// opaque cursor, and the containment flag. Keys never carry payloads,
// viewport state, or decoded cursors.

/** The summary of one Investigation's bounded geographic context. */
export function geointSummaryKey(investigationId: string): readonly string[] {
  return ["geoint", "summary", investigationId];
}

/** One Entity's Investigation-relative current geographic context. */
export function geointEntityKey(
  investigationId: string,
  entityId: string,
): readonly string[] {
  return ["geoint", "entity", investigationId, entityId];
}

/** One page of an Entity's Investigation-scoped observation history. */
export function geointEntityHistoryKey(
  investigationId: string,
  entityId: string,
  cursor: string | undefined,
): readonly string[] {
  return ["geoint", "entity-history", investigationId, entityId, cursor ?? ""];
}

/** One Location-scoped page of Entities (exact or contained). */
export function geointLocationEntitiesKey(
  investigationId: string,
  locationId: string,
  includeContained: boolean,
  cursor: string | undefined,
): readonly string[] {
  return [
    "geoint",
    "location-entities",
    investigationId,
    locationId,
    includeContained ? "contained" : "exact",
    cursor ?? "",
  ];
}

/** One Location-scoped page of observations (exact or contained). */
export function geointLocationObservationsKey(
  investigationId: string,
  locationId: string,
  includeContained: boolean,
  cursor: string | undefined,
): readonly string[] {
  return [
    "geoint",
    "location-observations",
    investigationId,
    locationId,
    includeContained ? "contained" : "exact",
    cursor ?? "",
  ];
}

/** One exact Investigation-scoped geographic observation. */
export function geointObservationKey(
  investigationId: string,
  observationId: string,
): readonly string[] {
  return ["geoint", "observation", investigationId, observationId];
}