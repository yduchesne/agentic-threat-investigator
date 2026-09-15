// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central geolocation query key (PR 25B).
//
// The geolocation projection is Investigation-scoped server state; the key
// must include the Investigation ID so different Investigations never share
// a cache entry. There is deliberately no global/unscoped geolocation key.

/** Query key for one Investigation's bounded geolocation projection. */
export function geolocationsKey(investigationId: string): unknown[] {
  return ["investigations", investigationId, "geolocations"];
}