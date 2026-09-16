// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT API boundary functions (PR 26E §2).
//
// All canonical geographic traffic funnels through the PR 24A centralized
// client and stays Investigation-scoped. The six PR 26D operations are
// wrapped verbatim with their exact parameters; the cursor is opaque and
// forwarded unchanged; ``includeContained`` maps to the exact server
// boolean. No navigation, no polling, no client-side reconstruction.

import { apiGet } from "../api/client";
import type {
  GeointEntityLocation,
  GeointLocationEntitiesPage,
  GeointLocationObservationsPage,
  GeointObservationDetail,
  GeointObservationPage,
  GeointSummary,
} from "../api/schema-types";

/** Bounded browser page size for the pageable GEOINT collections. */
export const GEOINT_PAGE_SIZE = 25;

/** Load the bounded Investigation-scoped geographic summary (PR 26D). */
export async function fetchGeointSummary(
  investigationId: string,
  signal?: AbortSignal,
): Promise<GeointSummary> {
  return apiGet<GeointSummary>(
    `/investigations/${investigationId}/geoint/summary`,
    signal,
  );
}

/** Load one Entity's Investigation-relative current geographic context. */
export async function fetchGeointEntity(
  investigationId: string,
  entityId: string,
  signal?: AbortSignal,
): Promise<GeointEntityLocation> {
  return apiGet<GeointEntityLocation>(
    `/investigations/${investigationId}/geoint/entities/${entityId}`,
    signal,
  );
}

/** Load one page of an Entity's Investigation-scoped observation history. */
export async function fetchGeointEntityHistory(
  investigationId: string,
  entityId: string,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<GeointObservationPage> {
  const query = new URLSearchParams();
  query.set("limit", String(GEOINT_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  return apiGet<GeointObservationPage>(
    `/investigations/${investigationId}/geoint/entities/${entityId}/observations?${query.toString()}`,
    signal,
  );
}

/** Load one Location-scoped page of Entities (exact or contained). */
export async function fetchGeointLocationEntities(
  investigationId: string,
  locationId: string,
  includeContained: boolean,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<GeointLocationEntitiesPage> {
  const query = new URLSearchParams();
  if (includeContained) {
    query.set("include_contained", "true");
  }
  query.set("limit", String(GEOINT_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  return apiGet<GeointLocationEntitiesPage>(
    `/investigations/${investigationId}/geoint/locations/${locationId}/entities?${query.toString()}`,
    signal,
  );
}

/** Load one Location-scoped page of observations (exact or contained). */
export async function fetchGeointLocationObservations(
  investigationId: string,
  locationId: string,
  includeContained: boolean,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<GeointLocationObservationsPage> {
  const query = new URLSearchParams();
  if (includeContained) {
    query.set("include_contained", "true");
  }
  query.set("limit", String(GEOINT_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  return apiGet<GeointLocationObservationsPage>(
    `/investigations/${investigationId}/geoint/locations/${locationId}/observations?${query.toString()}`,
    signal,
  );
}

/** Load one exact Investigation-scoped geographic observation detail. */
export async function fetchGeointObservation(
  investigationId: string,
  observationId: string,
  signal?: AbortSignal,
): Promise<GeointObservationDetail> {
  return apiGet<GeointObservationDetail>(
    `/investigations/${investigationId}/geoint/observations/${observationId}`,
    signal,
  );
}