// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships + RelationshipObservations API boundary (PR 24C §7, §9).
//
// All traffic funnels through the PR 24A centralized client and stays
// Investigation-scoped. Cursors are opaque and passed through unchanged.
// Observations list directly; there is no single-GET observation endpoint,
// so the browser never invents one — detail uses the exact list DTO.

import { apiGet } from "../api/client";
import type {
  Relationship,
  RelationshipObservationPage,
  RelationshipPage,
} from "../api/schema-types";
import type { ObservationFilters, RelationshipFilters } from "./relationships-filters";
import {
  observationFiltersToApi,
  relationshipFiltersToApi,
} from "./relationships-filters";

/** Bounded browser page sizes (backend maxima are higher). */
export const RELATIONSHIP_PAGE_SIZE = 25;
export const OBSERVATION_PAGE_SIZE = 25;

/** Load one bounded page of Relationships through the keyset contract. */
export async function fetchRelationshipsPage(
  investigationId: string,
  filters: RelationshipFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
): Promise<RelationshipPage> {
  const query = relationshipFiltersToApi(filters);
  query.set("limit", String(RELATIONSHIP_PAGE_SIZE));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<RelationshipPage>(
    `/investigations/${investigationId}/relationships${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Load one Investigation-scoped Relationship edge. */
export async function fetchRelationship(
  investigationId: string,
  relationshipId: string,
  signal?: AbortSignal,
): Promise<Relationship> {
  return apiGet<Relationship>(
    `/investigations/${investigationId}/relationships/${relationshipId}`,
    signal,
  );
}

/**
 * Load one bounded page of RelationshipObservations.
 *
 * Used both by the first-class observations route and by the bounded
 * preview inside Relationship detail (same endpoint, same DTO).
 */
export async function fetchObservationsPage(
  investigationId: string,
  filters: ObservationFilters,
  cursor: string | undefined,
  signal?: AbortSignal,
  limit: number = OBSERVATION_PAGE_SIZE,
): Promise<RelationshipObservationPage> {
  const query = observationFiltersToApi(filters);
  query.set("limit", String(limit));
  if (cursor !== undefined && cursor !== "") {
    query.set("cursor", cursor);
  }
  const qs = query.toString();
  return apiGet<RelationshipObservationPage>(
    `/investigations/${investigationId}/relationship-observations${qs ? `?${qs}` : ""}`,
    signal,
  );
}