// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT resource filter codecs (PR 26E §7-§9, §12).
//
// The GEOINT resources are scoped resource views driven by exact stable
// identities: one Entity (current + history), one Location (Entities or
// observations) with the server-owned containment flag, and one exact
// observation. The codecs mirror the PR 24C pattern: URL search params ->
// validated model -> API params, with the established UUID parsing and
// parameter-merge helpers. ``includeContained`` is a semantic query
// change: toggling it resets cursor/back-stack through the shared table
// controller and never performs client-side spatial calculation.

import {
  applyFilterParams,
  buildApiQuery,
  parseUuidParam,
} from "../analyst-table/filters";

/** One Entity-scoped GEOINT filter set (current + pageable history). */
export interface GeointEntityFilters {
  /** The exact stable Entity identity (the resource target). */
  entityId: string | undefined;
}

/** One Location-scoped GEOINT filter set (Entities or observations). */
export interface GeointLocationFilters {
  /** The exact stable canonical Location identity. */
  locationId: string | undefined;
  /** Server-owned containment expansion; exact is the default. */
  includeContained: boolean;
}

/** The URL parameter key owned by the Entity codec. */
export const GEOINT_ENTITY_FILTER_KEYS = ["entity_id"] as const;

/** The URL parameter keys owned by the Location codec. */
export const GEOINT_LOCATION_FILTER_KEYS = [
  "location_id",
  "include_contained",
] as const;

/** The neutral Entity filter state. */
export function emptyGeointEntityFilters(): GeointEntityFilters {
  return { entityId: undefined };
}

/** The neutral Location filter state (exact is the default). */
export function emptyGeointLocationFilters(): GeointLocationFilters {
  return { locationId: undefined, includeContained: false };
}

/** Parse one URL parameter set into a validated Entity filter model. */
export function parseGeointEntityFilters(
  params: URLSearchParams,
): GeointEntityFilters {
  return { entityId: parseUuidParam(params.get("entity_id")) };
}

/** Parse one URL parameter set into a validated Location filter model. */
export function parseGeointLocationFilters(
  params: URLSearchParams,
): GeointLocationFilters {
  const raw = params.get("include_contained");
  return {
    locationId: parseUuidParam(params.get("location_id")),
    includeContained: raw === "true" || raw === "1",
  };
}

/** Serialize a committed Entity filter model over one parameter set. */
export function geointEntityFiltersToParams(
  params: URLSearchParams,
  filters: GeointEntityFilters,
): URLSearchParams {
  return applyFilterParams(params, GEOINT_ENTITY_FILTER_KEYS, {
    entity_id: filters.entityId,
  });
}

/** Serialize a committed Location filter model over one parameter set. */
export function geointLocationFiltersToParams(
  params: URLSearchParams,
  filters: GeointLocationFilters,
): URLSearchParams {
  const next = applyFilterParams(params, GEOINT_LOCATION_FILTER_KEYS, {
    location_id: filters.locationId,
  });
  if (filters.includeContained) {
    next.set("include_contained", "true");
  } else {
    next.delete("include_contained");
  }
  return next;
}

/** Build API query parameters from a valid Entity filter model. */
export function geointEntityFiltersToApi(
  filters: GeointEntityFilters,
): URLSearchParams {
  return buildApiQuery({ entity_id: filters.entityId });
}

/** Build API query parameters from a valid Location filter model. */
export function geointLocationFiltersToApi(
  filters: GeointLocationFilters,
): URLSearchParams {
  const query = buildApiQuery({ location_id: filters.locationId });
  if (filters.includeContained) {
    query.set("include_contained", "true");
  }
  return query;
}

/** Whether the Entity filter model is complete (the resource target). */
export function geointEntityFiltersActive(filters: GeointEntityFilters): boolean {
  return filters.entityId !== undefined;
}

/** Whether the Location filter model is complete (the resource target). */
export function geointLocationFiltersActive(
  filters: GeointLocationFilters,
): boolean {
  return filters.locationId !== undefined;
}