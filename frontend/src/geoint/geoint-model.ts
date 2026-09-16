// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pure GEOINT presentation model (PR 26E §3).
//
// No React, no Leaflet objects, no network I/O. This module classifies
// bounded PR 26D results under a defensive coordinate policy, derives the
// deterministic viewport policy the Leaflet component applies, and owns all
// canonical display semantics (current-vs-history, containment status,
// precision/Location-type classification). Malformed runtime data stays
// table-visible and never reaches Leaflet; no value is ever clamped,
// zeroed, or otherwise recovered.
//
// The coordinate policy is the same defensive WGS84 policy the PR 25B map
// uses; the helper is reused because the semantics are identical
// (finite, in-range numbers only).

import type {
  GeointLocation,
  GeointObservation,
  GeointTopLocation,
  LocationPrecisionName,
  LocationTypeName,
} from "../api/schema-types";
import {
  isPlottableCoordinate,
  type LatLngPair,
  type MapViewport,
} from "../geolocation/geolocation-map-model";

/** Geographic latitude bounds of the WGS84 angular range. */
export const MIN_LATITUDE = -90;
export const MAX_LATITUDE = 90;
/** Geographic longitude bounds of the WGS84 angular range. */
export const MIN_LONGITUDE = -180;
export const MAX_LONGITUDE = 180;

/** One conservative fixed zoom for a single representative point. */
export const SINGLE_POINT_ZOOM = 8;

/** The multi-point fit zoom cap (same conservative approximation zoom). */
export const MAX_BOUNDS_ZOOM = SINGLE_POINT_ZOOM;

/** Fixed fitBounds padding in pixels for the multi-point viewport. */
export const BOUNDS_PADDING: readonly [number, number] = [24, 24];

/**
 * Whether a coordinate pair is plottable under the defensive policy.
 *
 * Both values must be finite numbers within WGS84 bounds; non-number,
 * non-finite, and out-of-range values are never plotted and no recovery is
 * performed. Reuses the identical PR 25B policy primitive because the
 * semantics match exactly.
 */
export function isPlottable(latitude: unknown, longitude: unknown): boolean {
  return isPlottableCoordinate(latitude, longitude);
}

/** One canonical Location display reference consumed by the map model. */
export interface PlottableLocationSource {
  latitude: number | null;
  longitude: number | null;
}

/** Whether a Location reference carries plottable representative coordinates. */
export function locationIsPlottable(
  location: PlottableLocationSource,
): location is PlottableLocationSource & { latitude: number; longitude: number } {
  return isPlottable(location.latitude, location.longitude);
}

/** Extract the plottable WGS84 pair of one Location reference. */
export function plottablePair(
  location: Pick<GeointLocation, "latitude" | "longitude">,
): LatLngPair | null {
  if (isPlottable(location.latitude, location.longitude)) {
    // The guard verified both coordinates are finite in-range numbers.
    return [location.latitude as number, location.longitude as number];
  }
  return null;
}

/** The classification of one bounded set of canonical Location references. */
export interface GeointLocationMapModel {
  /** Location references with valid plottable coordinates (server order). */
  mappable: readonly PlottableLocationSource[];
  /** Location references without plottable coordinates (server order). */
  unmappable: readonly PlottableLocationSource[];
  /** The total number of returned Location references. */
  totalCount: number;
  /** The number with valid plottable coordinates. */
  mappableCount: number;
  /** The number without plottable coordinates. */
  unmappableCount: number;
}

/**
 * Partition one bounded Location set into mappable/unmappable groups.
 *
 * Server order is preserved inside each group; transport objects are never
 * mutated. Null/null coordinates and defensive malformed values stay
 * table-visible.
 */
export function buildLocationMapModel(
  locations: readonly PlottableLocationSource[],
): GeointLocationMapModel {
  const mappable: PlottableLocationSource[] = [];
  const unmappable: PlottableLocationSource[] = [];
  for (const location of locations) {
    if (locationIsPlottable(location)) {
      mappable.push(location);
    } else {
      unmappable.push(location);
    }
  }
  return {
    mappable,
    unmappable,
    totalCount: locations.length,
    mappableCount: mappable.length,
    unmappableCount: unmappable.length,
  };
}

/**
 * Derive the deterministic viewport for one mappable Location dataset.
 *
 * - zero points: no meaningful viewport (the caller renders the non-map
 *   state instead of an empty world map);
 * - one point: the exact representative coordinate at the conservative
 *   fixed zoom;
 * - multiple points: the bounds over every mappable returned coordinate
 *   with fixed padding and a zoom cap no greater than the single-point
 *   zoom.
 */
export function geointViewport(
  locations: readonly PlottableLocationSource[],
): MapViewport {
  const plottable: LatLngPair[] = [];
  for (const location of locations) {
    const pair = locationIsPlottable(location)
      ? ([location.latitude, location.longitude] as LatLngPair)
      : null;
    if (pair !== null) {
      plottable.push(pair);
    }
  }
  if (plottable.length === 0) {
    return { kind: "none" };
  }
  if (plottable.length === 1) {
    return { kind: "single", center: plottable[0], zoom: SINGLE_POINT_ZOOM };
  }
  let south = plottable[0][0];
  let west = plottable[0][1];
  let north = plottable[0][0];
  let east = plottable[0][1];
  for (const [lat, lng] of plottable) {
    south = Math.min(south, lat);
    north = Math.max(north, lat);
    west = Math.min(west, lng);
    east = Math.max(east, lng);
  }
  return {
    kind: "bounds",
    bounds: [
      [south, west],
      [north, east],
    ],
    maxZoom: MAX_BOUNDS_ZOOM,
  };
}

// Canonical display semantics (PR 26E §3) --------------------------------

/** A source exposing the exact PR 26D Location-type vocabulary. */
export interface LocationTypeSource {
  location_type: LocationTypeName;
}

/** A source exposing the exact PR 26D precision vocabulary. */
export interface PrecisionSource {
  precision: LocationPrecisionName;
}

/** The exact PR 26D Location-type vocabulary (never invented). */
export const LOCATION_TYPE_VALUES: readonly LocationTypeName[] = [
  "country",
  "administrative_area",
  "city",
];

/** The exact PR 26D precision vocabulary (never invented). */
export const LOCATION_PRECISION_VALUES: readonly LocationPrecisionName[] = [
  "country",
  "administrative_area",
  "city",
];

/** Whether one value is a canonical Location type (defensive gate). */
export function isLocationType(value: string): value is LocationTypeName {
  return (LOCATION_TYPE_VALUES as readonly string[]).includes(value);
}

/** Whether one value is a canonical precision (defensive gate). */
export function isLocationPrecision(value: string): value is LocationPrecisionName {
  return (LOCATION_PRECISION_VALUES as readonly string[]).includes(value);
}

/**
 * The canonical display label of one Location reference.
 *
 * The canonical name is the analyst-facing label; the country/admin codes
 * are persistence identifiers, not display content. Missing/blank names
 * return null and the UI shows an explicit "unavailable" label.
 */
export function locationCanonicalLabel(
  location: Pick<GeointLocation, "canonical_name">,
): string | null {
  const name = location.canonical_name;
  return typeof name === "string" && name.trim() !== "" ? name.trim() : null;
}

/** Whether one observation is the Investigation-relative current reading. */
export function isCurrentObservation(
  observation: Pick<GeointObservation, "observation_id">,
  current: Pick<GeointObservation, "observation_id"> | null,
): boolean {
  return current !== null && current.observation_id === observation.observation_id;
}

/**
 * Whether one Entity's current observation exists in the Investigation.
 *
 * The Entity detail always returns a ``current_observation``; a null
 * observation is a defensive runtime signal and renders as "no current
 * context within this Investigation", never as a global current leak.
 */
export function hasInvestigationCurrent(
  entity: { current_observation: GeointObservation | null },
): boolean {
  return entity.current_observation !== null;
}

/**
 * The bounded top-Location population for proportions.
 *
 * The scoped entity count is an exact scoped fact, never a risk or
 * concentration label; zero-count rows are served only defensively and are
 * excluded from any map population.
 */
export function topLocationPopulation(
  top: Pick<GeointTopLocation, "scoped_entity_count">,
): number {
  return typeof top.scoped_entity_count === "number" && top.scoped_entity_count > 0
    ? top.scoped_entity_count
    : 0;
}