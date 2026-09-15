// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pure Investigation map view model (PR 25B).
//
// This module contains no React and no Leaflet objects. It classifies the
// bounded PR 25A projection into plottable and coordinate-less items under
// a defensive coordinate policy, preserves server order inside each group,
// never mutates transport objects, and derives the deterministic viewport
// policy that the Leaflet component applies.
//
// Backend validation remains authoritative, but the browser must never
// crash or manufacture coordinates if malformed runtime data somehow
// reaches it: a coordinate is plottable only when both values are finite
// numbers within the geographic bounds. Null/null is valid geographic
// context without plottable coordinates; partial, non-finite, or
// out-of-range values are classified safely as unavailable/unlocated.
// Forbidden recovery (0,0 substitution, clamping, centroids, geocoding,
// jitter) is never performed.

import type {
  GeoPrecisionName,
  InvestigationGeolocation,
} from "../api/schema-types";

/** Geographic latitude bounds of the WGS84 angular range. */
export const MIN_LATITUDE = -90;
export const MAX_LATITUDE = 90;
/** Geographic longitude bounds of the WGS84 angular range. */
export const MIN_LONGITUDE = -180;
export const MAX_LONGITUDE = 180;

/** One conservative fixed zoom for a single approximate point. */
export const SINGLE_POINT_ZOOM = 8;

/** Fixed fitBounds padding in pixels for the multi-point viewport. */
export const BOUNDS_PADDING: readonly [number, number] = [24, 24];

/** The multi-point fit zoom cap (same conservative approximation zoom). */
export const MAX_BOUNDS_ZOOM = SINGLE_POINT_ZOOM;

/** A plottable coordinate pair in Leaflet's [lat, lng] order. */
export type LatLngPair = [number, number];

/** A Leaflet-compatible bounds expression: [[south, west], [north, east]]. */
export type BoundsPair = [LatLngPair, LatLngPair];

/** The deterministic viewport policy for one mappable dataset. */
export type MapViewport =
  | { kind: "none" }
  | { kind: "single"; center: LatLngPair; zoom: number }
  | { kind: "bounds"; bounds: BoundsPair; maxZoom: number };

/** The classification of one bounded geolocation projection. */
export interface GeolocationMapModel {
  /** Returned items with valid plottable coordinates (server order). */
  mappable: readonly InvestigationGeolocation[];
  /** Returned items without plottable coordinates (server order). */
  unlocated: readonly InvestigationGeolocation[];
  /** Total number of returned items. */
  totalCount: number;
  /** Number of items with valid plottable coordinates. */
  mappableCount: number;
  /** Number of items without plottable coordinates. */
  unlocatedCount: number;
  /** Whether the server projection exceeded its owned bound. */
  truncated: boolean;
}

/**
 * Whether a coordinate pair is plottable under the defensive policy.
 *
 * Both coordinates must be numbers, both must be finite, latitude must be
 * within [-90, 90] and longitude within [-180, 180]. Non-number,
 * non-finite, and out-of-range values are never plotted; no value is ever
 * clamped, zeroed, or otherwise recovered.
 */
export function isPlottableCoordinate(
  latitude: unknown,
  longitude: unknown,
): latitude is number {
  if (typeof latitude !== "number" || typeof longitude !== "number") {
    return false;
  }
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    return false;
  }
  return (
    latitude >= MIN_LATITUDE &&
    latitude <= MAX_LATITUDE &&
    longitude >= MIN_LONGITUDE &&
    longitude <= MAX_LONGITUDE
  );
}

/**
 * Partition one bounded projection into plottable and coordinate-less items.
 *
 * Server order is preserved inside each derived group. The input transport
 * objects (and arrays) are never mutated. `truncated` propagates exactly.
 */
export function buildGeolocationMapModel(
  items: readonly InvestigationGeolocation[],
  truncated: boolean,
): GeolocationMapModel {
  const mappable: InvestigationGeolocation[] = [];
  const unlocated: InvestigationGeolocation[] = [];
  for (const item of items) {
    if (
      isPlottableCoordinate(item.latitude, item.longitude)
    ) {
      mappable.push(item);
    } else {
      // null/null context, partial pairs, and defensive malformed values
      // all stay visible and never reach Leaflet.
      unlocated.push(item);
    }
  }
  return {
    mappable,
    unlocated,
    totalCount: items.length,
    mappableCount: mappable.length,
    unlocatedCount: unlocated.length,
    truncated,
  };
}

/** The exact PR 25A precision vocabulary (never invented client-side). */
export const GEO_PRECISION_VALUES: readonly GeoPrecisionName[] = [
  "country",
  "region",
  "city",
  "unknown",
];

/** One geolocation item's available geographic label parts. */
export interface LocationLabelSource {
  city?: string | null;
  region?: string | null;
  country_code?: string | null;
}
/**
 * Build a pure comma-joined location label from available parts.
 *
 * Missing parts are omitted cleanly (no stray separators); when no part is
 * available the result is null and the UI shows an explicit
 * "unavailable" label. No reverse geocoding is performed.
 */
export function locationLabel(source: LocationLabelSource): string | null {
  const parts = [source.city, source.region, source.country_code].filter(
    (part): part is string => part !== null && part !== undefined && part !== "",
  );
  return parts.length > 0 ? parts.join(", ") : null;
}

/** The exact persisted DB-IP City Lite source identifier (PR 25A). */
export const DBIP_CITY_LITE_SOURCE_ID = "urn:ati:source:dbip_city_lite";

/**
 * Map the exact known provider identifier to a translation key.
 *
 * Unknown provider identifiers return null and render as escaped raw text;
 * no generalized provider registry exists. Never invented values.
 */
export function providerLabelKey(provider: string): string | null {
  return provider === DBIP_CITY_LITE_SOURCE_ID ? "provider.known.dbip" : null;
}

/**
 * Map one generated `GeoPrecision` value to its neutral translation key.
 *
 * Only the exact generated vocabulary is mapped; anything else (defensive
 * runtime data) falls back to the unknown label. Never used for risk or
 * confidence presentation.
 */
export function geoPrecisionKey(precision: GeoPrecisionName): string {
  switch (precision) {
    case "city":
      return "precision.city";
    case "region":
      return "precision.region";
    case "country":
      return "precision.country";
    default:
      return "precision.unknown";
  }
}

/**
 * Derive the deterministic viewport for one mappable dataset.
 *
 * - zero points: no meaningful viewport (`none`, the caller renders the
 *   non-map/empty state);
 * - one point: the exact PR 25A coordinate at the conservative fixed zoom;
 * - multiple points: the bounds over every mappable returned coordinate
 *   with fixed padding and a zoom cap no greater than the single-point
 *   approximate zoom.
 */
export function mapViewport(mappable: readonly InvestigationGeolocation[]): MapViewport {
  const plottable: LatLngPair[] = [];
  for (const item of mappable) {
    if (isPlottableCoordinate(item.latitude, item.longitude)) {
      // The guard verified longitude is a number within the valid range.
      plottable.push([item.latitude, item.longitude as number]);
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