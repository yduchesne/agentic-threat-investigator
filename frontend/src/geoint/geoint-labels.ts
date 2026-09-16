// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT canonical translation-key mapping (PR 26E §3, §13).
//
// Maps the exact PR 26D vocabularies (LocationType, LocationPrecision) and
// the fixed resolution-method contract to neutral translation keys. Only
// the exact generated vocabulary is mapped; anything else falls back to an
// explicit "unknown" label. Never used for risk or confidence presentation.

import type {
  LocationPrecisionName,
  LocationTypeName,
} from "../api/schema-types";

/** Map one `LocationType` value to its neutral translation key. */
export function locationTypeKey(locationType: LocationTypeName): string {
  switch (locationType) {
    case "city":
      return "locationType.city";
    case "administrative_area":
      return "locationType.administrativeArea";
    case "country":
      return "locationType.country";
    default:
      return "locationType.unknown";
  }
}

/** Map one `LocationPrecision` value to its neutral translation key. */
export function locationPrecisionKey(precision: LocationPrecisionName): string {
  switch (precision) {
    case "city":
      return "precision.city";
    case "administrative_area":
      return "precision.administrativeArea";
    case "country":
      return "precision.country";
    default:
      return "precision.unknown";
  }
}

/** Map one Location type + precision value pair to a combined label key. */
export function locationTypeCombinedKey(locationType: LocationTypeName): string {
  return locationTypeKey(locationType);
}

/**
 * The fixed v0.1 canonical resolution method rendered as a human label.
 *
 * Only the exact persisted method identity is mapped; unknown identities
 * return null and the caller renders the raw bounded string verbatim
 * (never a fabricated provider/source).
 */
export function resolutionMethodKey(method: string): string | null {
  return method === "canonical_geography_v1"
    ? "resolutionMethod.canonicalGeography"
    : null;
}