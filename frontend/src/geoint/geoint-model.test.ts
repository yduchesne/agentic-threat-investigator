// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pure GEOINT presentation-model tests (PR 26E §15 M01..M08).

import { describe, expect, it } from "vitest";

import type {
  GeointLocation,
  LocationPrecisionName,
  LocationTypeName,
} from "../api/schema-types";
import { locationPrecisionKey, locationTypeKey } from "./geoint-labels";
import {
  buildLocationMapModel,
  geointViewport,
  hasInvestigationCurrent,
  isCurrentObservation,
  isLocationPrecision,
  isLocationType,
  isPlottable,
  locationCanonicalLabel,
  plottablePair,
  topLocationPopulation,
} from "./geoint-model";

function location(
  overrides: Partial<GeointLocation> = {},
): GeointLocation {
  return {
    location_id: "60000000-0000-4000-8000-000000000001",
    location_type: "city" as LocationTypeName,
    canonical_name: "Seattle",
    country_code: "US",
    admin1_code: "WA",
    admin2_code: null,
    parent_location_id: null,
    latitude: 47.6062,
    longitude: -122.3321,
    ...overrides,
  };
}

const CITY_ID = "60000000-0000-4000-8000-000000000001";

describe("defensive plottability (M01..M03, M08)", () => {
  it("M01: a valid centroid pair is plottable", () => {
    expect(isPlottable(47.6062, -122.3321)).toBe(true);
    expect(plottablePair(location())).toEqual([47.6062, -122.3321]);
  });

  it("M02: null coordinates are non-mappable but remain present", () => {
    const nullLocation = location({ latitude: null, longitude: null });
    expect(isPlottable(null, null)).toBe(false);
    expect(plottablePair(nullLocation)).toBeNull();
    const model = buildLocationMapModel([location(), nullLocation]);
    expect(model.mappableCount).toBe(1);
    expect(model.unmappableCount).toBe(1);
    expect(model.totalCount).toBe(2);
  });

  it("M03: malformed/out-of-range coordinates never reach Leaflet", () => {
    expect(isPlottable(NaN, -122)).toBe(false);
    expect(isPlottable(47, Infinity)).toBe(false);
    expect(isPlottable(91, 0)).toBe(false);
    expect(isPlottable(0, 181)).toBe(false);
    expect(isPlottable("47.6", -122)).toBe(false);
    expect(plottablePair(location({ latitude: 95, longitude: 0 }))).toBeNull();
    // No clamping or (0,0) recovery is ever performed.
    expect(plottablePair(location({ latitude: null, longitude: 0 }))).toBeNull();
  });

  it("M08: same coordinates retain distinct stable identities", () => {
    const a = location({ location_id: CITY_ID, canonical_name: "Seattle" });
    const b = location({
      location_id: "60000000-0000-4000-8000-000000000002",
      canonical_name: "Seattle-area node",
    });
    const model = buildLocationMapModel([a, b]);
    expect(model.mappable).toHaveLength(2);
    // The map component keys markers by the returned identity, never by the
    // coordinate pair; the model preserves order and identity.
    expect(model.mappable[0]).toBe(a);
    expect(model.mappable[1]).toBe(b);
  });
});

describe("viewport derivation (M06/U06-U07)", () => {
  it("no points -> no viewport", () => {
    expect(geointViewport([])).toEqual({ kind: "none" });
  });

  it("one point -> conservative fixed zoom", () => {
    const viewport = geointViewport([location()]);
    expect(viewport).toEqual({
      kind: "single",
      center: [47.6062, -122.3321],
      zoom: 8,
    });
  });

  it("multiple points -> bounded fit with capped zoom", () => {
    const dallas = location({
      location_id: "60000000-0000-4000-8000-000000000003",
      canonical_name: "Dallas",
      latitude: 32.78306,
      longitude: -96.80667,
    });
    const viewport = geointViewport([location(), dallas]);
    expect(viewport.kind).toBe("bounds");
    if (viewport.kind === "bounds") {
      expect(viewport.bounds[0][0]).toBe(32.78306);
      expect(viewport.bounds[1][1]).toBe(-96.80667);
      expect(viewport.maxZoom).toBe(8);
    }
  });

  it("malformed points never corrupt the bounds derivation", () => {
    const bad = location({ latitude: 999, longitude: 0 });
    const viewport = geointViewport([location(), bad]);
    expect(viewport.kind).toBe("single");
  });
});

describe("current/history semantics (M06, M07)", () => {
  it("M06: current is Investigation-relative, never global", () => {
    const current = { observation_id: "70000000-0000-4000-8000-000000000001" };
    const other = { observation_id: "70000000-0000-4000-8000-000000000002" };
    expect(isCurrentObservation(current, current)).toBe(true);
    expect(isCurrentObservation(other, current)).toBe(false);
    expect(
      hasInvestigationCurrent({
        current_observation: current as never,
      }),
    ).toBe(true);
    expect(
      hasInvestigationCurrent({
        current_observation: null,
      } as never),
    ).toBe(false);
  });

  it("M07: history makes no ended/continuous inference (labels only)", () => {
    // The pure model exposes only labels/classification; the view renders
    // a neutral note. There is no state that could encode "ended" or
    // "still present" beyond the current/else distinction.
    expect(isCurrentObservation(
      { observation_id: "x1" },
      { observation_id: "x2" },
    )).toBe(false);
  });
});

describe("canonical labels (M04, M05)", () => {
  it("M04: Location-type labels cover the exact PR 26D vocabulary", () => {
    expect(locationTypeKey("country" as LocationTypeName)).toBe("locationType.country");
    expect(locationTypeKey("administrative_area" as LocationTypeName)).toBe(
      "locationType.administrativeArea",
    );
    expect(locationTypeKey("city" as LocationTypeName)).toBe("locationType.city");
    expect(isLocationType("city")).toBe(true);
    expect(isLocationType("hotspot")).toBe(false);
  });

  it("M05: precision labels cover the exact PR 26D vocabulary", () => {
    expect(locationPrecisionKey("country" as LocationPrecisionName)).toBe(
      "precision.country",
    );
    expect(locationPrecisionKey("administrative_area" as LocationPrecisionName)).toBe(
      "precision.administrativeArea",
    );
    expect(locationPrecisionKey("city" as LocationPrecisionName)).toBe(
      "precision.city",
    );
    expect(isLocationPrecision("administrative_area")).toBe(true);
    expect(isLocationPrecision("street")).toBe(false);
  });

  it("canonical names are the analyst-facing label; blanks stay null", () => {
    expect(locationCanonicalLabel(location())).toBe("Seattle");
    expect(locationCanonicalLabel({ canonical_name: "" })).toBeNull();
  });

  it("population is an exact scoped count, never a label", () => {
    expect(topLocationPopulation({ scoped_entity_count: 3 })).toBe(3);
    expect(topLocationPopulation({ scoped_entity_count: 0 })).toBe(0);
  });
});