// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic viewport policy tests (PR 25B §46 B-V01..B-V07).

import { describe, expect, it } from "vitest";

import type { GeoPrecisionName, InvestigationGeolocation } from "../api/schema-types";
import {
  MAX_BOUNDS_ZOOM,
  mapViewport,
  SINGLE_POINT_ZOOM,
} from "./geolocation-map-model";

function item(
  index: number,
  latitude: number | null,
  longitude: number | null,
): InvestigationGeolocation {
  return {
    evidence_id: `40000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    entity_id: `50000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    ip_address: `203.0.113.${index}`,
    country_code: null,
    region: null,
    city: null,
    latitude,
    longitude,
    precision: "unknown" as GeoPrecisionName,
    provider: "urn:ati:source:dbip_city_lite",
    observed_at: null,
    retrieved_at: "2026-06-01T10:00:00Z",
  };
}

describe("viewport policy (B-V01..B-V07)", () => {
  it("B-V01: zero points produce no fit command", () => {
    expect(mapViewport([])).toEqual({ kind: "none" });
  });

  it("B-V02: one point centers exactly with the conservative zoom", () => {
    const viewport = mapViewport([item(1, 47.6062, -122.3321)]);
    expect(viewport).toEqual({
      kind: "single",
      center: [47.6062, -122.3321],
      zoom: SINGLE_POINT_ZOOM,
    });
  });

  it("B-V03: two points bound both coordinates", () => {
    const viewport = mapViewport([item(1, 10, -10), item(2, 20, 5)]);
    expect(viewport.kind).toBe("bounds");
    if (viewport.kind !== "bounds") {
      return;
    }
    expect(viewport.bounds[0][0]).toBe(10); // south
    expect(viewport.bounds[0][1]).toBe(-10); // west
    expect(viewport.bounds[1][0]).toBe(20); // north
    expect(viewport.bounds[1][1]).toBe(5); // east
  });

  it("B-V04: many points include every mappable returned point", () => {
    const points = [
      item(1, -33.8688, 151.2093), // Sydney
      item(2, 48.8566, 2.3522), // Paris
      item(3, 35.6762, 139.6503), // Tokyo
      item(4, 37.7749, -122.4194), // San Francisco
    ];
    const viewport = mapViewport(points);
    expect(viewport.kind).toBe("bounds");
    if (viewport.kind !== "bounds") {
      return;
    }
    const [[south, west], [north, east]] = viewport.bounds;
    for (const point of points) {
      expect(point.latitude).not.toBeNull();
      expect(point.longitude).not.toBeNull();
      expect(point.latitude!).toBeGreaterThanOrEqual(south);
      expect(point.latitude!).toBeLessThanOrEqual(north);
      expect(point.longitude!).toBeGreaterThanOrEqual(west);
      expect(point.longitude!).toBeLessThanOrEqual(east);
    }
  });

  it("B-V05: multi-point fit enforces the max zoom", () => {
    const viewport = mapViewport([item(1, 1, 1), item(2, 2, 2)]);
    expect(viewport.kind).toBe("bounds");
    if (viewport.kind !== "bounds") {
      return;
    }
    expect(viewport.maxZoom).toBe(MAX_BOUNDS_ZOOM);
    expect(viewport.maxZoom).toBeLessThanOrEqual(SINGLE_POINT_ZOOM);
  });

  it("B-V06: coordinate-less items are ignored for bounds", () => {
    const mappable = [item(1, 47.6062, -122.3321)];
    const mixed = [item(1, 47.6062, -122.3321), item(2, null, null)];
    const one = mapViewport(mixed);
    const only = mapViewport(mappable);
    expect(one).toEqual(only);
    expect(one).toEqual({
      kind: "single",
      center: [47.6062, -122.3321],
      zoom: SINGLE_POINT_ZOOM,
    });
  });

  it("B-V07: malformed defensive coordinates are ignored", () => {
    const withMalformed = [
      item(1, 47.6062, -122.3321),
      item(2, Number.NaN, 5),
      item(3, 1, Number.POSITIVE_INFINITY),
      item(4, 120, 5),
    ];
    const viewport = mapViewport(withMalformed);
    expect(viewport).toEqual({
      kind: "single",
      center: [47.6062, -122.3321],
      zoom: SINGLE_POINT_ZOOM,
    });
  });
});