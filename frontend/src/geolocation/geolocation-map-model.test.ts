// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pure geolocation map-model tests (PR 25B §44 B-M01..B-M10).

import { describe, expect, it } from "vitest";

import type { GeoPrecisionName, InvestigationGeolocation } from "../api/schema-types";
import { buildGeolocationMapModel } from "./geolocation-map-model";

const EVIDENCE_BASE = "40000000-0000-4000-8000-0000000000";

/** One deterministic PR 25A-shaped item. */
function item(
  ordinal: number,
  overrides: Partial<InvestigationGeolocation> = {},
): InvestigationGeolocation {
  return {
    evidence_id: `${EVIDENCE_BASE}${String(ordinal).padStart(2, "0")}`,
    entity_id: `50000000-0000-4000-8000-0000000000${String(ordinal).padStart(2, "0")}`,
    ip_address: `203.0.113.${ordinal}`,
    country_code: "US",
    region: "Washington",
    city: "Seattle",
    latitude: 47.6062,
    longitude: -122.3321,
    precision: "city" as GeoPrecisionName,
    provider: "urn:ati:source:dbip_city_lite",
    observed_at: null,
    retrieved_at: "2026-06-01T10:00:00Z",
    ...overrides,
  };
}

describe("geolocation map model (B-M01..B-M10)", () => {
  it("B-M01: empty collection yields zero groups and counts", () => {
    const model = buildGeolocationMapModel([], false);
    expect(model.mappable).toEqual([]);
    expect(model.unlocated).toEqual([]);
    expect(model.totalCount).toBe(0);
    expect(model.mappableCount).toBe(0);
    expect(model.unlocatedCount).toBe(0);
    expect(model.truncated).toBe(false);
  });

  it("B-M02: valid paired coordinates are mappable", () => {
    const a = item(1);
    const model = buildGeolocationMapModel([a], false);
    expect(model.mappable).toEqual([a]);
    expect(model.unlocated).toEqual([]);
    expect(model.mappableCount).toBe(1);
    expect(model.unlocatedCount).toBe(0);
  });

  it("B-M03: null/null context is unlocated but retained", () => {
    const a = item(1, { latitude: null, longitude: null });
    const model = buildGeolocationMapModel([a], false);
    expect(model.mappable).toEqual([]);
    expect(model.unlocated).toEqual([a]);
    expect(model.totalCount).toBe(1);
  });

  it("B-M04: mixed items partition into both groups", () => {
    const a = item(1);
    const b = item(2, { latitude: null, longitude: null });
    const c = item(3, { latitude: 51.5074, longitude: -0.1278 });
    const model = buildGeolocationMapModel([a, b, c], false);
    expect(model.mappable).toEqual([a, c]);
    expect(model.unlocated).toEqual([b]);
    expect(model.totalCount).toBe(3);
    expect(model.mappableCount).toBe(2);
    expect(model.unlocatedCount).toBe(1);
  });

  it("B-M05: relative server order is preserved inside each group", () => {
    const a = item(1, { latitude: null, longitude: null });
    const b = item(2, { latitude: 1.0, longitude: 2.0 });
    const c = item(3, { latitude: null, longitude: null });
    const d = item(4, { latitude: 3.0, longitude: 4.0 });
    const model = buildGeolocationMapModel([a, b, c, d], false);
    expect(model.mappable.map((x) => x.ip_address)).toEqual([
      "203.0.113.2",
      "203.0.113.4",
    ]);
    expect(model.unlocated.map((x) => x.ip_address)).toEqual([
      "203.0.113.1",
      "203.0.113.3",
    ]);
  });

  it("B-M06: truncation propagates exactly", () => {
    const model = buildGeolocationMapModel([item(1)], true);
    expect(model.truncated).toBe(true);
    const untruncated = buildGeolocationMapModel([item(1)], false);
    expect(untruncated.truncated).toBe(false);
  });

  it("B-M07: a partial coordinate pair is never plotted", () => {
    const partial = item(1, { latitude: 47.6062, longitude: null });
    const model = buildGeolocationMapModel([partial], false);
    expect(model.mappable).toEqual([]);
    expect(model.unlocated).toEqual([partial]);
  });

  it("B-M08: NaN and infinity are never plotted", () => {
    const nan = item(1, { latitude: Number.NaN, longitude: -122.3321 });
    const inf = item(2, { latitude: Number.POSITIVE_INFINITY, longitude: -122.3321 });
    const negInf = item(3, { latitude: 47.6062, longitude: Number.NEGATIVE_INFINITY });
    const model = buildGeolocationMapModel([nan, inf, negInf], false);
    expect(model.mappable).toEqual([]);
    expect(model.unlocated).toEqual([nan, inf, negInf]);
  });

  it("B-M09: out-of-range coordinates are never plotted", () => {
    const latHigh = item(1, { latitude: 90.5, longitude: 0 });
    const latLow = item(2, { latitude: -90.5, longitude: 0 });
    const lngHigh = item(3, { latitude: 0, longitude: 180.5 });
    const lngLow = item(4, { latitude: 0, longitude: -180.5 });
    const model = buildGeolocationMapModel([latHigh, latLow, lngHigh, lngLow], false);
    expect(model.mappable).toEqual([]);
    expect(model.unlocated).toHaveLength(4);
    // Exact boundary values remain plottable (inclusive ranges).
    const boundary = item(5, { latitude: 90, longitude: 180 });
    const atEdge = buildGeolocationMapModel([boundary], false);
    expect(atEdge.mappable).toEqual([boundary]);
  });

  it("B-M10: input transport objects are never mutated", () => {
    const a = item(1);
    const b = item(2, { latitude: null, longitude: null });
    const before = [JSON.stringify(a), JSON.stringify(b)];
    buildGeolocationMapModel([a, b], true);
    expect([JSON.stringify(a), JSON.stringify(b)]).toEqual(before);
  });
});