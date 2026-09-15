// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Location-label formatter tests (PR 25B §45 B-L01..B-L05).

import { describe, expect, it } from "vitest";

import { locationLabel } from "./geolocation-map-model";

describe("location label formatter (B-L01..B-L05)", () => {
  it("B-L01: city + region + country join in order", () => {
    expect(
      locationLabel({ city: "Seattle", region: "Washington", country_code: "US" }),
    ).toBe("Seattle, Washington, US");
  });

  it("B-L02: region + country without punctuation artifacts", () => {
    expect(locationLabel({ city: null, region: "Washington", country_code: "US" })).toBe(
      "Washington, US",
    );
  });

  it("B-L03: country only", () => {
    expect(
      locationLabel({ city: null, region: null, country_code: "US" }),
    ).toBe("US");
  });

  it("B-L04: no geographic label yields an explicit unavailable signal", () => {
    expect(locationLabel({ city: null, region: null, country_code: null })).toBeNull();
    expect(locationLabel({ city: "", region: "", country_code: "" })).toBeNull();
    expect(locationLabel({})).toBeNull();
  });

  it("B-L05: external strings remain plain text, never interpreted", () => {
    expect(
      locationLabel({
        city: "<b>Evil</b>",
        region: "Washington",
        country_code: "US",
      }),
    ).toBe("<b>Evil</b>, Washington, US");
  });

  it("blank parts are omitted cleanly", () => {
    expect(
      locationLabel({ city: "", region: null, country_code: "DE" }),
    ).toBe("DE");
  });
});