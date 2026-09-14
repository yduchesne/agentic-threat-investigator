// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Filter codec primitives tests (PR 24C §6).
//
// Invalid/unknown enum and UUID values normalize to absence, empty values
// are never sent, and date conversions preserve UTC ISO round-trips.

import { describe, expect, it } from "vitest";

import {
  applyFilterParams,
  buildApiQuery,
  isIsoTimestamp,
  isUuidValue,
  isoToLocalDateTimeValue,
  localDateTimeToIso,
  parseEnumParam,
  parseTimestampParam,
  parseUuidParam,
} from "./filters";

describe("filter codec primitives", () => {
  it("validates UUID values and normalizes case", () => {
    const uuid = "40000000-0000-4000-8000-000000000001";
    expect(isUuidValue(uuid)).toBe(true);
    expect(isUuidValue("not-a-uuid")).toBe(false);
    expect(parseUuidParam(uuid.toUpperCase())).toBe(uuid);
    expect(parseUuidParam("garbage")).toBeUndefined();
    expect(parseUuidParam("")).toBeUndefined();
    expect(parseUuidParam(null)).toBeUndefined();
  });

  it("rejects unknown enum values instead of sending them", () => {
    const allowed = ["a", "b"] as const;
    expect(parseEnumParam("a", allowed)).toBe("a");
    expect(parseEnumParam("z", allowed)).toBeUndefined();
    expect(parseEnumParam("", allowed)).toBeUndefined();
  });

  it("accepts only app-serialized UTC ISO timestamps", () => {
    expect(isIsoTimestamp("2026-06-01T10:00:00Z")).toBe(true);
    expect(isIsoTimestamp("2026-06-01T10:00:00.000Z")).toBe(false);
    expect(isIsoTimestamp("2026-06-01")).toBe(false);
    expect(parseTimestampParam("2026-06-01T10:00:00Z")).toBe("2026-06-01T10:00:00Z");
    expect(parseTimestampParam("2026-06-01")).toBeUndefined();
  });

  it("converts local datetime values to UTC ISO with seconds precision", () => {
    const iso = localDateTimeToIso("2026-06-01T10:00");
    expect(iso).not.toBeUndefined();
    expect(iso).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(parseTimestampParam(iso)).toBe(iso);
  });

  it("converts UTC ISO back to a local datetime-local value", () => {
    const value = isoToLocalDateTimeValue("2026-06-01T10:00:00Z");
    expect(value).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    expect(isoToLocalDateTimeValue(undefined)).toBe("");
    expect(isoToLocalDateTimeValue("garbage")).toBe("");
  });

  it("builds API params only from non-empty values", () => {
    const query = buildApiQuery({ a: "x", b: undefined, c: "" });
    expect(query.get("a")).toBe("x");
    expect(query.get("b")).toBeNull();
    expect(query.get("c")).toBeNull();
  });

  it("applies committed filters over an existing URL, preserving others", () => {
    const params = new URLSearchParams("cursor=c1&selected=abc");
    const next = applyFilterParams(params, ["source", "type"], {
      source: "fake-dns",
      type: undefined,
    });
    expect(next.get("source")).toBe("fake-dns");
    expect(next.get("type")).toBeNull();
    expect(next.get("cursor")).toBe("c1");
    expect(next.get("selected")).toBe("abc");
  });
});