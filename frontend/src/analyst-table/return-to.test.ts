// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Transient internal route-origin validation tests (PR 35-1 Part 3).

import { describe, expect, it } from "vitest";

import { validatedReturnTo } from "./return-to";

describe("validatedReturnTo", () => {
  it("accepts a bounded internal Investigation path with query and hash", () => {
    expect(
      validatedReturnTo(
        "/investigations/20000000-0000-4000-8000-000000000001/evidence?source=rdap#top",
      ),
    ).toBe(
      "/investigations/20000000-0000-4000-8000-000000000001/evidence?source=rdap#top",
    );
    expect(validatedReturnTo("/investigations")).toBe("/investigations");
  });

  it("rejects absent and non-string values", () => {
    expect(validatedReturnTo(undefined)).toBeNull();
    expect(validatedReturnTo(null)).toBeNull();
    expect(validatedReturnTo("")).toBeNull();
    expect(validatedReturnTo("   ")).toBeNull();
    expect(validatedReturnTo(42)).toBeNull();
  });

  it("rejects external and protocol-relative URLs", () => {
    expect(validatedReturnTo("https://evil.example/steal")).toBeNull();
    expect(validatedReturnTo("//evil.example/steal")).toBeNull();
    expect(validatedReturnTo("javascript:alert(1)")).toBeNull();
    expect(validatedReturnTo("/etc/passwd")).toBeNull();
  });

  it("rejects control characters and backslashes", () => {
    expect(validatedReturnTo("/investigations/x\\..\\y")).toBeNull();
    expect(validatedReturnTo("/investigations/\u0000x")).toBeNull();
  });
});
