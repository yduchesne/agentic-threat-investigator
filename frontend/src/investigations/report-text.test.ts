// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Report text normalization tests (PR 38-10 R-E01..R-E07).
//
// One standards-compliant, single-pass HTML character-reference decode for
// report prose. The helper never parses markup, never recurses, and never
// introduces executable DOM: encoded markup stays ordinary text for React to
// escape at the render boundary.

import { describe, expect, it } from "vitest";

import { decodeReportText } from "./report-text";

describe("decodeReportText (PR 38-10)", () => {
  it("R-E01: decodes an escaped ampersand", () => {
    expect(decodeReportText("C&amp;C")).toBe("C&C");
  });

  it("R-E02: decodes numeric and named references together", () => {
    expect(decodeReportText("&#39;C&amp;C server&#39;")).toBe("'C&C server'");
  });

  it("R-E03: decodes escaped quotes", () => {
    expect(decodeReportText("&quot;x&quot;")).toBe('"x"');
  });

  it("R-E04: decodes encoded markup to plain text only", () => {
    expect(decodeReportText("&lt;script&gt;alert(1)&lt;/script&gt;")).toBe(
      "<script>alert(1)</script>",
    );
  });

  it("R-E05: decodes exactly one layer (never recursive)", () => {
    expect(decodeReportText("&amp;lt;script&amp;gt;")).toBe("&lt;script&gt;");
  });

  it("R-E06: leaves ordinary Unicode/plain text unchanged", () => {
    expect(decodeReportText("Café — 日本語 & AT&T")).toBe("Café — 日本語 & AT&T");
  });

  it("R-E07: leaves malformed/unknown references literal", () => {
    expect(decodeReportText("&unknown; and &amp no semicolon")).toBe(
      "&unknown; and &amp no semicolon",
    );
  });
});
