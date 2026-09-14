// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded CSV export tests (PR 24C T15, T16, T14, T16b).
//
// Export is explicitly the current page: quoting follows RFC 4180,
// spreadsheet formula injection is neutralized, and filenames never carry
// objective/IOC text.

import { describe, expect, it } from "vitest";

import { buildCsv, csvCell, exportFilename, sanitizeCsvValue } from "./export";

describe("current-page CSV export", () => {
  it("quotes commas, quotes and newlines (T15)", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("comma,value")).toBe('"comma,value"');
    expect(csvCell("carriage\rreturn")).toBe('"carriage\rreturn"');
  });

  it("neutralizes spreadsheet formula prefixes (T16)", () => {
    expect(sanitizeCsvValue("=SUM(A1)")).toBe("'=SUM(A1)");
    expect(sanitizeCsvValue("+cmd")).toBe("'+cmd");
    expect(sanitizeCsvValue("-1")).toBe("'-1");
    expect(sanitizeCsvValue("@cell")).toBe("'@cell");
    expect(sanitizeCsvValue("plain")).toBe("plain");
    expect(csvCell("=HYPERLINK(x)")).toBe("'=HYPERLINK(x)");
  });

  it("builds complete documents with CRLF rows (T15b)", () => {
    const csv = buildCsv(["a", "b"], [["1", "x,y"], ["2", 'say "hi"']]);
    expect(csv).toBe('a,b\r\n1,"x,y"\r\n2,"say ""hi"""');
  });

  it("builds filenames from fixed kinds and a safe short id (T16b)", () => {
    const now = new Date("2026-06-01T10:00:00Z");
    const name = exportFilename("evidence", "40000000-0000-4000-8000-000000000001", now);
    expect(name).toBe("ati-40000000-evidence-20260601100000.csv");
    expect(name).not.toContain("update-package");
  });
});