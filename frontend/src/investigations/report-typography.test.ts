// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Final Report typography contract tests (PR 35-7 U07..U15).
//
// The report owns a readable scale distinct from the compact workbench scale.
// These assertions pin the contract (size, weight, monotonic progression)
// instead of brittle screenshots.

import { describe, expect, it } from "vitest";

import {
  REPORT_HEADING_ORDER,
  REPORT_TYPOGRAPHY,
  type ReportTypographyRole,
} from "./report-typography";

/** The ATI root font size. */
const ROOT_FONT_PX = 16;

/** Convert one contract `rem` size to its pixel equivalent. */
function remToPx(role: ReportTypographyRole): number {
  expect(role.fontSize.endsWith("rem")).toBe(true);
  return Number.parseFloat(role.fontSize) * ROOT_FONT_PX;
}

describe("Final Report typography contract (PR 35-7)", () => {
  it("U07: support text is 14px (~10.5pt)", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.support)).toBe(14);
  });

  it("U08: criticality/confidence metadata is 14px (~10.5pt)", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.metadata)).toBe(14);
  });

  it("U09: finding description / report body is 16px (12pt)", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.body)).toBe(16);
  });

  it("U10: h5 is 16px", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.h5)).toBe(16);
  });

  it("U11: h4 is 18px", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.h4)).toBe(18);
  });

  it("U12: h3 is 20px", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.h3)).toBe(20);
  });

  it("U13: h2 is 24px", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.h2)).toBe(24);
  });

  it("U14: h1 is 28px", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.h1)).toBe(28);
  });

  it("U15: the heading scale increases monotonically above readable support text", () => {
    const sizes = REPORT_HEADING_ORDER.map((role) =>
      remToPx(REPORT_TYPOGRAPHY[role]),
    );
    for (let index = 1; index < sizes.length; index += 1) {
      expect(
        sizes[index],
        `${REPORT_HEADING_ORDER[index]} must be larger than ${
          REPORT_HEADING_ORDER[index - 1]
        }`,
      ).toBeGreaterThan(sizes[index - 1]);
    }
    expect(sizes[0]).toBeGreaterThan(remToPx(REPORT_TYPOGRAPHY.support));
  });

  it("gives headings weight 600 and body roles weight 400", () => {
    for (const role of REPORT_HEADING_ORDER) {
      expect(REPORT_TYPOGRAPHY[role].fontWeight).toBe(600);
    }
    for (const role of ["support", "metadata", "body"] as const) {
      expect(REPORT_TYPOGRAPHY[role].fontWeight).toBe(400);
    }
  });

  it("keeps finding prose as readable as the h5 heading it sits under", () => {
    expect(remToPx(REPORT_TYPOGRAPHY.body)).toBeGreaterThanOrEqual(
      remToPx(REPORT_TYPOGRAPHY.h5),
    );
  });
});
