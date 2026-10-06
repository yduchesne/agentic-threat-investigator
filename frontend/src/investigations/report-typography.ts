// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Final Report typography contract (PR 35-7).
//
// The Final Report is long-form analyst output, so it needs a readable scale
// that is deliberately larger and more spacious than the compact ATI
// workbench scale. This module is the single owner of that scale: report
// surfaces consume it instead of scattering literal ``fontSize`` values or
// inheriting MUI's default heading sizes.
//
// The lower bound is readable support text (14px / ~10.5pt). Headings then
// increase monotonically through h5 (16px), h4 (18px), h3 (20px), h2 (24px),
// and the report title h1 (28px). No report child heading is ever as large
// as its parent. Primary finding prose intentionally shares the h5 size:
// h5 gains hierarchy through weight and spacing, while the prose stays
// readable instead of shrinking below its heading.

/** One role in the Final Report typography scale. */
export interface ReportTypographyRole {
  /** CSS font-size (rem). ``1rem`` is the ATI root ``16px``. */
  readonly fontSize: string;
  /** Unitless line height. */
  readonly lineHeight: number;
  /** Font weight: 600 for headings, 400 for body/support/metadata. */
  readonly fontWeight: number;
}

/** Every typography role the Final Report renders. */
export type ReportTypographyRoleName =
  | "support"
  | "metadata"
  | "body"
  | "h5"
  | "h4"
  | "h3"
  | "h2"
  | "h1";

/**
 * The canonical Final Report typography scale.
 *
 * Sizes are rem with the pixel equivalent at the ATI ``16px`` root:
 * support/metadata ``0.875rem`` (14px / ~10.5pt), body/h5 ``1rem``
 * (16px / 12pt), h4 ``1.125rem`` (18px), h3 ``1.25rem`` (20px),
 * h2 ``1.5rem`` (24px), and h1 ``1.75rem`` (28px).
 */
export const REPORT_TYPOGRAPHY: Readonly<
  Record<ReportTypographyRoleName, ReportTypographyRole>
> = {
  support: { fontSize: "0.875rem", lineHeight: 1.45, fontWeight: 400 },
  metadata: { fontSize: "0.875rem", lineHeight: 1.45, fontWeight: 400 },
  body: { fontSize: "1rem", lineHeight: 1.5, fontWeight: 400 },
  h5: { fontSize: "1rem", lineHeight: 1.4, fontWeight: 600 },
  h4: { fontSize: "1.125rem", lineHeight: 1.4, fontWeight: 600 },
  h3: { fontSize: "1.25rem", lineHeight: 1.35, fontWeight: 600 },
  h2: { fontSize: "1.5rem", lineHeight: 1.3, fontWeight: 600 },
  h1: { fontSize: "1.75rem", lineHeight: 1.25, fontWeight: 600 },
};

/**
 * The report heading roles ordered from the smallest child heading (h5) to
 * the report title (h1). Used by the contract tests to assert the visual
 * scale increases monotonically.
 */
export const REPORT_HEADING_ORDER: readonly ReportTypographyRoleName[] = [
  "h5",
  "h4",
  "h3",
  "h2",
  "h1",
];
