// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Single-pass HTML character-reference normalization for Final Report prose.
//
// The persisted Final Report is model-authored plain text. The Report Writer
// can legitimately emit HTML character references (for example `&amp;`,
// `&#39;`, `&quot;`) inside otherwise plain prose, and those strings are
// persisted verbatim. The canonical React renderer renders every report
// string as escaped React text, so an encoded reference would otherwise be
// shown literally (`C&amp;C` instead of `C&C`).
//
// This helper decodes exactly one layer of valid HTML character references
// to ordinary Unicode text. It never parses markup, never inserts DOM nodes,
// never recurses, and never interprets the result as HTML: the decoded value
// is still inserted through React's escaped-text boundary. It is scoped to
// report prose/presentation only; canonical identifiers, enum values, URNs,
// timestamps and generated anchors must never pass through it.

import { decodeHTMLStrict } from "entities";

/**
 * Decode exactly one layer of valid HTML character references in report prose.
 *
 * Uses a standards-compliant HTML5 character-reference decoder in strict
 * mode, so only references terminated with a semicolon are decoded and
 * ordinary text such as `AT&T` or an unterminated `&amp` is preserved
 * literally. A single call decodes one layer only: `&amp;lt;` becomes
 * `&lt;`, never `<`.
 */
export function decodeReportText(value: string): string {
  return decodeHTMLStrict(value);
}
