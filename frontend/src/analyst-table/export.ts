// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded current-page CSV export (PR 24C §13).
//
// Export is explicitly the page already loaded in the browser — never an
// "Export all" over recursive cursor fetching. Cells are RFC 4180 quoted
// (commas, quotes, CR/LF), spreadsheet formula-injection prefixes are
// neutralized, output is UTF-8, and filenames never contain analyst
// objective or IOC text.

/** Dangerous spreadsheet formula prefixes (OWASP CSV injection guidance). */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * Neutralize spreadsheet formula injection for one cell.
 *
 * A single leading apostrophe is the safe, widely supported mitigation and
 * keeps the visible value intact. UUIDs, timestamps, and enum labels in
 * this application never start with these prefixes; the guard exists for
 * untrusted provider/analyst text.
 */
export function sanitizeCsvValue(value: string): string {
  return FORMULA_PREFIX.test(value) ? `'${value}` : value;
}

/**
 * Encode one cell for an RFC 4180 CSV row.
 *
 * Sanitization happens first, then commas/quotes/CR/LF force quoting with
 * doubled quote characters.
 */
export function csvCell(value: string): string {
  const sanitized = sanitizeCsvValue(value);
  if (/[",\r\n]/.test(sanitized)) {
    return `"${sanitized.replace(/"/g, '""')}"`;
  }
  return sanitized;
}

/** Build a complete CSV document (CRLF line endings, no trailing newline). */
export function buildCsv(
  header: readonly string[],
  rows: readonly (readonly string[])[],
): string {
  const lines = [header, ...rows].map((cells) => cells.map(csvCell).join(","));
  return lines.join("\r\n");
}

/**
 * Build a safe export filename.
 *
 * ``kind`` is one of the fixed analyst resource names (never user text);
 * the short investigation id is a URL-safe UUID prefix; the stamp is a UTC
 * timestamp. No objective or IOC text ever enters filenames.
 */
export function exportFilename(
  kind: string,
  investigationId: string,
  now: Date = new Date(),
): string {
  const stamp = now.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:TZ]/g, "");
  return `ati-${investigationId.slice(0, 8)}-${kind}-${stamp}.csv`;
}

/**
 * Start a browser download of one UTF-8 CSV document.
 *
 * The object URL is revoked after the click; environments without
 * ``URL.createObjectURL`` (unit tests) yield the document content for
 * assertions instead of failing.
 */
export function downloadCsv(filename: string, content: string): void {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  if (typeof URL.createObjectURL !== "function") {
    return;
  }
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}