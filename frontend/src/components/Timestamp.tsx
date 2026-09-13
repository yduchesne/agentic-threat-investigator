// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One frontend date/time formatter (PR 24B §30).
//
// ISO values are parsed and rendered in the browser local timezone with a
// fixed presentation locale so tests stay deterministic where needed; the
// exact ISO value is exposed in the title attribute for copy/verification.
// No ambiguous timezone-less timestamps are ever shown.

import type { ReactElement } from "react";

/** Fixed v0.1 presentation locale for formatted timestamps. */
export const PRESENTATION_LOCALE = "en-US";

const FORMATTER = new Intl.DateTimeFormat(PRESENTATION_LOCALE, {
  dateStyle: "medium",
  timeStyle: "short",
});

/** Format one ISO-8601 timestamp in the browser local timezone. */
export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : FORMATTER.format(date);
}

export interface TimestampProps {
  /** ISO-8601 timestamp from the API. */
  iso: string;
  /** Optional accessible label prefix (e.g. "Started"). */
  label?: string;
}

/** Render one timestamp in local time with the exact ISO in the title. */
export function Timestamp({ iso, label }: TimestampProps): ReactElement {
  return (
    <time dateTime={iso} title={iso}>
      {label !== undefined ? `${label} ` : ""}
      {formatDateTime(iso)}
    </time>
  );
}