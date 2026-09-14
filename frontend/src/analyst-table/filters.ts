// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Filter codec primitives (PR 24C §6, §14).
//
// Every resource filter follows the same pipeline:
//
//   URL search parameters -> validated frontend filter model -> API params
//
// Unknown/invalid enum values are never sent as valid API values, empty
// values normalize to absent, dates serialize as ISO 8601 UTC, and
// ``selected`` never alters the list query identity. Filters are
// server-backed semantics: the browser never decodes cursors or performs
// client-side exhaustive filtering over one loaded page.

/** Canonical UUID shape used by v0.1 resource identity filters. */
export const UUID_PATTERN =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Whether one value has the canonical v0.1 UUID shape. */
export function isUuidValue(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Parse and validate one UUID search parameter.
 *
 * Returns the normalized lowercase value only when it is a well-formed
 * UUID; anything else normalizes to absence so invalid values are never
 * sent to the API.
 */
export function parseUuidParam(value: string | null | undefined): string | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  if (!isUuidValue(value)) {
    return undefined;
  }
  return value.toLowerCase();
}

/**
 * Parse and validate one enum search parameter against the exact backend
 * values. Unknown/future enum values normalize to absence rather than
 * being presented or sent as valid API values.
 */
export function parseEnumParam<T extends string>(
  value: string | null | undefined,
  allowed: readonly T[],
): T | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  if ((allowed as readonly string[]).includes(value)) {
    return value as T;
  }
  return undefined;
}

/** The ISO-8601 UTC timestamps this app serializes (seconds precision). */
export const ISO_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** Whether one value is an app-serialized UTC ISO-8601 timestamp. */
export function isIsoTimestamp(value: string): boolean {
  return ISO_TIMESTAMP_PATTERN.test(value);
}

/**
 * Parse and validate one timestamp search parameter.
 *
 * Only app-serialized UTC timestamps round-trip; invalid/foreign formats
 * normalize to absence (never sent to the API).
 */
export function parseTimestampParam(value: string | null | undefined): string | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  if (!isIsoTimestamp(value)) {
    return undefined;
  }
  return value;
}

/** Loose shape check for a ``datetime-local`` value. */
const LOCAL_DATETIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

/**
 * Convert one HTML ``datetime-local`` input value to a UTC ISO-8601
 * timestamp (PR 24C §14).
 *
 * The browser supplies a local wall-clock value; it is parsed as browser
 * local time and serialized to UTC seconds (matching the app ISO format).
 * Invalid/empty values normalize to absence.
 */
export function localDateTimeToIso(value: string): string | undefined {
  if (value === "" || !LOCAL_DATETIME_PATTERN.test(value)) {
    return undefined;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return undefined;
  }
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Convert one UTC ISO-8601 timestamp back to a ``datetime-local`` input
 * value in the browser local timezone (URL round-trip).
 */
export function isoToLocalDateTimeValue(iso: string | undefined): string {
  if (iso === undefined || iso === "") {
    return "";
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const pad = (n: number, width = 2): string => String(n).padStart(width, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

/**
 * Build API query params from a validated filter model.
 *
 * Only non-empty values are included; ``undefined`` values are omitted so
 * they never reach the backend as invalid input.
 */
export function buildApiQuery(
  values: Record<string, string | undefined>,
): URLSearchParams {
  const query = new URLSearchParams();
  let any = false;
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      query.set(key, value);
      any = true;
    }
  }
  return any ? query : query;
}

/**
 * Apply a committed filter model to URL search parameters.
 *
 * Returns a new parameter set where each owned key reflects the model
 * value (present when set, removed otherwise). All other parameters
 * (cursor, selected) are preserved untouched.
 */
export function applyFilterParams(
  params: URLSearchParams,
  ownedKeys: readonly string[],
  values: Record<string, string | undefined>,
): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const key of ownedKeys) {
    next.delete(key);
  }
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") {
      next.set(key, value);
    }
  }
  return next;
}