// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Narrow double-submit CSRF cookie parsing (PR 24A).
//
// The HttpOnly `ati_session` cookie is never readable from JavaScript and
// this utility never attempts to access it. Only the non-HttpOnly
// `ati_csrf` cookie is read, using exact cookie-name matching and safe
// percent-decoding.

/** The double-submit CSRF cookie name delivered by PR 23C. */
export const CSRF_COOKIE_NAME = "ati_csrf";

/** The HttpOnly session cookie name; never readable by frontend code. */
export const SESSION_COOKIE_NAME = "ati_session";

/** The CSRF request header name delivered by PR 23C. */
export const CSRF_HEADER_NAME = "X-CSRF-Token";

/**
 * Read one cookie value by exact name, safely.
 *
 * Returns `null` when absent, blank, or when percent-decoding fails. The
 * cookie jar is treated as an untrusted string and never rendered.
 */
export function readCookie(name: string): string | null {
  if (name === SESSION_COOKIE_NAME) {
    // Structural guarantee: the HttpOnly session cookie is never read by
    // frontend code, even in test environments that do not enforce the
    // HttpOnly flag.
    return null;
  }
  if (typeof document === "undefined") {
    return null;
  }
  const jar = document.cookie;
  if (!jar) {
    return null;
  }
  for (const part of jar.split(";")) {
    const entry = part.trim();
    if (entry.length === 0) {
      continue;
    }
    const separator = entry.indexOf("=");
    if (separator < 0) {
      continue;
    }
    if (entry.slice(0, separator).trim() !== name) {
      continue;
    }
    const value = entry.slice(separator + 1).trim();
    if (value.length === 0) {
      return null;
    }
    try {
      return decodeURIComponent(value);
    } catch {
      // Malformed encoding is treated as an absent cookie value.
      return null;
    }
  }
  return null;
}

/** Read the `ati_csrf` double-submit CSRF token, or `null` when absent. */
export function readCsrfToken(): string | null {
  return readCookie(CSRF_COOKIE_NAME);
}