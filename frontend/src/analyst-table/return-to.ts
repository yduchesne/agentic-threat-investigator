// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Transient internal route-origin validation (PR 35-1 Part 3).
//
// Contextual ``< Back`` navigation carries the exact origin route as
// transient React Router location state (``returnTo``) rather than in the
// canonical URL. Only a bounded ATI-internal Investigation path is ever
// accepted: absolute external URLs, protocol-relative URLs, control
// characters, and backslashes are rejected so state can never drive
// arbitrary navigation. Invalid/absent values hide the Back control.

/** The only internal authenticated surface ATI navigation originates from. */
const INTERNAL_PREFIX = "/investigations";

/**
 * Return one validated ATI-internal origin path (pathname+search+hash), or
 * ``null`` when the candidate is absent, external, or malformed.
 */
export function validatedReturnTo(candidate: unknown): string | null {
  if (typeof candidate !== "string") {
    return null;
  }
  const trimmed = candidate.trim();
  if (!trimmed.startsWith(INTERNAL_PREFIX)) {
    return null;
  }
  if (trimmed.startsWith("//") || /[\u0000-\u001f\u007f\\]/.test(trimmed)) {
    return null;
  }
  const rest = trimmed.slice(INTERNAL_PREFIX.length);
  if (rest !== "" && !rest.startsWith("/")) {
    return null;
  }
  return trimmed;
}
