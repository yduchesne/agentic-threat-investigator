// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared cursor/selection URL parameter helpers (PR 24C §1, §6).
//
// Both the opaque cursor and the URL-addressable ``selected=<uuid>`` live
// in URL search parameters. ``selected`` never alters list query identity.

/** The URL parameter carrying the URL-addressable detail selection. */
export const SELECTED_PARAM = "selected";

/** The URL parameter carrying the opaque cursor. */
export const CURSOR_PARAM = "cursor";

/** Return a new parameter set with the cursor set/cleared (never decoded). */
export function setCursorParam(
  params: URLSearchParams,
  cursor: string | undefined,
): URLSearchParams {
  const next = new URLSearchParams(params);
  if (cursor === undefined || cursor === "") {
    next.delete(CURSOR_PARAM);
  } else {
    next.set(CURSOR_PARAM, cursor);
  }
  return next;
}

/** Return a new parameter set with ``selected`` set to one resource id. */
export function setSelectedParam(
  params: URLSearchParams,
  id: string,
): URLSearchParams {
  const next = new URLSearchParams(params);
  next.set(SELECTED_PARAM, id);
  return next;
}

/** Return a new parameter set with ``selected`` removed. */
export function clearSelectedParam(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete(SELECTED_PARAM);
  return next;
}

/** Read and validate the URL-addressable selection (UUID shape only). */
export function parseSelectedParam(
  params: URLSearchParams,
  isUuid: (value: string) => boolean,
): string | null {
  const value = params.get(SELECTED_PARAM);
  if (value === null || value === "") {
    return null;
  }
  return isUuid(value) ? value.toLowerCase() : null;
}