// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Opaque-cursor navigation helpers (PR 24C §6).
//
// Cursors are opaque strings: the frontend never decodes, compares, or
// performs arithmetic on them. This module owns only the browser-local
// Previous/Next bookkeeping:
//
//   - ``pushNextStack`` records the current page behind the next one;
//   - ``popBackStack`` restores the prior cursor when Previous is pressed;
//   - a filter change always resets the back stack and cursor.
//
// A page loaded from a direct URL cursor may only return to the first page
// (reload need not reconstruct the prior backward stack; PR 24C §6). The
// first page is represented by ``undefined``/``""`` — never a decoded
// value.

/** Sentinel entry representing the first page inside the back stack. */
export const FIRST_PAGE_MARKER = "";

/** Parse the opaque URL cursor parameter; empty values mean first page. */
export function parseCursorParam(value: string | null | undefined): string | undefined {
  if (value === null || value === undefined || value === "") {
    return undefined;
  }
  return value;
}

/**
 * Build the initial back stack for a page load.
 *
 * A direct URL cursor may load, but the browser only allows Previous back
 * to the first page (`[""]`); a first-page load starts with no history.
 */
export function initialBackStack(urlCursor: string | undefined): string[] {
  return urlCursor === undefined ? [] : [FIRST_PAGE_MARKER];
}

/**
 * Record the current page cursor before advancing to ``nextCursor``.
 *
 * Returns the new stack; the current page is appended with the first page
 * normalized to the empty-string marker.
 */
export function pushNextStack(
  backStack: readonly string[],
  current: string | undefined,
): string[] {
  return [...backStack, current ?? FIRST_PAGE_MARKER];
}

/**
 * Restore the prior cursor from the back stack.
 *
 * Returns the new stack and the previous cursor (``undefined`` for the
 * first page, which serializes to no cursor parameter). An empty stack is
 * returned unchanged — Previous must be disabled in that state.
 */
export function popBackStack(
  backStack: readonly string[],
): { stack: string[]; prior: string | undefined } {
  if (backStack.length === 0) {
    return { stack: [...backStack], prior: undefined };
  }
  const stack = [...backStack];
  const entry = stack.pop() ?? FIRST_PAGE_MARKER;
  return { stack, prior: entry === FIRST_PAGE_MARKER ? undefined : entry };
}

/** Previous is enabled only while the browser-local back stack is non-empty. */
export function hasPrevious(backStack: readonly string[]): boolean {
  return backStack.length > 0;
}

/** Normalize one cursor to its URL parameter value (or absence). */
export function cursorParam(cursor: string | undefined): string {
  return cursor === undefined ? "" : cursor;
}