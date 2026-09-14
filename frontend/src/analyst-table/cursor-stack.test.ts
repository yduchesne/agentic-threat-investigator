// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Opaque-cursor navigation tests (PR 24C T03, T05, T06, T07, T08).
//
// Cursors are opaque: the tests only ever move bytes around, never decode
// or compare them.

import { describe, expect, it } from "vitest";

import {
  FIRST_PAGE_MARKER,
  hasPrevious,
  initialBackStack,
  parseCursorParam,
  popBackStack,
  pushNextStack,
} from "./cursor-stack";

describe("opaque cursor navigation", () => {
  it("passes the next cursor unchanged into the back stack (T03/T04)", () => {
    const stack = pushNextStack([], undefined);
    expect(stack).toEqual([FIRST_PAGE_MARKER]);
    const next = pushNextStack(stack, "cursor-BYTE-1");
    expect(next).toEqual([FIRST_PAGE_MARKER, "cursor-BYTE-1"]);
    // The exact bytes are preserved; nothing is decoded.
    expect(next[1]).toBe("cursor-BYTE-1");
  });

  it("restores the prior cursor on Previous without decoding (T05)", () => {
    // Back stack model: it holds the pages BEFORE the current one.
    let backStack: readonly string[] = [];
    // First page -> Next (cursor-1): record the first page behind it.
    backStack = pushNextStack(backStack, undefined);
    expect(backStack).toEqual([FIRST_PAGE_MARKER]);
    // cursor-1 -> Next (cursor-2): record cursor-1 behind it.
    backStack = pushNextStack(backStack, "cursor-1");
    expect(backStack).toEqual([FIRST_PAGE_MARKER, "cursor-1"]);
    expect(hasPrevious(backStack)).toBe(true);
    // Previous restores cursor-1, then the first page.
    const first = popBackStack(backStack);
    expect(first.prior).toBe("cursor-1");
    const second = popBackStack(first.stack);
    expect(second.prior).toBe(undefined); // back to the first page
    expect(hasPrevious(second.stack)).toBe(false);
  });

  it("resets cursor/back stack for a filter change (T06)", () => {
    const stack = initialBackStack("cursor-1");
    expect(stack).toEqual([FIRST_PAGE_MARKER]);
    // A filter change starts from a clean first-page state.
    expect(initialBackStack(undefined)).toEqual([]);
  });

  it("loads a direct URL cursor but only allows Previous to the first page (T07)", () => {
    const stack = initialBackStack(parseCursorParam("cursor-1"));
    expect(stack).toEqual([FIRST_PAGE_MARKER]);
    const back = popBackStack(stack);
    expect(back.prior).toBe(undefined);
  });

  it("treats empty/missing URL cursors as the first page (T07b)", () => {
    expect(parseCursorParam(null)).toBeUndefined();
    expect(parseCursorParam("")).toBeUndefined();
    expect(parseCursorParam(undefined)).toBeUndefined();
    expect(parseCursorParam("opaque-bytes")).toBe("opaque-bytes");
  });

  it("offers first-page recovery on an invalid cursor (T08)", () => {
    // Recovery is simply: reset to the first page (no cursor).
    expect(initialBackStack(undefined)).toEqual([]);
    const reset = initialBackStack(undefined);
    expect(popBackStack(reset).prior).toBeUndefined();
    expect(hasPrevious(reset)).toBe(false);
  });
});