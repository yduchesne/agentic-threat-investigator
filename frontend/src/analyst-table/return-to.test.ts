// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Transient bounded navigation-context tests (PR 35-1 Part 3-4, amendment 1).

import { describe, expect, it } from "vitest";

import {
  MAX_NAVIGATION_RETURNS,
  contextualBack,
  internalLocationFromPath,
  navigationState,
  parseNavigationContext,
  preserveNavigationContext,
  pushNavigationReturn,
  resolveReturn,
  returnTargetHref,
  validatedReturnTo,
  type InternalLocation,
} from "./return-to";

const A: InternalLocation = {
  pathname: "/investigations/1/evidence",
  search: "?source=rdap",
  hash: "",
};
const B: InternalLocation = {
  pathname: "/investigations/1/evidence/ev-1",
  search: "",
  hash: "#top",
};
const REPORT: InternalLocation = {
  pathname: "/investigations/1/overview/report",
  search: "",
  hash: "",
};

function stateWith(context: ReturnType<typeof pushNavigationReturn>): unknown {
  return navigationState(context);
}

describe("validatedReturnTo", () => {
  it("N1: accepts a bounded internal Investigation path with query and hash", () => {
    expect(
      validatedReturnTo(
        "/investigations/20000000-0000-4000-8000-000000000001/evidence?source=rdap#top",
      ),
    ).toBe(
      "/investigations/20000000-0000-4000-8000-000000000001/evidence?source=rdap#top",
    );
    expect(validatedReturnTo("/investigations")).toBe("/investigations");
  });

  it("N2/N3/N4: rejects absent, external, protocol-relative, and malformed values", () => {
    expect(validatedReturnTo(undefined)).toBeNull();
    expect(validatedReturnTo(null)).toBeNull();
    expect(validatedReturnTo("")).toBeNull();
    expect(validatedReturnTo(42)).toBeNull();
    expect(validatedReturnTo("https://evil.example/steal")).toBeNull();
    expect(validatedReturnTo("//evil.example/steal")).toBeNull();
    expect(validatedReturnTo("javascript:alert(1)")).toBeNull();
    expect(validatedReturnTo("/etc/passwd")).toBeNull();
    expect(validatedReturnTo("/investigations/x\\..\\y")).toBeNull();
    expect(validatedReturnTo("/investigations/\u0000x")).toBeNull();
  });
});

describe("navigation context", () => {
  it("N5/N6: preserve keeps sibling/subview context unchanged", () => {
    const pushed = pushNavigationReturn(undefined, REPORT);
    expect(preserveNavigationContext(stateWith(pushed)).returns).toEqual([
      REPORT,
    ]);
    // Legacy single-string returnTo is upgraded to a one-element context.
    expect(parseNavigationContext({ returnTo: returnTargetHref(A) }).returns).toEqual([
      A,
    ]);
  });

  it("N7: a drill-down pushes the current location", () => {
    const context = pushNavigationReturn(undefined, REPORT);
    expect(context.returns).toEqual([REPORT]);
    expect(resolveReturn(stateWith(context))?.target).toEqual(REPORT);
  });

  it("N8: A -> B -> C then Back -> B (A retained) then Back -> A", () => {
    // A -> B: push A.
    let context = pushNavigationReturn(undefined, A);
    // B -> C: push B on top of A.
    context = pushNavigationReturn(stateWith(context), B);
    expect(context.returns).toEqual([B, A]);

    const first = resolveReturn(stateWith(context));
    expect(first?.target).toEqual(B);
    expect(first?.remaining.returns).toEqual([A]);

    const second = resolveReturn(navigationState(first!.remaining));
    expect(second?.target).toEqual(A);
    expect(second?.remaining.returns).toEqual([]);
  });

  it("N9: a direct load fabricates no contextual Back", () => {
    expect(resolveReturn(undefined)).toBeNull();
    expect(contextualBack(undefined, "/investigations/1/evidence")).toEqual({
      backTo: "/investigations/1/evidence",
      backState: undefined,
    });
  });

  it("N10: an adjacent duplicate push is suppressed", () => {
    const context = pushNavigationReturn(undefined, A);
    const again = pushNavigationReturn(stateWith(context), A);
    expect(again.returns).toEqual([A]);
  });

  it("N11: the stack is deterministically bounded", () => {
    let context = { returns: [] as InternalLocation[] };
    for (let index = 0; index < MAX_NAVIGATION_RETURNS + 5; index += 1) {
      context = pushNavigationReturn(navigationState(context), {
        pathname: `/investigations/1/evidence/${index}`,
        search: "",
        hash: "",
      });
    }
    expect(context.returns).toHaveLength(MAX_NAVIGATION_RETURNS);
    expect(context.returns[0]?.pathname).toBe(
      `/investigations/1/evidence/${MAX_NAVIGATION_RETURNS + 4}`,
    );
  });

  it("contextualBack prefers a valid origin and pops one level", () => {
    const context = pushNavigationReturn(undefined, REPORT);
    expect(contextualBack(stateWith(context), "/investigations/1/evidence")).toEqual({
      backTo: returnTargetHref(REPORT),
      backState: undefined,
    });
    const nested = pushNavigationReturn(stateWith(context), B);
    const resolved = contextualBack(stateWith(nested), "/investigations/1/evidence");
    expect(resolved.backTo).toBe(returnTargetHref(B));
    expect(parseNavigationContext(resolved.backState).returns).toEqual([REPORT]);
  });

  it("validates structured internal locations and ignores invalid entries", () => {
    expect(
      internalLocationFromPath(
        "/investigations/1/evidence",
        "?source=rdap",
        "#top",
      ),
    ).toEqual({ pathname: "/investigations/1/evidence", search: "?source=rdap", hash: "#top" });
    expect(internalLocationFromPath("/other", "", "")).toBeNull();
    expect(
      parseNavigationContext({
        navigation: { returns: [{ pathname: "/other" }, A] },
      }).returns,
    ).toEqual([A]);
  });
});
