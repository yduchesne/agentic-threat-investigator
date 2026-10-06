// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Transient bounded ATI navigation context (PR 35-1 Parts 3-4; amendment 1).
//
// Contextual ``< Back`` navigation must return to the actual ATI contextual
// origin, so the app carries a small ordered stack of validated internal
// locations in React Router transient state. This is deliberately not
// browser-history navigation and never a URL-persisted breadcrumb:
//
// - ``validatedReturnTo`` (string) is retained for the login redirect seam.
// - ``pushNavigationReturn`` records the current location as the immediate
//   return target for a genuine drill-down (Report -> Evidence detail).
// - ``preserveNavigationContext`` keeps the existing context unchanged for
//   sibling/subview transitions (EVOLUTION <-> GRAPH) or lateral focal
//   changes.
// - ``resolveReturn`` pops exactly one level and yields the remaining
//   context so the destination can continue the journey.
//
// Only bounded ``/investigations`` internal paths are ever accepted;
// external, protocol-relative, malformed, and control-character targets are
// rejected so transient state can never drive arbitrary navigation.

/** The only internal authenticated surface ATI navigation originates from. */
const INTERNAL_PREFIX = "/investigations";

/** The synthetic origin used to parse version-relative internal paths. */
const INTERNAL_ORIGIN = "http://ati.internal";

/** Bounded navigation-context depth (deterministic; never unbounded). */
export const MAX_NAVIGATION_RETURNS = 8;

/** One validated ATI-internal location (pathname + search + hash). */
export interface InternalLocation {
  pathname: string;
  search: string;
  hash: string;
}

/** One bounded ordered set of ATI-internal return locations. */
export interface NavigationContext {
  returns: InternalLocation[];
}

/** React Router transient state carrying the bounded navigation context. */
export interface NavigationState {
  navigation: NavigationContext;
}

/** A resolved one-level return: the target plus the remaining context. */
export interface ResolvedReturn {
  target: InternalLocation;
  remaining: NavigationContext;
}

/** Return one JSON object record, or ``null`` when the shape is unexpected. */
function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

/** Whether one candidate path segment list is a valid internal path. */
function locationFromParts(
  pathname: string,
  search: string,
  hash: string,
): InternalLocation | null {
  if (pathname !== INTERNAL_PREFIX && !pathname.startsWith(`${INTERNAL_PREFIX}/`)) {
    return null;
  }
  if (search !== "" && !search.startsWith("?")) {
    return null;
  }
  if (hash !== "" && !hash.startsWith("#")) {
    return null;
  }
  if (/[\u0000-\u001f\u007f\\]/.test(`${pathname}${search}${hash}`)) {
    return null;
  }
  return { pathname, search, hash };
}

/** Parse one version-relative internal path string into a location. */
function locationFromString(candidate: string): InternalLocation | null {
  const trimmed = candidate.trim();
  if (trimmed === "" || trimmed.startsWith("//")) {
    return null;
  }
  // Reject control characters and backslashes before URL normalization can
  // reinterpret them as equivalent path separators.
  if (/[\u0000-\u001f\u007f\\]/.test(trimmed)) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(trimmed, INTERNAL_ORIGIN);
  } catch {
    return null;
  }
  if (url.origin !== INTERNAL_ORIGIN) {
    return null;
  }
  return locationFromParts(url.pathname, url.search, url.hash);
}

/** Parse one structured internal-location value into a location. */
function locationFromValue(value: unknown): InternalLocation | null {
  if (typeof value === "string") {
    return locationFromString(value);
  }
  const record = asRecord(value);
  if (record === null) {
    return null;
  }
  const pathname = record.pathname;
  const search = record.search;
  const hash = record.hash;
  if (typeof pathname !== "string") {
    return null;
  }
  return locationFromParts(
    pathname,
    typeof search === "string" ? search : "",
    typeof hash === "string" ? hash : "",
  );
}

/** Render one internal location back to a navigable path string. */
export function returnTargetHref(target: InternalLocation): string {
  return `${target.pathname}${target.search}${target.hash}`;
}

/**
 * Return one validated ATI-internal origin path string, or ``null``.
 *
 * Retained for the login redirect seam where a single string origin is the
 * correct contract.
 */
export function validatedReturnTo(candidate: unknown): string | null {
  if (typeof candidate !== "string") {
    return null;
  }
  const location = locationFromString(candidate);
  return location === null ? null : returnTargetHref(location);
}

/** Build a validated internal location from one React Router location. */
export function internalLocationFromPath(
  pathname: string,
  search: string,
  hash: string,
): InternalLocation | null {
  return locationFromParts(pathname, search, hash);
}

/** Parse the bounded navigation context out of one transient state value. */
export function parseNavigationContext(state: unknown): NavigationContext {
  const record = asRecord(state);
  const navigation = asRecord(record?.navigation);
  const rawReturns = navigation?.returns;
  const returns: InternalLocation[] = [];
  if (Array.isArray(rawReturns)) {
    for (const raw of rawReturns) {
      const location = locationFromValue(raw);
      if (location !== null) {
        returns.push(location);
      }
      if (returns.length >= MAX_NAVIGATION_RETURNS) {
        break;
      }
    }
  } else {
    // Backwards-compatible single-string ``returnTo`` from the first PR
    // 35-1 pass: treat it as a one-element context.
    const legacy = record?.returnTo;
    if (typeof legacy === "string") {
      const location = locationFromString(legacy);
      if (location !== null) {
        returns.push(location);
      }
    }
  }
  return { returns };
}

/** Whether two locations are identical. */
export function sameInternalLocation(
  a: InternalLocation,
  b: InternalLocation,
): boolean {
  return a.pathname === b.pathname && a.search === b.search && a.hash === b.hash;
}

/** Build transient router state for one navigation context (or undefined). */
export function navigationState(context: NavigationContext): NavigationState | undefined {
  return context.returns.length === 0 ? undefined : { navigation: context };
}

/**
 * Record one drill-down: push the current location as the immediate return
 * target while retaining ancestors. An adjacent duplicate is suppressed and
 * the stack is deterministically bounded.
 */
export function pushNavigationReturn(
  state: unknown,
  current: InternalLocation | null,
): NavigationContext {
  const context = parseNavigationContext(state);
  if (current === null) {
    return context;
  }
  const top = context.returns[0];
  if (top !== undefined && sameInternalLocation(top, current)) {
    return context;
  }
  return {
    returns: [current, ...context.returns].slice(0, MAX_NAVIGATION_RETURNS),
  };
}

/** Keep the existing context unchanged for a sibling/subview transition. */
export function preserveNavigationContext(state: unknown): NavigationContext {
  return parseNavigationContext(state);
}

/** Pop exactly one level: the immediate target plus the remaining context. */
export function resolveReturn(state: unknown): ResolvedReturn | null {
  const context = parseNavigationContext(state);
  const [target, ...rest] = context.returns;
  if (target === undefined) {
    return null;
  }
  return { target, remaining: { returns: rest } };
}

/**
 * Resolve the Back destination + remaining context for a routed detail page.
 *
 * A valid contextual origin wins (drill-down/Report journeys); otherwise the
 * canonical list path is used so direct/deep links stay correct.
 */
export function contextualBack(
  state: unknown,
  fallbackPath: string,
): { backTo: string; backState: unknown } {
  const resolved = resolveReturn(state);
  if (resolved === null) {
    return { backTo: fallbackPath, backState: undefined };
  }
  return {
    backTo: returnTargetHref(resolved.target),
    backState: navigationState(resolved.remaining),
  };
}
