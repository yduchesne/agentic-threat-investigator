// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared URL-backed resource table controller (PR 24C §1, §6).
//
// Every PR 24C resource page follows the same contract:
//
//   URL search parameters -> validated filters -> bounded server query ->
//   opaque cursor page -> rows -> selection -> full-width detail (list/detail)
//
// This hook owns generic mechanics only: URL-backed filters, opaque-cursor
// Previous/Next over a browser-local back stack, cursor reset on semantic
// filter change, URL-addressable ``selected``, and first-page recovery for
// invalid/stale cursors. Resource semantics stay in each resource's codec.

import { useState } from "react";
import { useLocation, useSearchParams } from "react-router";

import { isUuidValue } from "./filters";
import {
  clearSelectedParam,
  CURSOR_PARAM,
  parseSelectedParam,
  setCursorParam,
  setSelectedParam,
  SELECTED_PARAM,
} from "./url-params";
import {
  hasPrevious,
  initialBackStack,
  parseCursorParam,
  popBackStack,
  pushNextStack,
} from "./cursor-stack";

/** One resource filter codec: URL -> validated model -> URL/API params. */
export interface ResourceFilterCodec<F> {
  /** Parse (and validate) one URL parameter set into a filter model. */
  parse: (params: URLSearchParams) => F;
  /** Serialize a committed filter model over one URL parameter set. */
  toParams: (params: URLSearchParams, filters: F) => URLSearchParams;
  /** The neutral/empty filter model (``Clear filters`` target). */
  empty: () => F;
}

export interface ResourceTableState<F> {
  filters: F;
  cursor: string | undefined;
  selection: string | null;
  canGoPrevious: boolean;
  applyFilters: (filters: F) => void;
  clearFilters: () => void;
  goNext: (nextCursor: string) => void;
  goPrevious: () => void;
  /** Recovery for invalid/stale cursors: back to the first page. */
  returnToFirstPage: () => void;
  openSelection: (id: string) => void;
  closeSelection: () => void;
}

/**
 * The URL-backed search-parameter surface consumed by the resource table.
 *
 * Normal routes use the live router search params; the pivot modal
 * (PR 24D) supplies a port projected from the active pivot step so the
 * same table controller works without duplicating resources.
 */
export interface SearchParamsPort {
  readonly searchParams: URLSearchParams;
  setSearchParams: (
    params: URLSearchParams,
    options?: { replace?: boolean; state?: unknown },
  ) => void;
}

/** The router search-parameter port used by the normal resource routes. */
export function useRouterSearchParamsPort(): SearchParamsPort {
  const [searchParams, setSearchParams] = useSearchParams();
  return { searchParams, setSearchParams };
}

/** One URL-backed resource table controller. */
export function useResourceTable<F>(
  codec: ResourceFilterCodec<F>,
  port?: SearchParamsPort,
): ResourceTableState<F> {
  const { searchParams, setSearchParams } = port ?? useRouterSearchParamsPort();
  const location = useLocation();
  const filters = codec.parse(searchParams);
  const cursor = parseCursorParam(searchParams.get(CURSOR_PARAM));
  const selection = parseSelectedParam(searchParams, isUuidValue);
  const [backStack, setBackStack] = useState<string[]>(() => initialBackStack(cursor));

  const commit = (next: URLSearchParams): void => {
    // PR 31F-6/31F-8: navigation commits are scheduled AFTER the originating
    // native pointer event completes (next macrotask). A synchronous
    // router commit + app-scale re-render inside a native pointer event
    // hard-freezes the browser main thread in both engines (minimal
    // in-harness reproduction: the same table, query and selection click
    // freeze synchronously and are clean when the commit is deferred).
    // PR 31F-8: EVERY accompanying controller state transition (the local
    // back stack) is deferred with the commit — a synchronous
    // ``setBackStack`` re-rendered the whole routed surface (AnalystTable +
    // TanStack + page chrome) inside the originating pointer event, which
    // reproduced the same deterministic Chromium/Firefox main-thread stall
    // on the routed GEOINT Location containment toggle (pointer AND
    // keyboard). No controller state change may run inside the native
    // pointer dispatch; the committed URL remains the single authority.
    // PR 35-1 amendment 1: committing a URL EQUIVALENT to the current one is
    // a same-URL navigation, which reproduced the same deterministic
    // real-stack pointer stall (e.g. Apply with an unchanged draft, or a
    // selection toggle that resolves to the current state). Equivalent
    // commits are therefore no-ops and never reach the router.
    if (sameSearchParams(next, searchParams)) {
      return;
    }
    // PR 35-1 amendment 1: a search-only change must preserve the transient
    // navigation context, otherwise filter/cursor/selection commits drop the
    // caller's Back origin.
    const state = location.state;
    window.setTimeout(
      () => setSearchParams(next, { replace: false, state }),
      0,
    );
  };

  /** Defer one controller state transition past the native event. */
  const deferState = (update: () => void): void => {
    window.setTimeout(update, 0);
  };

  const applyFilters = (next: F): void => {
    deferState(() => setBackStack([]));
    commit(codec.toParams(searchParams, next));
  };

  const goNext = (nextCursor: string): void => {
    deferState(() => setBackStack(pushNextStack(backStack, cursor)));
    commit(setCursorParam(searchParams, nextCursor));
  };

  const goPrevious = (): void => {
    const { stack, prior } = popBackStack(backStack);
    deferState(() => setBackStack(stack));
    commit(setCursorParam(searchParams, prior));
  };

  return {
    filters,
    cursor,
    selection,
    canGoPrevious: hasPrevious(backStack),
    applyFilters,
    clearFilters: () => applyFilters(codec.empty()),
    goNext,
    goPrevious,
    returnToFirstPage: () => {
      deferState(() => setBackStack([]));
      commit(setCursorParam(searchParams, undefined));
    },
    openSelection: (id: string) => commit(setSelectedParam(searchParams, id)),
    closeSelection: () => commit(clearSelectedParam(searchParams)),
  };
}

/** Whether two search-parameter sets are semantically identical. */
function sameSearchParams(
  a: URLSearchParams,
  b: URLSearchParams,
): boolean {
  if (a.size !== b.size) {
    return false;
  }
  for (const [key, value] of a) {
    if (b.get(key) !== value) {
      return false;
    }
  }
  return true;
}

/** Re-export the selection URL parameter name for aria/labels. */
export { SELECTED_PARAM };
