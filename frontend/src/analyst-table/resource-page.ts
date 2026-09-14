// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared URL-backed resource table controller (PR 24C §1, §6).
//
// Every PR 24C resource page follows the same contract:
//
//   URL search parameters -> validated filters -> bounded server query ->
//   opaque cursor page -> rows -> selection -> detail drawer
//
// This hook owns generic mechanics only: URL-backed filters, opaque-cursor
// Previous/Next over a browser-local back stack, cursor reset on semantic
// filter change, URL-addressable ``selected``, and first-page recovery for
// invalid/stale cursors. Resource semantics stay in each resource's codec.

import { useState } from "react";
import { useSearchParams } from "react-router";

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
    options?: { replace?: boolean },
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
  const filters = codec.parse(searchParams);
  const cursor = parseCursorParam(searchParams.get(CURSOR_PARAM));
  const selection = parseSelectedParam(searchParams, isUuidValue);
  const [backStack, setBackStack] = useState<string[]>(() => initialBackStack(cursor));

  const commit = (next: URLSearchParams): void => {
    setSearchParams(next, { replace: false });
  };

  const applyFilters = (next: F): void => {
    setBackStack([]);
    commit(codec.toParams(searchParams, next));
  };

  const goNext = (nextCursor: string): void => {
    setBackStack(pushNextStack(backStack, cursor));
    commit(setCursorParam(searchParams, nextCursor));
  };

  const goPrevious = (): void => {
    const { stack, prior } = popBackStack(backStack);
    setBackStack(stack);
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
      setBackStack([]);
      commit(setCursorParam(searchParams, undefined));
    },
    openSelection: (id: string) => commit(setSelectedParam(searchParams, id)),
    closeSelection: () => commit(clearSelectedParam(searchParams)),
  };
}

/** Re-export the selection URL parameter name for aria/labels. */
export { SELECTED_PARAM };