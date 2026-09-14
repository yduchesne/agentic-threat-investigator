// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared analyst-table type contracts (PR 24C §6).
//
// The generic layer owns presentation/state mechanics only — never ATI
// resource semantics. Columns are declarative: a header, a React cell
// renderer (text is auto-escaped by React), and a plain-text export value
// for the bounded current-page CSV.

import type { ReactNode } from "react";

/** One declarative analyst column. */
export interface Column<T> {
  /** Stable column identity (also the CSV header key). */
  id: string;
  /** Translated column header. */
  header: string;
  /** Cell renderer; all text is React-escaped, never raw HTML. */
  render: (row: T) => ReactNode;
  /** Plain-text export value for the bounded current-page CSV. */
  exportValue: (row: T) => string;
}

/** Bounded cursor-page navigation state decided by the backend. */
export interface PageNavigation {
  /** Previous enabled only when the browser-local back stack is non-empty. */
  canGoPrevious: boolean;
  /** Next enabled only when the API returned an opaque ``next_cursor``. */
  canGoNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
}

/** Shared table input contract (PR 24C §6). */
export interface AnalystTableInput<T> {
  columns: readonly Column<T>[];
  rows: readonly T[];
  getRowId: (row: T) => string;
  /** Accessible table label. */
  ariaLabel: string;
  /** True while the first page is still loading (no rows yet). */
  isLoading: boolean;
  /** Non-null while the list query failed. */
  error: ApiErrorLike | null;
  errorTitle: string;
  onRetry: () => void;
  emptyTitle: string;
  emptyMessage?: string;
  /** Whether any filter is active (empty state offers ``Clear filters``). */
  hasActiveFilters: boolean;
  onClearFilters: () => void;
  /** Row action opening the authoritative detail drawer. */
  onView: (row: T) => void;
  /** Translated ``View`` action label. */
  viewLabel: string;
  navigation: PageNavigation;
  /** Optional secondary notice (e.g. Investigation still running). */
  notice?: ReactNode;
}

/** Narrow error shape used by the table (never rendered as raw content). */
export interface ApiErrorLike {
  readonly kind: string;
  readonly status: number;
  readonly code: string;
}

/** The stable backend cursor-failure codes (invalid/stale/mismatch). */
export const CURSOR_ERROR_CODES = [
  "invalid_cursor",
  "cursor_query_mismatch",
  "cursor_filter_mismatch",
] as const;

/** Whether one error is the opaque-cursor failure contract. */
export function isCursorError(error: ApiErrorLike | null): boolean {
  return (
    error !== null &&
    error.kind === "api" &&
    (CURSOR_ERROR_CODES as readonly string[]).includes(error.code)
  );
}