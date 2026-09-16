// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable server-driven analyst table (PR 24C §6).
//
// TanStack Table is the sole table engine; it runs headless over Material
// UI primitives and in server/manual mode — no client sorting, no
// client-side exhaustive filtering over one loaded page, no page-number
// fiction. Rows render from the already-loaded bounded server page, and
// every row exposes a keyboard-operable ``View`` action. Loading/empty/
// error/refresh states and Previous/Next navigation are part of the
// generic layer; ATI resource semantics stay out.

import { Box, Button, Table, TableBody, TableCell, TableHead, TableRow } from "@mui/material";
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { TablePagination } from "./TablePagination";
import { isCursorError, type AnalystTableInput } from "./types";

export interface AnalystTableProps<T> extends AnalystTableInput<T> {
  /** Translated loading label. */
  loadingLabel: string;
  /** Translated warning shown when stale data is retained after an error. */
  staleErrorTitle: string;
  /** Recovery for invalid/stale opaque cursors; null hides the action. */
  onReturnToFirstPage: (() => void) | null;
}

/** One server-driven analyst table over TanStack Table + MUI primitives. */
export function AnalystTable<T>({
  columns,
  rows,
  getRowId,
  ariaLabel,
  isLoading,
  error,
  errorTitle,
  onRetry,
  emptyTitle,
  emptyMessage,
  hasActiveFilters,
  onClearFilters,
  onView,
  viewLabel,
  navigation,
  notice,
  loadingLabel,
  staleErrorTitle,
  onReturnToFirstPage,
}: AnalystTableProps<T>): ReactElement {
  const { t } = useTranslation("common");

  // TanStack Table in manual/server mode: declarative columns + the loaded
  // server page only. No sorting/filtering/grouping features are enabled.
  // An empty ``viewLabel`` omits the generic action column (used by
  // presentation-only tables whose rows carry their own Explore actions).
  const includeActions = viewLabel !== "";
  const table = useReactTable<T>({
    columns: [
      ...columns.map((column) => ({
        id: column.id,
        header: column.header,
        accessorFn: column.exportValue,
        cell: (info: { row: { original: T } }) => column.render(info.row.original),
      })),
      ...(includeActions
        ? [
            {
              id: "actions",
              header: "",
              accessorFn: () => "",
              cell: (info: { row: { original: T } }) => (
                <Button
                  size="small"
                  variant="text"
                  onClick={() => onView(info.row.original)}
                  aria-label={`${viewLabel} ${getRowId(info.row.original)}`}
                  sx={{ textTransform: "none" }}
                >
                  {viewLabel}
                </Button>
              ),
            },
          ]
        : []),
    ],
    data: [...rows],
    getRowId: (row) => getRowId(row),
    getCoreRowModel: getCoreRowModel(),
  });

  const hasRows = rows.length > 0;
  const showStaleError = error !== null && hasRows;

  return (
    <Box>
      {notice}
      {isLoading && !hasRows ? <LoadingState label={loadingLabel} /> : null}
      {error !== null && !hasRows ? (
        <ErrorNotice title={errorTitle} onRetry={onRetry} retryLabel={t("retry")} />
      ) : null}
      {error !== null && !hasRows && isCursorError(error) && onReturnToFirstPage !== null ? (
        <Box sx={{ textAlign: "center", mt: 1 }}>
          <Button
            size="small"
            variant="outlined"
            onClick={onReturnToFirstPage}
            sx={{ textTransform: "none" }}
          >
            {t("cursor.returnToFirstPage")}
          </Button>
        </Box>
      ) : null}
      {showStaleError ? (
        <ErrorNotice
          severity="warning"
          title={staleErrorTitle}
          onRetry={onRetry}
          retryLabel={t("retry")}
        />
      ) : null}
      {!isLoading && !hasRows && error === null ? (
        <Box sx={{ textAlign: "center", py: 2 }}>
          <EmptyState title={emptyTitle} message={emptyMessage} />
          {hasActiveFilters ? (
            <Button
              size="small"
              variant="outlined"
              onClick={onClearFilters}
              sx={{ mt: 1, textTransform: "none" }}
            >
              {t("filters.clear")}
            </Button>
          ) : null}
        </Box>
      ) : null}
      {hasRows ? (
        <Box>
          <Table size="small" aria-label={ariaLabel} sx={{ "& th": { fontWeight: 600 } }}>
            <TableHead>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <TableCell key={header.id} component="th" scope="col">
                      {flexRender(header.column.columnDef.header, header.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableHead>
            <TableBody>
              {table.getRowModel().rows.map((row) => (
                <TableRow key={row.id} hover>
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.column.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <TablePagination navigation={navigation} />
        </Box>
      ) : null}
    </Box>
  );
}