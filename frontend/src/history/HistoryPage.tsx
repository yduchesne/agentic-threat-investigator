// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Secondary Investigation History route (PR 24C §12).
//
// Reached through the workspace ``More`` menu — not a primary tab.
// Generic History shows only backend-public allowlisted rows; state/diff
// are rendered through the bounded safe JSON viewer. Exact-version detail
// uses the dedicated endpoint; object-scoped version browsing stays inside
// the History surface. RelationshipObservation never appears here: it is
// first-class immutable observation history, never generic domain history.

import { Box, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useOutletContext, useParams } from "react-router";

import type { HistoryOperationName, HistoryRecord } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer, DrawerLoading } from "../analyst-table/DetailDrawer";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { localDateTimeToIso } from "../analyst-table/filters";
import { useResourceTable } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { ShortId } from "../components/ShortId";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import { HistoryDetail } from "./HistoryDetail";
import { useHistoryPage } from "./history-queries";
import {
  emptyHistoryFilters,
  historyFiltersActive,
  historyFiltersToParams,
  parseHistoryFilters,
  type HistoryFilters,
} from "./history-filters";
import {
  HISTORY_OPERATIONS,
  historyOperationKey,
  PUBLIC_HISTORY_OBJECT_TYPES,
} from "./labels";

/** Draft values of the filter form (browser-local until Apply). */
interface HistoryDraft {
  objectType: string;
  operation: HistoryOperationName | "";
  occurredFrom: string;
  occurredTo: string;
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: HistoryFilters): HistoryDraft {
  return {
    objectType: filters.objectType ?? "",
    operation: filters.operation ?? "",
    occurredFrom: filters.occurredFrom ?? "",
    occurredTo: filters.occurredTo ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: HistoryDraft): HistoryFilters {
  return {
    objectType: nonBlank(draft.objectType),
    operation: draft.operation === "" ? undefined : draft.operation,
    occurredFrom: localDateTimeToIso(draft.occurredFrom),
    occurredTo: localDateTimeToIso(draft.occurredTo),
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: HistoryFilters): string {
  return JSON.stringify([filters.objectType, filters.operation, filters.occurredFrom, filters.occurredTo]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: HistoryDraft): string | null {
  if (draft.occurredFrom !== "" && localDateTimeToIso(draft.occurredFrom) === undefined) {
    return t("filters.time.invalid");
  }
  if (draft.occurredTo !== "" && localDateTimeToIso(draft.occurredTo) === undefined) {
    return t("filters.time.invalid");
  }
  return null;
}

/** Analyst-facing History columns (public allowlisted fields only). */
function historyColumns(t: (key: string) => string): Column<HistoryRecord>[] {
  return [
    {
      id: "occurredAt",
      header: t("columns.occurredAt"),
      render: (record) => <Timestamp iso={record.occurred_at} />,
      exportValue: (record) => record.occurred_at,
    },
    {
      id: "objectType",
      header: t("columns.objectType"),
      render: (record) => record.object_type,
      exportValue: (record) => record.object_type,
    },
    {
      id: "objectId",
      header: t("columns.objectId"),
      render: (record) => <ShortId id={record.object_id} />,
      exportValue: (record) => record.object_id,
    },
    {
      id: "operation",
      header: t("columns.operation"),
      render: (record) => (
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {t(historyOperationKey(record.operation))}
        </Typography>
      ),
      exportValue: (record) => t(historyOperationKey(record.operation)),
    },
    {
      id: "version",
      header: t("columns.version"),
      render: (record) => String(record.version),
      exportValue: (record) => String(record.version),
    },
    {
      id: "actor",
      header: t("columns.actor"),
      render: (record) => record.actor_id !== null ? <ShortId id={record.actor_id} /> : t("columns.nullable"),
      exportValue: (record) => record.actor_id ?? "",
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/** The secondary History route. */
export function HistoryPage(): ReactElement {
  const { t } = useTranslation("history");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<HistoryFilters>({
    parse: parseHistoryFilters,
    toParams: historyFiltersToParams,
    empty: emptyHistoryFilters,
  });

  const { page, isLoading, error, refetch } = useHistoryPage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<HistoryFilters, HistoryDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyHistoryFilters()),
    committedKey: filtersKey(table.filters),
  });

  const drawerOpen = table.selection !== null;
  const filtersActive = historyFiltersActive(table.filters);
  const selectedRecord = page?.items.find((record) => record.id === table.selection);

  const goNext = (): void => {
    if (page === null || page.next_cursor === null || page.next_cursor === undefined) {
      return;
    }
    table.goNext(page.next_cursor);
  };

  const exportCurrentPage = (): void => {
    if (page === null) {
      return;
    }
    const header = [
      t("columns.occurredAt"),
      t("columns.objectType"),
      t("columns.objectId"),
      t("columns.operation"),
      t("columns.version"),
      t("columns.actor"),
      t("columns.recordId"),
    ];
    const rows = page.items.map((record) => [
      record.occurred_at,
      record.object_type,
      record.object_id,
      t(historyOperationKey(record.operation)),
      String(record.version),
      record.actor_id ?? "",
      record.id,
    ]);
    downloadCsv(
      exportFilename("history", investigationId),
      buildCsv(header, rows),
    );
  };

  return (
    <Box>
      {runningNotice(
        investigation?.status,
        refetch,
        t("running.notice"),
        tCommon("table.refresh"),
      )}
      <Box>
        <Typography variant="h2" sx={{ mb: 0.25 }}>
          {t("title")}
        </Typography>
        <Typography variant="caption" component="div" role="note">
          {t("intro")}
        </Typography>
      </Box>
      <TableToolbar
        filters={<HistoryFiltersForm t={t} tCommon={tCommon} form={filterForm} />}
        onApply={filterForm.apply}
        onClear={filterForm.clear}
        onExport={exportCurrentPage}
        hasActiveFilters={filtersActive}
      />
      {filterForm.error !== null ? (
        <Typography variant="caption" role="alert" color="error" sx={{ display: "block", mb: 0.5 }}>
          {filterForm.error}
        </Typography>
      ) : null}
      <AnalystTable<HistoryRecord>
        columns={historyColumns(t)}
        rows={page?.items ?? []}
        getRowId={(record) => record.id}
        ariaLabel={t("title")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("list.error.title")}
        onRetry={refetch}
        emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
        emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
        hasActiveFilters={filtersActive}
        onClearFilters={table.clearFilters}
        onView={(record) => table.openSelection(record.id)}
        viewLabel={t("row.view")}
        navigation={{
          canGoPrevious: table.canGoPrevious,
          canGoNext: hasNext(page),
          onPrevious: table.goPrevious,
          onNext: goNext,
        }}
        loadingLabel={t("list.loading")}
        staleErrorTitle={t("list.error.stale")}
        onReturnToFirstPage={table.returnToFirstPage}
      />
      <DetailDrawer open={drawerOpen} title={t("detail.title")} onClose={table.closeSelection}>
        {drawerOpen && selectedRecord !== undefined ? (
          <HistoryDetail
            investigationId={investigationId}
            objectType={selectedRecord.object_type}
            objectId={selectedRecord.object_id}
            version={selectedRecord.version}
          />
        ) : drawerOpen ? (
          <DrawerLoading label={t("detail.loading")} />
        ) : null}
      </DetailDrawer>
    </Box>
  );
}

/** The filter form controls (apply on Apply/Enter, not keystrokes). */
export function HistoryFiltersForm({
  t,
  tCommon,
  form,
}: {
  t: (key: string) => string;
  tCommon: (key: string) => string;
  form: ReturnType<typeof useFilterForm<HistoryFilters, HistoryDraft>>;
}): ReactElement {
  const enter = (event: { key: string }) => {
    if (event.key === "Enter") {
      form.apply();
    }
  };
  const draft = form.draft;
  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      <FormControl size="small" sx={{ minWidth: 200 }}>
        <InputLabel id="history-object-type-filter-label">{t("filters.objectType.label")}</InputLabel>
        <Select
          labelId="history-object-type-filter-label"
          label={t("filters.objectType.label")}
          size="small"
          value={draft.objectType}
          onChange={(event) => form.setDraft({ ...draft, objectType: event.target.value })}
          sx={{ minWidth: 200 }}
        >
          <MenuItem value="">{tCommon("filters.all")}</MenuItem>
          {PUBLIC_HISTORY_OBJECT_TYPES.map((objectType) => (
            <MenuItem key={objectType} value={objectType}>
              {t(`objectTypes.${objectType}`)}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      <FormControl size="small" sx={{ minWidth: 130 }}>
        <InputLabel id="history-operation-filter-label">{t("filters.operation.label")}</InputLabel>
        <Select
          labelId="history-operation-filter-label"
          label={t("filters.operation.label")}
          size="small"
          value={draft.operation}
          onChange={(event) =>
            form.setDraft({
              ...draft,
              operation: event.target.value as HistoryOperationName | "",
            })}
          sx={{ minWidth: 130 }}
        >
          <MenuItem value="">{tCommon("filters.all")}</MenuItem>
          {HISTORY_OPERATIONS.map((operation) => (
            <MenuItem key={operation} value={operation}>
              {t(historyOperationKey(operation))}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.occurredFrom.label")}
        value={draft.occurredFrom}
        onChange={(event) => form.setDraft({ ...draft, occurredFrom: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.occurredTo.label")}
        value={draft.occurredTo}
        onChange={(event) => form.setDraft({ ...draft, occurredTo: event.target.value })}
        onKeyDown={enter}
      />
    </Box>
  );
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}