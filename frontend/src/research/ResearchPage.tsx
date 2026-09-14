// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Research workspace route (PR 24C §10).
//
// The page visibly says ``Research context``: Research is contextual
// knowledge, not observed Evidence. Columns are metadata + counts from the
// exact list DTO; the detail drawer renders structured claims/citations
// with inspectable claim-to-citation closure.

import { Box, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useOutletContext, useParams } from "react-router";

import type { ResearchResult } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer, DrawerError, DrawerLoading, DrawerNotFound } from "../analyst-table/DetailDrawer";
import { isNotFound404 } from "../analyst-table/detail-error";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { isUuidValue, localDateTimeToIso, parseUuidParam } from "../analyst-table/filters";
import { useResourceTable } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import { ResearchDetail } from "./ResearchDetail";
import { useResearchResultDetail, useResearchResultsPage } from "./research-queries";
import {
  emptyResearchFilters,
  parseResearchFilters,
  researchFiltersActive,
  researchFiltersToParams,
  type ResearchFilters,
} from "./research-filters";

/** Draft values of the filter form (browser-local until Apply). */
interface ResearchDraft {
  subjectEntityId: string;
  createdFrom: string;
  createdTo: string;
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: ResearchFilters): ResearchDraft {
  return {
    subjectEntityId: filters.subjectEntityId ?? "",
    createdFrom: filters.createdFrom ?? "",
    createdTo: filters.createdTo ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: ResearchDraft): ResearchFilters {
  return {
    subjectEntityId: parseUuidParam(draft.subjectEntityId),
    createdFrom: localDateTimeToIso(draft.createdFrom),
    createdTo: localDateTimeToIso(draft.createdTo),
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: ResearchFilters): string {
  return JSON.stringify([
    filters.subjectEntityId,
    filters.createdFrom,
    filters.createdTo,
  ]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: ResearchDraft): string | null {
  if (draft.subjectEntityId !== "" && !isUuidValue(draft.subjectEntityId)) {
    return t("filters.subjectEntity.invalid");
  }
  if (draft.createdFrom !== "" && localDateTimeToIso(draft.createdFrom) === undefined) {
    return t("filters.time.invalid");
  }
  if (draft.createdTo !== "" && localDateTimeToIso(draft.createdTo) === undefined) {
    return t("filters.time.invalid");
  }
  return null;
}

/** Analyst-facing Research columns — context metadata, never Evidence. */
function researchColumns(t: (key: string) => string): Column<ResearchResult>[] {
  return [
    {
      id: "subjectEntity",
      header: t("columns.subjectEntity"),
      render: (research) => <CompactId id={research.subject_entity_id} label={t("columns.subjectEntity")} />,
      exportValue: (research) => research.subject_entity_id,
    },
    {
      id: "created",
      header: t("columns.created"),
      render: (research) => <Timestamp iso={research.created_at} />,
      exportValue: (research) => research.created_at,
    },
    {
      id: "claimCount",
      header: t("columns.claimCount"),
      render: (research) => String(research.claims.length),
      exportValue: (research) => String(research.claims.length),
    },
    {
      id: "citationCount",
      header: t("columns.citationCount"),
      render: (research) => String(research.citations.length),
      exportValue: (research) => String(research.citations.length),
    },
    {
      id: "resultId",
      header: t("columns.resultId"),
      render: (research) => <CompactId id={research.id} label={t("columns.resultId")} />,
      exportValue: (research) => research.id,
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/** The Research workspace. */
export function ResearchPage(): ReactElement {
  const { t } = useTranslation("research");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<ResearchFilters>({
    parse: parseResearchFilters,
    toParams: researchFiltersToParams,
    empty: emptyResearchFilters,
  });

  const { page, isLoading, error, refetch } = useResearchResultsPage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<ResearchFilters, ResearchDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyResearchFilters()),
    committedKey: filtersKey(table.filters),
  });

  const detail = useResearchResultDetail(investigationId, table.selection);
  const drawerOpen = table.selection !== null;
  const filtersActive = researchFiltersActive(table.filters);

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
      t("columns.subjectEntity"),
      t("columns.created"),
      t("columns.claimCount"),
      t("columns.citationCount"),
      t("columns.resultId"),
    ];
    const rows = page.items.map((research) => [
      research.subject_entity_id,
      research.created_at,
      String(research.claims.length),
      String(research.citations.length),
      research.id,
    ]);
    downloadCsv(
      exportFilename("research", investigationId),
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
        filters={<ResearchFiltersForm t={t} form={filterForm} />}
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
      <AnalystTable<ResearchResult>
        columns={researchColumns(t)}
        rows={page?.items ?? []}
        getRowId={(research) => research.id}
        ariaLabel={t("title")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("list.error.title")}
        onRetry={refetch}
        emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
        emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
        hasActiveFilters={filtersActive}
        onClearFilters={table.clearFilters}
        onView={(research) => table.openSelection(research.id)}
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
      <DetailDrawer open={drawerOpen} title={t("title")} onClose={table.closeSelection}>
        {drawerOpen ? detailBody(t, detail) : null}
      </DetailDrawer>
    </Box>
  );
}

/** The drawer body with its bounded states. */
function detailBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useResearchResultDetail>,
): ReactElement {
  if (detail.isLoading && detail.research === null) {
    return <DrawerLoading label={t("detail.loading")} />;
  }
  if (detail.isError && detail.research === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("detail.notFound.title")} />;
    }
    return <DrawerError title={t("detail.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.research === null) {
    return <DrawerLoading label={t("detail.loading")} />;
  }
  return <ResearchDetail research={detail.research} />;
}

/** The filter form controls (apply on Apply/Enter, not keystrokes). */
export function ResearchFiltersForm({
  t,
  form,
}: {
  t: (key: string) => string;
  form: ReturnType<typeof useFilterForm<ResearchFilters, ResearchDraft>>;
}): ReactElement {
  const enter = (event: { key: string }) => {
    if (event.key === "Enter") {
      form.apply();
    }
  };
  const draft = form.draft;
  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      <TextField
        size="small"
        label={t("filters.subjectEntity.label")}
        value={draft.subjectEntityId}
        onChange={(event) => form.setDraft({ ...draft, subjectEntityId: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.createdFrom.label")}
        value={draft.createdFrom}
        onChange={(event) => form.setDraft({ ...draft, createdFrom: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.createdTo.label")}
        value={draft.createdTo}
        onChange={(event) => form.setDraft({ ...draft, createdTo: event.target.value })}
        onKeyDown={enter}
      />
    </Box>
  );
}