// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence workspace content (PR 24C §2, §8, §14-§17; PR 24D §10).
//
// Route-independent PR 24C Evidence surface: server-driven browsing with
// URL-backed exact filters -> bounded keyset page -> opaque Previous/Next
// -> row View -> authoritative Investigation-scoped detail drawer. The
// normal route wraps this with the live router search params; the PR 24D
// modal wraps the same component with the pivot-step port, so one table/
// query/detail implementation serves both contexts. Empty evidence never
// implies benign: the empty state says exactly what it is.

import { Box, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { Evidence, EvidenceTypeName, Investigation } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer, DrawerError, DrawerLoading, DrawerNotFound } from "../analyst-table/DetailDrawer";
import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { isUuidValue, localDateTimeToIso, parseUuidParam } from "../analyst-table/filters";
import type { ResourceTableState } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import { evidenceSubjectActions } from "../pivots/pivot-capabilities";
import { EvidenceDetail } from "./EvidenceDetail";
import { useEvidenceDetail, useEvidencePage } from "./evidence-queries";
import {
  emptyEvidenceFilters,
  evidenceFiltersActive,
  type EvidenceFilters,
} from "./evidence-filters";
import { evidenceTypeKey, EVIDENCE_TYPES } from "./labels";

/** Draft values of the filter form (browser-local until Apply). */
interface EvidenceDraft {
  source: string;
  subjectEntityId: string;
  type: EvidenceTypeName | "";
  retrievedFrom: string;
  retrievedTo: string;
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: EvidenceFilters): EvidenceDraft {
  return {
    source: filters.source ?? "",
    subjectEntityId: filters.subjectEntityId ?? "",
    type: filters.type ?? "",
    retrievedFrom: filters.retrievedFrom ?? "",
    retrievedTo: filters.retrievedTo ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: EvidenceDraft): EvidenceFilters {
  return {
    source: nonBlank(draft.source),
    subjectEntityId: parseUuidParam(draft.subjectEntityId),
    type: draft.type === "" ? undefined : draft.type,
    retrievedFrom: localDateTimeToIso(draft.retrievedFrom),
    retrievedTo: localDateTimeToIso(draft.retrievedTo),
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: EvidenceFilters): string {
  return JSON.stringify([
    filters.source,
    filters.subjectEntityId,
    filters.type,
    filters.retrievedFrom,
    filters.retrievedTo,
  ]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: EvidenceDraft): string | null {
  if (draft.subjectEntityId !== "" && !isUuidValue(draft.subjectEntityId)) {
    return t("filters.subjectEntity.invalid");
  }
  if (draft.retrievedFrom !== "" && localDateTimeToIso(draft.retrievedFrom) === undefined) {
    return t("filters.time.invalid");
  }
  if (draft.retrievedTo !== "" && localDateTimeToIso(draft.retrievedTo) === undefined) {
    return t("filters.time.invalid");
  }
  return null;
}

/** Analyst-facing Evidence columns (server-driven; no sort affordances). */
export function evidenceColumns(t: (key: string) => string): Column<Evidence>[] {
  return [
    {
      id: "subject",
      header: t("columns.subject"),
      render: (evidence) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {evidence.subject_value}
          </Typography>
          <PivotMenu
            actions={evidenceSubjectActions(evidence, "table_cell")}
            ariaLabel={t("columns.subject")}
          />
        </Box>
      ),
      exportValue: (evidence) => evidence.subject_value,
    },
    {
      id: "evidenceType",
      header: t("columns.evidenceType"),
      render: (evidence) => t(evidenceTypeKey(evidence.type)),
      exportValue: (evidence) => t(evidenceTypeKey(evidence.type)),
    },
    {
      id: "source",
      header: t("columns.source"),
      render: (evidence) => evidence.source,
      exportValue: (evidence) => evidence.source,
    },
    {
      id: "observedAt",
      header: t("columns.observedAt"),
      render: (evidence) =>
        evidence.observed_at !== null ? <Timestamp iso={evidence.observed_at} /> : t("detail.notObserved"),
      exportValue: (evidence) => evidence.observed_at ?? "",
    },
    {
      id: "retrievedAt",
      header: t("columns.retrievedAt"),
      render: (evidence) => <Timestamp iso={evidence.retrieved_at} />,
      exportValue: (evidence) => evidence.retrieved_at,
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

export interface EvidenceWorkspaceProps {
  investigationId: string;
  investigation: Investigation | null;
  table: ResourceTableState<EvidenceFilters>;
  /** Rendered inside the pivot modal: the modal chrome owns title/nav. */
  embedded?: boolean;
}

/** The Evidence workspace content shared by the route and the modal. */
export function EvidenceWorkspace({
  investigationId,
  investigation,
  table,
  embedded = false,
}: EvidenceWorkspaceProps): ReactElement {
  const { t } = useTranslation("evidence");
  const { t: tCommon } = useTranslation("common");

  const { page, isLoading, error, refetch } = useEvidencePage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<EvidenceFilters, EvidenceDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyEvidenceFilters()),
    committedKey: filtersKey(table.filters),
  });

  const detail = useEvidenceDetail(investigationId, table.selection);
  const drawerOpen = table.selection !== null;
  const filtersActive = evidenceFiltersActive(table.filters);

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
      t("columns.subject"),
      t("columns.evidenceType"),
      t("columns.source"),
      t("columns.observedAt"),
      t("columns.retrievedAt"),
      t("columns.id"),
      t("columns.sourceRecordId"),
      t("columns.sourceUrl"),
    ];
    const rows = page.items.map((evidence) => [
      evidence.subject_value,
      t(evidenceTypeKey(evidence.type)),
      evidence.source,
      evidence.observed_at ?? "",
      evidence.retrieved_at,
      evidence.id,
      evidence.source_record_id ?? "",
      evidence.source_url ?? "",
    ]);
    downloadCsv(
      exportFilename("evidence", investigationId),
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
      {!embedded ? (
        <Typography variant="h2" sx={{ mb: 1 }}>
          {t("title")}
        </Typography>
      ) : null}
      <TableToolbar
        filters={<EvidenceFiltersForm t={t} tCommon={tCommon} form={filterForm} />}
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
      <AnalystTable<Evidence>
        columns={evidenceColumns(t)}
        rows={page?.items ?? []}
        getRowId={(evidence) => evidence.id}
        ariaLabel={t("title")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("list.error.title")}
        onRetry={refetch}
        emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
        emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
        hasActiveFilters={filtersActive}
        onClearFilters={table.clearFilters}
        onView={(evidence) => table.openSelection(evidence.id)}
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
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DrawerLoading label={t("detail.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("detail.notFound.title")} />;
    }
    return <DrawerError title={t("detail.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DrawerLoading label={t("detail.loading")} />;
  }
  return (
    <Box>
      <EvidenceDetail evidence={detail.evidence} />
      {Object.keys(detail.evidence.facts ?? {}).length > 0 ? (
        <DetailSection title={t("detail.facts")}>
          <SafeJsonView data={detail.evidence.facts} label={t("detail.facts")} />
        </DetailSection>
      ) : null}
    </Box>
  );
}

/** The filter form controls (text/date apply on Apply/Enter, not keystrokes). */
export function EvidenceFiltersForm({
  t,
  tCommon,
  form,
}: {
  t: (key: string) => string;
  tCommon: (key: string) => string;
  form: ReturnType<typeof useFilterForm<EvidenceFilters, EvidenceDraft>>;
}): ReactElement {
  const enter = (event: { key: string }) => {
    if (event.key === "Enter") {
      form.apply();
    }
  };
  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      <TextField
        size="small"
        label={t("filters.source.label")}
        value={form.draft.source}
        onChange={(event) => form.setDraft({ ...form.draft, source: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        size="small"
        label={t("filters.subjectEntity.label")}
        value={form.draft.subjectEntityId}
        onChange={(event) =>
          form.setDraft({ ...form.draft, subjectEntityId: event.target.value })}
        onKeyDown={enter}
      />
      <FormControl size="small" sx={{ minWidth: 170 }}>
        <InputLabel id="evidence-type-filter-label">{t("filters.type.label")}</InputLabel>
        <Select
          labelId="evidence-type-filter-label"
          label={t("filters.type.label")}
          size="small"
          value={form.draft.type}
          onChange={(event) =>
            form.setDraft({
              ...form.draft,
              type: event.target.value as EvidenceTypeName | "",
            })}
          sx={{ minWidth: 170 }}
        >
          <MenuItem value="">{tCommon("filters.all")}</MenuItem>
          {EVIDENCE_TYPES.map((type) => (
            <MenuItem key={type} value={type}>
              {t(evidenceTypeKey(type))}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.retrievedFrom.label")}
        value={form.draft.retrievedFrom}
        onChange={(event) =>
          form.setDraft({ ...form.draft, retrievedFrom: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.retrievedTo.label")}
        value={form.draft.retrievedTo}
        onChange={(event) =>
          form.setDraft({ ...form.draft, retrievedTo: event.target.value })}
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