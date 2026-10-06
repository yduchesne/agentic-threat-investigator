// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence workspace content (PR 24C §2, §8, §14-§17; PR 24D §10).
//
// Route-independent PR 24C Evidence surface: server-driven browsing with
// URL-backed exact filters -> bounded keyset page -> opaque Previous/Next
// -> row View -> authoritative Investigation-scoped detail as the main
// in-flow list/detail content (PR 31F-6 amendment 4). The normal route
// wraps this with the live router search params; the PR 24D modal wraps
// the same component with the pivot-step port, so one table/query/detail
// implementation serves both contexts. Empty evidence never implies
// benign: the empty state says exactly what it is.

import { Box, Button, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router";

import type { Evidence, EvidenceTypeName, Investigation } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { isUuidValue, localDateTimeToIso, parseUuidParam } from "../analyst-table/filters";
import {
  navigationState,
  resolveReturn,
  returnTargetHref,
} from "../analyst-table/return-to";
import type { ResourceTableState } from "../analyst-table/resource-page";
import {
  DetailError,
  DetailLoading,
  DetailNotFound,
  ResourceDetailView,
} from "../analyst-table/ResourceDetailView";
import { runningNotice } from "../analyst-table/running";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { EntityReference } from "../components/EntityReference";
import { sourceLabel } from "../components/source-labels";
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

/** Analyst-facing Evidence columns (server-driven; no sort affordances).
 *
 * PR 31F-5 D2: the Subject cell renders the canonical Entity value primary
 * with the translated Entity type immediately adjacent and the Pivot action
 * right beside it in one wrapping Box — no separate Subject Type column and
 * never a UUID as primary Subject text.
 */
export function evidenceColumns(
  t: (key: string) => string,
  tCommon: (key: string) => string,
): Column<Evidence>[] {
  return [
    {
      id: "subject",
      header: t("columns.subject"),
      render: (evidence) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap", minWidth: 0 }}>
          <EntityReference value={evidence.subject_value} type={evidence.subject_type} />
          <PivotMenu
            actions={evidenceSubjectActions(evidence, "table_cell")}
            ariaLabel={t("columns.subject")}
          />
        </Box>
      ),
      exportValue: (evidence) => evidence.subject_value ?? "",
    },
    {
      id: "description",
      header: t("columns.description"),
      render: (evidence) => evidence.description,
      exportValue: (evidence) => evidence.description,
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
      render: (evidence) => sourceLabel(evidence.source, tCommon),
      exportValue: (evidence) => sourceLabel(evidence.source, tCommon),
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
  const location = useLocation();
  const navigate = useNavigate();
  const resolvedReturn = resolveReturn(location.state);
  const backTarget =
    resolvedReturn === null ? null : returnTargetHref(resolvedReturn.target);
  const backState =
    resolvedReturn === null
      ? undefined
      : navigationState(resolvedReturn.remaining);

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
    // PR 31F-5 D2: the CSV keeps human usefulness with the value/type/ID
    // triple expanded; the raw UUID is never the primary column.
    const header = [
      t("columns.subjectValue"),
      t("columns.subjectType"),
      t("columns.subjectEntityId"),
      t("columns.description"),
      t("columns.evidenceType"),
      t("columns.source"),
      t("columns.observedAt"),
      t("columns.retrievedAt"),
      t("columns.id"),
      t("columns.sourceRecordId"),
      t("columns.sourceUrl"),
    ];
    const rows = page.items.map((evidence) => [
      evidence.subject_value ?? "",
      evidence.subject_type ?? "",
      evidence.subject_entity_id ?? "",
      evidence.description,
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
          {table.selection !== null ? (
        <ResourceDetailView
          backLabel={tCommon("backToList", { resource: t("title") })}
          heading={tCommon("detail.title", { resource: t("title") })}
          onBack={table.closeSelection}
        >
          {evidenceDetailBody(t, detail)}
        </ResourceDetailView>
      ) : (
        <>
          {!embedded ? (
            <Box sx={{ mb: 1 }}>
              {backTarget !== null ? (
                <Button
                  size="small"
                  onClick={() => navigate(backTarget, { state: backState })}
                  sx={{ textTransform: "none", px: 0, mb: 0.5, display: "block" }}
                >
                  {tCommon("back")}
                </Button>
              ) : null}
              <Typography variant="h2">
                {t("title")}
              </Typography>
            </Box>
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
            columns={evidenceColumns(t, tCommon)}
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
        </>
      )}
    </Box>
  );
}

/** The detail body with its bounded states (shared by list and routed detail). */
export function evidenceDetailBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DetailLoading label={t("detail.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DetailNotFound title={t("detail.notFound.title")} />;
    }
    return <DetailError title={t("detail.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DetailLoading label={t("detail.loading")} />;
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
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
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
      </Box>
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
        <TextField
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          size="small"
          label={t("filters.retrievedFrom.label")}
          value={form.draft.retrievedFrom}
          onChange={(event) =>
            form.setDraft({ ...form.draft, retrievedFrom: event.target.value })}
          onKeyDown={enter}
        />
        <TextField
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          size="small"
          label={t("filters.retrievedTo.label")}
          value={form.draft.retrievedTo}
          onChange={(event) =>
            form.setDraft({ ...form.draft, retrievedTo: event.target.value })}
          onKeyDown={enter}
        />
      </Box>
    </Box>
  );
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}
