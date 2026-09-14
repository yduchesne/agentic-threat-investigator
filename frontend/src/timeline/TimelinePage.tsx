// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Timeline workspace route (PR 24C §11).
//
// Timeline answers: what did ATI do during this Investigation? Events come
// in the API's canonical chronological order; the table never sorts or
// re-orders. The detail drawer shows every safe public DTO field using
// the exact list DTO (no single-GET endpoint exists).
//
// Timeline is deliberately distinct from Relationship Evolution: no
// rendering here ever describes observations as relationship changes.

import { Box, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useOutletContext, useParams } from "react-router";

import type { TimelineEvent, TimelineEventTypeName } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer } from "../analyst-table/DetailDrawer";
import { DetailRows } from "../analyst-table/DetailRows";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { localDateTimeToIso } from "../analyst-table/filters";
import { useResourceTable } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { ShortId } from "../components/ShortId";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import { timelineEventTypeKey, TIMELINE_EVENT_TYPES } from "./labels";
import { useTimelinePage } from "./timeline-queries";
import {
  emptyTimelineFilters,
  parseTimelineFilters,
  timelineFiltersActive,
  timelineFiltersToParams,
  type TimelineFilters,
} from "./timeline-filters";

/** Draft values of the filter form (browser-local until Apply). */
interface TimelineDraft {
  eventType: TimelineEventTypeName | "";
  occurredFrom: string;
  occurredTo: string;
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: TimelineFilters): TimelineDraft {
  return {
    eventType: filters.eventType ?? "",
    occurredFrom: filters.occurredFrom ?? "",
    occurredTo: filters.occurredTo ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: TimelineDraft): TimelineFilters {
  return {
    eventType: draft.eventType === "" ? undefined : draft.eventType,
    occurredFrom: localDateTimeToIso(draft.occurredFrom),
    occurredTo: localDateTimeToIso(draft.occurredTo),
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: TimelineFilters): string {
  return JSON.stringify([filters.eventType, filters.occurredFrom, filters.occurredTo]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: TimelineDraft): string | null {
  if (draft.occurredFrom !== "" && localDateTimeToIso(draft.occurredFrom) === undefined) {
    return t("filters.time.invalid");
  }
  if (draft.occurredTo !== "" && localDateTimeToIso(draft.occurredTo) === undefined) {
    return t("filters.time.invalid");
  }
  return null;
}

/** The translation shape used by bounded summary helpers. */
type Translate = (key: string, params?: Record<string, string>) => string;

/** One safe bounded summary from public structured fields (no raw text). */
function eventSummary(t: Translate, event: TimelineEvent): string {
  const parts: string[] = [];
  if (event.entity_count !== null) {
    parts.push(t("summary.entities", { count: String(event.entity_count) }));
  }
  if (event.error_code !== null) {
    parts.push(`${t("summary.error")} ${event.error_code}`);
  }
  if (event.reason_code !== null) {
    parts.push(`${t("summary.reason")} ${event.reason_code}`);
  }
  if (event.pivot_depth !== null) {
    parts.push(t("summary.pivotDepth", { depth: String(event.pivot_depth) }));
  }
  return parts.length > 0 ? parts.join(" · ") : t("detail.noReference");
}

/** Analyst-facing Timeline columns — canonical order preserved. */
function timelineColumns(t: (key: string) => string): Column<TimelineEvent>[] {
  return [
    {
      id: "occurredAt",
      header: t("columns.occurredAt"),
      render: (event) => <Timestamp iso={event.occurred_at} />,
      exportValue: (event) => event.occurred_at,
    },
    {
      id: "eventType",
      header: t("columns.eventType"),
      render: (event) => (
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {t(timelineEventTypeKey(event.type))}
        </Typography>
      ),
      exportValue: (event) => t(timelineEventTypeKey(event.type)),
    },
    {
      id: "reference",
      header: t("columns.reference"),
      render: (event) =>
        event.target_entity_id !== null ? <ShortId id={event.target_entity_id} /> : t("detail.noReference"),
      exportValue: (event) => event.target_entity_id ?? "",
    },
    {
      id: "summary",
      header: t("columns.summary"),
      render: (event) => eventSummary(t, event),
      exportValue: (event) => eventSummary(t, event),
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/** The Timeline workspace. */
export function TimelinePage(): ReactElement {
  const { t } = useTranslation("timeline");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<TimelineFilters>({
    parse: parseTimelineFilters,
    toParams: timelineFiltersToParams,
    empty: emptyTimelineFilters,
  });

  const { page, isLoading, error, refetch } = useTimelinePage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<TimelineFilters, TimelineDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyTimelineFilters()),
    committedKey: filtersKey(table.filters),
  });

  const drawerOpen = table.selection !== null;
  const filtersActive = timelineFiltersActive(table.filters);

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
      t("columns.eventType"),
      t("columns.reference"),
      t("columns.summary"),
      t("columns.eventId"),
    ];
    const rows = page.items.map((event) => [
      event.occurred_at,
      t(timelineEventTypeKey(event.type)),
      event.target_entity_id ?? "",
      eventSummary(t, event),
      event.id,
    ]);
    downloadCsv(
      exportFilename("timeline", investigationId),
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
        filters={<TimelineFiltersForm t={t} tCommon={tCommon} form={filterForm} />}
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
      <AnalystTable<TimelineEvent>
        columns={timelineColumns(t)}
        rows={page?.items ?? []}
        getRowId={(event) => event.id}
        ariaLabel={t("title")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("list.error.title")}
        onRetry={refetch}
        emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
        emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
        hasActiveFilters={filtersActive}
        onClearFilters={table.clearFilters}
        onView={(event) => table.openSelection(event.id)}
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
      <DetailDrawer
        open={drawerOpen}
        title={t("detail.title")}
        onClose={table.closeSelection}
      >
        {drawerOpen ? detailBody(t, page, table.selection ?? "") : null}
      </DetailDrawer>
    </Box>
  );
}

/** Timeline event detail: every safe public DTO field (list DTO). */
function detailBody(
  t: (key: string) => string,
  page: { items: readonly TimelineEvent[] } | null,
  selectedId: string,
): ReactElement {
  const event = page?.items.find((row) => row.id === selectedId);
  if (event === undefined) {
    return (
      <Box role="status" sx={{ py: 2, textAlign: "center" }}>
        <Typography variant="body1">{t("detail.notOnPage.title")}</Typography>
        <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
          {t("detail.notOnPage.message")}
        </Typography>
      </Box>
    );
  }
  return (
    <DetailRows
      rows={[
        { label: t("detail.occurredAt"), value: <Timestamp iso={event.occurred_at} /> },
        { label: t("detail.eventType"), value: t(timelineEventTypeKey(event.type)) },
        {
          label: t("detail.provider"),
          value: event.provider ?? t("detail.nullable"),
        },
        {
          label: t("detail.targetEntity"),
          value: event.target_entity_id !== null ? <ShortId id={event.target_entity_id} /> : t("detail.nullable"),
        },
        {
          label: t("detail.entities"),
          value: event.entity_ids.length > 0 ? String(event.entity_ids.length) : t("detail.nullable"),
        },
        {
          label: t("detail.evidence"),
          value: event.evidence_ids.length > 0 ? String(event.evidence_ids.length) : t("detail.nullable"),
        },
        {
          label: t("detail.relationships"),
          value: event.relationship_ids.length > 0 ? String(event.relationship_ids.length) : t("detail.nullable"),
        },
        {
          label: t("detail.entityCount"),
          value: event.entity_count !== null ? String(event.entity_count) : t("detail.nullable"),
        },
        {
          label: t("detail.pivotDepth"),
          value: event.pivot_depth !== null ? String(event.pivot_depth) : t("detail.nullable"),
        },
        {
          label: t("detail.providerCalls"),
          value: event.provider_calls_used !== null ? String(event.provider_calls_used) : t("detail.nullable"),
        },
        {
          label: t("detail.replans"),
          value: event.replans_used !== null ? String(event.replans_used) : t("detail.nullable"),
        },
        {
          label: t("detail.errorCode"),
          value: event.error_code ?? t("detail.nullable"),
        },
        {
          label: t("detail.reasonCode"),
          value: event.reason_code ?? t("detail.nullable"),
        },
        {
          label: t("detail.eventId"),
          value: <ShortId id={event.id} />,
        },
      ]}
    />
  );
}

/** The filter form controls (apply on Apply/Enter, not keystrokes). */
export function TimelineFiltersForm({
  t,
  tCommon,
  form,
}: {
  t: (key: string) => string;
  tCommon: (key: string) => string;
  form: ReturnType<typeof useFilterForm<TimelineFilters, TimelineDraft>>;
}): ReactElement {
  const enter = (event: { key: string }) => {
    if (event.key === "Enter") {
      form.apply();
    }
  };
  const draft = form.draft;
  return (
    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
      <FormControl size="small" sx={{ minWidth: 240 }}>
        <InputLabel id="timeline-event-type-filter-label">{t("filters.eventType.label")}</InputLabel>
        <Select
          labelId="timeline-event-type-filter-label"
          label={t("filters.eventType.label")}
          size="small"
          value={draft.eventType}
          onChange={(event) =>
            form.setDraft({
              ...draft,
              eventType: event.target.value as TimelineEventTypeName | "",
            })}
          sx={{ minWidth: 240 }}
        >
          <MenuItem value="">{tCommon("filters.all")}</MenuItem>
          {TIMELINE_EVENT_TYPES.map((type) => (
            <MenuItem key={type} value={type}>
              {t(timelineEventTypeKey(type))}
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