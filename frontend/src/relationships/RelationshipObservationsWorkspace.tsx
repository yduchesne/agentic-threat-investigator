// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// RelationshipObservations workspace content (PR 24C §9; PR 24D §6, §10).
//
// Route-independent first-class RelationshipObservation surface: the
// immutable historical observation browsed directly, never through generic
// History. ``observed_at`` and ``retrieved_at`` remain visibly independent
// with half-open ranges; no started/ended/removed/continuous-validity
// semantics are inferred. Detail uses the exact list DTO (no single-GET
// endpoint exists and none is invented). The PR 24D modal embeds the same
// workspace through the pivot-step port.

import { Box, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import type { Investigation, RelationshipObservation } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer } from "../analyst-table/DetailDrawer";
import { DetailRows } from "../analyst-table/DetailRows";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { isUuidValue, localDateTimeToIso, parseUuidParam } from "../analyst-table/filters";
import type { ResourceTableState } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import { observationActions } from "../pivots/pivot-capabilities";
import { useObservationsPage } from "./relationships-queries";
import {
  emptyObservationFilters,
  observationFiltersActive,
  type ObservationFilters,
} from "./relationships-filters";

/** Draft values of the filter form (browser-local until Apply). */
interface ObservationDraft {
  relationshipId: string;
  source: string;
  observedFrom: string;
  observedTo: string;
  retrievedFrom: string;
  retrievedTo: string;
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: ObservationFilters): ObservationDraft {
  return {
    relationshipId: filters.relationshipId ?? "",
    source: filters.source ?? "",
    observedFrom: filters.observedFrom ?? "",
    observedTo: filters.observedTo ?? "",
    retrievedFrom: filters.retrievedFrom ?? "",
    retrievedTo: filters.retrievedTo ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: ObservationDraft): ObservationFilters {
  return {
    relationshipId: parseUuidParam(draft.relationshipId),
    source: nonBlank(draft.source),
    observedFrom: localDateTimeToIso(draft.observedFrom),
    observedTo: localDateTimeToIso(draft.observedTo),
    retrievedFrom: localDateTimeToIso(draft.retrievedFrom),
    retrievedTo: localDateTimeToIso(draft.retrievedTo),
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: ObservationFilters): string {
  return JSON.stringify([
    filters.relationshipId,
    filters.source,
    filters.observedFrom,
    filters.observedTo,
    filters.retrievedFrom,
    filters.retrievedTo,
  ]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: ObservationDraft): string | null {
  if (draft.relationshipId !== "" && !isUuidValue(draft.relationshipId)) {
    return t("filters.relationship.invalid");
  }
  for (const value of [draft.observedFrom, draft.observedTo, draft.retrievedFrom, draft.retrievedTo]) {
    if (value !== "" && localDateTimeToIso(value) === undefined) {
      return t("filters.time.invalid");
    }
  }
  return null;
}

/** Analyst-facing observation columns (from the exact list DTO). */
export function observationColumns(t: (key: string) => string): Column<RelationshipObservation>[] {
  return [
    {
      id: "relationship",
      header: t("columns.relationship"),
      render: (observation) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <CompactId id={observation.relationship_id} label={t("columns.relationship")} />
          <PivotMenu
            actions={observationActions(observation, "table_cell")}
            ariaLabel={t("columns.relationship")}
          />
        </Box>
      ),
      exportValue: (observation) => observation.relationship_id,
    },
    {
      id: "source",
      header: t("columns.source"),
      render: (observation) => observation.source,
      exportValue: (observation) => observation.source,
    },
    {
      id: "observedAt",
      header: t("columns.observedAt"),
      render: (observation) =>
        observation.observed_at !== null ? <Timestamp iso={observation.observed_at} /> : t("detail.notObserved"),
      exportValue: (observation) => observation.observed_at ?? "",
    },
    {
      id: "retrievedAt",
      header: t("columns.retrievedAt"),
      render: (observation) => <Timestamp iso={observation.retrieved_at} />,
      exportValue: (observation) => observation.retrieved_at,
    },
    {
      id: "evidence",
      header: t("columns.evidence"),
      render: (observation) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <CompactId id={observation.evidence_id} label={t("columns.evidence")} />
          <PivotMenu
            actions={observationActions(observation, "table_cell")}
            ariaLabel={t("columns.evidence")}
          />
        </Box>
      ),
      exportValue: (observation) => observation.evidence_id,
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

export interface RelationshipObservationsWorkspaceProps {
  investigationId: string;
  investigation: Investigation | null;
  table: ResourceTableState<ObservationFilters>;
  /** Rendered inside the pivot modal: the modal chrome owns title/nav. */
  embedded?: boolean;
}

/** The RelationshipObservations workspace content (route + modal). */
export function RelationshipObservationsWorkspace({
  investigationId,
  investigation,
  table,
  embedded = false,
}: RelationshipObservationsWorkspaceProps): ReactElement {
  const { t } = useTranslation("relationships");
  const { t: tCommon } = useTranslation("common");

  const { page, isLoading, error, refetch } = useObservationsPage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<ObservationFilters, ObservationDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyObservationFilters()),
    committedKey: filtersKey(table.filters),
  });

  const drawerOpen = table.selection !== null;
  const filtersActive = observationFiltersActive(table.filters);

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
      t("columns.relationship"),
      t("columns.source"),
      t("columns.observedAt"),
      t("columns.retrievedAt"),
      t("columns.evidence"),
      t("columns.observationId"),
    ];
    const rows = page.items.map((observation) => [
      observation.relationship_id,
      observation.source,
      observation.observed_at ?? "",
      observation.retrieved_at,
      observation.evidence_id,
      observation.id,
    ]);
    downloadCsv(
      exportFilename("relationship-observations", investigationId),
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
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <Typography variant="h2" sx={{ mr: 1 }}>
            {t("observations.title")}
          </Typography>
          <Typography variant="body2" component="span" role="navigation" aria-label={t("nav.label")}>
            <Link to={`/investigations/${investigationId}/relationships`} style={{ textDecoration: "none" }}>
              {t("nav.relationships")}
            </Link>
          </Typography>
        </Box>
      ) : null}
      {!embedded ? (
        <Typography variant="caption" component="div" sx={{ mb: 1 }}>
          {t("observations.intro")}
        </Typography>
      ) : null}
      <TableToolbar
        filters={<ObservationFiltersForm t={t} form={filterForm} />}
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
      <AnalystTable<RelationshipObservation>
        columns={observationColumns(t)}
        rows={page?.items ?? []}
        getRowId={(observation) => observation.id}
        ariaLabel={t("observations.title")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("list.error.title")}
        onRetry={refetch}
        emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
        emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
        hasActiveFilters={filtersActive}
        onClearFilters={table.clearFilters}
        onView={(observation) => table.openSelection(observation.id)}
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
        title={t("observations.detail.title")}
        onClose={table.closeSelection}
      >
        {drawerOpen ? observationDetailBody(t, page, table.selection ?? "") : null}
      </DetailDrawer>
    </Box>
  );
}

/**
 * The observation detail body: the exact list DTO, because no single-GET
 * observation endpoint exists and none is invented.
 */
function observationDetailBody(
  t: (key: string) => string,
  page: { items: readonly RelationshipObservation[] } | null,
  selectedId: string,
): ReactElement {
  const observation = page?.items.find((row) => row.id === selectedId);
  if (observation === undefined) {
    // The selected row is not on the currently loaded page; unlike
    // resource detail there is no single-GET endpoint to recover it, so the
    // drawer states exactly that instead of spinning forever.
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
        {
          label: t("detail.relationshipId"),
          value: <CompactId id={observation.relationship_id} label={t("detail.relationshipId")} />,
        },
        { label: t("detail.source"), value: observation.source },
        {
          label: t("detail.observedAt"),
          value:
            observation.observed_at !== null
              ? <Timestamp iso={observation.observed_at} />
              : t("detail.notObserved"),
        },
        { label: t("detail.retrievedAt"), value: <Timestamp iso={observation.retrieved_at} /> },
        {
          label: t("detail.evidenceId"),
          value: <CompactId id={observation.evidence_id} label={t("detail.evidenceId")} />,
        },
        {
          label: t("detail.confidence"),
          value: observation.confidence !== null ? String(observation.confidence) : t("detail.nullable"),
        },
        {
          label: t("detail.observationId"),
          value: <CompactId id={observation.id} label={t("detail.observationId")} />,
        },
      ]}
    />
  );
}

/** The filter form controls (apply on Apply/Enter, not keystrokes). */
export function ObservationFiltersForm({
  t,
  form,
}: {
  t: (key: string) => string;
  form: ReturnType<typeof useFilterForm<ObservationFilters, ObservationDraft>>;
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
        label={t("filters.relationship.label")}
        value={draft.relationshipId}
        onChange={(event) => form.setDraft({ ...draft, relationshipId: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        size="small"
        label={t("filters.source.label")}
        value={draft.source}
        onChange={(event) => form.setDraft({ ...draft, source: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.observedFrom.label")}
        value={draft.observedFrom}
        onChange={(event) => form.setDraft({ ...draft, observedFrom: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.observedTo.label")}
        value={draft.observedTo}
        onChange={(event) => form.setDraft({ ...draft, observedTo: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.retrievedFrom.label")}
        value={draft.retrievedFrom}
        onChange={(event) => form.setDraft({ ...draft, retrievedFrom: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        type="datetime-local"
        size="small"
        label={t("filters.retrievedTo.label")}
        value={draft.retrievedTo}
        onChange={(event) => form.setDraft({ ...draft, retrievedTo: event.target.value })}
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