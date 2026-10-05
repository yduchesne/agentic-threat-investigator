// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships workspace content (PR 24C §9; PR 24D §10).
//
// Route-independent PR 24C Relationships surface over the URL-backed
// resource table controller: stable semantic edges only, entity labels
// never fabricated or N+1-resolved, compact copyable IDs when the DTO
// exposes only UUIDs, and a full-width list/detail surface with a bounded
// observation preview (PR 31F-6 amendment 4). The normal route and the
// PR 24D pivot modal share this one component.

import { Box, FormControl, InputLabel, MenuItem, Select, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation } from "react-router";

import type { Investigation, Relationship, RelationshipTypeName } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { isNotFound404 } from "../analyst-table/detail-error";
import {
  DetailError,
  DetailLoading,
  DetailNotFound,
  ResourceDetailView,
} from "../analyst-table/ResourceDetailView";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { useFilterForm } from "../analyst-table/filter-form";
import { isUuidValue, parseUuidParam } from "../analyst-table/filters";
import type { ResourceTableState } from "../analyst-table/resource-page";
import { runningNotice } from "../analyst-table/running";
import { TableToolbar } from "../analyst-table/TableToolbar";
import { EntityReference } from "../components/EntityReference";
import { PivotMenu } from "../pivots/PivotMenu";
import { relationshipSourceActions, relationshipTargetActions } from "../pivots/pivot-capabilities";
import { relationshipTypeKey, RELATIONSHIP_TYPES } from "./labels";
import { EvolutionLink } from "./EvolutionLink";
import { RelationshipDetail } from "./RelationshipDetail";
import { useRelationshipDetail, useRelationshipsPage } from "./relationships-queries";
import {
  emptyRelationshipFilters,
  relationshipFiltersActive,
  type RelationshipFilters,
} from "./relationships-filters";

/** Draft values of the filter form (browser-local until Apply). */
interface RelationshipDraft {
  sourceEntityId: string;
  targetEntityId: string;
  entityId: string;
  relationshipType: RelationshipTypeName | "";
}

/** Build a draft from the committed URL-backed filters. */
function draftFromFilters(filters: RelationshipFilters): RelationshipDraft {
  return {
    sourceEntityId: filters.sourceEntityId ?? "",
    targetEntityId: filters.targetEntityId ?? "",
    entityId: filters.entityId ?? "",
    relationshipType: filters.relationshipType ?? "",
  };
}

/** Convert one validated draft back to the committed filter model. */
function draftToFilters(draft: RelationshipDraft): RelationshipFilters {
  return {
    sourceEntityId: parseUuidParam(draft.sourceEntityId),
    targetEntityId: parseUuidParam(draft.targetEntityId),
    entityId: parseUuidParam(draft.entityId),
    relationshipType: draft.relationshipType === "" ? undefined : draft.relationshipType,
  };
}

/** Canonical identity of the committed filters (draft resync detection). */
function filtersKey(filters: RelationshipFilters): string {
  return JSON.stringify([
    filters.sourceEntityId,
    filters.targetEntityId,
    filters.entityId,
    filters.relationshipType,
  ]);
}

/** One translated draft validation error, or null when commit-able. */
function draftError(t: (key: string) => string, draft: RelationshipDraft): string | null {
  if (draft.sourceEntityId !== "" && !isUuidValue(draft.sourceEntityId)) {
    return t("filters.entity.invalid");
  }
  if (draft.targetEntityId !== "" && !isUuidValue(draft.targetEntityId)) {
    return t("filters.entity.invalid");
  }
  return null;
}

/** Analyst-facing Relationship columns (server-driven; no sort affordances).
 *
 * PR 31F-5 D4: Source and Target use identical organization — the endpoint
 * Entity value/type precede every ID/action, the compact UUID never leads,
 * and Copy/Pivot/Evolution keep consuming the canonical Entity ID.
 */
export function relationshipColumns(
  t: (key: string) => string,
  investigationId: string,
): Column<Relationship>[] {
  return [
    {
      id: "sourceEntity",
      header: t("columns.sourceEntity"),
      render: (relationship) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap", minWidth: 0 }}>
          <EntityReference
            value={relationship.source_entity_value}
            type={relationship.source_entity_type}
            id={relationship.source_entity_id}
            label={t("columns.sourceEntity")}
          />
          <PivotMenu
            actions={relationshipSourceActions(relationship, "table_cell")}
            ariaLabel={t("columns.sourceEntity")}
          />
          <EvolutionLink
            investigationId={investigationId}
            entityId={relationship.source_entity_id}
            ariaLabel={t("evolution.sourceAria")}
          />
        </Box>
      ),
      exportValue: (relationship) => relationship.source_entity_value ?? "",
    },
    {
      id: "relationshipType",
      header: t("columns.relationshipType"),
      render: (relationship) => (
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {t(relationshipTypeKey(relationship.type))}
        </Typography>
      ),
      exportValue: (relationship) => t(relationshipTypeKey(relationship.type)),
    },
    {
      id: "targetEntity",
      header: t("columns.targetEntity"),
      render: (relationship) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, flexWrap: "wrap", minWidth: 0 }}>
          <EntityReference
            value={relationship.target_entity_value}
            type={relationship.target_entity_type}
            id={relationship.target_entity_id}
            label={t("columns.targetEntity")}
          />
          <PivotMenu
            actions={relationshipTargetActions(relationship, "table_cell")}
            ariaLabel={t("columns.targetEntity")}
          />
          <EvolutionLink
            investigationId={investigationId}
            entityId={relationship.target_entity_id}
            ariaLabel={t("evolution.targetAria")}
          />
        </Box>
      ),
      exportValue: (relationship) => relationship.target_entity_value ?? "",
    },
  ];
}

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

export interface RelationshipsWorkspaceProps {
  investigationId: string;
  investigation: Investigation | null;
  table: ResourceTableState<RelationshipFilters>;
  /** Rendered inside the pivot modal: the modal chrome owns title/nav. */
  embedded?: boolean;
}

/** The Relationships workspace content shared by the route and the modal. */
export function RelationshipsWorkspace({
  investigationId,
  investigation,
  table,
  embedded = false,
}: RelationshipsWorkspaceProps): ReactElement {
  const { t } = useTranslation("relationships");
  const location = useLocation();
  const returnTo = `${location.pathname}${location.search}${location.hash}`;
  const { t: tCommon } = useTranslation("common");

  const { page, isLoading, error, refetch } = useRelationshipsPage(
    investigationId,
    table.filters,
    table.cursor,
  );

  const filterForm = useFilterForm<RelationshipFilters, RelationshipDraft>({
    committed: table.filters,
    buildDraft: draftFromFilters,
    toFilters: draftToFilters,
    validateDraft: (draft) => draftError(t, draft),
    onApply: table.applyFilters,
    onClear: table.clearFilters,
    emptyDraft: draftFromFilters(emptyRelationshipFilters()),
    committedKey: filtersKey(table.filters),
  });

  const detail = useRelationshipDetail(investigationId, table.selection);
  const filtersActive = relationshipFiltersActive(table.filters);

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
    // PR 31F-5 D4: human-useful CSV with value/type + canonical IDs.
    const header = [
      t("columns.sourceEntityValue"),
      t("columns.sourceEntityType"),
      t("columns.sourceEntityId"),
      t("columns.relationshipType"),
      t("columns.targetEntityValue"),
      t("columns.targetEntityType"),
      t("columns.targetEntityId"),
      t("columns.relationshipId"),
    ];
    const rows = page.items.map((relationship) => [
      relationship.source_entity_value ?? "",
      relationship.source_entity_type ?? "",
      relationship.source_entity_id,
      t(relationshipTypeKey(relationship.type)),
      relationship.target_entity_value ?? "",
      relationship.target_entity_type ?? "",
      relationship.target_entity_id,
      relationship.id,
    ]);
    downloadCsv(
      exportFilename("relationships", investigationId),
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
          heading={t("detail.pageTitle")}
          onBack={table.closeSelection}
        >
          {relationshipDetailBody(t, detail, investigationId, embedded)}
        </ResourceDetailView>
      ) : (
        <>
          {!embedded ? (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
              <Typography variant="h2">{t("title")}</Typography>
              <Typography variant="body2" component="span" role="navigation" aria-label={t("nav.label")}>
                <Link to={`/investigations/${investigationId}/relationships/observations`} state={{ returnTo }} style={{ textDecoration: "none" }}>
                  {t("nav.observations")}
                </Link>
              </Typography>
            </Box>
          ) : null}
          <TableToolbar
            filters={<RelationshipFiltersForm t={t} tCommon={tCommon} form={filterForm} />}
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
          <AnalystTable<Relationship>
            columns={relationshipColumns(t, investigationId)}
            rows={page?.items ?? []}
            getRowId={(relationship) => relationship.id}
            ariaLabel={t("title")}
            isLoading={isLoading && page === null}
            error={error}
            errorTitle={t("list.error.title")}
            onRetry={refetch}
            emptyTitle={filtersActive ? t("list.empty.filtered.title") : t("list.empty.title")}
            emptyMessage={filtersActive ? t("list.empty.filtered.message") : t("list.empty.message")}
            hasActiveFilters={filtersActive}
            onClearFilters={table.clearFilters}
            onView={(relationship) => table.openSelection(relationship.id)}
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

/** The detail body with the stable edge + bounded observations preview. */
export function relationshipDetailBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useRelationshipDetail>,
  investigationId: string,
  embedded: boolean,
): ReactElement {
  if (detail.isLoading && detail.relationship === null) {
    return <DetailLoading label={t("detail.loading")} />;
  }
  if (detail.isError && detail.relationship === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DetailNotFound title={t("detail.notFound.title")} />;
    }
    return <DetailError title={t("detail.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.relationship === null) {
    return <DetailLoading label={t("detail.loading")} />;
  }
  return (
    <RelationshipDetail
      investigationId={investigationId}
      relationship={detail.relationship}
      embedded={embedded}
    />
  );
}

/** The filter form controls (apply on Apply/Enter, not keystrokes). */
export function RelationshipFiltersForm({
  t,
  tCommon,
  form,
}: {
  t: (key: string) => string;
  tCommon: (key: string) => string;
  form: ReturnType<typeof useFilterForm<RelationshipFilters, RelationshipDraft>>;
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
        label={t("filters.sourceEntity.label")}
        value={form.draft.sourceEntityId}
        onChange={(event) =>
          form.setDraft({ ...form.draft, sourceEntityId: event.target.value })}
        onKeyDown={enter}
      />
      <TextField
        size="small"
        label={t("filters.targetEntity.label")}
        value={form.draft.targetEntityId}
        onChange={(event) =>
          form.setDraft({ ...form.draft, targetEntityId: event.target.value })}
        onKeyDown={enter}
      />
      <FormControl size="small" sx={{ minWidth: 220 }}>
        <InputLabel id="relationship-type-filter-label">{t("filters.relationshipType.label")}</InputLabel>
        <Select
          labelId="relationship-type-filter-label"
          label={t("filters.relationshipType.label")}
          size="small"
          value={form.draft.relationshipType}
          onChange={(event) =>
            form.setDraft({
              ...form.draft,
              relationshipType: event.target.value as RelationshipTypeName | "",
            })}
          sx={{ minWidth: 220 }}
        >
          <MenuItem value="">{tCommon("filters.all")}</MenuItem>
          {RELATIONSHIP_TYPES.map((type) => (
            <MenuItem key={type} value={type}>
              {t(relationshipTypeKey(type))}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </Box>
  );
}
