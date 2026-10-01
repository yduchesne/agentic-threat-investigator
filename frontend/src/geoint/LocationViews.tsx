// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Location GEOINT resource views (PR 26E §9, §7; PR 31F-8 §10).
//
// Route-independent components (used by the routed Location Entities /
// observations pages): one canonical Location's Investigation-scoped
// Entities and observations, with the server-owned containment controller.
//
// PR 31F-8: the former local list/detail replacement (local evidenceId +
// table.selection -> ResourceDetailView) is retired. "View Evidence" is a
// semantic route link to the exact Evidence route and row View navigates
// to the exact GEOINT observation route; browser Back reconstructs the
// Location surface from route/query state alone.
//
// Exact (default) and "include contained" are semantic query changes:
// toggling resets cursor/back-stack through the shared table controller
// and sends the exact ``include_contained`` boolean to the server. The
// returned ``containment_applied`` flag is represented honestly — when the
// server could not expand (city Points, NULL boundary geometry), the
// exact-only explanation is shown. Containment is never computed
// client-side. A visible neutral note states that Entities at the same
// canonical Location are not implied to be related.

import { Alert, Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useNavigate } from "react-router";

import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { isNotFound404 } from "../analyst-table/detail-error";
import { DetailError, DetailLoading } from "../analyst-table/ResourceDetailView";
import type { ResourceTableState } from "../analyst-table/resource-page";
import { EmptyState } from "../components/AsyncState";
import { formatDateTime } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  entityActions,
  entityCompactLabel,
  entityGeointAction,
  geointObservationEvidenceAction,
  geointObservationLocationActions,
  type PivotAction,
} from "../pivots/pivot-capabilities";
import type {
  GeointEntityLocation,
  GeointObservation,
} from "../api/schema-types";
import type { GeointLocationFilters } from "./geoint-filters";
import { locationCanonicalLabel } from "./geoint-model";
import { locationPrecisionKey, locationTypeKey } from "./geoint-labels";
import {
  useGeointLocationEntities,
  useGeointLocationObservations,
} from "./geoint-queries";

/** Whether the backend page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/** The exact Explore actions of one Entity-location item. */
export function entityLocationExploreActions(
  item: GeointEntityLocation,
): PivotAction[] {
  const observation = item.current_observation;
  if (observation === null) {
    return [
      entityGeointAction(item, "geoint_location"),
      ...entityActions(item.entity_id, item.entity_value, "geoint_location"),
    ];
  }
  return [
    ...geointObservationEvidenceAction(observation, "geoint_observation"),
    ...geointObservationLocationActions(observation, "geoint_location"),
    entityGeointAction(item, "geoint_location"),
    ...entityActions(item.entity_id, item.entity_value, "geoint_location"),
  ];
}

/** The exact Explore actions of one Location observation row. */
function locationObservationActions(
  observation: GeointObservation,
): PivotAction[] {
  return [
    ...geointObservationEvidenceAction(observation, "geoint_observation"),
    ...geointObservationLocationActions(observation, "geoint_location"),
  ];
}

export interface LocationEntitiesViewProps {
  investigationId: string;
  /** URL-backed table state (location filter, containment, cursor, selection). */
  table: ResourceTableState<GeointLocationFilters>;
}

/** One canonical Location's scoped Entities. */
export function LocationEntitiesView({
  investigationId,
  table,
}: LocationEntitiesViewProps): ReactElement {
  const { t } = useTranslation("geoint");
  const navigate = useNavigate();
  const locationId = table.filters.locationId ?? null;
  const includeContained = table.filters.includeContained ?? false;

  const {
    page,
    isLoading,
    isError,
    error,
    refetch,
  } = useGeointLocationEntities(
    investigationId,
    locationId,
    includeContained,
    table.cursor,
  );

  // Route-owned exact navigation (PR 31F-8): observation rows and Evidence
  // actions are semantic destinations; the URL is the only detail state.
  const openObservation = (observationId: string): void => {
    navigate(`/investigations/${investigationId}/geoint/observations/${observationId}`);
  };

  if (locationId === null) {
    return (
      <EmptyState
        title={t("location.empty.title")}
        message={t("location.empty.message")}
      />
    );
  }
  if (isLoading && page === null) {
    return <DetailLoading label={t("location.loading")} />;
  }
  if (isError && page === null && error !== null && !isNotFound404(error)) {
    return <DetailError title={t("location.loadError.title")} onRetry={refetch} />;
  }
  if (isError && page === null && error !== null) {
    return (
      <Alert severity="info" role="status">
        {t("location.notFound.title")}
      </Alert>
    );
  }

  return (
    <Box>
      <LocationScopeControls
        includeContained={includeContained}
        onToggle={() =>
          table.applyFilters({
            ...table.filters,
            includeContained: !includeContained,
          })
        }
        containmentApplied={page?.containment_applied ?? null}
      />
      <Alert severity="info" role="note" sx={{ mt: 1 }}>
        {t("location.disclaimer")}
      </Alert>
      <AnalystTable<GeointEntityLocation>
        columns={locationEntitiesColumns(t, investigationId)}
        rows={page?.items ?? []}
        getRowId={(item) => item.entity_id}
        ariaLabel={t("location.entities.aria")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("location.entities.loadError.title")}
        onRetry={refetch}
        emptyTitle={t("location.entities.empty.title")}
        emptyMessage={t("location.entities.empty.message")}
        hasActiveFilters={false}
        onClearFilters={() => undefined}
        onView={(item) => {
          if (item.current_observation !== null) {
            openObservation(item.current_observation.observation_id);
          }
        }}
        viewLabel={t("location.entities.row.view")}
        navigation={{
          canGoPrevious: table.canGoPrevious,
          canGoNext: hasNext(page),
          onPrevious: table.goPrevious,
          onNext: () => {
            if (
              page !== null &&
              page.next_cursor !== null &&
              page.next_cursor !== undefined
            ) {
              table.goNext(page.next_cursor);
            }
          },
        }}
        loadingLabel={t("location.entities.loading")}
        staleErrorTitle={t("location.entities.staleError")}
        onReturnToFirstPage={table.returnToFirstPage}
      />
    </Box>
  );
}

export interface LocationObservationsViewProps {
  investigationId: string;
  table: ResourceTableState<GeointLocationFilters>;
}

/** One canonical Location's scoped observations. */
export function LocationObservationsView({
  investigationId,
  table,
}: LocationObservationsViewProps): ReactElement {
  const { t } = useTranslation("geoint");
  const navigate = useNavigate();
  const locationId = table.filters.locationId ?? null;
  const includeContained = table.filters.includeContained ?? false;

  const {
    page,
    isLoading,
    isError,
    error,
    refetch,
  } = useGeointLocationObservations(
    investigationId,
    locationId,
    includeContained,
    table.cursor,
  );

  // Route-owned exact navigation (PR 31F-8): observation rows and Evidence
  // actions are semantic destinations; the URL is the only detail state.
  const openObservation = (observationId: string): void => {
    navigate(`/investigations/${investigationId}/geoint/observations/${observationId}`);
  };

  if (locationId === null) {
    return (
      <EmptyState
        title={t("location.empty.title")}
        message={t("location.empty.message")}
      />
    );
  }
  if (isLoading && page === null) {
    return <DetailLoading label={t("location.loading")} />;
  }
  if (isError && page === null && error !== null && !isNotFound404(error)) {
    return <DetailError title={t("location.loadError.title")} onRetry={refetch} />;
  }
  if (isError && page === null && error !== null) {
    return (
      <Alert severity="info" role="status">
        {t("location.notFound.title")}
      </Alert>
    );
  }

  return (
    <Box>
      <LocationScopeControls
        includeContained={includeContained}
        onToggle={() =>
          table.applyFilters({
            ...table.filters,
            includeContained: !includeContained,
          })
        }
        containmentApplied={page?.containment_applied ?? null}
      />
      <Alert severity="info" role="note" sx={{ mt: 1 }}>
        {t("location.disclaimer")}
      </Alert>
      <AnalystTable<GeointObservation>
        columns={locationObservationsColumns(t, investigationId)}
        rows={page?.items ?? []}
        getRowId={(observation) => observation.observation_id}
        ariaLabel={t("location.observations.aria")}
        isLoading={isLoading && page === null}
        error={error}
        errorTitle={t("location.observations.loadError.title")}
        onRetry={refetch}
        emptyTitle={t("location.observations.empty.title")}
        emptyMessage={t("location.observations.empty.message")}
        hasActiveFilters={false}
        onClearFilters={() => undefined}
        onView={(observation) => openObservation(observation.observation_id)}
        viewLabel={t("location.observations.row.view")}
        navigation={{
          canGoPrevious: table.canGoPrevious,
          canGoNext: hasNext(page),
          onPrevious: table.goPrevious,
          onNext: () => {
            if (
              page !== null &&
              page.next_cursor !== null &&
              page.next_cursor !== undefined
            ) {
              table.goNext(page.next_cursor);
            }
          },
        }}
        loadingLabel={t("location.observations.loading")}
        staleErrorTitle={t("location.observations.staleError")}
        onReturnToFirstPage={table.returnToFirstPage}
      />
    </Box>
  );
}

/** The containment controller + honest containment status (PR 26E §9, §15).
 *
 * PR 31F-8: the control is two ordinary toggle buttons (the semantic
 * query change flows through the shared table controller, resetting the
 * cursor/back stack exactly like any other filter Apply). The former MUI
 * ToggleButtonGroup roving-focus internals are NOT used: on the real
 * stack the focused ToggleButton could be re-created by the router commit
 * re-render and Chromium's focus-fixup raced it to death (deterministic
 * main-thread stall reproduced with pointer AND keyboard activation).
 */
function LocationScopeControls({
  includeContained,
  onToggle,
  containmentApplied,
}: {
  includeContained: boolean;
  onToggle: () => void;
  containmentApplied: boolean | null;
}): ReactElement {
  const { t } = useTranslation("geoint");
  return (
    <Box role="group" aria-label={t("location.scope.aria")}>
      <Box sx={{ display: "inline-flex", gap: 1, alignItems: "center" }}>
        <Button
          size="small"
          variant={!includeContained ? "contained" : "outlined"}
          onClick={!includeContained ? undefined : onToggle}
          aria-pressed={!includeContained}
          aria-label={t("location.scope.exact")}
          sx={{ textTransform: "none" }}
        >
          {t("location.scope.exact")}
        </Button>
        <Button
          size="small"
          variant={includeContained ? "contained" : "outlined"}
          onClick={includeContained ? undefined : onToggle}
          aria-pressed={includeContained}
          aria-label={t("location.scope.contains")}
          sx={{ textTransform: "none" }}
        >
          {t("location.scope.contains")}
        </Button>
      </Box>
      {containmentApplied !== null ? (
        <Typography variant="caption" component="div" role="note" sx={{ mt: 0.5 }}>
          {containmentApplied
            ? t("location.containment.applied")
            : t("location.containment.exact")}
        </Typography>
      ) : null}
    </Box>
  );
}

/** The Location -> Entities columns (Step 7; route-owned Evidence links). */
function locationEntitiesColumns(
  t: (key: string, params?: Record<string, unknown>) => string,
  investigationId: string,
): Column<GeointEntityLocation>[] {
  const evidenceLink = (item: GeointEntityLocation): ReactElement =>
    item.current_observation !== null ? (
      <Button
        size="small"
        variant="text"
        component={RouterLink}
        to={`/investigations/${investigationId}/evidence/${item.current_observation.evidence_id}`}
        sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
      >
        {t("columns.evidenceAction")}
      </Button>
    ) : (
      <Typography variant="caption">{t("location.unavailable")}</Typography>
    );
  return [
    {
      id: "entity",
      header: t("columns.entity"),
      render: (item) => (
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {item.entity_value}
          </Typography>
        </Box>
      ),
      exportValue: (item) => item.entity_value,
    },
    {
      id: "entityType",
      header: t("columns.entityType"),
      render: (item) => t(`entityType.${item.entity_type}`),
      exportValue: (item) => t(`entityType.${item.entity_type}`),
    },
    {
      id: "location",
      header: t("columns.location"),
      render: (item) =>
        item.current_observation !== null
          ? (locationCanonicalLabel(item.current_observation.location) ??
            t("location.unavailable"))
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? (locationCanonicalLabel(item.current_observation.location) ?? "")
          : "",
    },
    {
      id: "locationType",
      header: t("columns.locationType"),
      render: (item) =>
        item.current_observation !== null
          ? t(locationTypeKey(item.current_observation.location.location_type))
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? t(locationTypeKey(item.current_observation.location.location_type))
          : "",
    },
    {
      id: "precision",
      header: t("columns.precision"),
      render: (item) =>
        item.current_observation !== null
          ? t(locationPrecisionKey(item.current_observation.precision))
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? t(locationPrecisionKey(item.current_observation.precision))
          : "",
    },
    {
      id: "observedAt",
      header: t("columns.observedAt"),
      render: (item) =>
        item.current_observation !== null
          ? (item.current_observation.observed_at !== null
              ? formatDateTime(item.current_observation.observed_at)
              : t("detail.observation.notObserved"))
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? (item.current_observation.observed_at ?? "")
          : "",
    },
    {
      id: "retrievedAt",
      header: t("columns.retrievedAt"),
      render: (item) =>
        item.current_observation !== null
          ? formatDateTime(item.current_observation.retrieved_at)
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? item.current_observation.retrieved_at
          : "",
    },
    {
      id: "resolvedAt",
      header: t("columns.resolvedAt"),
      render: (item) =>
        item.current_observation !== null
          ? formatDateTime(item.current_observation.resolved_at)
          : t("location.unavailable"),
      exportValue: (item) =>
        item.current_observation !== null
          ? item.current_observation.resolved_at
          : "",
    },
    {
      id: "evidence",
      header: t("columns.evidence"),
      render: evidenceLink,
      exportValue: () => "",
    },
    {
      id: "explore",
      header: t("columns.explore"),
      render: (item) => (
        <PivotMenu
          actions={entityLocationExploreActions(item)}
          triggerLabel={t("explore.trigger")}
          ariaLabel={t("explore.entityRowAria", { entity: item.entity_value })}
        />
      ),
      exportValue: () => "",
    },
  ];
}

/** The Location -> observations columns (Step 7; route-owned Evidence links). */
function locationObservationsColumns(
  t: (key: string, params?: Record<string, unknown>) => string,
  investigationId: string,
): Column<GeointObservation>[] {
  const evidenceLink = (observation: GeointObservation): ReactElement => (
    <Button
      size="small"
      variant="text"
      component={RouterLink}
      to={`/investigations/${investigationId}/evidence/${observation.evidence_id}`}
      sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
    >
      {t("columns.evidenceAction")}
    </Button>
  );
  return [
    {
      id: "entity",
      header: t("columns.entity"),
      render: (observation) => (
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {entityCompactLabel(observation.entity_id)}
        </Typography>
      ),
      exportValue: (observation) => entityCompactLabel(observation.entity_id),
    },
    {
      id: "location",
      header: t("columns.location"),
      render: (observation) =>
        locationCanonicalLabel(observation.location) ?? t("location.unavailable"),
      exportValue: (observation) =>
        locationCanonicalLabel(observation.location) ?? "",
    },
    {
      id: "precision",
      header: t("columns.precision"),
      render: (observation) => t(locationPrecisionKey(observation.precision)),
      exportValue: (observation) => t(locationPrecisionKey(observation.precision)),
    },
    {
      id: "observedAt",
      header: t("columns.observedAt"),
      render: (observation) =>
        observation.observed_at !== null
          ? formatDateTime(observation.observed_at)
          : t("detail.observation.notObserved"),
      exportValue: (observation) => observation.observed_at ?? "",
    },
    {
      id: "retrievedAt",
      header: t("columns.retrievedAt"),
      render: (observation) => formatDateTime(observation.retrieved_at),
      exportValue: (observation) => observation.retrieved_at,
    },
    {
      id: "resolvedAt",
      header: t("columns.resolvedAt"),
      render: (observation) => formatDateTime(observation.resolved_at),
      exportValue: (observation) => observation.resolved_at,
    },
    {
      id: "evidence",
      header: t("columns.evidence"),
      render: evidenceLink,
      exportValue: () => "",
    },
    {
      id: "explore",
      header: t("columns.explore"),
      render: (observation) => (
        <PivotMenu
          actions={locationObservationActions(observation)}
          triggerLabel={t("explore.trigger")}
          ariaLabel={t("explore.rowAria", {
            location:
              locationCanonicalLabel(observation.location) ?? t("location.unavailable"),
          })}
        />
      ),
      exportValue: () => "",
    },
  ];
}
