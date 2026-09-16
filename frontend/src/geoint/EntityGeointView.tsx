// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Entity GEOINT resource view (PR 26E §8).
//
// Route-independent component (usable inside the GEOINT route and the
// PR 24D PivotWorkspace): one Entity's Investigation-relative current
// geographic context plus its pageable immutable observation history.
//
// The current section is explicitly labelled "Current in this
// Investigation": it is the newest scoped observation under the exact
// PR 26A ordering, never the global materialized EntityLocation state.
// History rows are immutable observations in server order; no movement
// path is drawn and no ended/continuous presence is inferred. Current
// emphasis never implies historical observations were false. Row actions
// use the exact returned observation/evidence/location identities — no
// Evidence scanning, no client-side spatial inference.

import { Alert, Box, Button, Typography } from "@mui/material";
import { useState } from "react";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { GeointObservation } from "../api/schema-types";
import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import {
  DrawerError,
  DrawerLoading,
} from "../analyst-table/DetailDrawer";
import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import type { ResourceTableState } from "../analyst-table/resource-page";
import { EmptyState } from "../components/AsyncState";
import { formatDateTime } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  entityActions,
  entityCompactLabel,
  geointObservationEvidenceAction,
  geointObservationLocationActions,
  type PivotAction,
} from "../pivots/pivot-capabilities";
import type { GeointEntityFilters } from "./geoint-filters";
import { GeointDetailDrawer } from "./GeointDetailDrawer";
import { locationCanonicalLabel } from "./geoint-model";
import { locationPrecisionKey, locationTypeKey } from "./geoint-labels";
import { useGeointEntity, useGeointEntityHistory } from "./geoint-queries";

/** Whether the backend history page offers a next page. */
function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/** One observation row's exact Explore actions (entity/location/evidence). */
export function observationExploreActions(
  observation: Pick<
    GeointObservation,
    "entity_id" | "evidence_id" | "location"
  >,
): PivotAction[] {
  const entityLabel = entityCompactLabel(observation.entity_id);
  return [
    ...geointObservationEvidenceAction(observation, "geoint_observation"),
    ...geointObservationLocationActions(observation, "geoint_location"),
    ...entityActions(observation.entity_id, entityLabel, "geoint_observation"),
  ];
}

export interface EntityGeointViewProps {
  investigationId: string;
  /** URL-backed table state (entity filter, history cursor, selection). */
  table: ResourceTableState<GeointEntityFilters>;
}

/** One Entity's GEOINT current/history surface. */
export function EntityGeointView({
  investigationId,
  table,
}: EntityGeointViewProps): ReactElement {
  const { t } = useTranslation("geoint");
  const entityId = table.filters.entityId ?? null;

  const { entity, isLoading, isError, error, refetch } = useGeointEntity(
    investigationId,
    entityId,
  );
  const {
    page,
    isLoading: historyLoading,
    error: historyErrorValue,
    refetch: historyRefetch,
  } = useGeointEntityHistory(investigationId, entityId, table.cursor);

  // One shared drawer serves observation detail and exact Evidence; only
  // one is open at a time.
  const [evidenceId, setEvidenceId] = useState<string | null>(null);
  const drawerOpen = table.selection !== null || evidenceId !== null;
  const closeDrawer = (): void => {
    table.closeSelection();
    setEvidenceId(null);
  };
  const switchToEvidence = (id: string): void => {
    table.closeSelection();
    setEvidenceId(id);
  };

  if (entityId === null) {
    return (
      <EmptyState
        title={t("entity.empty.title")}
        message={t("entity.empty.message")}
      />
    );
  }
  if (isLoading && entity === null) {
    return <DrawingStatus label={t("entity.loading")} />;
  }
  if (isError && entity === null && error !== null) {
    if (isNotFound404(error)) {
      return (
        <Alert severity="info" role="status">
          {t("entity.notFound.title")}
        </Alert>
      );
    }
    return <DrawerError title={t("entity.loadError.title")} onRetry={refetch} />;
  }
  if (entity === null) {
    return <DrawingStatus label={t("entity.loading")} />;
  }

  const current = entity.current_observation;

  return (
    <Box>
      <Typography variant="h3" sx={{ mb: 0.75 }}>
        {entity.entity_value}
      </Typography>
      <Typography variant="caption" component="div" role="note" sx={{ mb: 1 }}>
        {t("entity.intro", { id: entity.entity_id })}
      </Typography>

      <Alert severity="info" role="note" sx={{ mb: 1 }}>
        {t("entity.disclaimer")}
      </Alert>

      <DetailSection title={t("entity.current.title")}>
        {current === null ? (
          <Typography variant="body2">{t("entity.current.none")}</Typography>
        ) : (
          <CurrentContextRow
            observation={current}
            onViewEvidence={switchToEvidence}
          />
        )}
      </DetailSection>

      <DetailSection title={t("entity.history.title")}>
        <Typography variant="caption" component="div" sx={{ mb: 1 }}>
          {t("entity.history.note")}
        </Typography>
        {historyErrorValue !== null && page === null ? (
          <DrawerError
            title={t("entity.history.loadError.title")}
            onRetry={historyRefetch}
          />
        ) : null}
        <AnalystTable<GeointObservation>
          columns={historyColumns(t, (evidenceIdValue) => setEvidenceId(evidenceIdValue))}
          rows={page?.items ?? []}
          getRowId={(observation) => observation.observation_id}
          ariaLabel={t("entity.history.aria")}
          isLoading={historyLoading && page === null}
          error={historyErrorValue}
          errorTitle={t("entity.history.loadError.title")}
          onRetry={historyRefetch}
          emptyTitle={t("entity.history.empty.title")}
          emptyMessage={t("entity.history.empty.message")}
          hasActiveFilters={false}
          onClearFilters={() => undefined}
          onView={(observation) => table.openSelection(observation.observation_id)}
          viewLabel={t("entity.history.row.view")}
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
          loadingLabel={t("entity.history.loading")}
          staleErrorTitle={t("entity.history.staleError")}
          onReturnToFirstPage={table.returnToFirstPage}
        />
      </DetailSection>

      <GeointDetailDrawer
        open={drawerOpen}
        title={
          table.selection !== null
            ? t("detail.observation.drawerTitle")
            : t("detail.evidence.drawerTitle")
        }
        onClose={closeDrawer}
        investigationId={investigationId}
        observationId={table.selection}
        onViewEvidence={switchToEvidence}
        evidenceId={evidenceId}
      />
    </Box>
  );
}

/** Loading-state wrapper with the shared text. */
function DrawingStatus({ label }: { label: string }): ReactElement {
  return <DrawerLoading label={label} />;
}

/** The Investigation-relative current context row of one Entity. */
function CurrentContextRow({
  observation,
  onViewEvidence,
}: {
  observation: GeointObservation;
  onViewEvidence: (evidenceId: string) => void;
}): ReactElement {
  const { t } = useTranslation("geoint");
  const locationLabel =
    locationCanonicalLabel(observation.location) ?? t("location.unavailable");
  const actions = observationExploreActions(observation);
  return (
    <Box>
      <DetailSection title={t("entity.current.location")}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {locationLabel}
        </Typography>
        <Typography variant="caption" component="div">
          {t("detail.observation.locationType", {
            type: t(locationTypeKey(observation.location.location_type)),
          })}
        </Typography>
        <Typography variant="caption" component="div">
          {t("detail.observation.precision", {
            precision: t(locationPrecisionKey(observation.precision)),
          })}
        </Typography>
      </DetailSection>
      <DetailSection title={t("entity.current.timestamps")}>
        <Typography variant="body2">
          {t("detail.observation.observed", {
            time:
              observation.observed_at !== null
                ? formatDateTime(observation.observed_at)
                : t("detail.observation.notObserved"),
          })}
        </Typography>
        <Typography variant="body2">
          {t("detail.observation.retrieved", {
            time: formatDateTime(observation.retrieved_at),
          })}
        </Typography>
        <Typography variant="body2">
          {t("detail.observation.resolved", {
            time: formatDateTime(observation.resolved_at),
          })}
        </Typography>
      </DetailSection>
      <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 1, mt: 0.5 }}>
        <Button
          size="small"
          variant="outlined"
          data-testid="geoint-current-view-evidence"
          onClick={() => onViewEvidence(observation.evidence_id)}
          sx={{ textTransform: "none" }}
        >
          {t("entity.current.viewEvidence")}
        </Button>
        <PivotMenu
          actions={actions}
          triggerLabel={t("entity.current.explore")}
          ariaLabel={t("entity.current.exploreAria", { location: locationLabel })}
        />
      </Box>
    </Box>
  );
}

/** The history table columns (server order is authoritative). */
function historyColumns(
  t: (key: string, params?: Record<string, unknown>) => string,
  onViewEvidence: (evidenceId: string) => void,
): Column<GeointObservation>[] {
  return [
    {
      id: "location",
      header: t("columns.location"),
      render: (observation) =>
        locationCanonicalLabel(observation.location) ?? t("location.unavailable"),
      exportValue: (observation) =>
        locationCanonicalLabel(observation.location) ?? "",
    },
    {
      id: "locationType",
      header: t("columns.locationType"),
      render: (observation) => t(locationTypeKey(observation.location.location_type)),
      exportValue: (observation) => t(locationTypeKey(observation.location.location_type)),
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
      render: (observation) => (
        <Button
          size="small"
          variant="text"
          onClick={() => onViewEvidence(observation.evidence_id)}
          sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
        >
          {t("columns.evidenceAction")}
        </Button>
      ),
      exportValue: () => "",
    },
    {
      id: "explore",
      header: t("columns.explore"),
      render: (observation) => (
        <PivotMenu
          actions={observationExploreActions(observation)}
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