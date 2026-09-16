// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT workspace route page (PR 26E §4-§6, §15).
//
// First-class Investigation-scoped GEOINT tab: the persistent semantic
// disclaimer, the bounded PR 26D summary, the canonical neutral map over
// the currently loaded top Locations, and an always-available non-map
// table with typed Explore actions. The map plots only the returned
// bounded top Locations (never all pages, never cached state); when no
// observation or no plottable coordinate exists the honest empty state is
// rendered — never an empty world map.
//
// Top Locations are exact scoped observation groups, never
// hotspots/threat concentration; no risk coloring exists anywhere.

import { Alert, Box, Paper, Typography } from "@mui/material";
import { useState } from "react";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router";

import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { DetailDrawer, DrawerError, DrawerLoading, DrawerNotFound } from "../analyst-table/DetailDrawer";
import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { useEvidenceDetail } from "../evidence/evidence-queries";
import { EvidenceDetail } from "../evidence/EvidenceDetail";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  locationEntitiesAction,
  locationObservationsAction,
} from "../pivots/pivot-capabilities";
import type {
  GeointSummary,
  GeointTopLocation,
} from "../api/schema-types";
import { GeointMap, type GeointMapPoint } from "./GeointMap";
import { buildLocationMapModel, locationCanonicalLabel } from "./geoint-model";
import { locationTypeKey } from "./geoint-labels";
import { useGeointSummary } from "./geoint-queries";

/** Build one neutral map point per returned top Location. */
function topLocationPoints(
  t: (key: string, params?: Record<string, unknown>) => string,
  topLocations: readonly GeointTopLocation[],
): GeointMapPoint[] {
  const points: GeointMapPoint[] = [];
  for (const top of topLocations) {
    const location = top.location;
    const name = locationCanonicalLabel(location) ?? location.location_id;
    points.push({
      key: location.location_id,
      lat: location.latitude ?? NaN,
      lng: location.longitude ?? NaN,
      title: name,
      locationType: location.location_type,
      locationId: location.location_id,
      context: t("mixed.entitiesContext", {
        count: String(top.scoped_entity_count),
      }),
    });
  }
  return points;
}

/** The top-Location table columns (Step 5). */
function topLocationColumns(
  t: (key: string, params?: Record<string, unknown>) => string,
): Column<GeointTopLocation>[] {
  return [
    {
      id: "location",
      header: t("summary.top.location"),
      render: (top) =>
        locationCanonicalLabel(top.location) ?? t("location.unavailable"),
      exportValue: (top) => locationCanonicalLabel(top.location) ?? "",
    },
    {
      id: "locationType",
      header: t("summary.top.locationType"),
      render: (top) => t(locationTypeKey(top.location.location_type)),
      exportValue: (top) => t(locationTypeKey(top.location.location_type)),
    },
    {
      id: "entities",
      header: t("summary.top.entities"),
      render: (top) => String(top.scoped_entity_count),
      exportValue: (top) => String(top.scoped_entity_count),
    },
    {
      id: "status",
      header: t("summary.top.status"),
      render: (top) =>
        top.location.latitude !== null && top.location.longitude !== null
          ? t("summary.top.plotted")
          : t("summary.top.notPlotted"),
      exportValue: (top) =>
        top.location.latitude !== null && top.location.longitude !== null
          ? t("summary.top.plotted")
          : t("summary.top.notPlotted"),
    },
    {
      id: "explore",
      header: t("summary.top.explore"),
      render: (top) => (
        <PivotMenu
          actions={[
            locationEntitiesAction(
              top.location.location_id,
              locationCanonicalLabel(top.location) ?? top.location.location_id,
              "geoint_location",
            ),
            locationObservationsAction(
              top.location.location_id,
              locationCanonicalLabel(top.location) ?? top.location.location_id,
              "geoint_location",
            ),
          ]}
          triggerLabel={t("explore.trigger")}
          ariaLabel={t("summary.top.exploreAria", {
            location: locationCanonicalLabel(top.location) ?? top.location.location_id,
          })}
        />
      ),
      exportValue: () => "",
    },
  ];
}

/** A small visible summary statistic card. */
function SummaryStat({
  label,
  value,
}: {
  label: string;
  value: string;
}): ReactElement {
  return (
    <Paper variant="outlined" sx={{ p: 1.25, minWidth: 120 }}>
      <Typography variant="h4" component="div" sx={{ fontWeight: 600 }}>
        {value}
      </Typography>
      <Typography variant="caption" component="div">
        {label}
      </Typography>
    </Paper>
  );
}

/** The first-class GEOINT workspace route. */
export function GeointPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "" } = useParams();
  const { summary, isLoading, isError, error, refetch } =
    useGeointSummary(investigationId);

  // Exact Evidence provenance drawer (PR 24C architecture) when a popup
  // item carries an exact evidence_id.
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const detail = useEvidenceDetail(investigationId, selectedEvidenceId);
  const openEvidence = (evidenceId: string): void => setSelectedEvidenceId(evidenceId);
  const closeEvidence = (): void => setSelectedEvidenceId(null);

  if (isLoading && summary === null) {
    return <LoadingState label={t("loading")} />;
  }
  if (isError && summary === null && error !== null) {
    return (
      <ErrorNotice
        title={isNotFound404(error) ? t("error.notFound.title") : t("error.title")}
        onRetry={refetch}
        retryLabel={t("error.retry")}
      />
    );
  }
  if (summary === null) {
    return <LoadingState label={t("loading")} />;
  }

  const model = buildLocationMapModel(summary.top_locations.map((top) => top.location));
  const points = topLocationPoints(t, summary.top_locations);

  return (
    <Box>
      <Box>
        <Typography variant="h2" sx={{ mb: 0.25 }}>
          {t("title")}
        </Typography>
        <Typography variant="caption" component="div" role="note">
          {t("intro")}
        </Typography>
      </Box>
      {isError ? (
        <Box sx={{ mt: 1 }}>
          <ErrorNotice
            severity="warning"
            title={t("error.title")}
            onRetry={refetch}
            retryLabel={t("error.retry")}
          />
        </Box>
      ) : null}
      {/* Persistent visible semantic disclaimer (never tooltip-only). */}
      <Alert severity="info" sx={{ mt: 1 }} role="note">
        {t("disclaimer.body")}
      </Alert>

      {summary.observation_count === 0 ? (
        <Box sx={{ mt: 2 }}>
          <EmptyState
            title={t("empty.title")}
            message={t("empty.message")}
          />
        </Box>
      ) : (
        <>
          {summary.truncated ? (
            <Alert severity="warning" sx={{ mt: 1 }}>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {t("truncated.title")}
              </Typography>
              <Typography variant="body2">{t("truncated.message")}</Typography>
            </Alert>
          ) : null}
          <Box sx={{ mt: 2 }}>
            <Typography variant="h3" sx={{ mb: 1 }}>
              {t("summary.title")}
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <SummaryStat
                label={t("summary.entities")}
                value={String(summary.entity_count_with_location)}
              />
              <SummaryStat
                label={t("summary.observations")}
                value={String(summary.observation_count)}
              />
              <SummaryStat
                label={t("summary.locations")}
                value={String(summary.location_count)}
              />
              <SummaryStat
                label={t("summary.types.country")}
                value={String(summary.country_count)}
              />
              <SummaryStat
                label={t("summary.types.administrativeArea")}
                value={String(summary.administrative_area_count)}
              />
              <SummaryStat
                label={t("summary.types.city")}
                value={String(summary.city_count)}
              />
            </Box>
            <Box sx={{ mt: 1 }}>
              <Typography variant="body2">
                {t("summary.precision", {
                  country: String(summary.precision_counts.country),
                  administrativeArea: String(summary.precision_counts.administrative_area),
                  city: String(summary.precision_counts.city),
                })}
              </Typography>
            </Box>
          </Box>

          {model.mappableCount > 0 ? (
            <>
              {model.totalCount > model.mappableCount ? (
                <Typography variant="body2" role="note" sx={{ mt: 1 }}>
                  {t("mixed.notice", {
                    count: String(model.totalCount - model.mappableCount),
                    total: String(model.totalCount),
                  })}
                </Typography>
              ) : null}
              <Box sx={{ mt: 1 }}>
                <GeointMap
                  investigationId={investigationId}
                  points={points}
                  onViewEvidence={openEvidence}
                />
              </Box>
            </>
          ) : (
            <Box sx={{ mt: 1 }}>
              <EmptyState
                title={t("unplottable.title")}
                message={t("unplottable.message")}
              />
            </Box>
          )}

          {summary.top_locations.length > 0 ? (
            <Box sx={{ mt: 2 }}>
              <Typography variant="h3" sx={{ mb: 1 }}>
                {t("summary.top.title")}
              </Typography>
              <AnalystTable<GeointTopLocation>
                columns={topLocationColumns(t)}
                rows={summary.top_locations}
                getRowId={(top) => top.location.location_id}
                ariaLabel={t("summary.top.aria")}
                isLoading={false}
                error={null}
                errorTitle={t("error.title")}
                onRetry={refetch}
                emptyTitle={t("summary.top.empty.title")}
                hasActiveFilters={false}
                onClearFilters={() => undefined}
                onView={() => undefined}
                viewLabel={""}
                navigation={{
                  canGoPrevious: false,
                  canGoNext: false,
                  onPrevious: () => undefined,
                  onNext: () => undefined,
                }}
                loadingLabel={t("loading")}
                staleErrorTitle={t("error.stale")}
                onReturnToFirstPage={null}
              />
            </Box>
          ) : null}

          <Box sx={{ mt: 2 }}>
            <Typography variant="body2" role="note">
              {t("summary.noInference")}
            </Typography>
          </Box>
        </>
      )}

      <DetailDrawer
        open={selectedEvidenceId !== null}
        title={t("detail.evidence.drawerTitle")}
        onClose={closeEvidence}
      >
        {selectedEvidenceId !== null ? evidenceDrawerBody(t, detail) : null}
      </DetailDrawer>
    </Box>
  );
}

/** The exact-Evidence drawer body with its bounded states. */
function evidenceDrawerBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DrawerLoading label={t("detail.evidence.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("detail.evidence.notFound.title")} />;
    }
    return <DrawerError title={t("detail.evidence.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DrawerLoading label={t("detail.evidence.loading")} />;
  }
  return (
    <Box>
      <EvidenceDetail evidence={detail.evidence} />
      {Object.keys(detail.evidence.facts ?? {}).length > 0 ? (
        <DetailSection title={t("detail.evidence.facts")}>
          <SafeJsonView data={detail.evidence.facts} label={t("detail.evidence.facts")} />
        </DetailSection>
      ) : null}
    </Box>
  );
}

/** Type guard for the summary shape used by the columns. */
export type { GeointSummary };