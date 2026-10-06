// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT TABLE presentation (PR 26E §4-§6, §15; PR 35-2 §D/§Step 11-13).
//
// Under the PR 35-2 information architecture, GEOINT is one first-class
// Investigation capability and this page is its non-map TABLE
// presentation: the persistent semantic disclaimer, the bounded PR 26D
// summary, the precision counts, and the always-available Top Locations
// analyst table with typed Explore actions. The MAP presentation owns the
// routed map; TABLE never embeds a second map.
//
// Top Locations are exact scoped observation groups, never
// hotspots/threat concentration; no risk coloring exists anywhere.

import { Alert, Box, Paper, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router";

import type { Column } from "../analyst-table/types";
import { AnalystTable } from "../analyst-table/AnalystTable";
import { isNotFound404 } from "../analyst-table/detail-error";
import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  locationEntitiesAction,
  locationObservationsAction,
} from "../pivots/pivot-capabilities";
import type { GeointTopLocation } from "../api/schema-types";
import { GeointViewTabs } from "./GeointViewTabs";
import { locationCanonicalLabel } from "./geoint-model";
import { locationTypeKey } from "./geoint-labels";
import { useGeointSummary } from "./geoint-queries";

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

/** The GEOINT TABLE presentation for one Investigation. */
export function GeointPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "" } = useParams();
  const { summary, isLoading, isError, error, refetch } =
    useGeointSummary(investigationId);

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

  return (
    <Box>
      <Box>
        <Typography variant="h2" sx={{ mb: 0.25 }}>
          {t("workspace.title")}
        </Typography>
        <GeointViewTabs investigationId={investigationId} />
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
        <Box>
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
        </Box>
      )}
    </Box>
  );
}
