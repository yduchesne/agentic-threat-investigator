// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Exact GEOINT observation route (PR 31F-8 §10, §3.6).
//
// ``/investigations/:id/geoint/observations/:observationId`` owns one
// exact Investigation-scoped geographic observation. It reuses the
// existing exact query hook and ``GeointObservationDetailBody`` — no new
// API. The exact Evidence action is route-owned (exact Evidence route).
// The semantic parent link targets the canonical GEOINT surface; browser
// Back restores the actual prior routed surface (Entity GEOINT, Location
// surface, ...) from URL state.

import { Alert, Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate, useParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import { isNotFound404 } from "../analyst-table/detail-error";
import {
  DetailError,
  DetailLoading,
  RouteDetailView,
} from "../analyst-table/ResourceDetailView";
import {
  contextualBack,
  internalLocationFromPath,
  navigationState,
  pushNavigationReturn,
} from "../analyst-table/return-to";
import { EmptyState } from "../components/AsyncState";
import { GeointBreadcrumbs } from "./GeointBreadcrumbs";
import { GeointObservationDetailBody } from "./GeointObservationDetail";
import { useGeointObservation } from "./geoint-queries";

/** The canonical exact GEOINT observation route. */
export function GeointObservationDetailPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "", observationId = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const validObservationId = parseUuidParam(observationId) ?? null;
  const { detail, isLoading, isError, error, refetch } = useGeointObservation(
    investigationId,
    validObservationId,
  );
  const { backTo, backState } = contextualBack(
    location.state,
    `/investigations/${investigationId}/geoint/table`,
  );
  const evidenceState = navigationState(
    pushNavigationReturn(
      location.state,
      internalLocationFromPath(location.pathname, location.search, location.hash),
    ),
  );

  const onViewEvidence = (evidenceId: string): void => {
    navigate(`/investigations/${investigationId}/evidence/${evidenceId}`, {
      state: evidenceState,
    });
  };

  if (validObservationId === null) {
    return (
      <EmptyState title={t("detail.observation.missing.title")} />
    );
  }

  return (
    <Box>
      <GeointBreadcrumbs
        investigationId={investigationId}
        crumbs={[{ key: "observation", label: t("detail.observation.title") }]}
      />
      <RouteDetailView
        backTo={backTo}
        backState={backState}
        backLabel={t("detail.observation.backToContext")}
        heading={t("detail.observation.detailTitle")}
      >
        {body(t, { detail, isLoading, isError, error, refetch }, onViewEvidence)}
      </RouteDetailView>
    </Box>
  );
}

/** The exact observation detail body with its bounded states. */
function body(
  t: (key: string) => string,
  read: ReturnType<typeof useGeointObservation>,
  onViewEvidence: (evidenceId: string) => void,
): ReactElement {
  const { detail, isLoading, isError, error, refetch } = read;
  if (isLoading && detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  if (isError && detail === null && error !== null) {
    if (isNotFound404(error)) {
      return <Alert severity="info" role="status">{t("detail.observation.notFound.title")}</Alert>;
    }
    return <DetailError title={t("detail.observation.loadError.title")} onRetry={refetch} />;
  }
  if (detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  return <GeointObservationDetailBody detail={detail} onViewEvidence={onViewEvidence} />;
}
