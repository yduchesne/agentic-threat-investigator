// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Exact RelationshipObservation route (PR 31F-8 §10).
//
// ``/investigations/:id/relationships/observations/:observationId`` owns
// one exact scoped observation: the persisted id resolves through the
// Investigation-scoped exact GET (never a list scan, never a substitute),
// rendered with the shared ``observationDetailRows`` shape, and a semantic
// Back link to the observations list carries the reconstructible
// filter/cursor query state. Exact observation navigation is route-owned.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useParams, useSearchParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import { isNotFound404 } from "../analyst-table/detail-error";
import {
  DetailError,
  DetailLoading,
  DetailNotFound,
  RouteDetailView,
} from "../analyst-table/ResourceDetailView";
import { contextualBack } from "../analyst-table/return-to";
import {
  listBackPath,
  ROUTE_LIST_PARAMS,
} from "../analyst-table/route-detail";
import { useObservationDetail } from "./relationships-queries";
import { observationDetailRows } from "./RelationshipObservationsWorkspace";

/** The exact scoped RelationshipObservation detail route. */
export function ObservationDetailPage(): ReactElement {
  const { t } = useTranslation("relationships");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "", observationId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const location = useLocation();

  const validObservationId = parseUuidParam(observationId) ?? null;
  const detail = useObservationDetail(investigationId, validObservationId);
  const { backTo, backState } = contextualBack(
    location.state,
    listBackPath(
      `/investigations/${investigationId}/relationships/observations`,
      searchParams,
      ROUTE_LIST_PARAMS.observations,
    ),
  );

  return (
    <RouteDetailView
      backTo={backTo}
      backState={backState}
      backLabel={tCommon("backToList", { resource: t("observations.title") })}
      heading={t("observations.detail.title")}
    >
      {body(t, detail)}
    </RouteDetailView>
  );
}

/** The exact observation detail body with its bounded states. */
function body(
  t: (key: string) => string,
  detail: ReturnType<typeof useObservationDetail>,
): ReactElement {
  if (detail.isLoading && detail.observation === null) {
    return <DetailLoading label={t("detail.loading")} />;
  }
  if (detail.isError && detail.observation === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DetailNotFound title={t("detail.notFound.title")} />;
    }
    return <DetailError title={t("detail.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.observation === null) {
    return <DetailLoading label={t("detail.loading")} />;
  }
  return observationDetailRows(t, detail.observation);
}
