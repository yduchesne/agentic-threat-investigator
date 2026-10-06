// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Exact Relationship route (PR 31F-8 §10).
//
// ``/investigations/:id/relationships/:relationshipId`` is the canonical
// routed detail of one scoped Relationship edge: the exact
// Investigation-scoped GET through the existing query hook, the shared
// ``relationshipDetailBody`` (stable edge + bounded observation preview),
// and a semantic Back link to the list carrying the reconstructible
// filter/cursor query state. No API semantic changes.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useParams, useSearchParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import { RouteDetailView } from "../analyst-table/ResourceDetailView";
import { contextualBack } from "../analyst-table/return-to";
import {
  listBackPath,
  ROUTE_LIST_PARAMS,
} from "../analyst-table/route-detail";
import { useRelationshipDetail } from "./relationships-queries";
import { relationshipDetailBody } from "./RelationshipsWorkspace";

/** The exact scoped Relationship detail route. */
export function RelationshipDetailPage(): ReactElement {
  const { t } = useTranslation("relationships");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "", relationshipId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const location = useLocation();

  const validRelationshipId = parseUuidParam(relationshipId) ?? null;
  const detail = useRelationshipDetail(investigationId, validRelationshipId);
  const { backTo, backState } = contextualBack(
    location.state,
    listBackPath(
      `/investigations/${investigationId}/relationships`,
      searchParams,
      ROUTE_LIST_PARAMS.relationships,
    ),
  );

  return (
    <RouteDetailView
      backTo={backTo}
      backState={backState}
      backLabel={tCommon("backToList", { resource: t("title") })}
      heading={t("detail.pageTitle")}
    >
      {relationshipDetailBody(t, detail, investigationId, false)}
    </RouteDetailView>
  );
}
