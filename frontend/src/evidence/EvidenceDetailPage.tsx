// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Exact Evidence route (PR 31F-8 §10).
//
// ``/investigations/:id/evidence/:evidenceId`` is the canonical routed
// detail surface of one scoped Evidence row: the exact Investigation-scoped
// GET through the existing query hook, the shared ``evidenceDetailBody``,
// and a semantic Back link to the list carrying the reconstructible
// filter/cursor query state. The page mounts WITHOUT the list underneath
// (one routed content surface, PR 31F-8 §2.1); Back/Forward owns the
// reverse journey. Deep links and refresh reconstruct from path/query only.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useParams, useSearchParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import {
  RouteDetailView,
} from "../analyst-table/ResourceDetailView";
import {
  listBackPath,
  ROUTE_LIST_PARAMS,
} from "../analyst-table/route-detail";
import { useEvidenceDetail } from "./evidence-queries";
import { evidenceDetailBody } from "./EvidenceWorkspace";

/** The exact scoped Evidence detail route. */
export function EvidenceDetailPage(): ReactElement {
  const { t } = useTranslation("evidence");
  const { t: tCommon } = useTranslation("common");
  const { investigationId = "", evidenceId = "" } = useParams();
  const [searchParams] = useSearchParams();

  const validEvidenceId = parseUuidParam(evidenceId) ?? null;
  const detail = useEvidenceDetail(investigationId, validEvidenceId);
  const backTo = listBackPath(
    `/investigations/${investigationId}/evidence`,
    searchParams,
    ROUTE_LIST_PARAMS.evidence,
  );

  return (
    <RouteDetailView
      backTo={backTo}
      backLabel={tCommon("backToList", { resource: t("title") })}
      heading={tCommon("detail.title", { resource: t("title") })}
    >
      {evidenceDetailBody(t, detail)}
    </RouteDetailView>
  );
}
