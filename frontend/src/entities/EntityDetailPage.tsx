// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Generic Investigation-scoped Entity details route (PR 35-8 Part 6).
//
// The smallest canonical read-only Entity details surface. It renders the
// exact server-provided Entity value/type and the canonical UUID (secondary,
// copyable) through the shared Entity query, and never becomes an Entity
// intelligence dashboard, never edits/deletes, and never infers a value from
// the UUID. ``< Back`` is a genuine contextual return: the exact originating
// workspace location when the surface was reached from a focal indicator,
// otherwise a safe canonical fallback (the Investigation Relationships table
// filtered by this Entity).

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useParams } from "react-router";

import { DetailRows } from "../analyst-table/DetailRows";
import {
  DetailError,
  DetailLoading,
  DetailNotFound,
  RouteDetailView,
} from "../analyst-table/ResourceDetailView";
import { contextualBack } from "../analyst-table/return-to";
import { CompactId } from "../components/CompactId";
import { useEntityDetail } from "./entity-queries";
import { entityTypeLabelKey } from "../relationship-graph/relationship-graph-presentation";

/** One canonical Investigation-scoped Entity details surface. */
export function EntityDetailPage(): ReactElement {
  const { investigationId = "", entityId = "" } = useParams();
  const location = useLocation();
  const { t } = useTranslation("common");
  const { t: tEvolution } = useTranslation("relationshipEvolution");
  const { entity, isLoading, isError, notFound, refetch } = useEntityDetail(
    investigationId,
    entityId,
  );
  const { backTo, backState } = contextualBack(
    location.state,
    `/investigations/${investigationId}/relationships?entity_id=${entityId}`,
  );

  return (
    <RouteDetailView
      backTo={backTo}
      backState={backState}
      backLabel={t("back")}
      heading={t("entityDetails.title")}
    >
      {isLoading ? <DetailLoading label={t("entityDetails.loading")} /> : null}
      {isError ? (
        <DetailError title={t("entityDetails.error")} onRetry={refetch} />
      ) : null}
      {notFound ? <DetailNotFound title={t("entityDetails.notFound")} /> : null}
      {entity !== null ? (
        <Box data-ati-id="entity.details">
          <DetailRows
            rows={[
              { label: t("entityDetails.value"), value: entity.value },
              {
                label: t("entityDetails.type"),
                value: tEvolution(entityTypeLabelKey(entity.entityType)),
              },
              {
                label: t("entityDetails.id"),
                value: (
                  <CompactId id={entity.entityId} label={t("entityDetails.id")} />
                ),
              },
            ]}
          />
        </Box>
      ) : null}
    </RouteDetailView>
  );
}
