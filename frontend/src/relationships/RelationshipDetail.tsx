// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship detail surface (PR 24C §9; PR 24D §6, §16).
//
// Presents the stable edge (source/type/target) plus a bounded first page
// of immutable observations filtered by ``relationship_id``. No start/end/
// removal semantics are ever inferred from observation gaps, and no entity
// labels are fabricated. ``View all observations`` is History-free
// cross-navigation into the first-class observations route; inside the
// PR 24D pivot modal the same affordance becomes an in-modal observation
// pivot so the exploration sequence stays inside one workspace.

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import type { Relationship } from "../api/schema-types";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { DrawerError, DrawerLoading } from "../analyst-table/DetailDrawer";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  relationshipObservationsAction,
  relationshipSourceActions,
  relationshipTargetActions,
} from "../pivots/pivot-capabilities";
import { relationshipTypeKey } from "./labels";
import { useRelationshipObservationPreview } from "./relationships-queries";

export interface RelationshipDetailProps {
  investigationId: string;
  relationship: Relationship;
  /** Rendered inside the pivot modal: observations navigate in-modal. */
  embedded?: boolean;
}

/** The stable edge plus a bounded observation preview. */
export function RelationshipDetail({
  investigationId,
  relationship,
  embedded = false,
}: RelationshipDetailProps): ReactElement {
  const { t } = useTranslation("relationships");
  const preview = useRelationshipObservationPreview(investigationId, relationship.id);

  return (
    <Box>
      <DetailRows
        rows={[
          {
            label: t("detail.sourceEntity"),
            value: <CompactId id={relationship.source_entity_id} label={t("detail.sourceEntity")} />,
          },
          {
            label: t("detail.relationshipType"),
            value: t(relationshipTypeKey(relationship.type)),
          },
          {
            label: t("detail.targetEntity"),
            value: <CompactId id={relationship.target_entity_id} label={t("detail.targetEntity")} />,
          },
          {
            label: t("detail.relationshipId"),
            value: <CompactId id={relationship.id} label={t("detail.relationshipId")} />,
          },
        ]}
      />
      <DetailSection title={t("detail.pivot.title")}>
        <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5, mt: 0.5 }}>
          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <Typography variant="caption" sx={{ flex: "0 0 150px", fontWeight: 600 }}>
              {t("detail.sourceEntity")}
            </Typography>
            <PivotMenu
              actions={relationshipSourceActions(relationship, "detail_field")}
              ariaLabel={`${t("detail.pivot.aria")} ${t("detail.sourceEntity")}`}
            />
          </Box>
          <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
            <Typography variant="caption" sx={{ flex: "0 0 150px", fontWeight: 600 }}>
              {t("detail.targetEntity")}
            </Typography>
            <PivotMenu
              actions={relationshipTargetActions(relationship, "detail_field")}
              ariaLabel={`${t("detail.pivot.aria")} ${t("detail.targetEntity")}`}
            />
          </Box>
        </Box>
      </DetailSection>
      <DetailSection title={t("detail.observations.title")}>
        {preview.isLoading && preview.page === null ? (
          <DrawerLoading label={t("detail.observations.loading")} />
        ) : null}
        {preview.isError && preview.page === null ? (
          <DrawerError title={t("detail.observations.error")} onRetry={preview.refetch} />
        ) : null}
        {preview.page !== null && preview.page.items.length === 0 ? (
          <Typography variant="body2">{t("detail.observations.none")}</Typography>
        ) : null}
        {preview.page !== null && preview.page.items.length > 0 ? (
          <Box>
            {preview.page.items.map((observation) => (
              <DetailRows
                key={observation.id}
                rows={[
                  {
                    label: t("detail.observations.source"),
                    value: observation.source,
                  },
                  {
                    label: t("detail.observations.observedAt"),
                    value:
                      observation.observed_at !== null
                        ? <Timestamp iso={observation.observed_at} />
                        : t("detail.observations.notObserved"),
                  },
                  {
                    label: t("detail.observations.retrievedAt"),
                    value: <Timestamp iso={observation.retrieved_at} />,
                  },
                  {
                    label: t("detail.observations.confidence"),
                    value: observation.confidence !== null ? String(observation.confidence) : t("detail.observations.nullable"),
                  },
                ]}
              />
            ))}
            {preview.page.next_cursor !== null && preview.page.next_cursor !== undefined ? (
              <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
                {t("detail.observations.more")}
              </Typography>
            ) : null}
          </Box>
        ) : null}
        {embedded ? (
          <Box sx={{ mt: 1 }}>
            <PivotMenu
              actions={[relationshipObservationsAction(relationship.id, "detail_field")]}
            />
          </Box>
        ) : (
          <Box sx={{ mt: 1 }}>
            <Link
              to={`/investigations/${investigationId}/relationships/observations?relationship_id=${relationship.id}`}
              style={{ textDecoration: "none" }}
            >
              <Typography variant="body2" sx={{ color: "primary.main" }}>
                {t("detail.observations.viewAll")}
              </Typography>
            </Link>
          </Box>
        )}
      </DetailSection>
    </Box>
  );
}