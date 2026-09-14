// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship detail surface (PR 24C §9).
//
// Presents the stable edge (source/type/target) plus a bounded first page
// of immutable observations filtered by ``relationship_id``. No start/end/
// removal semantics are ever inferred from observation gaps, and no entity
// labels are fabricated. ``View all observations`` is History-free
// cross-navigation into the first-class observations route.

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import type { Relationship } from "../api/schema-types";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { DrawerError, DrawerLoading } from "../analyst-table/DetailDrawer";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { relationshipTypeKey } from "./labels";
import { useRelationshipObservationPreview } from "./relationships-queries";

export interface RelationshipDetailProps {
  investigationId: string;
  relationship: Relationship;
}

/** The stable edge plus a bounded observation preview. */
export function RelationshipDetail({
  investigationId,
  relationship,
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
      </DetailSection>
    </Box>
  );
}