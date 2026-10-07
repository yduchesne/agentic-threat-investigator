// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Explicit focal-Entity indicator (PR 35-8 Parts 4 and 5).
//
// One reusable, bounded presentation of the current URL-backed focal Entity.
// The human-facing identity is the canonical server value (never the UUID),
// with the translated Entity type adjacent and the canonical UUID available
// only as secondary copyable metadata. The value is a genuine drill-down
// link to generic Entity details: activating it pushes the exact current
// location onto the existing bounded navigation context so the details
// surface's ``< Back`` returns to the exact originating workspace state.
//
// Loading, not-found and failure states never fabricate a value and never
// present the UUID as if it were the Entity value. The component is
// presentation-only: the caller supplies the exact Entity read state (the
// Graph view derives it from the already-loaded canonical neighborhood; the
// Evolution view and the Relationships table use the shared Entity query).

import { Box, Button, Link as MuiLink, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation } from "react-router";

import {
  internalLocationFromPath,
  navigationState,
  pushNavigationReturn,
} from "../analyst-table/return-to";
import { entityTypeLabelKey } from "../relationship-graph/relationship-graph-presentation";
import type { EntityDetailState } from "../entities/entity-queries";
import { CompactId } from "./CompactId";

export interface FocalEntityReferenceProps {
  investigationId: string;
  /** Canonical URL-backed focal Entity UUID. */
  entityId: string;
  /** The exact Entity read/projection state. */
  state: EntityDetailState;
}

/** Stable, locale-independent widget identity for the focal indicator. */
export const FOCAL_ENTITY_ATI_ID = "relationship.focal-entity";

/**
 * One explicit focal-Entity indicator with a canonical Entity-details link.
 *
 * Presentation only: it renders the exact Investigation-scoped Entity state
 * it is given and never infers value/type from the surrounding graph, table
 * or observation rows.
 */
export function FocalEntityReference({
  investigationId,
  entityId,
  state,
}: FocalEntityReferenceProps): ReactElement {
  const { t } = useTranslation("common");
  const { t: tEvolution } = useTranslation("relationshipEvolution");
  const location = useLocation();
  const { entity, isLoading, isError, notFound, refetch } = state;
  const detailsHref = `/investigations/${investigationId}/entities/${entityId}`;
  // Entity details are a genuine drill-down: push this exact location so the
  // details surface can offer a contextual Back to it.
  const detailsState = navigationState(
    pushNavigationReturn(
      location.state,
      internalLocationFromPath(location.pathname, location.search, location.hash),
    ),
  );

  return (
    <Box
      data-ati-id={FOCAL_ENTITY_ATI_ID}
      sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap", mb: 1 }}
    >
      <Typography variant="body2" component="span" sx={{ fontWeight: 600 }}>
        {t("focalEntity.label")}:
      </Typography>
      {isLoading ? (
        <Typography variant="body2" component="span" role="status" color="text.secondary">
          {t("focalEntity.loading")}
        </Typography>
      ) : null}
      {isError ? (
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <Typography variant="body2" component="span" role="alert" color="error">
            {t("focalEntity.error")}
          </Typography>
          <Button
            size="small"
            variant="outlined"
            data-testid="focal-entity-retry"
            onClick={refetch}
            sx={{ textTransform: "none" }}
          >
            {t("retry")}
          </Button>
        </Box>
      ) : null}
      {notFound ? (
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5 }}>
          <Typography variant="body2" component="span" color="text.secondary">
            {t("focalEntity.unavailable")}
          </Typography>
          <CompactId id={entityId} label={t("entityDetails.id")} />
        </Stack>
      ) : null}
      {entity !== null ? (
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
          <MuiLink
            component={RouterLink}
            to={detailsHref}
            state={detailsState}
            data-testid="focal-entity-value"
            underline="hover"
            sx={{ fontWeight: 600 }}
          >
            {entity.value}
          </MuiLink>
          <Typography variant="caption" component="span" sx={{ color: "text.secondary" }}>
            {tEvolution(entityTypeLabelKey(entity.entityType))}
          </Typography>
          <CompactId id={entity.entityId} label={t("entityDetails.id")} />
        </Stack>
      ) : null}
    </Box>
  );
}
