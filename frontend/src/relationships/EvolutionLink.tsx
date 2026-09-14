// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution entry links (PR 24E §10).
//
// Explicit typed internal navigation into the first-class Evolution route
// (``entity_id`` required, ``direction`` defaults to either server-side).
// These are plain internal links, not PR 24D pivot steps: Evolution is a
// first-class route/view, not a resource-table pivot target, so the pivot
// capability model is deliberately left unchanged.

import { Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

/** The Evolution route for one focal entity. */
export function evolutionRoute(investigationId: string, entityId: string): string {
  return `/investigations/${investigationId}/relationships/evolution?entity_id=${entityId}`;
}

/** One accessible "View relationship evolution" internal link. */
export function EvolutionLink({
  investigationId,
  entityId,
  ariaLabel,
}: {
  investigationId: string;
  entityId: string;
  ariaLabel: string;
}): ReactElement {
  const { t } = useTranslation("relationships");
  return (
    <Typography variant="caption" component="span">
      <Link to={evolutionRoute(investigationId, entityId)} style={{ textDecoration: "none" }} aria-label={ariaLabel}>
        {t("evolution.view")}
      </Link>
    </Typography>
  );
}