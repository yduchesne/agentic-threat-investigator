// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot breadcrumb navigation (PR 24D §1.5, §12, §13, §22).
//
// The breadcrumb path starts with ``Investigation`` and then reflects the
// analyst's exploration sequence: for each pivot step the motivating value
// label and the reached resource are visible (for example
// ``Investigation / 203.0.113.7 / Relationships / Entity a1b2c3d4…
// / Evidence``). Implementation filter syntax is never exposed; clicking
// an earlier item truncates the stack and restores that step's resource,
// filters, and selection. The current step is marked current and is not
// clickable. Semantic navigation markup makes the path accessible.

import { Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { Fragment } from "react";
import { useTranslation } from "react-i18next";

import type { PivotResource, PivotStep } from "./pivot-types";

/** i18n key of one resource within the ``pivots`` namespace. */
export function pivotResourceLabelKey(resource: PivotResource): string {
  switch (resource) {
    case "evidence":
      return "resources.evidence";
    case "relationships":
      return "resources.relationships";
    case "relationship-observations":
      return "resources.relationshipObservations";
    case "research":
      return "resources.research";
  }
}

/** Hard clamp for bounded breadcrumb segments (labels stay in the title). */
const MAX_VISIBLE_SEGMENT_CHARS = 32;

export interface PivotBreadcrumbsProps {
  steps: readonly PivotStep[];
  /** ``keep`` = steps to keep; 0 closes the workspace. */
  onNavigate: (keep: number) => void;
}

/** The bounded breadcrumb path of the active pivot stack. */
export function PivotBreadcrumbs({
  steps,
  onNavigate,
}: PivotBreadcrumbsProps): ReactElement {
  const { t } = useTranslation("pivots");
  const last = steps.length - 1;
  const clamp = (label: string): string =>
    label.length > MAX_VISIBLE_SEGMENT_CHARS
      ? `${label.slice(0, MAX_VISIBLE_SEGMENT_CHARS - 1)}…`
      : label;
  const segment = (
    key: string,
    label: string,
    index: number,
    isCurrent: boolean,
  ): ReactElement => {
    if (isCurrent) {
      return (
        <Typography
          key={key}
          variant="caption"
          component="span"
          aria-current="page"
          title={label}
          sx={{
            maxWidth: 220,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontWeight: 600,
          }}
        >
          {clamp(label)}
        </Typography>
      );
    }
    return (
      <Button
        key={key}
        size="small"
        variant="text"
        onClick={() => onNavigate(index + 1)}
        title={label}
        aria-label={t("breadcrumbs.restore", { step: label })}
        sx={{ minWidth: 0, p: 0, textTransform: "none", textDecoration: "underline" }}
      >
        {clamp(label)}
      </Button>
    );
  };
  return (
    <Box
      component="nav"
      role="navigation"
      aria-label={t("breadcrumbs.aria")}
      sx={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        rowGap: 0.25,
        columnGap: 0.25,
        mb: 0.5,
        borderBottom: 1,
        borderColor: "divider",
        pb: 0.5,
      }}
    >
      <Box component="ol" sx={{ listStyle: "none", display: "flex", m: 0, p: 0 }}>
        <li>
          <Button
            size="small"
            variant="text"
            onClick={() => onNavigate(0)}
            sx={{ minWidth: 0, p: 0, textTransform: "none", textDecoration: "underline" }}
          >
            {t("breadcrumbs.investigation")}
          </Button>
        </li>
        {steps.map((step, index) => (
          <Fragment key={index}>
            <Box component="li" aria-hidden="true" role="presentation" sx={{ px: 0.25 }}>
              <Typography variant="caption" component="span" sx={{ color: "text.disabled" }}>
                /
              </Typography>
            </Box>
            <li>{segment(`value-${index}`, step.label, index, index === last)}</li>
            <Box component="li" aria-hidden="true" role="presentation" sx={{ px: 0.25 }}>
              <Typography variant="caption" component="span" sx={{ color: "text.disabled" }}>
                /
              </Typography>
            </Box>
            <li>
              {segment(
                `resource-${index}`,
                t(pivotResourceLabelKey(step.resource)),
                index,
                index === last,
              )}
            </li>
          </Fragment>
        ))}
      </Box>
    </Box>
  );
}