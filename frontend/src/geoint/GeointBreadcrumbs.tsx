// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route-derived GEOINT breadcrumb navigation (PR 31F-8 §11; PR 35-2).
//
// The former Pivot-stack breadcrumbs/Close are replaced by route-derived
// semantic navigation: the chain starts at the canonical GEOINT TABLE
// presentation (the analytical surface every routed GEOINT resource is
// explored from) and reflects the current routed surface. Labels are
// presentation only — canonical IDs stay in the path; a navigated display
// label (e.g. the canonical Location name) is carried in transient router
// state and falls back to a compact identity on refresh/deep links, which
// always render from path/query alone. No opaque navigation stack exists.

import { Box, Link, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { Fragment } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation } from "react-router";

/** One route-derived breadcrumb segment. */
export interface GeointCrumb {
  /** React key (stable per segment identity). */
  key: string;
  /** Analyst-facing label (presentation only). */
  label: string;
  /** Known parent route destination, or undefined for the current segment. */
  to?: string;
}

export interface GeointBreadcrumbsProps {
  investigationId: string;
  /** The routed GEOINT surface chain, excluding the Geometric context root. */
  crumbs: readonly GeointCrumb[];
}

/** The bounded route-derived GEOINT breadcrumb path. */
export function GeointBreadcrumbs({
  investigationId,
  crumbs,
}: GeointBreadcrumbsProps): ReactElement {
  const { t } = useTranslation("geoint");
  const location = useLocation();
  const segments: GeointCrumb[] = [
    {
      key: "context",
      label: t("title"),
      to: `/investigations/${investigationId}/geoint/table`,
    },
    ...crumbs,
  ];
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
        {segments.map((segment, index) => (
          <Fragment key={segment.key}>
            {index > 0 ? (
              <Box component="li" aria-hidden="true" role="presentation" sx={{ px: 0.25 }}>
                <Typography variant="caption" component="span" sx={{ color: "text.disabled" }}>
                  /
                </Typography>
              </Box>
            ) : null}
            <li>
              {segment.to !== undefined && segment.to !== location.pathname ? (
                <Link
                  component={RouterLink}
                  to={segment.to}
                  sx={{ fontSize: "0.8125rem", textDecoration: "underline" }}
                >
                  {segment.label}
                </Link>
              ) : (
                <Typography
                  variant="caption"
                  component="span"
                  aria-current={index === segments.length - 1 ? "page" : undefined}
                  title={segment.label}
                  sx={{
                    maxWidth: 260,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    fontWeight: 600,
                  }}
                >
                  {segment.label}
                </Typography>
              )}
            </li>
          </Fragment>
        ))}
      </Box>
    </Box>
  );
}
