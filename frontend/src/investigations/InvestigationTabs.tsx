// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace navigation (PR 24B §18).
//
// Workspace tabs are real route links; tab state belongs to the route
// path, never local selected-tab state. Only Overview is substantive in
// 24B; the other routes render bounded placeholders.

import { Tab, Tabs } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation } from "react-router";

export interface InvestigationTabsProps {
  investigationId: string;
}

const WORKSPACE_TABS = [
  { path: "overview", key: "overview" },
  { path: "evidence", key: "evidence" },
  { path: "relationships", key: "relationships" },
  { path: "map", key: "map" },
  { path: "geoint", key: "geoint" },
  { path: "research", key: "research" },
  { path: "timeline", key: "timeline" },
] as const;

/** Map the current path to the selected tab index (Overview owns report). */
function selectedTab(pathname: string, base: string): number | false {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  const normalized = rest.replace(/^\/+/, "");
  if (normalized === "overview" || normalized.startsWith("overview/")) {
    return 0;
  }
  const index = WORKSPACE_TABS.findIndex((tab) => normalized === tab.path);
  return index >= 0 ? index : false;
}

/** Route links for Overview/Evidence/Relationships/Map/Research/Timeline. */
export function InvestigationTabs({
  investigationId,
}: InvestigationTabsProps): ReactElement {
  const { t } = useTranslation("investigations");
  const location = useLocation();
  const base = `/investigations/${investigationId}`;
  const value = selectedTab(location.pathname, base);

  return (
    <Tabs
      value={value}
      role="navigation"
      aria-label={t("tabs.label")}
      variant="scrollable"
      scrollButtons="auto"
    >
      {WORKSPACE_TABS.map((tab, index) => (
        <Tab
          key={tab.key}
          component={RouterLink}
          to={`${base}/${tab.path}`}
          label={t(`tabs.${tab.key}`)}
          value={index}
        />
      ))}
    </Tabs>
  );
}