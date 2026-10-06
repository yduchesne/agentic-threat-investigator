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
  // PR 31F-8: the routed exact-detail families stay under their module tab.
  if (normalized === "evidence" || normalized.startsWith("evidence/")) {
    return 1;
  }
  if (normalized === "relationships" || normalized.startsWith("relationships/")) {
    return 2;
  }
  // PR 35-2: the legacy `/map` URL is a transient redirect to GEOINT MAP;
  // it still selects GEOINT while the redirect settles, and every
  // `/geoint...` presentation/resource surface selects GEOINT.
  if (
    normalized === "map" ||
    normalized === "geoint" ||
    normalized.startsWith("geoint/")
  ) {
    return 3;
  }
  if (normalized === "research" || normalized.startsWith("research/")) {
    return 4;
  }
  if (normalized === "timeline") {
    return 5;
  }
  return false;
}

/** Route links for Overview/Evidence/Graph/GEOINT/Research/Timeline. */
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
      {WORKSPACE_TABS.map((tab, index) => {
        const to = `${base}/${tab.path}`;
        const active = value === index;
        // PR 31F-8: re-activating the ALREADY-ACTIVE tab must not fire a
        // same-URL router navigation (a deterministic real-stack
        // Chromium/Firefox main-thread stall reproduced with pointer AND
        // keyboard activation — the routed same-URL navigation class). The
        // active tab renders as an inert tab (still announced, still in
        // tab order); destination tabs stay semantic links.
        if (active) {
          return (
            <Tab
              key={tab.key}
              label={t(`tabs.${tab.key}`)}
              value={index}
            />
          );
        }
        return (
          <Tab
            key={tab.key}
            component={RouterLink}
            to={to}
            label={t(`tabs.${tab.key}`)}
            value={index}
          />
        );
      })}
    </Tabs>
  );
}
