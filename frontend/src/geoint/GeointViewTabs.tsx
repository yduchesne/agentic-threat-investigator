// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// GEOINT presentation sub-navigation (PR 35-2 §B/§Step 6).
//
// GEOINT is one first-class Investigation capability with exactly two
// URL-owned presentation sub-views: MAP and TABLE. This component owns
// presentation navigation only: it holds no query, Evidence/map data,
// durable state or backend calls. The active sub-tab is derived from the
// route path (refresh/deep links/Back reconstruct it), the selected
// destination is inert (PR 35-1/31F-8 same-URL inertness), and the other
// destination is a semantic React Router link.

import { Box, Tab, Tabs } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation } from "react-router";

export interface GeointViewTabsProps {
  investigationId: string;
}

const VIEW_TABS = [
  { path: "map", key: "view.map" },
  { path: "table", key: "view.table" },
] as const;

/** Map the current GEOINT path to the selected presentation sub-tab. */
function selectedView(pathname: string, base: string): number | false {
  const rest = pathname.startsWith(base) ? pathname.slice(base.length) : pathname;
  const normalized = rest.replace(/^\/+/, "");
  if (normalized === "map" || normalized.startsWith("map/")) {
    return 0;
  }
  if (normalized === "table" || normalized.startsWith("table/")) {
    return 1;
  }
  // Routed GEOINT resource descendants keep the primary GEOINT tab active
  // but select neither presentation sub-tab.
  return false;
}

/** Route links for the MAP/TABLE GEOINT presentation sub-views. */
export function GeointViewTabs({
  investigationId,
}: GeointViewTabsProps): ReactElement {
  const { t } = useTranslation("geoint");
  const location = useLocation();
  const base = `/investigations/${investigationId}/geoint`;
  const value = selectedView(location.pathname, base);

  return (
    <Box component="nav" role="navigation" aria-label={t("view.aria")}>
      <Tabs value={value} variant="standard" sx={{ minHeight: 36, mb: 1 }}>
        {VIEW_TABS.map((view, index) => {
          const to = `${base}/${view.path}`;
          const active = value === index;
          // Activating the already-active presentation is a same-URL
          // navigation (the documented Chromium/Firefox input-pipeline
          // stall class), so the active tab renders inert while remaining
          // announced and in tab order.
          if (active) {
            return (
              <Tab key={view.key} label={t(view.key)} value={index} />
            );
          }
          return (
            <Tab
              key={view.key}
              component={RouterLink}
              to={to}
              label={t(view.key)}
              value={index}
            />
          );
        })}
      </Tabs>
    </Box>
  );
}
