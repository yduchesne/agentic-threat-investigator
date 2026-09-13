// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Primary shell navigation (PR 24A).
//
// Only routes that exist in 24A are exposed; no clickable dead future
// tabs. Keyboard-operable real links with visible active state.

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { NavLink } from "react-router";

/** Primary navigation for the authenticated analyst shell. */
export function Navigation(): ReactElement {
  const { t } = useTranslation("shell");
  return (
    <Box
      component="nav"
      aria-label={t("nav.label")}
      sx={{ display: "flex", gap: 1, alignItems: "center", ml: 2 }}
    >
      <NavLink to="/investigations">
        {({ isActive }) => (
          <Box
            component="span"
            aria-current={isActive ? "page" : undefined}
            sx={{
              px: 1.5,
              py: 0.5,
              borderRadius: 1,
              bgcolor: isActive ? "primary.main" : "transparent",
              color: isActive ? "common.white" : "text.primary",
              fontWeight: isActive ? 700 : 500,
            }}
          >
            {t("nav.investigations")}
          </Box>
        )}
      </NavLink>
    </Box>
  );
}