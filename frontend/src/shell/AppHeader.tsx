// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Authenticated shell app header (PR 24A): product identity, primary
// navigation, current user alias + bounded role display, logout.

import { AppBar, Box, Button, CircularProgress, Toolbar, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

import type { PublicUser, UserRoleName } from "../api/schema-types";
import { useLogoutMutation } from "../auth/auth-queries";
import { Navigation } from "./Navigation";

/** Bounded role label lookup; unknown roles stay invisible. */
function roleLabel(role: UserRoleName | undefined, t: (key: string) => string): string | null {
  if (role === "analyst") {
    return t("role.analyst");
  }
  if (role === "admin") {
    return t("role.admin");
  }
  return null;
}

/** The authenticated shell header. */
export function AppHeader({ user }: { user: PublicUser }): ReactElement {
  const { t } = useTranslation("shell");
  const { t: ta } = useTranslation("auth");
  const navigate = useNavigate();
  const { run, isPending, error: logoutError } = useLogoutMutation(() => {
    navigate("/login");
  });

  const label = roleLabel(user.role, t);

  return (
    <AppBar
      position="sticky"
      elevation={1}
      component="header"
      sx={{ bgcolor: "background.paper", color: "text.primary" }}
    >
      <Toolbar sx={{ minHeight: 56 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flexGrow: 1, minWidth: 0 }}>
          <Typography variant="h3" component="h1" sx={{ whiteSpace: "nowrap", flexShrink: 0 }}>
            {t("title")}
          </Typography>
          <Navigation />
        </Box>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <Box sx={{ textAlign: "right" }}>
            <Typography variant="body2" component="p">
              {user.alias}
            </Typography>
            {label !== null ? (
              <Typography variant="caption" component="p" color="text.secondary">
                {t("user.role")}: {label}
              </Typography>
            ) : null}
          </Box>
          <Button
            variant="outlined"
            size="small"
            onClick={() => run()}
            disabled={isPending}
            sx={{ textTransform: "none", whiteSpace: "nowrap" }}
          >
            {isPending ? <CircularProgress size={16} aria-label={ta("submitting")} /> : ta("logout")}
          </Button>
        </Box>
      </Toolbar>
      {logoutError !== null ? (
        <Box role="alert" sx={{ px: 1.5, py: 0.25, bgcolor: "background.default" }}>
          <Typography variant="caption" color="error.main">
            {ta("logout.failed")}
          </Typography>
        </Box>
      ) : null}
    </AppBar>
  );
}