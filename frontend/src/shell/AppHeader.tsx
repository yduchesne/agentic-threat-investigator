// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Authenticated shell app header (PR 24A): product identity, primary
// navigation, current user alias + bounded role display, logout.

import { AppBar, Box, Button, CircularProgress, Toolbar, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

import type { PublicUser, UserRoleName } from "../api/schema-types";
import { useLogoutMutation } from "../auth/auth-queries";
import { Navigation } from "./Navigation";
import { PreferencesDialog } from "./PreferencesDialog";

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

  // PR 31F-4: the Preferences dialog is modal/non-navigational presentation
  // state beside the authenticated user controls.
  const [preferencesOpen, setPreferencesOpen] = useState(false);

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
          <Box
            component="h1"
            sx={{
              m: 0,
              display: "flex",
              flexDirection: "column",
              flexShrink: 0,
              lineHeight: 1,
              whiteSpace: "nowrap",
            }}
          >
            <Typography
              component="span"
              sx={{
                fontFamily: '"OCR A Std", "Lucida Console", "Courier New", monospace',
                fontSize: { xs: "1.5rem", sm: "1.8rem" },
                fontWeight: 700,
                lineHeight: 1,
              }}
            >
              {t("brand.mark")}
            </Typography>
            <Typography
              component="span"
              sx={{
                mt: 0.25,
                fontSize: "0.625rem",
                fontWeight: 500,
                lineHeight: 1.2,
                letterSpacing: "0.015em",
                color: "text.secondary",
              }}
            >
              {t("title")}
            </Typography>
          </Box>
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
          {/* Preferences gear: accessible button with an explicit text label;
           * the gear glyph is decorative-only. Opens a modal dialog, never
           * navigates or mutates the URL. */}
          <Button
            variant="outlined"
            size="small"
            onClick={() => setPreferencesOpen(true)}
            aria-haspopup="dialog"
            sx={{ textTransform: "none", whiteSpace: "nowrap" }}
          >
            <Box component="span" aria-hidden="true" sx={{ mr: 0.5 }}>
              ⚙
            </Box>
            {t("preferences.open")}
          </Button>
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
      <PreferencesDialog
        open={preferencesOpen}
        onClose={() => setPreferencesOpen(false)}
      />
    </AppBar>
  );
}
