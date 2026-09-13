// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Safe not-found page (PR 24A).

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

/** Rendered by the catch-all route for unknown paths. */
export function NotFoundPage(): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Box sx={{ py: 6, textAlign: "center" }}>
      <Typography variant="h1" component="h1">
        {t("notFound.title")}
      </Typography>
      <Typography variant="body1" sx={{ mt: 0.5 }}>
        {t("notFound.message")}
      </Typography>
      <Box sx={{ mt: 2 }}>
        <Link to="/investigations">{t("notFound.home")}</Link>
      </Box>
    </Box>
  );
}