// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded `/investigations` placeholder (PR 24A).
//
// Deliberately renders no Investigation data: PR 24B owns the real
// list/create workflow.

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

/** Authenticated placeholder for the future Investigations module. */
export function InvestigationsPlaceholderPage(): ReactElement {
  const { t } = useTranslation("shell");
  return (
    <Box sx={{ mx: "auto", maxWidth: 900, py: 3 }}>
      <Typography variant="h1" sx={{ mb: 1 }}>
        {t("investigations.placeholder.title")}
      </Typography>
      <Typography variant="body1">{t("investigations.placeholder.message")}</Typography>
    </Box>
  );
}