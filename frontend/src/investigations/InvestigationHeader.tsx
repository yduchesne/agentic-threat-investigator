// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Persistent Investigation workspace header (PR 24B §17).
//
// Shows only API-authoritative fields: identity/objective, exact persisted
// status, started/completed timestamps, stop reason when present, and
// Assessment/Report availability. Never fabricates a human-readable
// subject from root Entity UUIDs.

import { Box, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { Investigation } from "../api/schema-types";
import { Timestamp } from "../components/Timestamp";
import { InvestigationStatusBadge } from "./InvestigationStatusBadge";

export interface InvestigationHeaderProps {
  investigation: Investigation | null;
}

/** One availability line (text always visible; icon is decorative). */
function Availability({
  available,
  label,
}: {
  available: boolean;
  label: string;
}): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <Typography variant="body2" component="span" sx={{ display: "inline-flex", alignItems: "center", gap: 0.5 }}>
      {available ? (
        <span aria-hidden="true" role="presentation">
          ✓
        </span>
      ) : null}
      {label}
      {available ? ` ${t("artifacts.available")}` : ""}
    </Typography>
  );
}

/** Persistent investigation identity/status/timestamps surface. */
export function InvestigationHeader({
  investigation,
}: InvestigationHeaderProps): ReactElement | null {
  const { t } = useTranslation("investigations");
  if (investigation === null) {
    return null;
  }
  return (
    <Box
      component="header"
      sx={(theme) => ({
        borderBottom: 1,
        borderColor: theme.palette.divider,
        pb: 1.5,
        mb: 1,
      })}
    >
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Typography variant="h1">
          {investigation.objective}
        </Typography>
        <InvestigationStatusBadge status={investigation.status} />
        <Typography variant="caption" component="span" title={investigation.id}>
          {investigation.id.slice(0, 8)}
        </Typography>
      </Stack>
      <Stack direction="row" spacing={3} sx={{ alignItems: "center", flexWrap: "wrap", mt: 0.5 }}>
        <Typography variant="body2">
          {t("header.started")}{" "}
          <Timestamp iso={investigation.started_at ?? investigation.created_at} />
        </Typography>
        {investigation.completed_at !== null ? (
          <Typography variant="body2">
            {t("header.completed")} <Timestamp iso={investigation.completed_at} />
          </Typography>
        ) : null}
        {investigation.stop_reason !== null ? (
          <Typography variant="body2">
            {t("header.stopReason", { reason: investigation.stop_reason })}
          </Typography>
        ) : null}
        <Availability
          available={investigation.assessment_id !== null}
          label={t("artifacts.assessment")}
        />
        <Availability
          available={investigation.report_id !== null}
          label={t("artifacts.report")}
        />
      </Stack>
    </Box>
  );
}