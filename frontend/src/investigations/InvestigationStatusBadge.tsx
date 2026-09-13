// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation status presentation (PR 24B §17).
//
// Status is always communicated by visible text, never by color alone; the
// chip color is only a secondary reinforcement.

import { Chip } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { InvestigationStatusName } from "../api/schema-types";
import { statusLabelKey } from "./investigation-status";

const STATUS_COLORS: Record<InvestigationStatusName, "default" | "info" | "success" | "warning" | "error"> = {
  pending: "info",
  running: "info",
  completed: "success",
  partial: "warning",
  failed: "error",
};

export interface InvestigationStatusBadgeProps {
  status: InvestigationStatusName;
}

/** Text-first lifecycle status badge (never color-only). */
export function InvestigationStatusBadge({
  status,
}: InvestigationStatusBadgeProps): ReactElement {
  const { t } = useTranslation("investigations");
  const label = t(statusLabelKey(status));
  return (
    <Chip
      size="small"
      color={STATUS_COLORS[status]}
      label={label}
      aria-label={`${t("status.label")}: ${label}`}
    />
  );
}