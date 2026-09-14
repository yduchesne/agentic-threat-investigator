// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Compact copyable opaque identifier (PR 24C §17, §18).
//
// Renders a bounded UUID prefix in monospace with the full value available
// in the tooltip and a keyboard-operable copy action. Identifiers are never
// decoded, re-typed, or resolved to fabricated labels.

import { Button, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { shortUuid } from "../analyst-table/present";

/** Copy one text value through the clipboard when the browser allows it. */
export function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText !== undefined) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() => false);
  }
  return Promise.resolve(false);
}

export interface CompactIdProps {
  id: string;
  /** Accessible description (e.g. "Evidence ID"). */
  label: string;
}

/** One compact copyable identifier with the full value in the tooltip. */
export function CompactId({ id, label }: CompactIdProps): ReactElement {
  const { t } = useTranslation("common");
  const handleCopy = () => void copyText(id);
  return (
    <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
      <Typography
        variant="caption"
        component="code"
        title={id}
        aria-label={label}
        sx={{ fontFamily: "monospace" }}
      >
        {shortUuid(id)}
      </Typography>
      <Button
        size="small"
        onClick={handleCopy}
        aria-label={t("copyId.action", { id: shortUuid(id) })}
        title={t("copyId.tooltip")}
        sx={{ minWidth: 0, p: 0, textTransform: "none", color: "text.secondary" }}
      >
        {t("copyId.short")}
      </Button>
    </Stack>
  );
}