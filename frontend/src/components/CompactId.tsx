// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Compact copyable opaque identifier (PR 24C §17, §18; PR 35-1 Part 2).
//
// Renders a bounded UUID prefix in monospace with the full value available
// in the tooltip and a keyboard-operable copy action. Identifiers are never
// decoded, re-typed, or resolved to fabricated labels.
//
// When ``to`` is supplied the short ID becomes a semantic internal link to
// the exact resource while the copy control stays a separate sibling, so
// activating copy can never navigate and the visible short ID appears
// exactly once (PR 35-1 Part 2).

import { IconButton, Stack, SvgIcon, Tooltip, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

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
  /**
   * Optional canonical internal route. When present the short ID renders
   * as a semantic link to that exact resource; the copy control remains a
   * separate, non-navigating sibling.
   */
  to?: string;
  /** Optional React Router location state passed with the link. */
  state?: unknown;
}

/** One compact copyable identifier with the full value in the tooltip. */
export function CompactId({ id, label, to, state }: CompactIdProps): ReactElement {
  const { t } = useTranslation("common");
  const handleCopy = () => void copyText(id);
  const short = shortUuid(id);
  const idText = (
    <Typography
      variant="caption"
      component="code"
      title={id}
      aria-label={to === undefined ? label : undefined}
      sx={{ fontFamily: "monospace", color: to === undefined ? "inherit" : "primary.main" }}
    >
      {short}
    </Typography>
  );
  return (
    <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
      {to === undefined ? (
        idText
      ) : (
        <Link
          to={to}
          state={state}
          aria-label={label}
          style={{ textDecoration: "none", color: "inherit" }}
        >
          {idText}
        </Link>
      )}
      <Tooltip title={t("copyId.tooltip")}>
        <IconButton
          size="small"
          onClick={handleCopy}
          aria-label={t("copyId.action", { id: short })}
          sx={{ p: 0.25, color: "text.secondary" }}
        >
          <SvgIcon fontSize="inherit" aria-hidden="true">
            <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1Zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2Zm0 16H8V7h11v14Z" />
          </SvgIcon>
        </IconButton>
      </Tooltip>
    </Stack>
  );
}
