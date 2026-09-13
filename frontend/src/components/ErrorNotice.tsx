// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded error presentation primitive (PR 24A).
//
// Renders only safe text: the public backend envelope fields
// (code/message/request_id), stable client-side codes, or translated
// generic text. Raw response bodies, Python exceptions and internal
// tracebacks are never rendered.

import { Alert, AlertTitle, Button, Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
export interface ErrorNoticeProps {
  title: string;
  /** Safe server-provided message (public envelope only). */
  message?: string | null;
  /** Pre-localized support reference line; omit to hide the reference. */
  supportText?: string | null;
  /** Optional retry action. */
  onRetry?: () => void;
  retryLabel?: string;
  severity?: "error" | "warning";
}

/**
 * Present one failure in a bounded, accessible alert region.
 *
 * All text is plain text rendered via React (auto-escaped); it is never
 * built from raw backend bodies with dangerous HTML.
 */
export function ErrorNotice({
  title,
  message,
  supportText,
  onRetry,
  retryLabel,
  severity = "error",
}: ErrorNoticeProps): ReactElement {
  return (
    <Alert severity={severity} role="alert" sx={{ width: "100%" }}>
      <AlertTitle>{title}</AlertTitle>
      {message ? <Typography variant="body2">{message}</Typography> : null}
      {supportText ? (
        <Typography variant="caption" sx={{ display: "block", mt: 0.5 }}>
          {supportText}
        </Typography>
      ) : null}
      {onRetry ? (
        <Box sx={{ mt: 1 }}>
          <Button size="small" variant="outlined" onClick={onRetry} sx={{ textTransform: "none" }}>
            {retryLabel ?? "Retry"}
          </Button>
        </Box>
      ) : null}
    </Alert>
  );
}