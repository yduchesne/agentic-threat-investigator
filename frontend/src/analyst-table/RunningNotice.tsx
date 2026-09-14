// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Running-Investigation freshness notice (PR 24C §15).
//
// PR 24C tables never poll. While the Investigation is pending/running the
// table shows currently persisted rows plus this small notice and an
// explicit Refresh — never a continuous timer.

import { Alert, Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";

export interface RunningNoticeProps {
  text: string;
  onRefresh: () => void;
  refreshLabel: string;
}

/** One persistent freshness notice with an explicit Refresh action. */
export function RunningNotice({
  text,
  onRefresh,
  refreshLabel,
}: RunningNoticeProps): ReactElement {
  return (
    <Alert severity="info" role="status" aria-live="polite" sx={{ mb: 1 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Typography variant="caption">{text}</Typography>
        <Button size="small" variant="text" onClick={onRefresh} sx={{ textTransform: "none" }}>
          {refreshLabel}
        </Button>
      </Box>
    </Alert>
  );
}