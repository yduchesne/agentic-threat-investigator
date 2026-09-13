// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Small reusable async-state primitives (PR 24A): loading and empty states.

import { Box, CircularProgress, Typography } from "@mui/material";
import type { ReactElement } from "react";

interface LoadingStateProps {
  /** Screen-reader-announced loading label. */
  label: string;
}

/** Accessible bounded loading surface with a polite live region. */
export function LoadingState({ label }: LoadingStateProps): ReactElement {
  return (
    <Box
      role="status"
      aria-live="polite"
      sx={{ display: "flex", alignItems: "center", gap: 1, py: 3 }}
    >
      <CircularProgress size={20} aria-hidden="true" />
      <Typography variant="body2">{label}</Typography>
    </Box>
  );
}

interface EmptyStateProps {
  title: string;
  message?: string;
}

/** Accessible neutral empty surface; never fabricates data. */
export function EmptyState({ title, message }: EmptyStateProps): ReactElement {
  return (
    <Box sx={{ textAlign: "center", py: 4 }} role="status">
      <Typography variant="h2">{title}</Typography>
      {message ? (
        <Typography variant="body1" sx={{ mt: 0.5 }}>
          {message}
        </Typography>
      ) : null}
    </Box>
  );
}