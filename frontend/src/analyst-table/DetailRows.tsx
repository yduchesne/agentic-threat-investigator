// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Generic key/value detail presentation (PR 24C §8).
//
// Drawer content shares one deterministic label/value layout. Values are
// React-rendered (auto-escaped); nothing here ever builds raw HTML.

import { Box, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";

export interface DetailRow {
  /** Translated field label. */
  label: string;
  /** Escaped value renderer. */
  value: ReactNode;
}

/** One label/value line of a resource detail surface. */
export function DetailRow({ label, value }: DetailRow): ReactElement {
  return (
    <Box sx={{ display: "flex", gap: 1, alignItems: "baseline" }}>
      <Typography
        variant="caption"
        component="span"
        sx={{ flex: "0 0 180px", color: "text.secondary", fontWeight: 600 }}
      >
        {label}
      </Typography>
      <Typography variant="body2" component="span" sx={{ flexGrow: 1, wordBreak: "break-word" }}>
        {value}
      </Typography>
    </Box>
  );
}

export interface DetailRowsProps {
  rows: readonly DetailRow[];
}

/** A bounded list of label/value lines. */
export function DetailRows({ rows }: DetailRowsProps): ReactElement {
  return (
    <Box role="list" sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
      {rows.map((row, index) => (
        <DetailRow key={row.label ?? index} label={row.label} value={row.value} />
      ))}
    </Box>
  );
}

/** One section heading inside a detail drawer. */
export function DetailSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}): ReactElement {
  return (
    <Box sx={{ mt: 1.5 }}>
      <Typography variant="h3">{title}</Typography>
      <Box sx={{ mt: 0.5 }}>{children}</Box>
    </Box>
  );
}