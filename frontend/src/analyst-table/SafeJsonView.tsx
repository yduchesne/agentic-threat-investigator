// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Small safe structured-data viewer (PR 24C §12, §19).
//
// Renders allowlisted public ``state``/``diff`` mappings (and Evidence
// facts) as deterministic escaped text — bounded nesting, deterministic
// key order, no HTML, no editor behavior. Data is never executable markup.

import { Box, Typography } from "@mui/material";
import type { ReactElement } from "react";

/** Present one JSON-compatible value as a bounded text string. */
export function jsonScalarText(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  return JSON.stringify(value);
}

/** Bound nesting depth for the safe viewer. */
export const MAX_SAFE_JSON_DEPTH = 3;

/** Deterministic ordered keys of one public mapping (sorted for stability). */
function orderedKeys(value: Record<string, unknown>): string[] {
  return Object.keys(value).sort();
}

export interface SafeJsonViewProps {
  /** The allowlisted public mapping (state/diff/facts). */
  data: unknown;
  /** Accessible label for the bounded surface. */
  label: string;
  /** Maximum nesting depth before values collapse to an ellipsis. */
  maxDepth?: number;
}

/**
 * One bounded structured-data viewer.
 *
 * Objects render as ``key: value`` lines with indentation per depth; arrays
 * render index-prefixed entries; nested depth beyond ``maxDepth`` collapses
 * to ``…``. All text is React-escaped.
 */
export function SafeJsonView({
  data,
  label,
  maxDepth = MAX_SAFE_JSON_DEPTH,
}: SafeJsonViewProps): ReactElement {
  return (
    <Box
      component="pre"
      role="region"
      aria-label={label}
      sx={(theme) => ({
        fontFamily: "monospace",
        fontSize: "0.82rem",
        p: 1,
        borderRadius: 0.5,
        border: 1,
        borderColor: theme.palette.divider,
        maxHeight: 320,
        overflow: "auto",
        whiteSpace: "pre-wrap",
      })}
    >
      {renderValue(data, 0, maxDepth)}
    </Box>
  );
}

/** Render one value at a depth with bounded nesting. */
function renderValue(value: unknown, depth: number, maxDepth: number): ReactElement {
  if (depth > maxDepth) {
    return <Typography component="span" variant="caption">…</Typography>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <Typography component="span" variant="caption">[]</Typography>;
    }
    return (
      <Box component="span" sx={{ display: "block" }}>
        {value.map((entry, index) => (
          <Box key={index} component="span" sx={{ display: "block" }}>
            {renderArrayEntry(entry, index, depth, maxDepth)}
          </Box>
        ))}
      </Box>
    );
  }
  if (isRecord(value)) {
    const keys = orderedKeys(value);
    if (keys.length === 0) {
      return <Typography component="span" variant="caption">{"{}"}</Typography>;
    }
    return (
      <Box component="span" sx={{ display: "block" }}>
        {keys.map((key) => (
          <Box key={key} component="span" sx={{ display: "block" }}>
            {renderObjectEntry(key, value[key], depth, maxDepth)}
          </Box>
        ))}
      </Box>
    );
  }
  return <Typography component="span" variant="body2">{jsonScalarText(value)}</Typography>;
}

/** One array entry with a deterministic index prefix. */
function renderArrayEntry(
  entry: unknown,
  index: number,
  depth: number,
  maxDepth: number,
): ReactElement {
  return (
    <Box component="span" sx={{ display: "block", pl: 1 }}>
      <Typography component="span" variant="caption" sx={{ color: "text.secondary" }}>
        [{index}]
      </Typography>{" "}
      {renderValue(entry, depth + 1, maxDepth)}
    </Box>
  );
}

/** One object entry with a deterministic key label. */
function renderObjectEntry(
  key: string,
  entry: unknown,
  depth: number,
  maxDepth: number,
): ReactElement {
  return (
    <Box component="span" sx={{ display: "block", pl: 1 }}>
      <Typography component="span" variant="caption" sx={{ fontWeight: 700 }}>
        {key}:
      </Typography>{" "}
      {renderValue(entry, depth + 1, maxDepth)}
    </Box>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}