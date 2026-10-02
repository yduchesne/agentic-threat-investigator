// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31I bounded path-finding controls and result panel.
//
// Path finding is a transient workbench interaction on top of the committed
// graph context: the analyst enters path mode, picks two canonical Entities
// already present in the graph (selection issues NO request), optionally
// bounds the path depth/count, and only the explicit Find action enables the
// dedicated TanStack path query. The result panel reuses the canonical graph
// vocabulary: nodes/edges render through the existing graph component while
// this panel owns endpoint labels, bound controls, the explicit Find/Exit
// actions, the deterministic path selector ("All returned paths" or one
// path), the hop-count/ordinal display, the no-connection state and the
// truthful truncation notice. None of this state is persisted or URL-backed;
// the committed graph context is owned by the route parameters.

import {
  Alert,
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";

import type { GraphPathResult } from "../api/schema-types";

/** The analyst-selected canonical path endpoints (no request yet). */
export interface PathEndpointSelection {
  source: string | null;
  target: string | null;
}

/** The currently highlighted path choice. */
export type PathSelection = number | "all";

export interface GraphPathPanelProps {
  t: (key: string, options?: Record<string, unknown>) => string;
  /** Whether the analyst is in path mode. */
  pathMode: boolean;
  /** The canonical endpoint selection (transient workbench state). */
  endpoints: PathEndpointSelection;
  /** Human-readable labels for the selected endpoint Entity IDs. */
  sourceLabel: string | null;
  targetLabel: string | null;
  /** Path-owned bounds (local controls; part of the query key on Find). */
  maxDepth: number;
  maxPaths: number;
  /** The active path-query result (null while none is displayed). */
  result: GraphPathResult | null;
  /** True while a path request is in flight. */
  loading: boolean;
  /** True after a failed path request (Retry is bounded). */
  error: boolean;
  /** The highlighted path ("all" or one ordinal). */
  selected: PathSelection;
  /** The path endpoints the current result was requested for. */
  resultEndpoints: { source: string; target: string } | null;
  onEnter: () => void;
  onExit: () => void;
  onFind: () => void;
  onEndpointsChanged: () => void;
  onDepthChange: (value: number) => void;
  onPathsChange: (value: number) => void;
  onSelect: (selection: PathSelection) => void;
  onRetry: () => void;
}

/** The bounded PR 31I path-mode toolbar: enter/exit, selection, bounds, Find. */
export function GraphPathModeToolbar(props: GraphPathPanelProps): ReactElement {
  const { t, pathMode } = props;
  if (!pathMode) {
    return (
      <Box sx={{ mb: 1 }}>
        <Button
          size="small"
          variant="outlined"
          onClick={props.onEnter}
          role="button"
          name="path-mode-enter"
        >
          {t("graph.path.enter")}
        </Button>
      </Box>
    );
  }
  const bothSelected =
    props.endpoints.source !== null && props.endpoints.target !== null;
  return (
    <Box role="region" aria-label={t("graph.path.toolbarAria")} sx={{ mb: 1 }}>
      <Typography variant="subtitle2" component="div" sx={{ fontWeight: 600 }}>
        {t("graph.path.title")}
      </Typography>
      <Typography variant="caption" component="div" role="note">
        {bothSelected
          ? t("graph.path.bothSelected")
          : t("graph.path.selectInstruction")}
      </Typography>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }} role="group" aria-label={t("graph.path.selectionAria")}>
        <Typography variant="caption" component="span">
          {t("graph.path.source")}: {props.sourceLabel ?? "—"}
        </Typography>
        <Typography variant="caption" component="span">
          {t("graph.path.target")}: {props.targetLabel ?? "—"}
        </Typography>
        <Button size="small" variant="text" onClick={props.onEndpointsChanged}>
          {t("graph.path.clearEndpoints")}
        </Button>
      </Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mt: 0.5 }}>
        <FormControl size="small" sx={{ minWidth: 110 }}>
          <InputLabel id="path-max-depth-label">{t("graph.path.depth")}</InputLabel>
          <Select
            labelId="path-max-depth-label"
            label={t("graph.path.depth")}
            value={props.maxDepth}
            onChange={(event) =>
              props.onDepthChange(Number(event.target.value))
            }
            aria-label={t("graph.path.depth")}
          >
            {[1, 2, 3, 4, 5, 6].map((depth) => (
              <MenuItem key={depth} value={depth}>
                {depth}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 110 }}>
          <InputLabel id="path-max-paths-label">{t("graph.path.limit")}</InputLabel>
          <Select
            labelId="path-max-paths-label"
            label={t("graph.path.limit")}
            value={props.maxPaths}
            onChange={(event) => props.onPathsChange(Number(event.target.value))}
            aria-label={t("graph.path.limit")}
          >
            {[5, 10, 25].map((limit) => (
              <MenuItem key={limit} value={limit}>
                {limit}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button
          size="small"
          variant="contained"
          disabled={!bothSelected}
          onClick={props.onFind}
          name="path-find"
        >
          {t("graph.path.find")}
        </Button>
        <Button size="small" variant="outlined" onClick={props.onExit} name="path-mode-exit">
          {t("graph.path.exit")}
        </Button>
      </Box>
    </Box>
  );
}

/** Path-query loading/error banners (errors offer a bounded Retry). */
export function GraphPathStatus(props: GraphPathPanelProps): ReactElement | null {
  const { t, result, loading, error } = props;
  if (result !== null) {
    return null;
  }
  if (loading) {
    return (
      <Alert severity="info" role="status" sx={{ mb: 1 }}>
        {t("graph.path.loading")}
      </Alert>
    );
  }
  if (error) {
    return (
      <Alert severity="error" role="alert" sx={{ mb: 1 }}>
        {t("graph.path.error.message")}
        <Button
          size="small"
          variant="outlined"
          onClick={props.onRetry}
          sx={{ ml: 1, textTransform: "none" }}
        >
          {t("error.retry")}
        </Button>
      </Alert>
    );
  }
  return null;
}

/**
 * The displayed path result: no-connection state, deterministic selector,
 * hop counts, truncation notice and the highlighted-path excerpt.
 */
export function GraphPathResultPanel(props: GraphPathPanelProps): ReactElement | null {
  const { t, result, selected, onSelect } = props;
  if (result === null) {
    return null;
  }
  return (
    <Box
      role="region"
      aria-label={t("graph.path.results")}
      sx={{ mb: 1 }}
    >
      <Typography variant="subtitle2" component="div" sx={{ fontWeight: 600 }}>
        {t("graph.path.results")}
      </Typography>
      {result.paths.length === 0 ? (
        <Alert severity="info" role="status" sx={{ mt: 0.5 }}>
          {t("graph.path.noPath.title")}: {t("graph.path.noPath.message")}
        </Alert>
      ) : (
        <>
          {result.truncated ? (
            <Alert severity="warning" role="status" sx={{ mt: 0.5 }}>
              {t("graph.path.truncated")}
            </Alert>
          ) : null}
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.5 }}>
            <FormControl size="small" sx={{ minWidth: 220 }}>
              <InputLabel id="path-select-label">
                {t("graph.path.selector")}
              </InputLabel>
              <Select
                labelId="path-select-label"
                label={t("graph.path.selector")}
                value={String(selected)}
                onChange={(event) => {
                  const value = event.target.value;
                  onSelect(value === "all" ? "all" : Number(value));
                }}
                aria-label={t("graph.path.selector")}
              >
                <MenuItem value="all">{t("graph.path.all")}</MenuItem>
                {result.paths.map((path, index) => (
                  <MenuItem key={index} value={index}>
                    {t("graph.path.path", {
                      ordinal: String(index + 1),
                      hops: String(Math.max(path.entity_ids.length - 1, 0)),
                    })}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        </>
      )}
    </Box>
  );
}
