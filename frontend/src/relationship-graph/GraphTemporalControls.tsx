// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph temporal controls (PR 31J).
//
// Presentation-focused temporal toolbar for the Graph workspace. The
// committed temporal tuple's ONLY authority is the route URL (refresh and
// Back/Forward reproduce the same frame); this component owns no state
// beyond the browser-local draft passed in, exactly like GraphFilters.
// Draft edits never issue graph requests before Apply; Apply commits the
// validated tuple in one URL transition starting at frame 0; Disable
// removes the temporal-owned URL parameters; Previous/Next change only the
// committed frame index through the existing codec (no wrapping, no local
// frame state). When temporal mode is active the component renders an
// analyst-facing frame banner whose wording is strictly observational
// (``observed_at`` within the half-open frame) and never implies a
// Relationship lifetime.
//
// Half-open semantics: every frame is ``[observed_from, observed_to)``; the
// upper bound is exclusive, and an observation at a shared boundary
// timestamp belongs to exactly one frame.

import {
  Box,
  Button,
  Checkbox,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import type { TFunction } from "i18next";

import { isoToLocalDateTimeValue, localDateTimeToIso } from "../analyst-table/filters";
import {
  GRAPH_TEMPORAL_FRAME_COUNTS,
  graphTemporalActive,
  graphTemporalFrameAt,
  type GraphTemporalContext,
  type GraphTemporalFrameCount,
} from "./graph-temporal";

/** One browser-local temporal draft (never committed before Apply). */
export interface GraphTemporalDraft {
  /** Whether temporal exploration is enabled in the draft. */
  temporal: boolean;
  /** Draft overall range start (``datetime-local`` wall-clock value). */
  rangeStart: string;
  /** Draft overall range end (``datetime-local`` wall-clock value). */
  rangeEnd: string;
  /** Draft frame count (exactly 4/8/12/24). */
  frameCount: GraphTemporalFrameCount;
}

/** Build a draft from the committed temporal tuple (URL resync/init). */
export function graphTemporalDraftFromCommitted(
  context: GraphTemporalContext,
): GraphTemporalDraft {
  return {
    temporal: context.temporal,
    rangeStart: isoToLocalDateTimeValue(context.rangeStart),
    rangeEnd: isoToLocalDateTimeValue(context.rangeEnd),
    frameCount: context.frameCount,
  };
}

/**
 * Convert one VALIDATED draft to the committed temporal tuple.
 *
 * Only called after ``graphTemporalDraftError`` passes; defensively still
 * fails closed (mode off) if the validated range cannot round-trip. A new
 * Apply ALWAYS starts at the first frame (frameIndex 0) per PR 31J B4 — a
 * stale frame index from a previous range/count configuration is never
 * retained.
 */
export function graphTemporalDraftToCommitted(
  draft: GraphTemporalDraft,
): GraphTemporalContext {
  const rangeStart = localDateTimeToIso(draft.rangeStart);
  const rangeEnd = localDateTimeToIso(draft.rangeEnd);
  const valid =
    draft.temporal &&
    rangeStart !== undefined &&
    rangeEnd !== undefined &&
    rangeStart < rangeEnd;
  return {
    temporal: valid,
    rangeStart: valid ? rangeStart : undefined,
    rangeEnd: valid ? rangeEnd : undefined,
    frameCount: draft.frameCount,
    frameIndex: 0,
  };
}

/**
 * Validate one draft for Apply (PR 31J B3).
 *
 * Rejects when a ranged draft misses either bound, carries a malformed
 * timestamp, has ``start >= end``, or selects a frame count outside
 * 4/8/12/24. A reversed/empty range is NEVER silently repaired. A disabled
 * draft is always committable (it commits ordinary mode off).
 */
export function graphTemporalDraftError(
  t: TFunction,
  draft: GraphTemporalDraft,
): string | null {
  if (!draft.temporal) {
    return null;
  }
  if (draft.rangeStart === "" && draft.rangeEnd === "") {
    return t("graph.temporal.error.range");
  }
  if (draft.rangeStart === "") {
    return t("graph.temporal.error.rangeStart");
  }
  if (draft.rangeEnd === "") {
    return t("graph.temporal.error.rangeEnd");
  }
  const rangeStart = localDateTimeToIso(draft.rangeStart);
  const rangeEnd = localDateTimeToIso(draft.rangeEnd);
  if (rangeStart === undefined || rangeEnd === undefined) {
    return t("graph.temporal.error.range");
  }
  if (rangeStart >= rangeEnd) {
    return t("graph.temporal.error.range");
  }
  if (!(GRAPH_TEMPORAL_FRAME_COUNTS as readonly number[]).includes(draft.frameCount)) {
    return t("graph.temporal.error.frames");
  }
  return null;
}

export interface GraphTemporalControlsProps {
  t: TFunction;
  /** The committed temporal tuple (URL-backed; the only committed authority). */
  committed: GraphTemporalContext;
  /** The browser-local draft (never committed before Apply). */
  draft: GraphTemporalDraft;
  /** Localized draft validation error, or null when commit-able. */
  error: string | null;
  /** ``Previous`` availability for the committed frame. */
  canPrevious: boolean;
  /** ``Next`` availability for the committed frame. */
  canNext: boolean;
  onSetDraft: (draft: GraphTemporalDraft) => void;
  onApply: () => void;
  /** Disable temporal mode and restore ordinary graph behavior. */
  onDisable: () => void;
  onPrevious: () => void;
  onNext: () => void;
}

/** The compact temporal exploration toolbar for the Graph workspace. */
export function GraphTemporalControls({
  t,
  committed,
  draft,
  error,
  canPrevious,
  canNext,
  onSetDraft,
  onApply,
  onDisable,
  onPrevious,
  onNext,
}: GraphTemporalControlsProps): ReactElement {
  const set = (patch: Partial<GraphTemporalDraft>): void => {
    onSetDraft({ ...draft, ...patch });
  };
  const active = graphTemporalActive(committed);
  const frame = active ? graphTemporalFrameAt(committed) : undefined;
  return (
    <Box
      role="group"
      aria-label={t("graph.temporal.aria")}
      sx={(theme) => ({
        display: "flex",
        flexDirection: "column",
        gap: 1,
        p: 1,
        borderRadius: 0.5,
        border: 1,
        borderColor: theme.palette.divider,
        bgcolor: "action.hover",
        mt: 1,
        mb: 1,
      })}
    >
      <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 1 }}>
        <FormControlLabel
          control={
            <Checkbox
              checked={draft.temporal}
              onChange={(event) => set({ temporal: event.target.checked })}
              size="small"
            />
          }
          label={t("graph.temporal.enable")}
        />
        <TextField
          size="small"
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.rangeStart")}
          disabled={!draft.temporal}
          value={draft.rangeStart}
          onChange={(event) => set({ rangeStart: event.target.value })}
        />
        <TextField
          size="small"
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.rangeEnd")}
          disabled={!draft.temporal}
          value={draft.rangeEnd}
          onChange={(event) => set({ rangeEnd: event.target.value })}
        />
        <Tooltip title={t("graph.temporal.framesTooltip")}>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel id="graph-temporal-frames-label">
            {t("graph.temporal.frames")}
          </InputLabel>
          <Select
            labelId="graph-temporal-frames-label"
            label={t("graph.temporal.frames")}
            disabled={!draft.temporal}
            value={String(draft.frameCount)}
            onChange={(event) =>
              set({ frameCount: parseInt(event.target.value, 10) as GraphTemporalFrameCount })
            }
          >
            {GRAPH_TEMPORAL_FRAME_COUNTS.map((count) => (
              <MenuItem key={count} value={String(count)}>
                {String(count)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        </Tooltip>
        <Button size="small" variant="contained" onClick={onApply} sx={{ textTransform: "none" }}>
          {t("graph.temporal.apply")}
        </Button>
        <Button
          size="small"
          variant="outlined"
          disabled={!active}
          onClick={onDisable}
          sx={{ textTransform: "none" }}
        >
          {t("graph.temporal.disable")}
        </Button>
        <Button
          size="small"
          variant="outlined"
          disabled={!canPrevious}
          onClick={onPrevious}
          aria-label={t("graph.temporal.previous")}
          sx={{ textTransform: "none" }}
        >
          {t("graph.temporal.previous")}
        </Button>
        <Button
          size="small"
          variant="outlined"
          disabled={!canNext}
          onClick={onNext}
          aria-label={t("graph.temporal.next")}
          sx={{ textTransform: "none" }}
        >
          {t("graph.temporal.next")}
        </Button>
      </Box>
      {error !== null ? (
        <Typography
          variant="caption"
          role="alert"
          color="error"
          sx={{ display: "block", mb: 0.5 }}
        >
          {error}
        </Typography>
      ) : null}
      {active && frame !== undefined ? (
        <Typography
          variant="caption"
          component="div"
          role="status"
          aria-label={t("graph.temporal.status", {
            current: String(committed.frameIndex + 1),
            total: String(committed.frameCount),
            from: frame.observedFrom ?? "",
            to: frame.observedTo ?? "",
          })}
        >
          {t("graph.temporal.status", {
            current: String(committed.frameIndex + 1),
            total: String(committed.frameCount),
            from: frame.observedFrom ?? "",
            to: frame.observedTo ?? "",
          })}
        </Typography>
      ) : null}
    </Box>
  );
}
