// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph temporal-range controls (PR 38-8, simplifying PR 31J).
//
// Presentation-focused temporal toolbar for the Graph workspace. The
// committed temporal range's ONLY authority is the route URL (refresh and
// Back/Forward reproduce the same range); this component owns no state
// beyond the browser-local draft passed in, exactly like GraphFilters.
// Draft edits never issue graph requests before Apply; Apply commits the
// validated range in one URL transition; Disable removes the temporal-owned
// URL parameters.
//
// The draft represents each boundary as a required local DATE plus an
// OPTIONAL local TIME. A blank time is interpreted as local midnight
// (``00:00:00``) when the draft is normalized, never as end-of-day/current
// time, and never by forcing a ``datetime-local`` control to display
// midnight. A neutral, uncommitted draft defaults its end DATE to the
// browser user's local current calendar date and leaves its end time blank.
//
// Half-open semantics: the committed range is
// ``[observed_from, observed_to)``; the upper bound is exclusive, and an
// observation at the upper-bound timestamp is never included. The wording
// stays observational: it constrains ``observed_at`` within the range and
// never implies a Relationship lifetime.

import { Box, Button, Checkbox, FormControlLabel, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import type { TFunction } from "i18next";

import { isoToLocalDateTimeValue, localDateTimeToIso } from "../analyst-table/filters";
import {
  graphTemporalActive,
  type GraphTemporalContext,
} from "./graph-temporal";

/** One browser-local temporal draft (never committed before Apply). */
export interface GraphTemporalDraft {
  /** Whether temporal exploration is enabled in the draft. */
  temporal: boolean;
  /** Draft range start local calendar date (``YYYY-MM-DD``; required). */
  startDate: string;
  /** Draft range start local wall-clock time (blank = local midnight). */
  startTime: string;
  /** Draft range end local calendar date (``YYYY-MM-DD``; required). */
  endDate: string;
  /** Draft range end local wall-clock time (blank = local midnight). */
  endTime: string;
}

/**
 * The browser user's local current calendar date as ``YYYY-MM-DD``.
 *
 * Derived from local calendar fields (never a UTC ``toISOString`` slice) so
 * a timezone boundary cannot produce tomorrow/yesterday relative to the
 * user's calendar. ``now`` is injectable so tests never depend on the wall
 * clock.
 */
export function localToday(now: Date = new Date()): string {
  const pad = (value: number): string => String(value).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}

/**
 * Normalize one local date + optional local time to the app ISO UTC instant.
 *
 * A blank time means local ``00:00:00``. Malformed dates/times and impossible
 * calendar dates normalize to absence (never appended ``Z`` directly).
 */
export function graphTemporalBoundaryToIso(
  date: string,
  time: string,
): string | undefined {
  if (date === "") {
    return undefined;
  }
  const normalizedTime = time === "" ? "00:00" : time;
  return localDateTimeToIso(`${date}T${normalizedTime}`);
}

/**
 * Split one committed ISO instant back into local date and time parts.
 *
 * A committed midnight instant renders as ``00:00``; the codec cannot
 * distinguish an explicit midnight from a blank time and deliberately does
 * not persist that distinction (both have identical semantics).
 */
function localDateAndTime(iso: string | undefined): { date: string; time: string } {
  const local = isoToLocalDateTimeValue(iso);
  if (local === "") {
    return { date: "", time: "" };
  }
  const [date, time] = local.split("T");
  return { date: date ?? "", time: time ?? "" };
}

/**
 * Build a draft from the committed temporal tuple (URL resync/init).
 *
 * An active tuple reconstructs both boundaries. A neutral, uncommitted tuple
 * leaves the start boundary blank and defaults the end DATE to the browser
 * user's local current calendar date with a blank end time.
 */
export function graphTemporalDraftFromCommitted(
  context: GraphTemporalContext,
  now: Date = new Date(),
): GraphTemporalDraft {
  if (!graphTemporalActive(context)) {
    return {
      temporal: false,
      startDate: "",
      startTime: "",
      endDate: localToday(now),
      endTime: "",
    };
  }
  const start = localDateAndTime(context.rangeStart);
  const end = localDateAndTime(context.rangeEnd);
  return {
    temporal: true,
    startDate: start.date,
    startTime: start.time,
    endDate: end.date,
    endTime: end.time,
  };
}

/**
 * Convert one VALIDATED draft to the committed temporal tuple.
 *
 * Only called after ``graphTemporalDraftError`` passes; defensively still
 * fails closed (mode off) if the validated range cannot round-trip.
 */
export function graphTemporalDraftToCommitted(
  draft: GraphTemporalDraft,
): GraphTemporalContext {
  const rangeStart = graphTemporalBoundaryToIso(draft.startDate, draft.startTime);
  const rangeEnd = graphTemporalBoundaryToIso(draft.endDate, draft.endTime);
  const valid =
    draft.temporal &&
    rangeStart !== undefined &&
    rangeEnd !== undefined &&
    rangeStart < rangeEnd;
  return {
    temporal: valid,
    rangeStart: valid ? rangeStart : undefined,
    rangeEnd: valid ? rangeEnd : undefined,
  };
}

/**
 * Validate one draft for Apply.
 *
 * Rejects a missing start date, a missing end date, a malformed date or
 * optional time, and a normalized ``start >= end``. A blank time is valid
 * and means local midnight. A reversed/equal range is NEVER silently
 * repaired. A disabled draft is always committable (it commits mode off).
 */
export function graphTemporalDraftError(
  t: TFunction,
  draft: GraphTemporalDraft,
): string | null {
  if (!draft.temporal) {
    return null;
  }
  if (draft.startDate === "") {
    return t("graph.temporal.error.startDate");
  }
  if (draft.endDate === "") {
    return t("graph.temporal.error.endDate");
  }
  const rangeStart = graphTemporalBoundaryToIso(draft.startDate, draft.startTime);
  const rangeEnd = graphTemporalBoundaryToIso(draft.endDate, draft.endTime);
  if (rangeStart === undefined || rangeEnd === undefined) {
    return t("graph.temporal.error.invalid");
  }
  if (rangeStart >= rangeEnd) {
    return t("graph.temporal.error.range");
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
  onSetDraft: (draft: GraphTemporalDraft) => void;
  onApply: () => void;
  /** Disable temporal mode and restore ordinary graph behavior. */
  onDisable: () => void;
}

/** The compact temporal exploration toolbar for the Graph workspace. */
export function GraphTemporalControls({
  t,
  committed,
  draft,
  error,
  onSetDraft,
  onApply,
  onDisable,
}: GraphTemporalControlsProps): ReactElement {
  const set = (patch: Partial<GraphTemporalDraft>): void => {
    onSetDraft({ ...draft, ...patch });
  };
  const active = graphTemporalActive(committed);
  const disabled = !draft.temporal;
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
          type="date"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.startDate")}
          disabled={disabled}
          value={draft.startDate}
          onChange={(event) => set({ startDate: event.target.value })}
        />
        <TextField
          size="small"
          type="time"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.startTime")}
          disabled={disabled}
          value={draft.startTime}
          onChange={(event) => set({ startTime: event.target.value })}
        />
        <TextField
          size="small"
          type="date"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.endDate")}
          disabled={disabled}
          value={draft.endDate}
          onChange={(event) => set({ endDate: event.target.value })}
        />
        <TextField
          size="small"
          type="time"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.temporal.endTime")}
          disabled={disabled}
          value={draft.endTime}
          onChange={(event) => set({ endTime: event.target.value })}
        />
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
    </Box>
  );
}
