// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable pivot action trigger (PR 24D §1.3, §8, §22; PR 31E §7-§14;
// PR 31F-6 amendment 2).
//
// Renders the explicit registered actions for one source identity. A
// single legal target renders as a direct accessible action; multiple
// targets expand into a compact in-flow action bar. No-ops against the
// active step's resource/filter context are suppressed, and at the
// maximum pivot depth URL-backed navigation pivots are omitted entirely
// (the modal shows the textual depth explanation). Actions are never
// inferred client-side.
//
// PR 31E extends the trigger with explicit local/context actions
// (``localActions``): read-only commands such as graph expansion that are
// not Pivot resources. Local actions are never no-op suppressed, never
// blocked by Pivot depth, never converted to PivotSteps, never URL
// serialized, and never enter the Pivot workspace — they collapse the
// action bar and invoke a caller callback. Existing ``PivotAction``
// semantics, URL validation, no-op suppression, depth limits, and
// navigation behavior remain unchanged.
//
// PR 31F-6 amendment 2 presentation: expanding a multi-target trigger
// renders ordinary in-flow action buttons (a labelled action region with
// a Cancel control) — no Portal, no MUI Menu/Popover, no fixed
// popup, no backdrop, no anchor bookkeeping, no document outside-click/
// pointerdown listener, no focus trap or floating-menu focus transfer,
// and no body scroll mutation. ``expanded`` is transient presentation
// state only: it is not serialized, never a PivotStep, consumes no
// depth, and resets when the hosting Pivot context changes. The bar is
// a labelled group of ordinary buttons in natural Tab order; no
// ``role=menu/menuitem`` semantics exist.

import { Box, Button } from "@mui/material";
import type { ReactElement } from "react";
import { useEffect, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import {
  MAX_PIVOT_STEPS,
  type PivotStep,
} from "./pivot-types";
import { pushPivotStep, readPivotState } from "./pivot-url";
import { suppressNoOps, type PivotAction } from "./pivot-capabilities";

/**
 * One explicit local/context action (PR 31E §8).
 *
 * A UI command hosted by the pivot trigger that is not a Pivot resource:
 * no PivotStep, no ``pivot=`` URL mutation, no Pivot depth accounting, no
 * no-op suppression. ``key`` must be caller-unique (e.g.
 * ``graph-expand-either``); ``label`` is the final analyst-facing text.
 */
export interface PivotLocalAction {
  readonly key: string;
  readonly label: string;
  readonly disabled?: boolean;
  readonly onSelect: () => void;
}

export interface PivotMenuProps {
  /** Explicit registered actions for this source (never inferred). */
  actions: readonly PivotAction[];
  /** Explicit local/context commands (PR 31E); never URL-backed pivots. */
  localActions?: readonly PivotLocalAction[];
  /** Optional accessible trigger name describing the source value. */
  ariaLabel?: string;
  /** Optional visible trigger label (defaults to the pivots namespace). */
  triggerLabel?: string;
}

/** One unified action-bar entry (URL pivot or local command). */
type ActionEntry =
  | {
      kind: "pivot";
      key: string;
      label: string;
      onSelect: () => void;
    }
  | {
      kind: "local";
      key: string;
      label: string;
      disabled: boolean;
      onSelect: () => void;
    };

/** A small disclosure caret shown after the trigger label. */
function CaretGlyph(): ReactElement {
  return <span aria-hidden="true"> ▾</span>;
}

/**
 * One pivot trigger bound to the URL-backed pivot stack, extended with
 * explicit local/context actions (PR 31E).
 *
 * Works identically on base routes (starts a new stack) and inside the
 * pivot modal (appends to the active stack). Local actions never touch
 * the URL/pivot state and ignore Pivot depth and no-op suppression.
 *
 * Multi-target triggers expand into an ordinary in-flow action bar
 * (PR 31F-6 amendment 2): a labelled group of semantic buttons with a
 * Cancel control. ``expanded`` is presentation-only and resets whenever
 * the active Pivot context changes.
 */
export function PivotMenu({
  actions,
  localActions = [],
  ariaLabel,
  triggerLabel,
}: PivotMenuProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const [searchParams, setSearchParams] = useSearchParams();
  const [expanded, setExpanded] = useState(false);
  const actionBarId = useId();
  const state = readPivotState(searchParams);
  const active = state === null ? null : state.steps[state.steps.length - 1];
  const legalPivotActions = suppressNoOps(actions, active);
  const push = (action: PivotAction): void => {
    setExpanded(false);
    // A step-swap unmounts the source surface (e.g. a resource detail or
    // table) in the same navigation. If the initiating control is the focused
    // element, the removal of the focused node under Chromium's focus
    // fixup races the re-render and can spin/crash the main thread
    // (real-stack E22). Drop focus before the URL navigation so the
    // swap never removes a focused node.
    (document.activeElement as HTMLElement | null)?.blur();
    const step = {
      ...action.target,
      sourceKind: action.sourceKind,
    } as PivotStep;
    // PR 31F-6: the pivot navigation commit runs AFTER the native pointer
    // event completes (next macrotask) — same rationale as the
    // resource-table commit(); a synchronous router commit inside a
    // native pointer event hard-freezes the browser main thread.
    window.setTimeout(() => {
      setSearchParams(pushPivotStep(searchParams, step), { replace: false });
    }, 0);
  };
  const runLocal = (onSelect: () => void): void => {
    setExpanded(false);
    // Same focus-safety blur as pivot navigation: the action bar closes
    // and the initiating control may disappear; drop focus before any
    // action runs.
    (document.activeElement as HTMLElement | null)?.blur();
    onSelect();
  };
  // Presentation-only expansion resets when the hosting Pivot context
  // changes (URL-backed step identity), so a stale expanded bar can never
  // outlive the context that produced it (PR 31F-6 A2-PM08).
  const stateKey = state === null ? "" : JSON.stringify(state);
  useEffect(() => {
    setExpanded(false);
  }, [stateKey]);

  // Depth limit applies to URL-backed navigation pivots only; local
  // commands remain legal at the maximum depth (PR 31E §10).
  const depthReached = state !== null && state.steps.length >= MAX_PIVOT_STEPS;
  const pivotEntries: ActionEntry[] = depthReached
    ? []
    : legalPivotActions.map((action) => ({
        kind: "pivot",
        key: action.key,
        label: t(action.labelKey),
        onSelect: () => push(action),
      }));
  const localEntries: ActionEntry[] = localActions.map((action) => ({
    kind: "local",
    key: action.key,
    label: action.label,
    disabled: action.disabled ?? false,
    onSelect: () => runLocal(action.onSelect),
  }));
  const entries: ActionEntry[] = [...localEntries, ...pivotEntries];
  if (entries.length === 0) {
    return null;
  }
  // Single obvious actionable target: one direct accessible action (the
  // action text is the accessible name; an explicit ariaLabel stays
  // overridable). A sole disabled local action renders as a disabled
  // direct action that can never execute.
  if (entries.length === 1) {
    const entry = entries[0];
    return (
      <Button
        size="small"
        variant="text"
        onClick={entry.onSelect}
        disabled={entry.kind === "local" && entry.disabled}
        aria-label={ariaLabel ?? undefined}
        sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
      >
        {entry.label}
      </Button>
    );
  }

  return (
    <Box sx={{ display: "inline-block" }}>
      <Button
        size="small"
        variant="text"
        onClick={() => setExpanded((current) => !current)}
        aria-expanded={expanded}
        aria-controls={expanded ? actionBarId : undefined}
        aria-label={ariaLabel ?? undefined}
        sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
      >
        {triggerLabel ?? t("trigger.label")}
        <CaretGlyph />
      </Button>
      {expanded ? (
        <Box
          id={actionBarId}
          role="group"
          aria-label={t("trigger.aria")}
          sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, alignItems: "center", mt: 0.5 }}
        >
          {entries.map((entry) => (
            <Button
              key={entry.key}
              size="small"
              variant="text"
              disabled={entry.kind === "local" && entry.disabled}
              onClick={entry.onSelect}
              sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
            >
              {entry.label}
            </Button>
          ))}
          <Button
            size="small"
            variant="text"
            onClick={() => setExpanded(false)}
            sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
          >
            {t("cancel")}
          </Button>
        </Box>
      ) : null}
    </Box>
  );
}
