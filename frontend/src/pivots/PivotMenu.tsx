// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable pivot action trigger (PR 24D §1.3, §8, §22; PR 31E §7-§14).
//
// Renders the explicit registered actions for one source identity. A
// single legal target renders as a direct accessible action; multiple
// targets render as an accessible menu. No-ops against the active step's
// resource/filter context are suppressed, and at the maximum pivot depth
// URL-backed navigation pivots are omitted entirely (the modal shows the
// textual depth explanation). Actions are never inferred client-side.
//
// PR 31E extends the trigger with explicit local/context actions
// (``localActions``): read-only commands such as graph expansion that are
// not Pivot resources. Local actions are never no-op suppressed, never
// blocked by Pivot depth, never converted to PivotSteps, never URL
// serialized, and never enter the Pivot workspace — they close the menu
// and invoke a caller callback. Existing ``PivotAction`` semantics,
// URL validation, no-op suppression, depth limits, and navigation
// behavior remain unchanged.
//
// The multi-target menu deliberately does NOT use the MUI Menu
// (Popover/Modal) primitive: in this material-ui 7 release a Modal that
// mounts while two other modals (the pivot workspace Dialog and the
// scoped DetailDrawer) are already open permanently freezes the browser
// main thread on the triggering mouse interaction (reproduced on the
// real Chromium stack, E2E PR 24D). The menu here is therefore a
// non-modal Portal: fixed viewport coordinates from the trigger rect, an
// outside-close layer, and full WAI-ARIA menubar semantics
// (role=menu/menuitem, Arrow/Escape/Tab handling). It participates in no
// ModalManager bookkeeping, so nesting depth can never deadlock focus
// management. Disabled items are skipped by keyboard traversal when
// practical and can never be activated.

import { Box, Button, Paper, Portal } from "@mui/material";
import type { ReactElement } from "react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import {
  MAX_PIVOT_STEPS,
  type PivotStep,
} from "./pivot-types";
import { pushPivotStep, readPivotState } from "./pivot-url";
import { suppressNoOps, type PivotAction } from "./pivot-capabilities";

/**
 * One explicit local/context menu action (PR 31E §8).
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

/** One unified menu entry (URL pivot or local command, or a separator). */
type MenuEntry =
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
    }
  | { kind: "separator"; key: string };

/** Menu sits above the detail drawer (1300) and the workspace dialog (1250). */
const MENU_Z_INDEX = 1400;

/**
 * Non-modal action menu: a portal-mounted Paper positioned at the
 * trigger's viewport rect, with an outside-close layer directly beneath.
 */
function ActionMenu({
  triggerRef,
  entries,
  open,
  setOpen,
}: {
  triggerRef: React.RefObject<HTMLElement | null>;
  entries: readonly MenuEntry[];
  open: boolean;
  setOpen: (next: boolean) => void;
}): ReactElement | null {
  const itemRefs = useRef<Array<HTMLElement | null>>([]);
  const paperRef = useRef<HTMLElement | null>(null);
  // Enabled button entry indices (separators and disabled items excluded).
  const enabledIndices = entries.flatMap((entry, index) =>
    entry.kind !== "separator" && (entry.kind !== "local" || !entry.disabled)
      ? [index]
      : [],
  );
  const firstEnabledIndex = enabledIndices[0] ?? -1;
  useEffect(() => {
    if (!open) {
      return;
    }
    // Move focus into the menu when it opens (roving keyboard model),
    // landing on the first enabled item (disabled items are skipped).
    //
    // The MUI Portal materializes its mount container through its own
    // state effect, so the menu items are not in the DOM during the very
    // commit that flips ``open``; focus is therefore deferred one tick so
    // the item refs are populated before ``focus()`` runs.
    const focusTimer = window.setTimeout(() => {
      const first = firstEnabledIndex;
      if (first >= 0) {
        itemRefs.current[first]?.focus();
      }
    }, 0);
    // Non-modal close: any pointer press outside the menu and its trigger
    // (which may arrive on the very click that opened us — pointerdown
    // precedes the click event, and the trigger check covers that case)
    // dismisses the menu. Document-capture ordering keeps this in sync
    // with the real event stream, unlike a painted full-screen layer.
    const closeOnOutside = (event: PointerEvent): void => {
      const target = event.target as Node | null;
      if (target === null) {
        return;
      }
      if (target === triggerRef.current || (paperRef.current?.contains(target) ?? false)) {
        return;
      }
      setOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutside, true);
    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("pointerdown", closeOnOutside, true);
    };
  }, [open, triggerRef, setOpen]);
  if (!open || triggerRef.current === null) {
    return null;
  }
  const rect = triggerRef.current.getBoundingClientRect();
  const onKeyDown = (event: React.KeyboardEvent): void => {
    const activeIndex = itemRefs.current.findIndex(
      (node) => node === document.activeElement,
    );
    let target = -1;
    if (event.key === "ArrowDown" || event.key === "ArrowRight") {
      const position = enabledIndices.indexOf(activeIndex);
      target = enabledIndices[(position + 1) % enabledIndices.length];
    } else if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
      const position = enabledIndices.indexOf(activeIndex);
      target = enabledIndices[
        (position - 1 + enabledIndices.length) % enabledIndices.length
      ];
    } else if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
      return;
    } else {
      return;
    }
    event.preventDefault();
    itemRefs.current[target]?.focus();
  };
  return (
    <Portal>
      <Paper
        ref={(node) => {
          paperRef.current = node;
        }}
        elevation={8}
        role="menu"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        sx={{
          position: "fixed",
          // The trigger rect is viewport-relative; the Portal renders at
          // document.body so these coordinates are exact.
          left: Math.max(0, rect.left),
          top: rect.bottom + 4,
          zIndex: MENU_Z_INDEX,
          maxHeight: 320,
          overflowY: "auto",
          minWidth: Math.min(Math.max(rect.width, 220), 420),
          borderRadius: 1,
        }}
      >
        {entries.map((entry, index) => {
          if (entry.kind === "separator") {
            return (
              <Box
                key={entry.key}
                role="separator"
                aria-orientation="horizontal"
                sx={{ mx: 1, my: 0.5, borderTop: 1, borderColor: "divider" }}
              />
            );
          }
          return (
            <Button
              key={entry.key}
              role="menuitem"
              ref={(node) => {
                itemRefs.current[index] = node;
              }}
              tabIndex={index === firstEnabledIndex ? 0 : -1}
              size="small"
              variant="text"
              fullWidth
              disabled={entry.kind === "local" && entry.disabled}
              title={entry.label}
              onClick={entry.onSelect}
              sx={{ justifyContent: "flex-start", textTransform: "none", p: 0.75 }}
            >
              {entry.label}
            </Button>
          );
        })}
      </Paper>
    </Portal>
  );
}

/**
 * One pivot trigger bound to the URL-backed pivot stack, extended with
 * explicit local/context actions (PR 31E).
 *
 * Works identically on base routes (starts a new stack) and inside the
 * pivot modal (appends to the active stack). Local actions never touch
 * the URL/pivot state and ignore Pivot depth and no-op suppression.
 */
export function PivotMenu({
  actions,
  localActions = [],
  ariaLabel,
  triggerLabel,
}: PivotMenuProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const [searchParams, setSearchParams] = useSearchParams();
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const state = readPivotState(searchParams);
  const active = state === null ? null : state.steps[state.steps.length - 1];
  const legalPivotActions = suppressNoOps(actions, active);
  const push = (action: PivotAction): void => {
    setOpen(false);
    // A step-swap unmounts the source surface (e.g. a detail drawer) in
    // the same navigation. If the initiating control is the focused
    // element, the removal of the focused node under Chromium's focus
    // fixup races the re-render and can spin/crash the main thread
    // (real-stack E22). Drop focus before the URL navigation so the
    // swap never removes a focused node.
    (document.activeElement as HTMLElement | null)?.blur();
    const step = {
      ...action.target,
      sourceKind: action.sourceKind,
    } as PivotStep;
    setSearchParams(pushPivotStep(searchParams, step), { replace: false });
  };
  const runLocal = (onSelect: () => void): void => {
    setOpen(false);
    // Same focus-safety blur as pivot navigation: the menu closes and the
    // initiating control may disappear; drop focus before any action runs.
    (document.activeElement as HTMLElement | null)?.blur();
    onSelect();
  };
  // Depth limit applies to URL-backed navigation pivots only; local
  // commands remain legal at the maximum depth (PR 31E §10).
  const depthReached = state !== null && state.steps.length >= MAX_PIVOT_STEPS;
  const pivotEntries: MenuEntry[] = depthReached
    ? []
    : legalPivotActions.map((action) => ({
        kind: "pivot",
        key: action.key,
        label: t(action.labelKey),
        onSelect: () => push(action),
      }));
  const localEntries: MenuEntry[] = localActions.map((action) => ({
    kind: "local",
    key: action.key,
    label: action.label,
    disabled: action.disabled ?? false,
    onSelect: () => runLocal(action.onSelect),
  }));
  const entries: MenuEntry[] = [
    ...localEntries,
    ...(localEntries.length > 0 && pivotEntries.length > 0
      ? [{ kind: "separator", key: "local-navigation-separator" } as const]
      : []),
    ...pivotEntries,
  ];
  if (entries.length === 0) {
    return null;
  }
  // Single obvious actionable target: one direct accessible action (the
  // action text is the accessible name; an explicit ariaLabel stays
  // overridable). A sole disabled local action renders as a disabled
  // direct action that can never execute.
  if (entries.length === 1) {
    const entry = entries[0];
    if (entry.kind !== "separator") {
      return (
        <Button
          size="small"
          variant="text"
          onClick={entry.onSelect}
          disabled={entry.kind === "local" && entry.disabled}
          aria-label={ariaLabel ?? undefined}
          title={entry.label}
          sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
        >
          {entry.label}
        </Button>
      );
    }
  }
  const onTriggerKeyDown = (event: React.KeyboardEvent): void => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      setOpen(true);
    }
  };
  return (
    <Box sx={{ display: "inline-block" }}>
      <Button
        ref={(node) => {
          triggerRef.current = node;
        }}
        size="small"
        variant="text"
        onClick={() => setOpen(true)}
        onKeyDown={onTriggerKeyDown}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={ariaLabel ?? triggerLabel ?? t("trigger.aria")}
        sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
      >
        {triggerLabel ?? t("trigger.label")}
      </Button>
      <ActionMenu
        triggerRef={triggerRef}
        entries={entries}
        open={open}
        setOpen={setOpen}
      />
    </Box>
  );
}
