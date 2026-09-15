// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable pivot action trigger (PR 24D §1.3, §8, §22).
//
// Renders the explicit registered actions for one source identity. A
// single legal target renders as a direct accessible action; multiple
// targets render as an accessible menu. No-ops against the active step's
// resource/filter context are suppressed, and at the maximum pivot depth
// the trigger is omitted entirely (the modal shows the textual depth
// explanation). Actions are never inferred client-side.
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
// management.

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

export interface PivotMenuProps {
  /** Explicit registered actions for this source (never inferred). */
  actions: readonly PivotAction[];
  /** Optional accessible trigger name describing the source value. */
  ariaLabel?: string;
  /** Optional visible trigger label (defaults to the pivots namespace). */
  triggerLabel?: string;
}

/** Menu sits above the detail drawer (1300) and the workspace dialog (1250). */
const MENU_Z_INDEX = 1400;

/**
 * Non-modal action menu: a portal-mounted Paper positioned at the
 * trigger's viewport rect, with an outside-close layer directly beneath.
 */
function ActionMenu({
  triggerRef,
  actions,
  onSelect,
  open,
  setOpen,
}: {
  triggerRef: React.RefObject<HTMLElement | null>;
  actions: readonly PivotAction[];
  onSelect: (action: PivotAction) => void;
  open: boolean;
  setOpen: (next: boolean) => void;
}): ReactElement | null {
  const { t } = useTranslation("pivots");
  const itemRefs = useRef<Array<HTMLElement | null>>([]);
  const paperRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    // Move focus into the menu when it opens (roving keyboard model).
    itemRefs.current[0]?.focus();
    if (!open) {
      return;
    }
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
      document.removeEventListener("pointerdown", closeOnOutside, true);
    };
  }, [open]);
  if (!open || triggerRef.current === null) {
    return null;
  }
  const rect = triggerRef.current.getBoundingClientRect();
  const onKeyDown = (event: React.KeyboardEvent): void => {
    const current = itemRefs.current;
    let index = current.findIndex((node) => node === document.activeElement);
    if (event.key === "ArrowDown" || event.key === "ArrowRight") {
      event.preventDefault();
      index = index < 0 ? 0 : (index + 1) % current.length;
      current[index]?.focus();
    } else if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
      event.preventDefault();
      index = index <= 0 ? current.length - 1 : index - 1;
      current[index]?.focus();
    } else if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    }
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
        {actions.map((action, index) => (
          <Button
            key={action.key}
            role="menuitem"
            ref={(node) => {
              itemRefs.current[index] = node;
            }}
            tabIndex={index === 0 ? 0 : -1}
            size="small"
            variant="text"
            fullWidth
            title={t(action.labelKey)}
            onClick={() => onSelect(action)}
            sx={{ justifyContent: "flex-start", textTransform: "none", p: 0.75 }}
          >
            {t(action.labelKey)}
          </Button>
        ))}
      </Paper>
    </Portal>
  );
}

/**
 * One pivot trigger bound to the URL-backed pivot stack.
 *
 * Works identically on base routes (starts a new stack) and inside the
 * pivot modal (appends to the active stack).
 */
export function PivotMenu({
  actions,
  ariaLabel,
  triggerLabel,
}: PivotMenuProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const [searchParams, setSearchParams] = useSearchParams();
  const state = readPivotState(searchParams);
  const active = state === null ? null : state.steps[state.steps.length - 1];
  const legal = suppressNoOps(actions, active);
  if (legal.length === 0) {
    return null;
  }
  // Depth limit: no further pivot actions at depth MAX_PIVOT_STEPS. The
  // modal chrome explains the limit textually (PR 24D §6, §20, §22).
  if (state !== null && state.steps.length >= MAX_PIVOT_STEPS) {
    return null;
  }
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
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
  // Single obvious target: one direct accessible action (the action text
  // is the accessible name; an explicit ariaLabel stays overridable).
  if (legal.length === 1) {
    const action = legal[0];
    return (
      <Button
        size="small"
        variant="text"
        onClick={() => push(action)}
        aria-label={ariaLabel ?? undefined}
        title={t(action.labelKey)}
        sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
      >
        {t(action.labelKey)}
      </Button>
    );
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
        actions={legal}
        onSelect={push}
        open={open}
        setOpen={setOpen}
      />
    </Box>
  );
}
