// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable pivot action trigger (PR 24D §1.3, §8, §22; PR 31E §7-§14;
// PR 31F-6 amendment 2; PR 31F-8 §8).
//
// Renders the explicit registered actions for one source identity. PR 31F-8
// converts every route-known resource action from the generic encoded
// Pivot stack mutation to an ordinary React Router semantic link produced
// by the exhaustive ``pivotTargetToRoute`` mapper: one legal target renders
// as a direct accessible link action; multiple targets expand into a
// compact in-flow action bar of links. Actions are never inferred
// client-side.
//
// PR 31E local/context actions (``localActions``) are unchanged: read-only
// commands such as graph expansion that are not Pivot resources. They are
// never converted to routes, never URL serialized, never no-op suppressed,
// and never enter a routed resource surface — they collapse the action bar
// and invoke a caller callback.
//
// Presentation (PR 31F-6 amendment 2, unchanged): expanding a multi-target
// trigger renders ordinary in-flow action links (a labelled action region
// with a Cancel control) — no Portal, no MUI Menu/Popover, no fixed
// popup, no backdrop, no anchor bookkeeping, no document outside-click/
// pointerdown listener, no focus trap or floating-menu focus transfer, and
// no body scroll mutation. ``expanded`` is transient presentation state
// only. The bar is a labelled group in natural Tab order; no
// ``role=menu/menuitem`` semantics exist.

import { Box, Button } from "@mui/material";
import type { ReactElement } from "react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation, useParams } from "react-router";

import {
  type PivotAction,
} from "./pivot-capabilities";
import { pivotTargetToRoute } from "./pivot-route";

/**
 * One explicit local/context action (PR 31E §8).
 *
 * A UI command hosted by the pivot trigger that is not a Pivot resource:
 * no route destination, no URL mutation, no no-op suppression. ``key``
 * must be caller-unique (e.g. ``graph-expand-either``); ``label`` is the
 * final analyst-facing text.
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
  /** Explicit local/context commands (PR 31E); never routed resources. */
  localActions?: readonly PivotLocalAction[];
  /** Optional accessible trigger name describing the source value. */
  ariaLabel?: string;
  /** Optional visible trigger label (defaults to the pivots namespace). */
  triggerLabel?: string;
}

/** One unified action-bar entry (routed resource link or local command). */
type ActionEntry =
  | {
      kind: "pivot";
      key: string;
      label: string;
      /** Canonical Investigation-scoped route destination. */
      to: string;
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
 * Whether a canonical destination equals the current routed surface
 * (same pathname + same query-parameter set). Re-activating the current
 * surface is a no-op under the routed architecture (the older Pivot-stack
 * doctrine had the same rule) and MUST NOT fire a same-URL router
 * navigation — such navigations reproduced a deterministic real-stack
 * main-thread stall in Chromium/Firefox (pointer AND keyboard).
 */
function isSameRoutedSurface(
  pathname: string,
  search: string,
  targetPathname: string,
  targetSearch: string | undefined,
): boolean {
  if (pathname !== targetPathname) {
    return false;
  }
  const current = new URLSearchParams(search.replace(/^\?/, ""));
  const target = new URLSearchParams(targetSearch ?? "");
  if (current.size !== target.size) {
    return false;
  }
  for (const [key, value] of current) {
    if (target.get(key) !== value) {
      return false;
    }
  }
  return true;
}

/**
 * One pivot trigger bound to the canonical Investigation-scoped routes,
 * extended with explicit local/context actions (PR 31E).
 *
 * Route-known resource actions are semantic react-router links (or MUI
 * component-as-Link) produced by the exhaustive typed mapper — no native
 * click -> encoded Pivot stack mutation, no depth accounting, no deferred
 * navigation. Local actions never touch the URL and remain buttons.
 *
 * Multi-target triggers expand into an ordinary in-flow action bar
 * (PR 31F-6 amendment 2): a labelled group of semantic links/buttons with
 * a Cancel control. ``expanded`` is presentation-only.
 */
export function PivotMenu({
  actions,
  localActions = [],
  ariaLabel,
  triggerLabel,
}: PivotMenuProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const { investigationId = "" } = useParams();
  const location = useLocation();
  const [expanded, setExpanded] = useState(false);
  const actionBarId = useId();

  // Route-known actions translate through the exhaustive allowlisted
  // mapper; a target that cannot be represented safely is never rendered
  // as a navigation (R12). Actions outside an Investigation route are
  // never converted (no canonical scope exists), and actions whose
  // destination equals the current routed surface are suppressed as
  // no-ops (same-URL navigations are both redundant and the documented
  // native-pointer stall class).
  const pivotEntries: ActionEntry[] = [];
  for (const action of actions) {
    if (investigationId === "") {
      continue;
    }
    const destination = pivotTargetToRoute(investigationId, action.target);
    if (destination === null) {
      continue;
    }
    if (
      isSameRoutedSurface(
        location.pathname,
        location.search,
        destination.pathname,
        destination.search,
      )
    ) {
      continue;
    }
    pivotEntries.push({
      kind: "pivot",
      key: action.key,
      label: t(action.labelKey),
      to:
        destination.search === undefined
          ? destination.pathname
          : `${destination.pathname}?${destination.search}`,
    });
  }
  const localEntries: ActionEntry[] = localActions.map((action) => ({
    kind: "local",
    key: action.key,
    label: action.label,
    disabled: action.disabled ?? false,
    onSelect: () => {
      setExpanded(false);
      action.onSelect();
    },
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
    const commonProps = {
      size: "small" as const,
      variant: "text" as const,
      "aria-label": ariaLabel ?? undefined,
      sx: { textTransform: "none", minWidth: 0, p: 0.5 },
    };
    if (entry.kind === "local") {
      return (
        <Button
          {...commonProps}
          disabled={entry.disabled}
          onClick={entry.onSelect}
        >
          {entry.label}
        </Button>
      );
    }
    return (
      <Button {...commonProps} component={RouterLink} to={entry.to}>
        {entry.label}
      </Button>
    );
  }

  const closeBar = (): void => setExpanded(false);
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
          {entries.map((entry) => {
            const commonProps = {
              size: "small" as const,
              variant: "text" as const,
              sx: { textTransform: "none", minWidth: 0, p: 0.5 },
            };
            return entry.kind === "local" ? (
              <Button
                key={entry.key}
                {...commonProps}
                disabled={entry.disabled}
                onClick={entry.onSelect}
              >
                {entry.label}
              </Button>
            ) : (
              <Button
                key={entry.key}
                {...commonProps}
                component={RouterLink}
                to={entry.to}
                onClick={closeBar}
              >
                {entry.label}
              </Button>
            );
          })}
          <Button
            size="small"
            variant="text"
            onClick={closeBar}
            sx={{ textTransform: "none", minWidth: 0, p: 0.5 }}
          >
            {t("cancel")}
          </Button>
        </Box>
      ) : null}
    </Box>
  );
}
