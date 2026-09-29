// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable right-side resource detail drawer (PR 24C §1, §16, §18).
//
// The drawer is URL-addressable (``selected=<uuid>``) and closing it
// preserves filters/cursor. Detail loading/error/not-found states render
// inside the drawer while the list stays intact. Focus is deterministic:
// the close control receives focus one tick after the drawer opens
// (PR 31F-5 A1), Escape and a backdrop click close it, and a nested
// drawer's Escape is consumed so the enclosing PivotWorkspace never also
// closes (PR 31F-5 B/ND02, topmost-only Escape).
//
// Implemented with Material UI primitives (fixed-position paper + backdrop)
// rather than the MUI Drawer modal chain, which spins the main thread on
// pointer interaction under this React 19 / MUI 7 stack in real browsers.
// The component contract (right-side panel, dialog semantics, aria labels,
// close/backdrop behavior) is identical; jsdom and browser behavior agree.
//
// PR 31F-5 lifecycle rationale: ``autoFocus`` was removed from the close
// control. Browser autofocus inside the very commit that mounts the drawer
// races React's re-render with Chromium/Firefox focus fixup when a focused
// node is removed on close (the freeze class documented by PR 24D/P24E).
// Deterministic deferred focus (matched to the PivotMenu strategy) keeps
// the close control focused for keyboard analysts without racing the mount
// commit, and every close path drops focus before navigation so the
// unmount never removes a focused node.

import { Box, IconButton, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";

import { ErrorNotice } from "../components/ErrorNotice";
import { LoadingState } from "../components/AsyncState";

/** Accessible close glyph without a second icon dependency. */
function CloseGlyph(): ReactElement {
  return <span aria-hidden="true">✕</span>;
}

export interface DetailDrawerProps {
  open: boolean;
  /** Accessible drawer title (the resource name). */
  title: string;
  onClose: () => void;
  /** Detail content (loading/error/not-found states render inline). */
  children: ReactNode;
}

/** One right-side detail drawer with an accessible title and focus. */
export function DetailDrawer({
  open,
  title,
  onClose,
  children,
}: DetailDrawerProps): ReactElement {
  const { t } = useTranslation("common");
  const titleId = useId();
  const closeRef = useRef<HTMLButtonElement | null>(null);
  // Hooks stay unconditional (React rules) before the closed-state return.
  useEffect(() => {
    if (!open) {
      return;
    }
    // Deterministic focus after mount: the MUI Portal/primitive materializes
    // its content through its own state effect, so focusing during the very
    // commit that flips ``open`` could target a not-yet-mounted node or race
    // the mount commit; one deferred tick lands on the mounted close control
    // (the same strategy PivotMenu uses for its menu items).
    const focusTimer = window.setTimeout(() => {
      closeRef.current?.focus();
    }, 0);
    return () => {
      window.clearTimeout(focusTimer);
    };
  }, [open]);
  const close = (): void => {
    // Drop focus before any navigation closes this drawer (PR 31F-5 A1):
    // the close control is usually the focused node and this commit removes
    // it; blurring first keeps the unmount from deleting a focused node
    // under the active pointer event, the focus-fixup race class that can
    // wedge the real-browser main thread (same mitigation as PivotMenu).
    (document.activeElement as HTMLElement | null)?.blur();
    onClose();
  };
  const handleKeyDown = (event: { key: string; stopPropagation?: () => void }): void => {
    if (event.key === "Escape") {
      // Topmost-only Escape (PR 31F-5 ND02): a nested drawer consumes the
      // key so the enclosing PivotWorkspace and breadcrumbs never also
      // close; standalone drawers (Timeline/History) have no enclosing
      // Escape handler to suppress.
      event.stopPropagation?.();
      close();
    }
  };
  if (!open) {
    return <></>;
  }
  return (
    <Box>
      <Box
        aria-hidden="true"
        tabIndex={-1}
        onClick={close}
        sx={{
          position: "fixed",
          inset: 0,
          bgcolor: "rgba(0, 0, 0, 0.32)",
          zIndex: 1299,
        }}
      />
      <Box
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={handleKeyDown}
        sx={(theme) => ({
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: 420,
          zIndex: 1300,
          bgcolor: "background.paper",
          borderLeft: 1,
          borderColor: theme.palette.divider,
          boxShadow: "0px 4px 16px rgba(0, 0, 0, 0.24)",
          overflowY: "auto",
          p: 2,
        })}
      >
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Typography id={titleId} variant="h2">
            {title}
          </Typography>
          <IconButton
            ref={(node) => {
              closeRef.current = node;
            }}
            onClick={close}
            aria-label={t("drawer.close")}
            size="small"
          >
            <CloseGlyph />
          </IconButton>
        </Box>
        <Box sx={{ mt: 1.5 }}>{children}</Box>
      </Box>
    </Box>
  );
}

/** Detail is still loading (list remains intact). */
export function DrawerLoading({ label }: { label: string }): ReactElement {
  return <LoadingState label={label} />;
}

/** Detail load failed with a bounded retry. */
export function DrawerError({
  title,
  onRetry,
}: {
  title: string;
  onRetry: () => void;
}): ReactElement {
  const { t } = useTranslation("common");
  return <ErrorNotice title={title} onRetry={onRetry} retryLabel={t("retry")} />;
}

/** Detail 404 surface: resource unknown or outside the Investigation. */
export function DrawerNotFound({ title }: { title: string }): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Box role="status" aria-live="polite" sx={{ py: 2, textAlign: "center" }}>
      <Typography variant="body1">{title}</Typography>
      <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
        {t("drawer.notFound.scoped")}
      </Typography>
    </Box>
  );
}
