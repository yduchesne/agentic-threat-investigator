// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Reusable right-side resource detail drawer (PR 24C §1, §16, §18).
//
// The drawer is URL-addressable (``selected=<uuid>``) and closing it
// preserves filters/cursor. Detail loading/error/not-found states render
// inside the drawer while the list stays intact. Focus is deterministic:
// the close control receives initial focus when the drawer opens, Escape
// and a backdrop click close it.
//
// Implemented with Material UI primitives (fixed-position paper + backdrop)
// rather than the MUI Drawer modal chain, which spins the main thread on
// pointer interaction under this React 19 / MUI 7 stack in real browsers.
// The component contract (right-side panel, dialog semantics, aria labels,
// close/backdrop behavior) is identical; jsdom and browser behavior agree.

import { Box, IconButton, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useId } from "react";
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
  if (!open) {
    return <></>;
  }
  const handleKeyDown = (event: { key: string }): void => {
    if (event.key === "Escape") {
      onClose();
    }
  };
  return (
    <Box>
      <Box
        aria-hidden="true"
        tabIndex={-1}
        onClick={onClose}
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
            onClick={onClose}
            autoFocus
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