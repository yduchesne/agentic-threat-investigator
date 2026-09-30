// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared conservative list/detail resource view (PR 31F-6 amendment 4).
//
// Ordinary AnalystTable resources use a list/detail model: ``View`` renders
// the exact scoped resource detail as the MAIN workspace content, and a
// semantic ``Back to <resource>`` control returns to the bounded list.
// The list and detail are ALTERNATIVE full-width in-flow views — never a
// side panel and never an interactive table rendered beneath/beside the
// detail.
//
// The existing resource-page URL/state port stays authoritative
// (``selected=<id>`` -> detail, absent -> list). The Back control clears
// the exact selection through the existing close path (next-macrotask
// deferred navigation boundary preserved); filters/order/cursor,
// investigation scope, resource tab and Pivot stack are untouched. No
// Portal/modal/drawer/backdrop/focus trap/body masking/click-away
// machinery exists; no second durable selection state is introduced.
//
// The detail heading is human-readable (shared ``detail.title``
// ``{{resource}} details`` label); technical identities stay secondary
// inside the detail bodies.

import { Box, Divider, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";

export interface ResourceDetailViewProps {
  /** Accessible + visible Back label (e.g. "Back to Evidence"). */
  backLabel: string;
  /** Human-readable detail heading (e.g. "Evidence details"). */
  heading: string;
  /** Clears the existing selection through the existing close path. */
  onBack: () => void;
  /** The exact detail content (loading/error/not-found states inline). */
  children: ReactNode;
}

/**
 * One full-width in-flow resource detail view with a semantic Back
 * control. The detail replaces the list as the main workspace content.
 */
export function ResourceDetailView({
  backLabel,
  heading,
  onBack,
  children,
}: ResourceDetailViewProps): ReactElement {
  return (
    <Box sx={{ minWidth: 0 }}>
      <Box
        component="button"
        type="button"
        onClick={onBack}
        data-testid="resource-detail-back"
        sx={{
          px: 1,
          py: 0.5,
          fontSize: "0.875rem",
          lineHeight: 1.2,
          fontFamily: "inherit",
          cursor: "pointer",
          color: "text.primary",
          borderRadius: 1,
          bgcolor: "transparent",
          "&:hover": { bgcolor: "action.hover" },
          "&:focus-visible": {
            outline: "2px solid",
            outlineColor: "focus.visible",
          },
          "&:active": { bgcolor: "action.hover" },
        }}
      >
        {backLabel}
      </Box>
      <Typography variant="h2" sx={{ mt: 0.5 }}>
        {heading}
      </Typography>
      <Divider sx={{ my: 1 }} />
      <Box sx={{ minWidth: 0 }}>{children}</Box>
    </Box>
  );
}

/** Detail is still loading (list context remains intact). */
export function DetailLoading({ label }: { label: string }): ReactElement {
  return <LoadingState label={label} />;
}

/** Detail load failed with a bounded retry. */
export function DetailError({
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
export function DetailNotFound({ title }: { title: string }): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Box role="status" aria-live="polite" sx={{ py: 2, textAlign: "center" }}>
      <Typography variant="body1">{title}</Typography>
      <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
        {t("detail.notFound.scoped")}
      </Typography>
    </Box>
  );
}
