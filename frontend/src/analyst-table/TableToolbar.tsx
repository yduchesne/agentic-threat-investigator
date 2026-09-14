// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Resource filter toolbar (PR 24C §14).
//
// Layout: [resource filters] [Apply] [Clear] | [Export current page].
// Selects may apply immediately (resource pages decide); text/date inputs
// apply on explicit Apply/Enter — never on every keystroke. Export is
// explicitly current-page scope and never claims exhaustiveness.

import { Box, Button, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useTranslation } from "react-i18next";

export interface TableToolbarProps {
  /** Labeled filter controls supplied by the resource page. */
  filters: ReactNode;
  /** Commit the URL-backed filters (resets cursor/back stack). */
  onApply: () => void;
  /** Restore the default filter state (also resets cursor/back stack). */
  onClear: () => void;
  /** Export exactly the rows of the current page. */
  onExport: () => void;
  /** Whether any filter value is currently active. */
  hasActiveFilters: boolean;
}

/** Consistent analyst filter/action toolbar. */
export function TableToolbar({
  filters,
  onApply,
  onClear,
  onExport,
  hasActiveFilters,
}: TableToolbarProps): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Box
      role="group"
      aria-label={t("toolbar.label")}
      sx={(theme) => ({
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 1,
        p: 1,
        borderRadius: 0.5,
        border: 1,
        borderColor: theme.palette.divider,
        bgcolor: "action.hover",
      })}
    >
      {filters}
      <Button
        size="small"
        variant="contained"
        onClick={onApply}
        sx={{ textTransform: "none" }}
      >
        {t("toolbar.apply")}
      </Button>
      <Button
        size="small"
        variant="outlined"
        disabled={!hasActiveFilters}
        onClick={onClear}
        sx={{ textTransform: "none" }}
      >
        {t("toolbar.clear")}
      </Button>
      <Box sx={{ flexGrow: 1 }} />
      <Button
        size="small"
        variant="outlined"
        onClick={onExport}
        aria-label={t("export.currentPage")}
        title={t("export.scope.hint")}
        sx={{ textTransform: "none" }}
      >
        {t("export.currentPage")}
      </Button>
      {hasActiveFilters ? (
        <Typography
          variant="caption"
          component="span"
          role="status"
          sx={{ ml: 1 }}
        >
          {t("toolbar.filtersActive")}
        </Typography>
      ) : null}
    </Box>
  );
}