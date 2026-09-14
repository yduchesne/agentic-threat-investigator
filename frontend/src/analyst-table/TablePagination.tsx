// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Previous/Next opaque-cursor control (PR 24C §6, §18).
//
// Navigation mirrors the backend keyset contract exactly: Previous is
// enabled only while the browser-local back stack is non-empty, Next only
// while the API returned ``next_cursor``. No page numbers, no totals, no
// cursor decoding.

import { Button, Stack } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { PageNavigation } from "./types";

export interface TablePaginationProps {
  navigation: PageNavigation;
}

/** Bounded Previous/Next navigation with descriptive labels. */
export function TablePagination({
  navigation,
}: TablePaginationProps): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Stack
      direction="row"
      spacing={1}
      sx={{ justifyContent: "flex-end", mt: 1 }}
      role="navigation"
      aria-label={t("pagination.label")}
    >
      <Button
        size="small"
        variant="outlined"
        disabled={!navigation.canGoPrevious}
        onClick={navigation.onPrevious}
        aria-label={t("pagination.previousPage")}
      >
        {t("pagination.previous")}
      </Button>
      <Button
        size="small"
        variant="contained"
        disabled={!navigation.canGoNext}
        onClick={navigation.onNext}
        aria-label={t("pagination.nextPage")}
      >
        {t("pagination.next")}
      </Button>
    </Stack>
  );
}