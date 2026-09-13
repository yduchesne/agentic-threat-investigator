// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigations landing page (PR 24B §10).
//
// Real PR 23C cursor API, exact lifecycle status filter, opaque-cursor
// Previous/Next via a browser-local cursor stack, bounded page size and no
// total-count/page-number fiction. Filter and cursor live in URL search
// parameters; objective/indicators/idempotency keys never appear in URLs.

import { Box, Button, FormControl, InputLabel, MenuItem, Select, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";

import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import {
  INVESTIGATION_STATUSES,
  statusLabelKey,
} from "./investigation-status";
import { useInvestigationsPage } from "./investigation-queries";
import type { InvestigationStatusName } from "../api/schema-types";
import { InvestigationList } from "./InvestigationList";

/** Validate the URL status parameter against the exact backend values. */
function parseStatusParam(value: string | null): InvestigationStatusName | undefined {
  if (value !== null && (INVESTIGATION_STATUSES as readonly string[]).includes(value)) {
    return value as InvestigationStatusName;
  }
  return undefined;
}

/** The Investigations landing page. */
export function InvestigationsPage(): ReactElement {
  const { t } = useTranslation("investigations");
  const [searchParams, setSearchParams] = useSearchParams();
  const status = parseStatusParam(searchParams.get("status"));
  const cursor = searchParams.get("cursor") ?? undefined;
  // Browser-local cursor stack: the cursors used to fetch each earlier
  // page, never decoded. Initialized so a refreshed later page can only
  // return to the first page (documented PR 24B trade-off).
  const [history, setHistory] = useState<string[]>(() =>
    cursor !== undefined && cursor !== "" ? [""] : [],
  );
  const { page, isLoading, isError, refetch } = useInvestigationsPage({
    status,
    cursor,
  });

  const updateParams = (next: { status?: InvestigationStatusName; cursor?: string }) => {
    const params = new URLSearchParams(searchParams);
    if (next.status === undefined) {
      params.delete("status");
    } else {
      params.set("status", next.status);
    }
    if (next.cursor === undefined || next.cursor === "") {
      params.delete("cursor");
    } else {
      params.set("cursor", next.cursor);
    }
    setSearchParams(params, { replace: false });
  };

  const changeStatus = (next: InvestigationStatusName | "") => {
    setHistory([]);
    updateParams({ status: next === "" ? undefined : next, cursor: undefined });
  };

  const goNext = () => {
    if (page === null || page.next_cursor === null || page.next_cursor === undefined) {
      return;
    }
    setHistory((previous) => [...previous, cursor ?? ""]);
    updateParams({ status, cursor: page.next_cursor });
  };

  const goPrevious = () => {
    if (history.length === 0) {
      return;
    }
    const next = [...history];
    const prior = next.pop() ?? "";
    setHistory(next);
    updateParams({ status, cursor: prior === "" ? undefined : prior });
  };

  const hasNext = page?.next_cursor !== null && page?.next_cursor !== undefined;
  const hasPrevious = history.length > 0;

  return (
    <Box sx={{ mx: "auto", maxWidth: 960, py: 2 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Typography variant="h1">{t("title")}</Typography>
        <Button component={Link} to="/investigations/new" variant="contained" sx={{ textTransform: "none" }}>
          {t("newInvestigation")}
        </Button>
      </Stack>

      <FormControl size="small" sx={{ minWidth: 200, mb: 2 }}>
        <InputLabel id="investigation-status-filter-label">{t("filter.status.label")}</InputLabel>
        <Select
          labelId="investigation-status-filter-label"
          label={t("filter.status.label")}
          value={status ?? ""}
          onChange={(event) => changeStatus(event.target.value as InvestigationStatusName | "")}
        >
          <MenuItem value="">{t("filter.status.all")}</MenuItem>
          {INVESTIGATION_STATUSES.map((value) => (
            <MenuItem key={value} value={value}>
              {t(statusLabelKey(value))}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      {isLoading && page === null ? (
        <LoadingState label={t("row.loading")} />
      ) : null}

      {isError && page === null ? (
        <ErrorNotice
          title={t("listError.title")}
          message={t("listError.message")}
          onRetry={refetch}
        />
      ) : null}

      {page !== null && page.items.length === 0 ? (
        <EmptyState title={t("empty.title")} message={t("empty.message")} />
      ) : null}

      {page !== null && page.items.length > 0 ? (
        <InvestigationList
          investigations={page.items}
          canGoPrevious={hasPrevious}
          canGoNext={hasNext}
          onPrevious={goPrevious}
          onNext={goNext}
        />
      ) : null}
    </Box>
  );
}