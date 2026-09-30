// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace (PR 24B §14, §15, §17, §18; PR 24C §12;
// PR 31F-6 amendment 5).
//
// The workspace route owns the authoritative Investigation detail query
// (with bounded polling), the persistent header, and — as ALTERNATIVE
// primary views — the normal Investigation workbench (tabs + resource
// outlet) OR the URL-selected in-flow Pivot workbench. When the bounded
// ``pivot`` URL state is non-empty the Pivot workbench is the page's only
// main content: the normal workbench is not mounted underneath (no
// simultaneous interactive layer), and no durable ``pivotOpen`` state
// exists. The persistent header stays shared in both modes.

import { Box, Button, Menu, MenuItem } from "@mui/material";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, Link as RouterLink, useParams, useSearchParams } from "react-router";

import type { ApiError } from "../api/errors";
import type { Investigation } from "../api/schema-types";
import { LoadingState } from "../components/AsyncState";
import { EmptyState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { useInvestigationDetail } from "./investigation-queries";
import { InvestigationHeader } from "./InvestigationHeader";
import { InvestigationTabs } from "./InvestigationTabs";
import { readPivotState } from "../pivots/pivot-url";
import { PivotWorkspace } from "../pivots/PivotWorkspace";

/** Detail state shared with workspace child routes via the outlet. */
export interface WorkspaceOutletContext {
  investigation: Investigation | null;
  detailIsLoading: boolean;
  detailError: ApiError | null;
  refetchDetail: () => void;
}

/** Whether one error is the scoped 404 contract (no enumeration). */
export function isInvestigationNotFound(error: ApiError): boolean {
  return error.kind === "api" && error.status === 404;
}

/** Secondary workspace menu: History is not a primary tab (PR 24C §12). */
function MoreMenu({ investigationId }: { investigationId: string }): ReactElement {
  const { t } = useTranslation("investigations");
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const open = anchorEl !== null;
  const close = (): void => setAnchorEl(null);
  return (
    <Box sx={{ display: "inline-block" }}>
      <Button
        size="small"
        variant="text"
        onClick={(event) => setAnchorEl(event.currentTarget)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? "investigation-more-menu" : undefined}
        sx={{ textTransform: "none", mr: 1 }}
      >
        {t("more.label")}
      </Button>
      <Menu
        id="investigation-more-menu"
        open={open}
        anchorEl={anchorEl}
        onClose={close}
      >
        <MenuItem
          component={RouterLink}
          to={`/investigations/${investigationId}/history`}
          onClick={close}
        >
          {t("more.history")}
        </MenuItem>
      </Menu>
    </Box>
  );
}

/** The Investigation workspace. */
export function InvestigationWorkspace(): ReactElement {
  const { t } = useTranslation("investigations");
  const { investigationId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const { investigation, isLoading, isError, error, refetch } =
    useInvestigationDetail(investigationId);

  const outletContext = useMemo<WorkspaceOutletContext>(
    () => ({
      investigation,
      detailIsLoading: isLoading,
      detailError: error,
      refetchDetail: refetch,
    }),
    [investigation, isLoading, error, refetch],
  );

  // The bounded pivot URL state is the sole authority: a valid non-empty
  // stack activates the in-flow Pivot workbench as the primary content;
  // otherwise the normal Investigation workbench renders. No durable
  // ``pivotOpen`` state exists (PR 31F-6 amendment 5).
  const pivotActive = readPivotState(searchParams) !== null;

  // Initial load (no previous data yet).
  if (isLoading && investigation === null) {
    return <LoadingState label={t("detail.loading")} />;
  }

  // Detail failure without previous data: scoped 404 or bounded error.
  if (isError && investigation === null) {
    if (error !== null && isInvestigationNotFound(error)) {
      return (
        <EmptyState
          title={t("detail.notFound.title")}
          message={t("detail.notFound.message")}
        />
      );
    }
    return (
      <ErrorNotice
        title={t("detail.loadError.title")}
        onRetry={refetch}
      />
    );
  }

  return (
    <Box sx={{ mx: "auto", maxWidth: 1024, py: 2 }}>
      {isError ? (
        <Box sx={{ mb: 1 }}>
          <ErrorNotice
            severity="warning"
            title={t("poll.error.title")}
            message={t("poll.error.message")}
            onRetry={refetch}
          />
        </Box>
      ) : null}
      <InvestigationHeader investigation={investigation} />
      {pivotActive ? (
        <PivotWorkspace
          investigationId={investigationId}
          investigation={investigation}
        />
      ) : (
        <>
          <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 0.5 }}>
            <InvestigationTabs investigationId={investigationId} />
            <MoreMenu investigationId={investigationId} />
          </Box>
          <Box component="section" sx={{ mt: 2 }}>
            <Outlet context={outletContext} />
          </Box>
        </>
      )}
    </Box>
  );
}
