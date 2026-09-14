// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace (PR 24B §14, §15, §17, §18; PR 24C §12).
//
// The workspace route owns the authoritative Investigation detail query
// (with bounded polling), the persistent header, the workspace tabs and
// the secondary ``More -> History`` access, and provides the detail state
// to child routes through the router outlet context so children never
// duplicate the polling query.

import { Box, Button, Menu, MenuItem } from "@mui/material";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, Link as RouterLink, useParams } from "react-router";

import type { ApiError } from "../api/errors";
import type { Investigation } from "../api/schema-types";
import { LoadingState } from "../components/AsyncState";
import { EmptyState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { useInvestigationDetail } from "./investigation-queries";
import { InvestigationHeader } from "./InvestigationHeader";
import { InvestigationTabs } from "./InvestigationTabs";

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
  const [open, setOpen] = useState(false);
  return (
    <Box sx={{ display: "inline-block" }}>
      <Button
        size="small"
        variant="text"
        onClick={() => setOpen(true)}
        aria-haspopup="menu"
        aria-expanded={open}
        sx={{ textTransform: "none", mr: 1 }}
      >
        {t("more.label")}
      </Button>
      <Menu open={open} anchorEl={undefined} onClose={() => setOpen(false)}>
        <MenuItem
          component={RouterLink}
          to={`/investigations/${investigationId}/history`}
          onClick={() => setOpen(false)}
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
      <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 0.5 }}>
        <InvestigationTabs investigationId={investigationId} />
        <MoreMenu investigationId={investigationId} />
      </Box>
      <Box component="section" sx={{ mt: 2 }}>
        <Outlet context={outletContext} />
      </Box>
    </Box>
  );
}