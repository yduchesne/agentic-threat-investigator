// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation REPORT workspace route (PR 24B; PR 35-5; PR 35-5 amendment).
//
// The primary Investigation surface is the one canonical persisted Final
// Report. `/overview` loads the current Report through the durable report
// pointer and renders it directly with the shared `ReportSurface`; there is no
// `View report` indirection and no separate abbreviated Overview lifecycle
// rendering. Nonterminal Investigations keep a bounded in-progress state, and
// terminal Investigations without a persisted Report show an explicit
// unavailable state. No Report content is synthesized in the browser.

import { Alert, Box, LinearProgress, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useOutletContext } from "react-router";

import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import type { Investigation } from "../api/schema-types";
import { statusLabelKey } from "./investigation-status";
import type { WorkspaceOutletContext } from "./InvestigationWorkspace";
import {
  isPointerRace404,
  useCurrentReport,
} from "./investigation-queries";
import { ReportSurface } from "./ReportSurface";

/** pending/running surface: indeterminate progress, no invented metrics. */
function RunningOverview({
  investigation,
}: {
  investigation: Investigation;
}): ReactElement {
  const { t } = useTranslation("overview");
  const { t: tStatus } = useTranslation("investigations");
  return (
    <Alert severity="info" role="status" aria-live="polite">
      <Typography variant="body1" sx={{ fontWeight: 600 }}>
        {t("pending.title")}
      </Typography>
      <Typography variant="body2">{t("pending.message")}</Typography>
      <Box sx={{ pt: 0.5 }}>
        <LinearProgress aria-label={t("pending.progressLabel")} />
      </Box>
      <Typography variant="caption" sx={{ display: "block", mt: 0.5 }}>
        {t("pending.caption", {
          status: tStatus(statusLabelKey(investigation.status)),
        })}
      </Typography>
    </Alert>
  );
}

/**
 * The terminal-without-Report state.
 */
function NoReportState(): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <EmptyState
      title={t("artifacts.unavailable.title")}
      message={t("artifacts.unavailable.message")}
    />
  );
}

/** The canonical REPORT surface. */
export function OverviewPage(): ReactElement {
  const { investigation } = useOutletContext<WorkspaceOutletContext>();
  if (investigation === null) {
    // The workspace renders the outlet only with data; defensively safe.
    return <EmptyState title="" />;
  }
  return <ReportContentSurface investigation={investigation} />;
}

function ReportContentSurface({
  investigation,
}: {
  investigation: Investigation;
}): ReactElement | null {
  const { t } = useTranslation("overview");
  const { refetchDetail } = useOutletContext<WorkspaceOutletContext>();

  const reportEnabled = investigation.report_id !== null;
  const {
    report,
    isLoading: reportLoading,
    isError: reportErrorState,
    error: reportError,
    refetch: refetchReport,
  } = useCurrentReport(investigation.id, reportEnabled);

  // Bounded pointer/read-race reconciliation: one detail refetch per
  // pointer/error combination when a current-resource 404 contradicts the
  // durable pointer; never an infinite loop.
  const lastRaceKey = useRef<string>("");
  const raceKey = reportError !== null ? "r" : "";
  useEffect(() => {
    if (
      reportError !== null &&
      isPointerRace404(reportError) &&
      lastRaceKey.current !== raceKey
    ) {
      lastRaceKey.current = raceKey;
      refetchDetail();
    }
  }, [reportError, raceKey, refetchDetail]);

  if (reportEnabled) {
    if (reportLoading && report === null) {
      return <LoadingState label={t("loading.report")} />;
    }
    if (reportErrorState && report === null) {
      return (
        <ErrorNotice
          title={t("error.report.title")}
          onRetry={refetchReport}
        />
      );
    }
    if (report !== null) {
      return (
        <ReportSurface investigationId={investigation.id} report={report} />
      );
    }
    return null;
  }

  const nonTerminal =
    investigation.status === "pending" || investigation.status === "running";
  if (nonTerminal) {
    return <RunningOverview investigation={investigation} />;
  }
  return <NoReportState />;
}
