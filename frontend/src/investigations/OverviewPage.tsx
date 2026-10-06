// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation Overview route (PR 24B; PR 35-5).
//
// The Overview is the Investigation workspace landing surface: lifecycle,
// running/failed/partial state, the current analytical outcome, and
// navigation. PR 35-5 removes the abbreviated terminal report from the
// Overview: there is one canonical Final Report, reachable through a single
// link. The Overview never renders a second bounded copy of the Summary,
// findings, recommendations, or report-only at-a-glance counts, and never
// synthesizes Report content in the browser.

import {
  Alert,
  Box,
  Button,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation, useOutletContext } from "react-router";

import {
  internalLocationFromPath,
  navigationState,
  pushNavigationReturn,
} from "../analyst-table/return-to";

import type { Assessment, Investigation, Report } from "../api/schema-types";
import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Timestamp } from "../components/Timestamp";
import { InvestigationStatusBadge } from "./InvestigationStatusBadge";
import { statusLabelKey } from "./investigation-status";
import { stopReasonLabelKey } from "./investigation-stop-reason";
import type { WorkspaceOutletContext } from "./InvestigationWorkspace";
import {
  isPointerRace404,
  useCurrentAssessment,
  useCurrentReport,
} from "./investigation-queries";

/** Lifecycle block: status, timestamps, stop reason. */
function LifecycleBlock({
  investigation,
}: {
  investigation: Investigation;
}): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <Box>
      <Stack
        direction="row"
        spacing={1.5}
        sx={{ alignItems: "center", flexWrap: "wrap" }}
      >
        <Typography variant="h2">{t("overview.lifecycle.title")}</Typography>
        <InvestigationStatusBadge status={investigation.status} />
      </Stack>
      <Typography variant="body2">
        {t("overview.lifecycle.started")}{" "}
        <Timestamp iso={investigation.started_at ?? investigation.created_at} />
      </Typography>
      {investigation.completed_at !== null ? (
        <Typography variant="body2">
          {t("overview.lifecycle.completed")}{" "}
          <Timestamp iso={investigation.completed_at} />
        </Typography>
      ) : null}
      {investigation.stop_reason !== null ? (
        <Typography variant="body2">
          {t("overview.lifecycle.stopReason", {
            reason: t(stopReasonLabelKey(investigation.stop_reason)),
          })}
        </Typography>
      ) : null}
    </Box>
  );
}

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

/** The navigation/action row: one Final Report link plus workspace routes. */
function NavigationRow({
  investigationId,
  reportAvailable,
}: {
  investigationId: string;
  reportAvailable: boolean;
}): ReactElement {
  const { t } = useTranslation("overview");
  const { t: tInvestigations } = useTranslation("investigations");
  const location = useLocation();
  const drillDownState = navigationState(
    pushNavigationReturn(
      location.state,
      internalLocationFromPath(location.pathname, location.search, location.hash),
    ),
  );
  const base = `/investigations/${investigationId}`;
  return (
    <Stack
      direction="row"
      spacing={1.5}
      sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}
    >
      {reportAvailable ? (
        <Button
          component={RouterLink}
          to={`${base}/overview/report`}
          variant="contained"
          sx={{ textTransform: "none" }}
        >
          {t("report.action")}
        </Button>
      ) : null}
      <RouterLink to={`${base}/evidence`}>
        {tInvestigations("tabs.evidence")}
      </RouterLink>
      <RouterLink to={`${base}/relationships`}>
        {tInvestigations("tabs.relationships")}
      </RouterLink>
      <RouterLink to={`${base}/timeline`}>
        {tInvestigations("tabs.timeline")}
      </RouterLink>
      <RouterLink to={`${base}/relationships/evolution`} state={drillDownState}>
        {tInvestigations("tabs.graph")}
      </RouterLink>
    </Stack>
  );
}

/** One pointer-gated resource error with a bounded retry. */
function ResourceError({
  title,
  error,
  onRetry,
}: {
  title: string;
  error: unknown;
  onRetry: () => void;
}): ReactElement {
  const { t } = useTranslation("common");
  const message =
    error !== null &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
      ? (error as { message: string }).message
      : null;
  return (
    <ErrorNotice
      title={title}
      message={message}
      onRetry={onRetry}
      retryLabel={t("retry")}
    />
  );
}

/**
 * Terminal Report surface: a single link to the canonical Final Report plus
 * the consistency warning. It never renders Report content.
 */
function TerminalReportSurface({
  investigation,
  report,
  assessment,
}: {
  investigation: Investigation;
  report: Report;
  assessment: Assessment | null;
}): ReactElement {
  const { t } = useTranslation("overview");
  const mismatch =
    assessment !== null &&
    (report.verdict !== assessment.verdict ||
      report.confidence !== assessment.confidence);
  void report;
  return (
    <Stack spacing={2}>
      <NavigationRow investigationId={investigation.id} reportAvailable />
      {mismatch ? (
        <Alert severity="warning">{t("report.consistency")}</Alert>
      ) : null}
    </Stack>
  );
}

/** Assessment-only fallback: Report unavailable, analytical summary only. */
function AssessmentFallback({
  investigation,
  assessment,
}: {
  investigation: Investigation;
  assessment: Assessment;
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Stack spacing={2}>
      <Alert severity="info">{t("reportAvailable.notice")}</Alert>
      <Box>
        <Typography variant="h2">{t("assessment.summary.title")}</Typography>
        <Typography variant="body1">{assessment.summary}</Typography>
      </Box>
      <NavigationRow investigationId={investigation.id} reportAvailable={false} />
    </Stack>
  );
}

/** Render the terminal artifact surface with its loading/error guards. */
function ArtifactSurface({
  investigation,
  report,
  reportLoading,
  reportError,
  reportErrorState,
  refetchReport,
  assessment,
  assessmentLoading,
  assessmentError,
  assessmentErrorState,
  refetchAssessment,
}: {
  investigation: Investigation;
  report: Report | null;
  reportLoading: boolean;
  reportError: unknown;
  reportErrorState: boolean;
  refetchReport: () => void;
  assessment: Assessment | null;
  assessmentLoading: boolean;
  assessmentError: unknown;
  assessmentErrorState: boolean;
  refetchAssessment: () => void;
}): ReactElement | null {
  const { t } = useTranslation("overview");
  const hasReport = investigation.report_id !== null;
  const hasAssessment = investigation.assessment_id !== null;

  if (hasReport) {
    if (reportLoading && report === null) {
      return <LoadingState label={t("loading.report")} />;
    }
    if (reportErrorState && report === null) {
      return (
        <ResourceError
          title={t("error.report.title")}
          error={reportError}
          onRetry={refetchReport}
        />
      );
    }
    if (report !== null) {
      return (
        <Stack spacing={2}>
          <TerminalReportSurface
            investigation={investigation}
            report={report}
            assessment={assessment}
          />
          {reportErrorState ? (
            <ResourceError
              title={t("error.report.title")}
              error={reportError}
              onRetry={refetchReport}
            />
          ) : null}
        </Stack>
      );
    }
    return null;
  }
  if (hasAssessment) {
    if (assessmentLoading && assessment === null) {
      return <LoadingState label={t("loading.assessment")} />;
    }
    if (assessmentErrorState && assessment === null) {
      return (
        <ResourceError
          title={t("error.assessment.title")}
          error={assessmentError}
          onRetry={refetchAssessment}
        />
      );
    }
    if (assessment !== null) {
      return (
        <AssessmentFallback
          investigation={investigation}
          assessment={assessment}
        />
      );
    }
    return null;
  }
  return (
    <EmptyState
      title={t("artifacts.unavailable.title")}
      message={t("artifacts.unavailable.message")}
    />
  );
}

/** The substantive Overview route. */
export function OverviewPage(): ReactElement {
  const { investigation } = useOutletContext<WorkspaceOutletContext>();
  if (investigation === null) {
    // The workspace renders the outlet only with data; defensively safe.
    return <EmptyState title="" />;
  }
  return <OverviewContent investigation={investigation} />;
}

function OverviewContent({
  investigation,
}: {
  investigation: Investigation;
}): ReactElement {
  const { t } = useTranslation("overview");
  const { refetchDetail } = useOutletContext<WorkspaceOutletContext>();

  const assessmentEnabled = investigation.assessment_id !== null;
  const reportEnabled = investigation.report_id !== null;
  const {
    assessment,
    isLoading: assessmentLoading,
    isError: assessmentErrorState,
    error: assessmentError,
    refetch: refetchAssessment,
  } = useCurrentAssessment(investigation.id, assessmentEnabled);
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
  const raceKey = `${assessmentError !== null ? "a" : ""}${
    reportError !== null ? "r" : ""
  }`;
  useEffect(() => {
    const race =
      (assessmentError !== null && isPointerRace404(assessmentError)) ||
      (reportError !== null && isPointerRace404(reportError));
    if (race && lastRaceKey.current !== raceKey) {
      lastRaceKey.current = raceKey;
      refetchDetail();
    }
  }, [assessmentError, reportError, raceKey, refetchDetail]);

  const nonTerminal =
    investigation.status === "pending" || investigation.status === "running";

  return (
    <Stack spacing={3}>
      <LifecycleBlock investigation={investigation} />

      {investigation.status === "partial" ? (
        <Alert severity="warning">{t("partial.warning")}</Alert>
      ) : null}
      {investigation.status === "failed" ? (
        <Alert severity="error">{t("failed.state")}</Alert>
      ) : null}

      {nonTerminal ? (
        <RunningOverview investigation={investigation} />
      ) : (
        <ArtifactSurface
          investigation={investigation}
          report={report}
          reportLoading={reportLoading}
          reportError={reportError}
          reportErrorState={reportErrorState}
          refetchReport={refetchReport}
          assessment={assessment}
          assessmentLoading={assessmentLoading}
          assessmentError={assessmentError}
          assessmentErrorState={assessmentErrorState}
          refetchAssessment={refetchAssessment}
        />
      )}
    </Stack>
  );
}
