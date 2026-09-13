// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation Overview route (PR 24B §19-§26, §33).
//
// Answers: what did ATI conclude, why, how confident, what remains
// uncertain, and what should be investigated next. Composition follows the
// preferred order: lifecycle state, verdict/confidence, executive summary,
// findings, limitations, unresolved questions, recommended next steps,
// Research context, full Report action. Current Assessment/Report load
// only through durable-pointer-gated `/current` queries; a brief
// pointer/read-race 404 triggers exactly one bounded detail reconciliation,
// never an infinite loop. Research is visibly distinct from Evidence, and
// no Report or Assessment content is synthesized in the browser.

import { Alert, Box, Button, LinearProgress, Stack, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Link, useOutletContext } from "react-router";

import type { Assessment, Investigation, Report } from "../api/schema-types";
import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Timestamp } from "../components/Timestamp";
import { InvestigationStatusBadge } from "./InvestigationStatusBadge";
import { statusLabelKey } from "./investigation-status";
import {
  isPointerRace404,
  useCurrentAssessment,
  useCurrentReport,
} from "./investigation-queries";
import type { WorkspaceOutletContext } from "./InvestigationWorkspace";
import { FindingList } from "./FindingList";
import {
  ListSection,
  ReportContent,
  VerdictConfidenceBlock,
} from "./ReportView";

/** Lifecycle block: status, objective, timestamps, stop reason. */
function LifecycleBlock({ investigation }: { investigation: Investigation }): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <Box>
      <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap" }}>
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
            reason: investigation.stop_reason,
          })}
        </Typography>
      ) : null}
    </Box>
  );
}

/** pending/running surface: indeterminate progress, no invented metrics. */
function RunningOverview({ investigation }: { investigation: Investigation }): ReactElement {
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

/** Assessment fallback; Report explicitly unavailable. */
function AssessmentFallback({ assessment }: { assessment: Assessment }): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Stack spacing={2}>
      <Alert severity="info">{t("reportAvailable.notice")}</Alert>
      <Box>
        <VerdictConfidenceBlock
          verdict={assessment.verdict}
          confidence={assessment.confidence}
        />
      </Box>
      <Box>
        <Typography variant="h2">{t("assessment.summary.title")}</Typography>
        <Typography variant="body1">{assessment.summary}</Typography>
      </Box>
      <Box>
        <Typography variant="h2">{t("findings.title")}</Typography>
        <Box sx={{ mt: 0.5 }}>
          <FindingList findings={assessment.findings} />
        </Box>
      </Box>
      <ListSection title={t("limitations.title")} items={assessment.limitations} />
      <ListSection
        title={t("unresolved.title")}
        items={assessment.unresolved_questions}
      />
      <ListSection
        title={t("nextSteps.title")}
        items={assessment.recommended_next_steps}
      />
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
    <ErrorNotice title={title} message={message} onRetry={onRetry} retryLabel={t("retry")} />
  );
}

/** Render one terminal-artifact surface with its loading/error guards. */
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
}): ReactNode {
  const { t } = useTranslation("overview");
  const hasReport = investigation.report_id !== null;
  const hasAssessment = investigation.assessment_id !== null;

  if (hasReport) {
    if (reportLoading && report === null) {
      return <LoadingState label={t("loading.report")} />;
    }
    if (reportErrorState && report === null) {
      return <ResourceError title={t("error.report.title")} error={reportError} onRetry={refetchReport} />;
    }
    if (report !== null) {
      return (
        <Box>
          <ReportContent report={report} />
          <Box sx={{ mt: 2 }}>
            <Button
              component={Link}
              to={`/investigations/${investigation.id}/overview/report`}
              variant="outlined"
              sx={{ textTransform: "none" }}
            >
              {t("report.action")}
            </Button>
          </Box>
          {assessment !== null &&
          (report.verdict !== assessment.verdict ||
            report.confidence !== assessment.confidence) ? (
            <Alert severity="warning" sx={{ mt: 2 }}>
              {t("report.consistency")}
            </Alert>
          ) : null}
          {assessmentErrorState && assessment === null ? (
            <Box sx={{ mt: 1 }}>
              <ResourceError
                title={t("error.assessment.title")}
                error={assessmentError}
                onRetry={refetchAssessment}
              />
            </Box>
          ) : null}
        </Box>
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
      return <AssessmentFallback assessment={assessment} />;
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

function OverviewContent({ investigation }: { investigation: Investigation }): ReactElement {
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
  const raceKey = `${assessmentError !== null ? "a" : ""}${reportError !== null ? "r" : ""}`;
  useEffect(() => {
    const race =
      (assessmentError !== null && isPointerRace404(assessmentError)) ||
      (reportError !== null && isPointerRace404(reportError));
    if (race && lastRaceKey.current !== raceKey) {
      lastRaceKey.current = raceKey;
      refetchDetail();
    }
  }, [assessmentError, reportError, raceKey, refetchDetail]);

  const nonTerminal = investigation.status === "pending" || investigation.status === "running";

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