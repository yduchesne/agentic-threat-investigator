// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation Overview route (PR 24B §19-§26, §33; PR 31F-5 §3.4).
//
// Answers: what did ATI conclude, why, how confident, what remains
// uncertain, and what should be investigated next. PR 31F-5 separates the
// Overview (concise landing/dashboard) from the Report (complete analytical
// deliverable): the terminal surface follows the exact section order —
// lifecycle, analytical outcome, executive summary, at-a-glance counts,
// key findings (first 3), recommended next actions (first 3), and the
// navigation/action row. The full Report never renders below that row and
// stays reachable through ``View full report``. Current Assessment/Report
// load only through durable-pointer-gated ``/current`` queries; a brief
// pointer/read-race 404 triggers exactly one bounded detail reconciliation,
// never an infinite loop. Research is visibly distinct from Evidence, and
// no Report or Assessment content is synthesized in the browser.

import { Alert, Box, Button, LinearProgress, Stack, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Link as RouterLink, useLocation, useOutletContext } from "react-router";

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
import { FindingList } from "./FindingList";
import {
  VerdictConfidenceBlock,
  ExecutiveSummaryList,
} from "./ReportView";
import { useSupportPresentations } from "./support-presentations-queries";

/** Bounded Overview sizes (the full Report stays complete on its route). */
const OVERVIEW_MAX_FINDINGS = 3;
const OVERVIEW_MAX_NEXT_STEPS = 3;

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
            reason: t(stopReasonLabelKey(investigation.stop_reason)),
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

/** Linear progress is imported directly from MUI alongside the alert. */

/** One bounded at-a-glance count row derived from loaded artifact arrays. */
function AtAGlance({
  counts,
}: {
  counts: readonly { label: string; value: number }[];
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Box>
      <Typography variant="h2">{t("atAGlance.title")}</Typography>
      <Box component="ul" sx={{ m: 0, pl: 3 }}>
        {counts.map((count, index) => (
          <Typography key={index} component="li" variant="body2">
            {count.label}: {count.value}
          </Typography>
        ))}
      </Box>
    </Box>
  );
}

/** Bounded recommended-next-actions list (the full list lives in Report). */
function NextStepsList({ items }: { items: readonly string[] }): ReactElement | null {
  const { t } = useTranslation("overview");
  if (items.length === 0) {
    return null;
  }
  return (
    <Box>
      <Typography variant="h2">{t("nextSteps.title")}</Typography>
      <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
        {items.slice(0, OVERVIEW_MAX_NEXT_STEPS).map((item, index) => (
          <Typography key={index} component="li" variant="body2">
            {item}
          </Typography>
        ))}
      </Stack>
    </Box>
  );
}

/**
 * The navigation/action row: ``View full report`` primary, then the
 * existing workspace routes. The full Report never renders below this row.
 */
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
  const returnTo = `${location.pathname}${location.search}${location.hash}`;
  const base = `/investigations/${investigationId}`;
  return (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
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
      <RouterLink to={`${base}/evidence`}>{tInvestigations("tabs.evidence")}</RouterLink>
      <RouterLink to={`${base}/relationships`}>{tInvestigations("tabs.relationships")}</RouterLink>
      <RouterLink to={`${base}/timeline`}>{tInvestigations("tabs.timeline")}</RouterLink>
      <RouterLink to={`${base}/relationships/evolution`} state={{ returnTo }}>{tInvestigations("tabs.graph")}</RouterLink>
    </Stack>
  );
}

/** Concise analytical-outcome block of the Report (title + verdict). */
function ReportOutcome({ report }: { report: Report }): ReactElement {
  return (
    <Box>
      <Typography variant="h2">{report.title}</Typography>
      <Box sx={{ mt: 1 }}>
        <VerdictConfidenceBlock
          verdict={report.verdict}
          confidence={report.confidence}
        />
      </Box>
    </Box>
  );
}

/** The full persisted executive summary statements in authored order. */
function ExecutiveSummary({ report }: { report: Report }): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Box>
      <Typography variant="h2">{t("executiveSummary.title")}</Typography>
      <Box sx={{ mt: 0.5 }}>
        <ExecutiveSummaryList statements={report.executive_summary} />
      </Box>
    </Box>
  );
}

/** Key findings bounded to the first 3 in authoritative order (no ranking). */
function KeyFindings({
  report,
  presentation,
}: {
  report: Report;
  presentation: ReturnType<typeof useSupportPresentations>["presentation"];
}): ReactElement {
  const { t } = useTranslation("overview");
  const total = report.findings.length;
  const shown = report.findings.slice(0, OVERVIEW_MAX_FINDINGS);
  return (
    <Box>
      <Typography variant="h2">{t("findings.title")}</Typography>
      <Box sx={{ mt: 0.5 }}>
        <FindingList findings={shown} presentation={presentation} />
      </Box>
      {total > OVERVIEW_MAX_FINDINGS ? (
        <Typography variant="body2" sx={{ mt: 0.5 }}>
          <RouterLink
            to={`/investigations/${report.investigation_id}/overview/report`}
          >
            {t("findings.more", { count: String(total - OVERVIEW_MAX_FINDINGS) })}
          </RouterLink>
        </Typography>
      ) : null}
    </Box>
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
        <ReportSummarySurface
          investigation={investigation}
          report={report}
          assessment={assessment}
          assessmentErrorState={assessmentErrorState}
          assessmentError={assessmentError}
          refetchAssessment={refetchAssessment}
          reportError={reportError}
          reportErrorState={reportErrorState}
          refetchReport={refetchReport}
        />
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
      return <AssessmentFallback investigation={investigation} assessment={assessment} />;
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

/**
 * The concise Report surface (PR 31F-5 §3.4): outcome, executive summary,
 * at-a-glance counts, first 3 findings, first 3 next actions, then the
 * navigation/action row. The full Report renders only on its own route.
 */
function ReportSummarySurface({
  investigation,
  report,
  assessment,
  assessmentErrorState,
  assessmentError,
  refetchAssessment,
  reportError,
  reportErrorState,
  refetchReport,
}: {
  investigation: Investigation;
  report: Report;
  assessment: Assessment | null;
  assessmentErrorState: boolean;
  assessmentError: unknown;
  refetchAssessment: () => void;
  reportError: unknown;
  reportErrorState: boolean;
  refetchReport: () => void;
}): ReactElement {
  const { t } = useTranslation("overview");
  const presentation = useSupportPresentations(
    investigation.id,
    report.findings,
    true,
  ).presentation;
  const counts = [
    { label: t("atAGlance.findings"), value: report.findings.length },
    { label: t("atAGlance.limitations"), value: report.limitations.length },
    { label: t("atAGlance.unresolved"), value: report.unresolved_questions.length },
    { label: t("atAGlance.nextSteps"), value: report.recommended_next_steps.length },
  ];
  return (
    <Stack spacing={2.5}>
      <ReportOutcome report={report} />
      <ExecutiveSummary report={report} />
      <AtAGlance counts={counts} />
      <KeyFindings report={report} presentation={presentation} />
      <NextStepsList items={report.recommended_next_steps} />
      <NavigationRow
        investigationId={investigation.id}
        reportAvailable
      />
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
      {reportErrorState && report !== null ? (
        <Box sx={{ mt: 1 }}>
          <ResourceError
            title={t("error.report.title")}
            error={reportError}
            onRetry={refetchReport}
          />
        </Box>
      ) : null}
    </Stack>
  );
}

/** Assessment-only fallback: Report unavailable, same concise shape. */
function AssessmentFallback({
  investigation,
  assessment,
}: {
  investigation: Investigation;
  assessment: Assessment;
}): ReactElement {
  const { t } = useTranslation("overview");
  const presentation = useSupportPresentations(
    investigation.id,
    assessment.findings,
    true,
  ).presentation;
  const counts = [
    { label: t("atAGlance.findings"), value: assessment.findings.length },
    { label: t("atAGlance.limitations"), value: assessment.limitations.length },
    { label: t("atAGlance.unresolved"), value: assessment.unresolved_questions.length },
    { label: t("atAGlance.nextSteps"), value: assessment.recommended_next_steps.length },
  ];
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
      <AtAGlance counts={counts} />
      <Box>
        <Typography variant="h2">{t("findings.title")}</Typography>
        <Box sx={{ mt: 0.5 }}>
          <FindingList
            findings={assessment.findings.slice(0, OVERVIEW_MAX_FINDINGS)}
            presentation={presentation}
          />
        </Box>
        {assessment.findings.length > OVERVIEW_MAX_FINDINGS ? (
          <Typography variant="body2" sx={{ mt: 0.5 }}>
            {t("findings.moreUnlinked", {
              count: String(assessment.findings.length - OVERVIEW_MAX_FINDINGS),
            })}
          </Typography>
        ) : null}
      </Box>
      <NextStepsList items={assessment.recommended_next_steps.slice(0, OVERVIEW_MAX_NEXT_STEPS)} />
      <NavigationRow investigationId={investigation.id} reportAvailable={false} />
    </Stack>
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
