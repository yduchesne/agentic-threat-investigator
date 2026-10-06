// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical Final Report presentation (PR 35-5; PR 35-5 amendment).
//
// One evidence-backed Final Report: Status, Summary, Contents, and Details
// (Findings with direct Evidence / Graph Analysis support, then the optional
// Research Context, Limitations, Unresolved Questions, and Recommended Next
// Steps). The Summary and Details are deterministic projections of the same
// canonical ordered finding set; the browser never sorts, filters, ranks, or
// invents findings, criticality, numbers, or anchors. Every string renders as
// escaped React text. `Graph Analysis` is only the report presentation label
// for existing relationship-observation support; no domain/API type changes.
//
// Stable anchors are centralized here and never derived from model-authored
// titles, so direct fragment navigation survives refresh.

import { Box, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type {
  AssessmentConfidenceName,
  Report,
  ReportCriticalityName,
  ReportFinding,
  ReportSummaryItem,
} from "../api/schema-types";
import { Timestamp } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import { researchSupportAction } from "../pivots/pivot-capabilities";
import { stopReasonLabelKey } from "./investigation-stop-reason";
import { statusLabelKey } from "./investigation-status";
import type { SupportPresentationLookup } from "./support-presentations-queries";
import { SupportReference } from "./FindingList";

/** Stable, deterministic fragment identifiers for the Final Report. */
export const REPORT_ANCHORS = {
  summary: "summary",
  status: "status",
  contents: "contents",
  details: "details",
  findings: "findings",
  research: "research-context",
  limitations: "limitations",
  unresolved: "unresolved-questions",
  nextSteps: "recommended-next-steps",
} as const;

/** Deterministic finding anchor: never derived from the title text. */
export function findingAnchor(reportFindingNumber: number): string {
  return `finding-${reportFindingNumber}`;
}

/** Deterministic human-readable duration derived only from timestamps. */
export function formatReportDuration(
  startedAt: string | null,
  endedAt: string | null,
): string | null {
  if (startedAt === null || endedAt === null) {
    return null;
  }
  const start = Date.parse(startedAt);
  const end = Date.parse(endedAt);
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return null;
  }
  let remaining = Math.floor((end - start) / 1000);
  const days = Math.floor(remaining / 86400);
  remaining -= days * 86400;
  const hours = Math.floor(remaining / 3600);
  remaining -= hours * 3600;
  const minutes = Math.floor(remaining / 60);
  const seconds = remaining - minutes * 60;
  const parts: string[] = [];
  if (days > 0) {
    parts.push(`${days} day${days === 1 ? "" : "s"}`);
  }
  if (hours > 0) {
    parts.push(`${hours} hour${hours === 1 ? "" : "s"}`);
  }
  if (minutes > 0) {
    parts.push(`${minutes} minute${minutes === 1 ? "" : "s"}`);
  }
  if (seconds > 0 && days === 0) {
    parts.push(`${seconds} second${seconds === 1 ? "" : "s"}`);
  }
  return parts.length > 0 ? parts.join(" ") : "0 seconds";
}

function criticalityText(
  t: (key: string) => string,
  criticality: ReportCriticalityName,
): string {
  return t(`criticality.${criticality}`);
}

function confidenceText(
  t: (key: string) => string,
  confidence: AssessmentConfidenceName,
): string {
  return t(`confidence.${confidence}`);
}

/** One Summary bullet: the same finding number used everywhere else. */
function SummarySection({
  report,
}: {
  report: Report;
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Box component="section" id={REPORT_ANCHORS.summary}>
      <Typography variant="h2">{t("summary.title")}</Typography>
      {report.summary.length > 0 ? (
        <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
          {report.summary.map((item: ReportSummaryItem) => (
            <Typography key={item.report_finding_number} component="li" variant="body1">
              {t("summary.item", {
                number: item.report_finding_number,
                text: item.text,
              })}
            </Typography>
          ))}
        </Stack>
      ) : null}
    </Box>
  );
}

/** Status: criticality, confidence, deterministic timeline, and outcome. */
function StatusSection({ report }: { report: Report }): ReactElement {
  const { t } = useTranslation("overview");
  const { t: tInvestigations } = useTranslation("investigations");
  const duration = formatReportDuration(report.started_at, report.ended_at);
  const outcome =
    report.stop_reason !== null
      ? tInvestigations(stopReasonLabelKey(report.stop_reason))
      : tInvestigations(statusLabelKey(report.outcome_status));
  return (
    <Box component="section" id={REPORT_ANCHORS.status}>
      <Typography variant="h2">{t("status.title")}</Typography>
      <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
        <Typography component="li" variant="body2">
          {t("status.criticality")} {criticalityText(t, report.criticality)}
        </Typography>
        <Typography component="li" variant="body2">
          {t("status.confidence")} {confidenceText(t, report.confidence)}
        </Typography>
        {report.started_at !== null || report.ended_at !== null || duration !== null ? (
          <Typography component="li" variant="body2">
            {t("status.timeline")}
            <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
              {report.started_at !== null ? (
                <Typography component="li" variant="body2">
                  {t("status.startedAt")} <Timestamp iso={report.started_at} />
                </Typography>
              ) : null}
              {report.ended_at !== null ? (
                <Typography component="li" variant="body2">
                  {t("status.endedAt")} <Timestamp iso={report.ended_at} />
                </Typography>
              ) : null}
              {duration !== null ? (
                <Typography component="li" variant="body2">
                  {t("status.duration")} {duration}
                </Typography>
              ) : null}
            </Stack>
          </Typography>
        ) : null}
        <Typography component="li" variant="body2">
          {t("status.outcome")} {outcome}
        </Typography>
      </Stack>
    </Box>
  );
}

/** Deterministic Contents generated from the actual rendered structure. */
function ContentsSection({ report }: { report: Report }): ReactElement {
  const { t } = useTranslation("overview");
  const hasResearch = report.research_context.length > 0;
  const hasLimitations = report.limitations.length > 0;
  const hasUnresolved = report.unresolved_questions.length > 0;
  const hasNextSteps = report.recommended_next_steps.length > 0;
  return (
    <Box component="nav" id={REPORT_ANCHORS.contents} aria-label={t("contents.title")}>
      <Typography variant="h2">{t("contents.title")}</Typography>
      <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
        <li>
          <a href={`#${REPORT_ANCHORS.status}`}>{t("status.title")}</a>
        </li>
        <li>
          <a href={`#${REPORT_ANCHORS.summary}`}>{t("summary.title")}</a>
        </li>
        <li>
          <a href={`#${REPORT_ANCHORS.details}`}>{t("details.title")}</a>
          <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
            <li>
              <a href={`#${REPORT_ANCHORS.findings}`}>{t("findings.title")}</a>
              <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
                {report.findings.map((finding) => (
                  <li key={finding.report_finding_number}>
                    <a href={`#${findingAnchor(finding.report_finding_number)}`}>
                      {t("finding.heading", {
                        number: finding.report_finding_number,
                        title: finding.title,
                      })}
                    </a>
                  </li>
                ))}
              </Stack>
            </li>
            {hasResearch ? (
              <li>
                <a href={`#${REPORT_ANCHORS.research}`}>{t("research.title")}</a>
              </li>
            ) : null}
            {hasLimitations ? (
              <li>
                <a href={`#${REPORT_ANCHORS.limitations}`}>{t("limitations.title")}</a>
              </li>
            ) : null}
            {hasUnresolved ? (
              <li>
                <a href={`#${REPORT_ANCHORS.unresolved}`}>{t("unresolved.title")}</a>
              </li>
            ) : null}
            {hasNextSteps ? (
              <li>
                <a href={`#${REPORT_ANCHORS.nextSteps}`}>{t("nextSteps.title")}</a>
              </li>
            ) : null}
          </Stack>
        </li>
      </Stack>
    </Box>
  );
}

/** Evidence and Graph Analysis support rendered directly for one finding. */
function FindingSupport({
  finding,
  presentation,
}: {
  finding: ReportFinding;
  presentation?: SupportPresentationLookup | null;
}): ReactElement | null {
  const { t } = useTranslation("overview");
  const evidence = finding.support.filter((support) => support.kind === "evidence");
  const relationships = finding.support.filter(
    (support) => support.kind === "relationship_observation",
  );
  if (evidence.length === 0 && relationships.length === 0) {
    return null;
  }
  return (
    <>
      {evidence.length > 0 ? (
        <Box sx={{ mt: 1 }}>
          <Typography variant="h4">{t("support.evidence")}</Typography>
          <Stack component="ul" sx={{ listStyle: "none", m: 0, p: 0, gap: 0.25 }}>
            {evidence.map((support, index) => (
              <SupportReference
                key={`e-${index}`}
                support={support}
                presentation={presentation}
              />
            ))}
          </Stack>
        </Box>
      ) : null}
      {relationships.length > 0 ? (
        <Box sx={{ mt: 1 }}>
          <Typography variant="h4">{t("support.graphAnalysis")}</Typography>
          <Stack component="ul" sx={{ listStyle: "none", m: 0, p: 0, gap: 0.25 }}>
            {relationships.map((support, index) => (
              <SupportReference
                key={`r-${index}`}
                support={support}
                presentation={presentation}
              />
            ))}
          </Stack>
        </Box>
      ) : null}
    </>
  );
}

/** One detailed finding with numbered short title and direct support. */
function ReportFindingItem({
  finding,
  presentation,
}: {
  finding: ReportFinding;
  presentation?: SupportPresentationLookup | null;
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Box
      component="article"
      id={findingAnchor(finding.report_finding_number)}
      sx={(theme) => ({
        border: 1,
        borderColor: theme.palette.divider,
        borderRadius: 1,
        p: 1.5,
      })}
    >
      <Typography variant="h3">
        {t("finding.heading", {
          number: finding.report_finding_number,
          title: finding.title,
        })}
      </Typography>
      <Typography variant="body2" sx={{ mt: 0.5 }}>
        {t("finding.criticality")} {criticalityText(t, finding.criticality)}
      </Typography>
      <Typography variant="body2">
        {t("finding.confidence")} {confidenceText(t, finding.confidence)}
      </Typography>
      <Typography variant="body1" sx={{ mt: 0.75 }}>
        {finding.description}
      </Typography>
      <FindingSupport finding={finding} presentation={presentation} />
    </Box>
  );
}

/** One optional detail section rendered only when it has content. */
function OptionalSection({
  id,
  title,
  items,
}: {
  id: string;
  title: string;
  items: readonly string[];
}): ReactElement | null {
  if (items.length === 0) {
    return null;
  }
  return (
    <Box component="section" id={id}>
      <Typography variant="h3">{title}</Typography>
      <Stack component="ul" sx={{ m: 0, pl: 3, gap: 0.25 }}>
        {items.map((item, index) => (
          <Typography key={index} component="li" variant="body2">
            {item}
          </Typography>
        ))}
      </Stack>
    </Box>
  );
}

/** Research context: visibly contextual claims, never Evidence. */
function ResearchContext({ report }: { report: Report }): ReactElement | null {
  const { t } = useTranslation("overview");
  const claims = report.research_context;
  if (claims.length === 0) {
    return null;
  }
  return (
    <Box component="section" id={REPORT_ANCHORS.research}>
      <Typography variant="h3">{t("research.title")}</Typography>
      <Typography variant="caption" sx={{ display: "block" }}>
        {t("research.intro")}
      </Typography>
      <Stack component="ul" sx={{ listStyle: "none", m: 0, p: 0, gap: 1 }}>
        {claims.map((claim) => (
          <Box
            component="li"
            key={claim.research_claim_id}
            sx={(theme) => ({
              borderLeft: 3,
              borderColor: theme.palette.divider,
              pl: 1.5,
            })}
          >
            <Typography variant="body2">{claim.claim_text}</Typography>
            {claim.citations.length > 0 ? (
              <Typography variant="caption" sx={{ display: "block", mt: 0.25 }}>
                {claim.citations
                  .slice(0, MAX_RENDERED_CITATIONS)
                  .map((citation) => citation.title ?? citation.source_id)
                  .join(" • ")}
              </Typography>
            ) : null}
            <Box sx={{ mt: 0.5 }}>
              <PivotMenu
                actions={[
                  researchSupportAction(claim.research_result_id, "research_reference"),
                ]}
              />
            </Box>
          </Box>
        ))}
      </Stack>
    </Box>
  );
}

/** Bounded number of citation metadata lines rendered per claim. */
const MAX_RENDERED_CITATIONS = 2;

/**
 * The canonical Final Report content.
 *
 * Summary and Details are projections of the same persisted, ordered finding
 * set. Optional empty sections (and their Contents entries) are omitted.
 */
export function ReportContent({
  report,
  presentation = undefined,
}: {
  report: Report;
  presentation?: SupportPresentationLookup | null;
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Stack spacing={2.5}>
      <Box>
        <Typography variant="h1">{report.title}</Typography>
      </Box>
      <StatusSection report={report} />
      <SummarySection report={report} />
      <ContentsSection report={report} />
      <Box component="section" id={REPORT_ANCHORS.details}>
        <Typography variant="h2">{t("details.title")}</Typography>
        <Box component="section" id={REPORT_ANCHORS.findings} sx={{ mt: 1 }}>
          <Typography variant="h3">{t("findings.title")}</Typography>
          <Stack spacing={1.5} sx={{ mt: 1 }}>
            {report.findings.map((finding) => (
              <ReportFindingItem
                key={finding.report_finding_number}
                finding={finding}
                presentation={presentation}
              />
            ))}
          </Stack>
        </Box>
        <Box sx={{ mt: 2 }}>
          <ResearchContext report={report} />
          <OptionalSection
            id={REPORT_ANCHORS.limitations}
            title={t("limitations.title")}
            items={report.limitations}
          />
          <OptionalSection
            id={REPORT_ANCHORS.unresolved}
            title={t("unresolved.title")}
            items={report.unresolved_questions}
          />
          <OptionalSection
            id={REPORT_ANCHORS.nextSteps}
            title={t("nextSteps.title")}
            items={report.recommended_next_steps}
          />
        </Box>
      </Box>
    </Stack>
  );
}
