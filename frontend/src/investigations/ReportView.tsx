// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Structured persisted Report presentation (PR 24B §23-§27).
//
// Renders the authoritative persisted Report as safe React text (no raw
// HTML, no Markdown interpretation). Verdict/confidence, executive
// summary statements with typed support, findings, distinctly labeled
// Research context, and the persisted caveat lists. Shared by the Overview
// report surface and the full Report route.

import { Box, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type {
  AssessmentConfidenceName,
  NarrativeStatement,
  Report,
  ReportResearchClaim,
  VerdictName,
} from "../api/schema-types";
import { PivotMenu } from "../pivots/PivotMenu";
import { researchSupportAction } from "../pivots/pivot-capabilities";
import { FindingList } from "./FindingList";

const VERDICT_LABEL_KEYS: Record<VerdictName, string> = {
  benign: "verdicts.benign",
  suspicious: "verdicts.suspicious",
  malicious: "verdicts.malicious",
  inconclusive: "verdicts.inconclusive",
};

const CONFIDENCE_LABEL_KEYS: Record<AssessmentConfidenceName, string> = {
  low: "confidence.low",
  medium: "confidence.medium",
  high: "confidence.high",
};

/** Bounded number of citation metadata lines rendered per claim. */
const MAX_RENDERED_CITATIONS = 2;

/** Verdict + confidence presentation (exact backend enums only). */
export function VerdictConfidenceBlock({
  verdict,
  confidence,
}: {
  verdict: VerdictName;
  confidence: AssessmentConfidenceName;
}): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Stack direction="row" spacing={3}>
      <Typography variant="body1">
        <strong>{t("verdict.label")}:</strong> {t(VERDICT_LABEL_KEYS[verdict])}
      </Typography>
      <Typography variant="body1">
        <strong>{t("confidence.label")}:</strong> {t(CONFIDENCE_LABEL_KEYS[confidence])}
      </Typography>
    </Stack>
  );
}

/** One ordered caveat section (limitations/questions/next steps). */
export function ListSection({
  title,
  items,
}: {
  title: string;
  items: readonly string[];
}): ReactElement | null {
  if (items.length === 0) {
    return null;
  }
  return (
    <Box>
      <Typography variant="h2">{title}</Typography>
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

/** One support reference of a narrative statement (compact form). */
function NarrativeSupport({ support }: { support: NarrativeStatement["support"][number] }): ReactElement {
  const { t } = useTranslation("overview");
  if (support.kind === "assessment_finding") {
    return (
      <li>
        {t("execSummary.support.assessmentFinding", {
          ordinal: support.finding_ordinal,
        })}
      </li>
    );
  }
  return (
    <li>
      <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5 }}>
        <Box component="span">{t("execSummary.support.researchClaim")}</Box>
        <PivotMenu
          actions={[researchSupportAction(support.research_result_id, "research_reference")]}
        />
      </Stack>
    </li>
  );
}

/** Executive summary statements, each with compact support references. */
export function ExecutiveSummaryList({
  statements,
}: {
  statements: readonly NarrativeStatement[];
}): ReactElement {
  const { t } = useTranslation("overview");
  if (statements.length === 0) {
    return <Typography variant="body2">{t("execSummary.none")}</Typography>;
  }
  return (
    <Stack spacing={1} component="ul" sx={{ listStyle: "none", m: 0, p: 0 }}>
      {statements.map((statement, index) => (
        <Box component="li" key={index}>
          <Typography variant="body1">{statement.text}</Typography>
          {statement.support.length > 0 ? (
            <Stack
              component="ul"
              sx={{ listStyle: "none", m: 0, p: 0, mt: 0.25, gap: 0.25 }}
            >
              {statement.support.map((support, supportIndex) => (
                <NarrativeSupport key={supportIndex} support={support} />
              ))}
            </Stack>
          ) : null}
        </Box>
      ))}
    </Stack>
  );
}

/** Research context: visibly contextual claims, never Evidence. */
export function ResearchContextBlock({
  claims,
}: {
  claims: readonly ReportResearchClaim[];
}): ReactElement {
  const { t } = useTranslation("overview");
  if (claims.length === 0) {
    return <Typography variant="body2">{t("research.noClaims")}</Typography>;
  }
  return (
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
              {claim.citations.length > MAX_RENDERED_CITATIONS
                ? ` ${t("research.moreCitations", {
                    count: claim.citations.length - MAX_RENDERED_CITATIONS,
                  })}`
                : ""}
            </Typography>
          ) : null}
          <Box sx={{ mt: 0.5 }}>
            <PivotMenu
              actions={[researchSupportAction(claim.research_result_id, "research_reference")]}
            />
          </Box>
        </Box>
      ))}
    </Stack>
  );
}

/**
 * The full structured persisted Report content.
 *
 * Used by the Overview report surface and the secondary full Report route.
 * Every string renders as escaped React text.
 */
export function ReportContent({ report }: { report: Report }): ReactElement {
  const { t } = useTranslation("overview");
  return (
    <Stack spacing={2.5}>
      <Box>
        <Typography variant="h2">{report.title}</Typography>
        <Box sx={{ mt: 1 }}>
          <VerdictConfidenceBlock
            verdict={report.verdict}
            confidence={report.confidence}
          />
        </Box>
      </Box>
      <Box>
        <Typography variant="h2">{t("executiveSummary.title")}</Typography>
        <Box sx={{ mt: 0.5 }}>
          <ExecutiveSummaryList statements={report.executive_summary} />
        </Box>
      </Box>
      <Box>
        <Typography variant="h2">{t("findings.title")}</Typography>
        <Box sx={{ mt: 0.5 }}>
          <FindingList findings={report.findings} />
        </Box>
      </Box>
      <Box>
        <Typography variant="h2">{t("research.title")}</Typography>
        <Typography variant="caption" sx={{ display: "block" }}>
          {t("research.intro")}
        </Typography>
        <Box sx={{ mt: 0.5 }}>
          <ResearchContextBlock claims={report.research_context} />
        </Box>
      </Box>
      <ListSection title={t("limitations.title")} items={report.limitations} />
      <ListSection
        title={t("unresolved.title")}
        items={report.unresolved_questions}
      />
      <ListSection
        title={t("nextSteps.title")}
        items={report.recommended_next_steps}
      />
    </Stack>
  );
}