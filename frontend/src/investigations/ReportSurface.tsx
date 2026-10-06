// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared persisted Final Report surface (PR 35-5 amendment).
//
// One canonical renderer for the current persisted Report: persisted metadata,
// `ReportContent`, and the optional deterministic Markdown view (preformatted
// text, never parsed HTML). It never regenerates a Report or invokes an LLM.
// The primary REPORT workspace route and any compatibility surface reuse this
// component; no second report projection exists.

import { Box, Button, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import type { Report } from "../api/schema-types";
import { ErrorNotice } from "../components/ErrorNotice";
import { Timestamp } from "../components/Timestamp";
import { LoadingState } from "../components/AsyncState";
import { useReportMarkdown } from "./investigation-queries";
import { useSupportPresentations } from "./support-presentations-queries";
import { ReportContent } from "./ReportView";

export interface ReportSurfaceProps {
  investigationId: string;
  report: Report;
}

/** The one canonical persisted Final Report surface. */
export function ReportSurface({
  investigationId,
  report,
}: ReportSurfaceProps): ReactElement {
  const { t } = useTranslation("report");
  const [showMarkdown, setShowMarkdown] = useState(false);
  const markdownQuery = useReportMarkdown(
    investigationId,
    report.id,
    showMarkdown,
  );
  const supports = useSupportPresentations(
    investigationId,
    report.findings,
    true,
  );

  return (
    <Stack spacing={2}>
      <Stack direction="row" spacing={3}>
        <Typography variant="body2">
          {t("meta.createdAt")} <Timestamp iso={report.created_at} />
        </Typography>
        <Typography variant="body2">
          {t("meta.version")} {report.version}
        </Typography>
      </Stack>
      <ReportContent report={report} presentation={supports.presentation} />
      <Box>
        <Button
          variant="text"
          sx={{ textTransform: "none" }}
          onClick={() => setShowMarkdown((current) => !current)}
        >
          {showMarkdown ? t("hideMarkdown") : t("viewMarkdown")}
        </Button>
        {showMarkdown ? (
          <Box>
            {markdownQuery.isLoading && markdownQuery.markdown === null ? (
              <LoadingState label={t("markdown.loading")} />
            ) : null}
            {markdownQuery.isError && markdownQuery.markdown === null ? (
              <ErrorNotice
                title={t("markdown.error")}
                onRetry={markdownQuery.refetch}
              />
            ) : null}
            {markdownQuery.markdown !== null ? (
              <Box
                component="pre"
                aria-label={t("markdown.label")}
                sx={(theme) => ({
                  border: 1,
                  borderColor: theme.palette.divider,
                  borderRadius: 1,
                  p: 2,
                  maxHeight: 480,
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  fontSize: "0.82rem",
                })}
              >
                {markdownQuery.markdown}
              </Box>
            ) : null}
          </Box>
        ) : null}
      </Box>
    </Stack>
  );
}
