// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Full persisted Report route (PR 24B §27).
//
// Secondary presentation surface for the authoritative persisted Report:
// structured content plus persisted metadata and an optional deterministic
// Markdown view rendered as plain/preformatted text (never parsed HTML).
// Nothing here regenerates a Report or invokes an LLM.

import { Box, Button, Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useOutletContext, useParams } from "react-router";

import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Timestamp } from "../components/Timestamp";
import { useCurrentReport, useReportMarkdown } from "./investigation-queries";
import type { WorkspaceOutletContext } from "./InvestigationWorkspace";
import { ReportContent } from "./ReportView";

/** The secondary full Report surface. */
export function ReportPage(): ReactElement | null {
  const { t } = useTranslation("report");
  const { investigation } = useOutletContext<WorkspaceOutletContext>();
  const { investigationId = "" } = useParams();
  const [showMarkdown, setShowMarkdown] = useState(false);

  // Hooks stay unconditional (React rules); the Investigation is always
  // present because the workspace renders its outlet only with data, but
  // the queries remain pointer-gated either way.
  const reportEnabled = investigation !== null && investigation.report_id !== null;
  const { report, isLoading, isError, refetch } = useCurrentReport(
    investigation?.id ?? investigationId,
    reportEnabled,
  );
  const markdownQuery = useReportMarkdown(
    investigationId,
    report?.id ?? "",
    showMarkdown && report !== null,
  );

  if (investigation === null) {
    return <EmptyState title={t("title")} />;
  }

  if (!reportEnabled) {
    return (
      <Box>
        <Typography variant="h1">{t("title")}</Typography>
        <AlertInfo text={t("none")} />
        <Button
          component={Link}
          to={`/investigations/${investigation.id}/overview`}
          variant="outlined"
          sx={{ mt: 2, textTransform: "none" }}
        >
          {t("backToOverview")}
        </Button>
      </Box>
    );
  }
  if (isLoading && report === null) {
    return <LoadingState label={t("loading")} />;
  }
  if (isError && report === null) {
    return <ErrorNotice title={t("loadError")} onRetry={refetch} />;
  }
  if (report === null) {
    return null;
  }

  return (
    <Stack spacing={2}>
      <Typography variant="h1">{t("title")}</Typography>
      <Button
        component={Link}
        to={`/investigations/${investigation.id}/overview`}
        variant="outlined"
        sx={{ alignSelf: "flex-start", textTransform: "none" }}
      >
        {t("backToOverview")}
      </Button>
      <Stack direction="row" spacing={3}>
        <Typography variant="body2">
          {t("meta.createdAt")} <Timestamp iso={report.created_at} />
        </Typography>
        <Typography variant="body2">
          {t("meta.version")} {report.version}
        </Typography>
      </Stack>
      <ReportContent report={report} />
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
              <ErrorNotice title={t("markdown.error")} onRetry={markdownQuery.refetch} />
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

/** Minimal informational alert (no full import surface). */
function AlertInfo({ text }: { text: string }): ReactElement {
  return (
    <Box
      role="status"
      sx={(theme) => ({
        mt: 1,
        p: 1.5,
        borderRadius: 1,
        border: 1,
        borderColor: theme.palette.divider,
      })}
    >
      <Typography variant="body2">{text}</Typography>
    </Box>
  );
}