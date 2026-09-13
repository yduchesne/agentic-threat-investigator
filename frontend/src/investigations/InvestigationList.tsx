// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation list presentation (PR 24B §10, §28).
//
// Simple MUI primitives only; no TanStack Table, no page numbers, no total
// counts, no fabricated subject labels. The cursor is opaque: Previous /
// Next navigation is decided by the caller from a browser-local cursor
// stack and the backend's next_cursor.

import { Box, Button, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import type { Investigation } from "../api/schema-types";
import { Timestamp } from "../components/Timestamp";
import { InvestigationStatusBadge } from "./InvestigationStatusBadge";

export interface InvestigationListProps {
  investigations: readonly Investigation[];
  canGoPrevious: boolean;
  canGoNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
}

/** One read-only canary text for artifact availability (never color-only). */
function ArtifactCell({
  available,
  label,
}: {
  available: boolean;
  label: string;
}): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <Typography variant="body2" aria-label={label}>
      {available ? t("artifacts.available") : t("artifacts.unavailable")}
    </Typography>
  );
}

/** Bounded Investigation rows with opaque Previous/Next navigation. */
export function InvestigationList({
  investigations,
  canGoPrevious,
  canGoNext,
  onPrevious,
  onNext,
}: InvestigationListProps): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <Box>
      <Table aria-label={t("title")} size="small">
        <TableHead>
          <TableRow>
            <TableCell>{t("columns.objective")}</TableCell>
            <TableCell>{t("columns.status")}</TableCell>
            <TableCell>{t("columns.started")}</TableCell>
            <TableCell>{t("columns.completed")}</TableCell>
            <TableCell>{t("columns.artifacts")}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {investigations.map((investigation) => (
            <TableRow key={investigation.id} hover>
              <TableCell>
                <Link
                  to={`/investigations/${investigation.id}/overview`}
                  style={{ textDecoration: "none" }}
                >
                  <Typography
                    variant="body1"
                    sx={{ fontWeight: 600, color: "primary.main" }}
                  >
                    {investigation.objective}
                  </Typography>
                </Link>
                <Typography variant="caption" component="div" title={investigation.id}>
                  {investigation.id.slice(0, 8)}
                </Typography>
              </TableCell>
              <TableCell>
                <InvestigationStatusBadge status={investigation.status} />
              </TableCell>
              <TableCell>
                {investigation.started_at ? (
                  <Timestamp iso={investigation.started_at} />
                ) : (
                  <Timestamp iso={investigation.created_at} />
                )}
              </TableCell>
              <TableCell>
                {investigation.completed_at !== null ? (
                  <Timestamp iso={investigation.completed_at} />
                ) : (
                  t("artifacts.unavailable")
                )}
              </TableCell>
              <TableCell>
                <Stack direction="row" spacing={2}>
                  <ArtifactCell
                    available={investigation.assessment_id !== null}
                    label={t("artifacts.assessment")}
                  />
                  <ArtifactCell
                    available={investigation.report_id !== null}
                    label={t("artifacts.report")}
                  />
                </Stack>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end", mt: 1 }}>
        <Button size="small" disabled={!canGoPrevious} onClick={onPrevious}>
          {t("pagination.previous")}
        </Button>
        <Button size="small" disabled={!canGoNext} onClick={onNext}>
          {t("pagination.next")}
        </Button>
      </Stack>
    </Box>
  );
}