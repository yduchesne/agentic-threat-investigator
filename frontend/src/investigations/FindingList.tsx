// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation finding presentation (PR 24B §24; PR 24D §7).
//
// One bounded finding card with statement, category, disposition,
// confidence, and visible typed support references. Evidence support
// pivots to the exact scoped Evidence workspace (PR 24D); Relationship-
// Observation support stays visible but non-pivotable because the v0.1
// API exposes observations only through a ``relationship_id``-filtered
// list and the support DTO carries only the observation id (PR 24D §7,
// §34 STOP condition 3). Rich resource resolution belongs to pivots.

import { Stack, Typography } from "@mui/material";
import Box from "@mui/material/Box";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type {
  Finding,
  FindingSupportRef,
  ReportFinding,
} from "../api/schema-types";
import { ShortId } from "../components/ShortId";
import { PivotMenu } from "../pivots/PivotMenu";
import { evidenceSupportAction } from "../pivots/pivot-capabilities";

type FindingLike = Finding | ReportFinding;

const CATEGORY_LABEL_KEYS: Record<string, string> = {
  reputation: "category.reputation",
  geolocation: "category.geolocation",
  registration: "category.registration",
  network: "category.network",
  association: "category.association",
};

const DISPOSITION_LABEL_KEYS: Record<string, string> = {
  supporting: "disposition.supporting",
  contradicting: "disposition.contradicting",
};

/** One typed support reference in compact form. */
export function SupportReference({
  support,
}: {
  support: FindingSupportRef;
}): ReactElement {
  const { t } = useTranslation("overview");
  if (support.kind === "evidence" && support.evidence_id !== null && support.evidence_id !== undefined) {
    return (
      <li>
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5 }}>
          <Typography variant="caption" component="span">
            {t("support.evidence")} <ShortId id={support.evidence_id} />
          </Typography>
          <PivotMenu
            actions={[evidenceSupportAction(support.evidence_id, "report_support")]}
          />
        </Stack>
      </li>
    );
  }
  if (
    support.kind === "relationship_observation" &&
    support.relationship_observation_id !== null &&
    support.relationship_observation_id !== undefined
  ) {
    // Visible but not pivotable: no bounded route exists from the support
    // observation id (PR 24D STOP condition 3).
    return (
      <li>
        {t("support.relationshipObservation")}{" "}
        <ShortId id={support.relationship_observation_id} />
      </li>
    );
  }
  return <li>{t("support.unknown")}</li>;
}

export interface FindingListProps {
  findings: readonly FindingLike[];
}

/** The bounded findings section for Overview and Report surfaces. */
export function FindingList({ findings }: FindingListProps): ReactElement {
  const { t } = useTranslation("overview");
  if (findings.length === 0) {
    return <Typography variant="body2">{t("finding.noFindings")}</Typography>;
  }
  return (
    <Stack spacing={1.5} component="ul" sx={{ listStyle: "none", m: 0, p: 0 }}>
      {findings.map((finding, index) => (
        <Box
          component="li"
          key={`${finding.statement}-${index}`}
          sx={(theme) => ({
            border: 1,
            borderColor: theme.palette.divider,
            borderRadius: 1,
            p: 1.5,
          })}
        >
          <Typography variant="body1">{finding.statement}</Typography>
          <Typography variant="caption" sx={{ display: "block", mt: 0.5 }}>
            {t(CATEGORY_LABEL_KEYS[finding.category] ?? "category.unknown")} •{" "}
            {t(`confidence.${finding.confidence}`)} confidence •{" "}
            {t(DISPOSITION_LABEL_KEYS[finding.disposition] ?? "disposition.unknown")}
          </Typography>
          {finding.support.length > 0 ? (
            <Box sx={{ mt: 0.5 }}>
              <Typography variant="caption" component="div" sx={{ fontWeight: 700 }}>
                {t("support.title")}
              </Typography>
              <Stack component="ul" sx={{ listStyle: "none", m: 0, p: 0, gap: 0.25 }}>
                {finding.support.map((support, supportIndex) => (
                  <SupportReference key={supportIndex} support={support} />
                ))}
              </Stack>
            </Box>
          ) : null}
        </Box>
      ))}
    </Stack>
  );
}