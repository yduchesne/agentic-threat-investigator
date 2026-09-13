// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation finding presentation (PR 24B §24).
//
// One bounded finding card with statement, category, disposition,
// confidence, and visible typed support references. Support references are
// compact identifiers with the full value in the title tooltip; rich
// resource resolution and pivots belong to PR 24C/24D.

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
        {t("support.evidence")} <ShortId id={support.evidence_id} />
      </li>
    );
  }
  if (
    support.kind === "relationship_observation" &&
    support.relationship_observation_id !== null &&
    support.relationship_observation_id !== undefined
  ) {
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