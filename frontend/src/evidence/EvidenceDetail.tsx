// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence detail surface (PR 24C §8).
//
// Shows every safe public DTO field: subject, type, source, source record
// id, source URL (safe-link policy), the distinct observed/retrieved
// timestamps, and normalized facts. External content renders as escaped
// text; the source URL is clickable only for explicit HTTP(S) and is never
// auto-fetched.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { Box } from "@mui/material";
import type { Evidence } from "../api/schema-types";
import { SafeExternalLink } from "../components/SafeExternalLink";
import { Timestamp } from "../components/Timestamp";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import { evidenceSubjectActions } from "../pivots/pivot-capabilities";
import { evidenceTypeKey } from "./labels";

/** All safe public Evidence fields rendered as a bounded detail surface. */
export function EvidenceDetail({ evidence }: { evidence: Evidence }): ReactElement {
  const { t } = useTranslation("evidence");
  const { t: tPivots } = useTranslation("pivots");
  const nullish = t("detail.unavailable");
  return (
    <Box>
      <DetailRows
        rows={[
          {
            label: t("detail.subject"),
            value: evidence.subject_value ?? nullish,
          },
          {
            label: t("detail.subjectType"),
            value: evidence.subject_type ?? nullish,
          },
          { label: t("detail.evidenceType"), value: t(evidenceTypeKey(evidence.type)) },
          { label: t("detail.source"), value: evidence.source },
          {
            label: t("detail.sourceRecordId"),
            value: evidence.source_record_id ?? nullish,
          },
          {
            label: t("detail.sourceUrl"),
            value: (
              <SafeExternalLink
                url={evidence.source_url}
                ariaLabel={t("detail.sourceUrl")}
              />
            ),
          },
          {
            label: t("detail.observedAt"),
            value:
              evidence.observed_at !== null ? <Timestamp iso={evidence.observed_at} /> : t("detail.notObserved"),
          },
          {
            label: t("detail.retrievedAt"),
            value: <Timestamp iso={evidence.retrieved_at} />,
          },
          {
            label: t("detail.id"),
            value: <CompactId id={evidence.id} label={t("detail.id")} />,
          },
        ]}
      />
      <DetailSection title={tPivots("detail.pivot.title")}>
        <PivotMenu
          actions={evidenceSubjectActions(evidence, "detail_field")}
          ariaLabel={tPivots("detail.pivot.aria", { value: evidence.subject_value })}
        />
      </DetailSection>
    </Box>
  );
}
