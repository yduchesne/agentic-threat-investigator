// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation finding presentation (PR 24B §24; PR 24D §7; PR 24F).
//
// One bounded finding card with statement, category, disposition,
// confidence, and visible typed support references. Evidence support
// pivots to the exact scoped Evidence workspace; RelationshipObservation
// support pivots to the exact Investigation-scoped observation read
// (PR 24F). Rich resource resolution belongs to pivots — never list
// scans, never substitute observations.
//
// PR 31F-5 E3: support references are human-readable first. The persisted
// support ID is secondary technical identity; the primary line is the
// semantic description supplied by the Investigation-scoped batch
// presentation projection (passed in through ``presentation``). Supports
// that cannot resolve render the localized unavailable statement plus the
// secondary ID and keep their exact scoped action.

import { Stack, Typography } from "@mui/material";
import Box from "@mui/material/Box";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type {
  EvidenceSupportPresentation,
  FindingLike,
  FindingSupportRef,
  RelationshipObservationSupportPresentation,
} from "../api/schema-types";
import { ShortId } from "../components/ShortId";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  evidenceSupportAction,
  observationSupportAction,
} from "../pivots/pivot-capabilities";
import { evidenceTypeKey } from "../evidence/labels";
import { relationshipTypeKey } from "../relationships/labels";
import { entityTypeLabelKey } from "../relationship-graph/relationship-graph-presentation";
import type { SupportPresentationLookup } from "./support-presentations-queries";

export const CATEGORY_LABEL_KEYS: Record<string, string> = {
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

/** Translate one Entity type value (unknown values fall back safely). */
function entityTypeText(
  t: (key: string, params?: Record<string, string | number>) => string,
  type: string | null | undefined,
): string | null {
  if (type === undefined || type === null) {
    return null;
  }
  return t(entityTypeLabelKey(type));
}

/** Semantic Evidence support line: source · type · subject value (type). */
function evidenceSupportLine(
  tEvidence: (key: string) => string,
  tEvolution: (key: string) => string,
  evidence: EvidenceSupportPresentation,
): string {
  const parts: string[] = [];
  if (evidence.source !== undefined && evidence.source !== null) {
    parts.push(evidence.source);
  }
  parts.push(tEvidence(evidenceTypeKey(evidence.evidence_type)));
  if (
    evidence.subject_entity_value !== undefined &&
    evidence.subject_entity_value !== null
  ) {
    parts.push(evidence.subject_entity_value);
    const typeText = entityTypeText(tEvolution, evidence.subject_entity_type);
    if (typeText !== null) {
      parts.push(typeText);
    }
  }
  return parts.join(" · ");
}

/** Semantic RelationshipObservation edge line: source → type → target. */
function observationSupportLine(
  tRelationships: (key: string) => string,
  tEvolution: (key: string) => string,
  observation: RelationshipObservationSupportPresentation,
): string {
  const sourceValue = observation.source_entity_value;
  const targetValue = observation.target_entity_value;
  const typeText = tRelationships(relationshipTypeKey(observation.relationship_type));
  if (
    (sourceValue === undefined || sourceValue === null) &&
    (targetValue === undefined || targetValue === null)
  ) {
    return typeText;
  }
  const endpoint = (
    value: string | null | undefined,
    type: string | null | undefined,
  ): string =>
    [value ?? "", entityTypeText(tEvolution, type) ?? ""].filter((part) => part !== "").join(" · ");
  return `${endpoint(sourceValue, observation.source_entity_type)} → ${typeText} → ${endpoint(
    targetValue,
    observation.target_entity_type,
  )}`;
}

/** One typed support reference: semantic description primary, ID second. */
export function SupportReference({
  support,
  presentation = undefined,
}: {
  support: FindingSupportRef;
  presentation?: SupportPresentationLookup | null;
}): ReactElement {
  const { t } = useTranslation("overview");
  const { t: tEvidence } = useTranslation("evidence");
  const { t: tRelationships } = useTranslation("relationships");
  const { t: tEvolution } = useTranslation("relationshipEvolution");
  if (support.kind === "evidence" && support.evidence_id !== null && support.evidence_id !== undefined) {
    const presentationItem =
      presentation?.[support.evidence_id] as
        | EvidenceSupportPresentation
        | undefined;
    const semantic =
      presentationItem !== undefined
        ? evidenceSupportLine(tEvidence, tEvolution, presentationItem)
        : t("support.evidenceUnavailable");
    return (
      <li>
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
          <Typography variant="caption" component="span">
            {semantic}
          </Typography>
          <Typography variant="caption" component="span" sx={{ color: "text.secondary" }}>
            {t("support.evidenceId")} <ShortId id={support.evidence_id} />
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
    // Exact provenance (PR 24D/24F): the persisted observation id opens
    // the exact Investigation-scoped observation through the pivot step.
    const presentationItem =
      presentation?.[support.relationship_observation_id] as
        | RelationshipObservationSupportPresentation
        | undefined;
    const semantic =
      presentationItem !== undefined
        ? observationSupportLine(tRelationships, tEvolution, presentationItem)
        : t("support.observationUnavailable");
    return (
      <li>
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center", gap: 0.5, flexWrap: "wrap" }}>
          <Typography variant="caption" component="span">
            {semantic}
          </Typography>
          <Typography variant="caption" component="span" sx={{ color: "text.secondary" }}>
            {t("support.observationId")} <ShortId id={support.relationship_observation_id} />
          </Typography>
          <PivotMenu
            actions={[
              observationSupportAction(
                support.relationship_observation_id,
                "report_support",
              ),
            ]}
          />
        </Stack>
      </li>
    );
  }
  return <li>{t("support.unknown")}</li>;
}

export interface FindingListProps {
  findings: readonly FindingLike[];
  /** Support presentation lookup keyed by support observation ID. */
  presentation?: SupportPresentationLookup | null;
}

/** The bounded findings section for Overview and Report surfaces. */
export function FindingList({
  findings,
  presentation = undefined,
}: FindingListProps): ReactElement {
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
                  <SupportReference
                    key={supportIndex}
                    support={support}
                    presentation={presentation}
                  />
                ))}
              </Stack>
            </Box>
          ) : null}
        </Box>
      ))}
    </Stack>
  );
}
