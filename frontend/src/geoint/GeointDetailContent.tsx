// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared GEOINT detail content (PR 26E §8-§10, §14; PR 31F-6).
//
// One inline content surface serves two exact reads inside the shared
// list/detail workspace: the Investigation-scoped observation detail
// (exact ``observation_id``) and the exact Evidence (exact returned
// ``evidence_id`` through the existing Evidence detail surface). Only one
// is open at a time; switching swaps content in place inside the same
// detail view. Both resolve through exact Investigation-scoped GET
// endpoints — no Evidence list scan, no lookup by Entity, no substituted
// row, and no second overlay.

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import {
  DetailError,
  DetailLoading,
  DetailNotFound,
} from "../analyst-table/ResourceDetailView";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { useEvidenceDetail } from "../evidence/evidence-queries";
import { EvidenceDetail } from "../evidence/EvidenceDetail";
import { GeointObservationDetailBody } from "./GeointObservationDetail";
import { useGeointObservation } from "./geoint-queries";

export interface GeointDetailContentProps {
  investigationId: string;
  /** The exact selected observation id, or null. */
  observationId: string | null;
  /** Switch in place from an observation to its exact Evidence. */
  onViewEvidence: (evidenceId: string) => void;
  /** The exact selected Evidence id, or null. */
  evidenceId: string | null;
}

/**
 * One Observation<->Evidence content region for a shared detail view.
 *
 * Only one of ``observationId``/``evidenceId`` is open at a time; a
 * ``onViewEvidence`` call swaps the detail content in place.
 */
export function GeointDetailContent({
  investigationId,
  observationId,
  onViewEvidence,
  evidenceId,
}: GeointDetailContentProps): ReactElement {
  const { t } = useTranslation("geoint");
  const observationDetail = useGeointObservation(investigationId, observationId);
  const evidenceDetail = useEvidenceDetail(investigationId, evidenceId);
  return (
    <Box>
      {observationId !== null
        ? observationBody(t, observationDetail, onViewEvidence)
        : evidenceId !== null
          ? evidenceBody(t, evidenceDetail)
          : null}
    </Box>
  );
}

/** The observation detail body with its bounded states. */
function observationBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useGeointObservation>,
  onViewEvidence: (evidenceId: string) => void,
): ReactElement {
  if (detail.isLoading && detail.detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  if (detail.isError && detail.detail === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DetailNotFound title={t("detail.observation.notFound.title")} />;
    }
    return (
      <DetailError title={t("detail.observation.loadError.title")} onRetry={detail.refetch} />
    );
  }
  if (detail.detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  return <GeointObservationDetailBody detail={detail.detail} onViewEvidence={onViewEvidence} />;
}

/** The exact Evidence detail body (shared by GeointPage). */
export function GeointEvidenceBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DetailLoading label={t("detail.evidence.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DetailNotFound title={t("detail.evidence.notFound.title")} />;
    }
    return <DetailError title={t("detail.evidence.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DetailLoading label={t("detail.evidence.loading")} />;
  }
  return (
    <Box>
      <EvidenceDetail evidence={detail.evidence} />
      {Object.keys(detail.evidence.facts ?? {}).length > 0 ? (
        <DetailSection title={t("detail.evidence.facts")}>
          <SafeJsonView data={detail.evidence.facts} label={t("detail.evidence.facts")} />
        </DetailSection>
      ) : null}
    </Box>
  );
}

/** The exact Evidence detail body for one observation-detail read. */
function evidenceBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  return GeointEvidenceBody(t, detail);
}
