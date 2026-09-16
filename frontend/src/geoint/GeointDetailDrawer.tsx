// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared GEOINT detail drawer (PR 26E §8-§10, §14).
//
// One right-side drawer serves two exact surfaces: the Investigation-
// scoped observation detail (exact ``observation_id``) and the exact
// Evidence (exact returned ``evidence_id`` through the existing Evidence
// detail surface). Only one opens at a time; switching swaps content in
// place. Both resolve through exact Investigation-scoped GET endpoints —
// no Evidence list scan, no lookup by Entity, no substituted row.

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import {
  DetailDrawer,
  DrawerError,
  DrawerLoading,
  DrawerNotFound,
} from "../analyst-table/DetailDrawer";
import { DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { useEvidenceDetail } from "../evidence/evidence-queries";
import { EvidenceDetail } from "../evidence/EvidenceDetail";
import { GeointObservationDetailBody } from "./GeointObservationDetail";
import { useGeointObservation } from "./geoint-queries";

export interface GeointDetailDrawerProps {
  open: boolean;
  /** Accessible drawer title (observation or evidence context). */
  title: string;
  onClose: () => void;
  investigationId: string;
  /** The exact selected observation, or null. */
  observationId: string | null;
  /** Switch in place from an observation to its exact Evidence. */
  onViewEvidence: (evidenceId: string) => void;
  /** The exact selected Evidence id, or null. */
  evidenceId: string | null;
}

/** One Observation<->Evidence detail drawer with exact IDs only. */
export function GeointDetailDrawer({
  open,
  title,
  onClose,
  investigationId,
  observationId,
  onViewEvidence,
  evidenceId,
}: GeointDetailDrawerProps): ReactElement {
  const { t } = useTranslation("geoint");
  const observationDetail = useGeointObservation(investigationId, observationId);
  const evidenceDetail = useEvidenceDetail(investigationId, evidenceId);
  return (
    <DetailDrawer open={open} title={title} onClose={onClose}>
      {observationId !== null
        ? observationBody(t, observationDetail, onViewEvidence)
        : evidenceId !== null
          ? evidenceBody(t, evidenceDetail)
          : null}
    </DetailDrawer>
  );
}

/** The observation detail drawer body with its bounded states. */
function observationBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useGeointObservation>,
  onViewEvidence: (evidenceId: string) => void,
): ReactElement {
  if (detail.isLoading && detail.detail === null) {
    return <DrawerLoading label={t("detail.observation.loading")} />;
  }
  if (detail.isError && detail.detail === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("detail.observation.notFound.title")} />;
    }
    return (
      <DrawerError title={t("detail.observation.loadError.title")} onRetry={detail.refetch} />
    );
  }
  if (detail.detail === null) {
    return <DrawerLoading label={t("detail.observation.loading")} />;
  }
  return <GeointObservationDetailBody detail={detail.detail} onViewEvidence={onViewEvidence} />;
}

/** The exact Evidence drawer body. */
function evidenceBody(
  t: (key: string) => string,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DrawerLoading label={t("detail.evidence.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("detail.evidence.notFound.title")} />;
    }
    return <DrawerError title={t("detail.evidence.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DrawerLoading label={t("detail.evidence.loading")} />;
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