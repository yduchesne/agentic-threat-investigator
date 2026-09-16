// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Geographic observation detail body (PR 26E §10, §13).
//
// One exact Investigation-scoped observation shows the Entity, canonical
// Location/type, precision, a human-readable resolution method, the three
// distinct timestamps (observed/retrieved/resolved) and the exact Evidence
// surface. The Evidence action always uses the exact returned
// ``evidence_id`` through the existing Evidence detail/pivot surface;
// nothing is ever scanned, searched by Entity, or substituted.
//
// Current/history and precision are conveyed by text; the timestamps stay
// distinct; no provider is fabricated (only the fixed resolution method is
// labelled, unknown identities render the raw bounded string).

import { Box, Button, Divider, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { GeointObservationDetail } from "../api/schema-types";
import {
  DetailSection,
} from "../analyst-table/DetailRows";
import { formatDateTime } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  geointEntityActions,
  geointObservationEvidenceAction,
  geointObservationLocationActions,
} from "../pivots/pivot-capabilities";
import { locationCanonicalLabel } from "./geoint-model";
import { locationPrecisionKey, locationTypeKey, resolutionMethodKey } from "./geoint-labels";

/** One observation's display provenance with the exact Evidence action. */
export interface GeointObservationDetailBodyProps {
  /** One exact Investigation-scoped observation detail. */
  detail: GeointObservationDetail;
  /** Exact Evidence action surface (drawer switch or pivot). */
  onViewEvidence?: (evidenceId: string) => void;
}

/** The full geographic observation detail body. */
export function GeointObservationDetailBody({
  detail,
  onViewEvidence,
}: GeointObservationDetailBodyProps): ReactElement {
  const { t } = useTranslation("geoint");
  const observation = detail.observation;
  const locationLabel =
    locationCanonicalLabel(observation.location) ?? t("location.unavailable");
  const methodKey = resolutionMethodKey(observation.resolution_method);

  return (
    <Box>
      <DetailSection title={t("detail.observation.entity")}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {detail.entity_value}
        </Typography>
        <Typography variant="caption" component="div">
          {t("detail.observation.entityType", { type: t(`entityType.${detail.entity_type}`) })}
        </Typography>
        {detail.display_name !== null && detail.display_name !== detail.entity_value ? (
          <Typography variant="caption" component="div">
            {detail.display_name}
          </Typography>
        ) : null}
      </DetailSection>
      <DetailSection title={t("detail.observation.location")}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {locationLabel}
        </Typography>
        <Typography variant="caption" component="div">
          {t("detail.observation.locationType", {
            type: t(locationTypeKey(observation.location.location_type)),
          })}
        </Typography>
        <Typography variant="caption" component="div">
          {t("detail.observation.precision", {
            precision: t(locationPrecisionKey(observation.precision)),
          })}
        </Typography>
      </DetailSection>
      <DetailSection title={t("detail.observation.resolution")}>
        <Typography variant="body2">
          {methodKey !== null
            ? t(methodKey)
            : t("detail.observation.resolutionMethod", {
                method: observation.resolution_method,
              })}
        </Typography>
      </DetailSection>
      <DetailSection title={t("detail.observation.timestamps")}>
        <Typography variant="body2">
          {t("detail.observation.observed", {
            time:
              observation.observed_at !== null
                ? formatDateTime(observation.observed_at)
                : t("detail.observation.notObserved"),
          })}
        </Typography>
        <Typography variant="body2">
          {t("detail.observation.retrieved", {
            time: formatDateTime(observation.retrieved_at),
          })}
        </Typography>
        <Typography variant="body2">
          {t("detail.observation.resolved", {
            time: formatDateTime(observation.resolved_at),
          })}
        </Typography>
        <Typography variant="caption" component="div" sx={{ mt: 0.5, color: "text.secondary" }}>
          {t("detail.observation.timestampsNote")}
        </Typography>
      </DetailSection>
      <Divider sx={{ my: 1 }} />
      <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 1 }}>
        <Button
          size="small"
          variant="outlined"
          data-testid="geoint-view-evidence"
          onClick={() =>
            onViewEvidence !== undefined
              ? onViewEvidence(observation.evidence_id)
              : undefined
          }
          sx={{ textTransform: "none" }}
        >
          {t("detail.observation.viewEvidence")}
        </Button>
        <PivotMenu
          actions={geointObservationEvidenceAction(observation, "geoint_observation")}
          triggerLabel={t("detail.observation.openEvidencePivot")}
          ariaLabel={t("detail.observation.evidenceAria")}
        />
        <PivotMenu
          actions={geointObservationLocationActions(observation, "geoint_observation")}
          triggerLabel={t("detail.observation.exploreLocation")}
          ariaLabel={t("detail.observation.locationAria", {
            location: locationLabel,
          })}
        />
      </Box>
      <Box sx={{ mt: 1 }}>
        <EntityExploreRow detail={detail} />
      </Box>
    </Box>
  );
}

/** The existing valid Entity exploration actions of one observation. */
function EntityExploreRow({
  detail,
}: {
  detail: GeointObservationDetail;
}): ReactElement {
  const { t } = useTranslation("geoint");
  const entityIdentity = {
    entity_id: detail.observation.entity_id,
    entity_value: detail.entity_value,
  };
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
      <Typography variant="caption">{t("detail.observation.exploreEntity")}</Typography>
      <PivotMenu
        actions={geointEntityActions(entityIdentity, "geoint_observation")}
        triggerLabel={t("explore.trigger")}
        ariaLabel={t("detail.observation.entityAria", { entity: detail.entity_value })}
      />
    </Box>
  );
}