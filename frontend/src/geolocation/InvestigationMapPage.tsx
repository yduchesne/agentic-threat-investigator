// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation Map route page (PR 25B §15-§20, §32, §36, §40).
//
// The route owns the Investigation ID, the geolocation query state, the
// pure map-model partition, the persistent approximation disclaimer, the
// Leaflet map, and the always-available non-map representation. It never
// calls raw fetch, never parses generic Evidence, never performs a
// geolocation lookup, and never renders an empty world map while the
// authoritative PR 25A request is unresolved.
//
// Exact Evidence provenance reuses the PR 24C architecture: an
// Investigation-scoped detail query feeding the shared DetailDrawer +
// EvidenceDetail surface. The drawer opens from both the marker popup and
// the non-map table with the exact persisted PR 25A ``evidence_id`` — no
// lookup by IP, no Evidence list scan, no History substitution. The page's
// URL state remains only the route itself.

import { Alert, Box, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router";

import {
  DetailDrawer,
  DrawerError,
  DrawerLoading,
  DrawerNotFound,
} from "../analyst-table/DetailDrawer";
import { DetailSection } from "../analyst-table/DetailRows";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { isNotFound404 } from "../analyst-table/detail-error";
import { EmptyState, LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { useEvidenceDetail } from "../evidence/evidence-queries";
import { EvidenceDetail } from "../evidence/EvidenceDetail";
import { GeolocationList } from "./GeolocationList";
import { InvestigationMap } from "./InvestigationMap";
import { buildGeolocationMapModel } from "./geolocation-map-model";
import { useInvestigationGeolocations } from "./geolocation-queries";

/** Translate shape accepted by bounded presentation helpers. */
type Translate = (key: string, params?: Record<string, unknown>) => string;

/** The Investigation Map route. */
export function InvestigationMapPage(): ReactElement {
  const { t } = useTranslation("geolocation");
  const { t: tEvidence } = useTranslation("evidence");
  const { investigationId = "" } = useParams();
  const { collection, isLoading, isError, error, refetch } =
    useInvestigationGeolocations(investigationId);

  // Exact Evidence provenance drawer (PR 24C architecture): the precise
  // persisted evidence_id resolves through the Investigation-scoped GET.
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const detail = useEvidenceDetail(investigationId, selectedEvidenceId);
  const openEvidence = (evidenceId: string): void => setSelectedEvidenceId(evidenceId);
  const closeEvidence = (): void => setSelectedEvidenceId(null);

  const model = useMemo(
    () =>
      collection === null
        ? null
        : buildGeolocationMapModel(collection.items, collection.truncated),
    [collection],
  );

  // Initial load: never render an empty world map while the authoritative
  // geolocation request is unresolved.
  if (isLoading && collection === null) {
    return <LoadingState label={t("loading")} />;
  }
  // Geolocation API failure: retain the workspace via the route shell and
  // offer Retry; there is no fallback to generic Evidence or any lookup.
  if (isError && collection === null && error !== null) {
    return (
      <ErrorNotice
        title={t("error.title")}
        onRetry={refetch}
        retryLabel={t("error.retry")}
      />
    );
  }
  if (model === null) {
    return <LoadingState label={t("loading")} />;
  }

  return (
    <Box>
      <Box>
        <Typography variant="h2" sx={{ mb: 0.25 }}>
          {t("title")}
        </Typography>
        <Typography variant="caption" component="div" role="note">
          {t("intro")}
        </Typography>
      </Box>
      {isError ? (
        <Box sx={{ mt: 1 }}>
          <ErrorNotice
            severity="warning"
            title={t("error.title")}
            onRetry={refetch}
            retryLabel={t("error.retry")}
          />
        </Box>
      ) : null}
      {/* Persistent visible approximation disclaimer (never tooltip-only). */}
      <Alert severity="info" sx={{ mt: 1 }} role="note">
        {t("disclaimer.body")}
      </Alert>
      {model.truncated ? (
        <Alert severity="warning" sx={{ mt: 1 }}>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {t("truncated.title")}
          </Typography>
          <Typography variant="body2">{t("truncated.message")}</Typography>
        </Alert>
      ) : null}
      {model.mappableCount > 0 ? (
        <>
          {model.unlocatedCount > 0 ? (
            <Typography variant="body2" role="note" sx={{ mt: 1 }}>
              {t("mixed.notice", {
                count: String(model.unlocatedCount),
                total: String(model.totalCount),
              })}
            </Typography>
          ) : null}
          <Box sx={{ mt: 1 }}>
            <InvestigationMap
              investigationId={investigationId}
              items={model.mappable}
              onViewEvidence={openEvidence}
            />
          </Box>
        </>
      ) : (
        <Box sx={{ mt: 1 }}>
          {model.totalCount === 0 ? (
            <EmptyState
              title={t("empty.title")}
              message={t("empty.message")}
            />
          ) : (
            <EmptyState
              title={t("unlocated.title")}
              message={t("unlocated.message")}
            />
          )}
        </Box>
      )}
      {collection !== null ? (
        <GeolocationList items={collection.items} onViewEvidence={openEvidence} />
      ) : null}
      <DetailDrawer
        open={selectedEvidenceId !== null}
        title={t("evidence.drawerTitle")}
        onClose={closeEvidence}
      >
        {selectedEvidenceId !== null
          ? evidenceDrawerBody(t, tEvidence, detail)
          : null}
      </DetailDrawer>
    </Box>
  );
}

/** The exact-Evidence drawer body with its bounded states. */
function evidenceDrawerBody(
  t: Translate,
  tEvidence: Translate,
  detail: ReturnType<typeof useEvidenceDetail>,
): ReactElement {
  if (detail.isLoading && detail.evidence === null) {
    return <DrawerLoading label={t("evidence.loading")} />;
  }
  if (detail.isError && detail.evidence === null) {
    if (detail.error !== null && isNotFound404(detail.error)) {
      return <DrawerNotFound title={t("evidence.notFound.title")} />;
    }
    return <DrawerError title={t("evidence.loadError.title")} onRetry={detail.refetch} />;
  }
  if (detail.evidence === null) {
    return <DrawerLoading label={t("evidence.loading")} />;
  }
  return (
    <Box>
      <EvidenceDetail evidence={detail.evidence} />
      {Object.keys(detail.evidence.facts ?? {}).length > 0 ? (
        <DetailSection title={tEvidence("detail.facts")}>
          <SafeJsonView data={detail.evidence.facts} label={tEvidence("detail.facts")} />
        </DetailSection>
      ) : null}
    </Box>
  );
}