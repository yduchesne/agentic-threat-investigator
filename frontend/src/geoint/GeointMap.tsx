// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical GEOINT Leaflet map (PR 26E §6, §14).
//
// Reuses the PR 25B React-Leaflet lifecycle/configuration patterns: local
// assets/CSS, OSM attribution, deterministic viewport derived from the
// currently loaded bounded results, neutral markers, keyboard support,
// defensive coordinates, and no persisted viewport. Only the currently
// loaded bounded items are plotted; the map never expands pagination or
// fetches additional pages.
//
// Marker keys are stable returned identities (Location/observation IDs),
// never coordinates alone; same-coordinate items stay individually
// actionable. Popups render Location/type, precision, current-vs-history,
// distinct timestamps, and the exact Evidence/Location/Entity actions when
// the item carries them. No marker visual encoding exists for
// maliciousness, confidence, severity, risk, co-location, or attribution;
// no clustering, heat map, fabricated radius, polygon, movement path, or
// inferred route is rendered.

import "leaflet/dist/leaflet.css";
import { Icon } from "leaflet";
import iconRetinaUrl from "leaflet/dist/images/marker-icon-2x.png";
import iconUrl from "leaflet/dist/images/marker-icon.png";
import shadowUrl from "leaflet/dist/images/marker-shadow.png";
import type { ReactElement } from "react";
import { useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { MapContainer, Marker, Popup, TileLayer, useMap } from "react-leaflet";

import { Box, Button, Typography } from "@mui/material";
import { formatDateTime } from "../components/Timestamp";
import { PivotMenu } from "../pivots/PivotMenu";
import {
  entityActions,
  locationEntitiesAction,
  locationObservationsAction,
  type PivotAction,
} from "../pivots/pivot-capabilities";
import { MAP_HEIGHT_PX, TILE_ATTRIBUTION, TILE_URL } from "../geolocation/map-config";
import type { LocationPrecisionName, LocationTypeName } from "../api/schema-types";
import { BOUNDS_PADDING, geointViewport, isPlottable } from "./geoint-model";
import { locationPrecisionKey, locationTypeKey } from "./geoint-labels";

// Vite-bundle-safe marker assets (identical PR 25B configuration).
Icon.Default.mergeOptions({
  iconRetinaUrl,
  iconUrl,
  shadowUrl,
});

/** One plottable GEOINT item rendered as a neutral marker. */
export interface GeointMapPoint {
  /** Stable returned identity (Location or observation ID). */
  key: string;
  lat: number;
  lng: number;
  /** Primary popup label (canonical Location name). */
  title: string;
  locationType?: LocationTypeName;
  precision?: LocationPrecisionName;
  /** Investigation-relative current marker when known. */
  isCurrent?: boolean;
  entityValue?: string;
  observedAt?: string | null;
  retrievedAt?: string | null;
  resolvedAt?: string | null;
  evidenceId?: string;
  entityId?: string;
  locationId?: string;
  /** Neutral bounded context line (never risk/concentration). */
  context?: string;
  /** Extra explicit actions (e.g. top-Location exploration). */
  actions?: readonly PivotAction[];
}

/** Re-apply the deterministic viewport when the dataset changes. */
function ViewportController({
  viewport,
}: {
  viewport: ReturnType<typeof geointViewport>;
}): ReactElement | null {
  const map = useMap();
  useEffect(() => {
    if (viewport.kind === "single") {
      map.setView(viewport.center, viewport.zoom, { animate: false });
    } else if (viewport.kind === "bounds") {
      map.fitBounds(viewport.bounds, {
        padding: [...BOUNDS_PADDING],
        maxZoom: viewport.maxZoom,
        animate: false,
      });
    }
  }, [map, viewport]);
  return null;
}

/** Separate the defensively plottable points for rendering. */
function plottablePoints(points: readonly GeointMapPoint[]): GeointMapPoint[] {
  return points.filter((point) => isPlottable(point.lat, point.lng));
}

export interface GeointMapProps {
  /** Owns remount identity so a route change never reuses a live map. */
  investigationId: string;
  /** Only plottable items reach the map (already defensively filtered). */
  points: readonly GeointMapPoint[];
  /** Exact Evidence provenance action (exact returned evidence_id). */
  onViewEvidence?: (evidenceId: string) => void;
}

/** One Investigation's canonical GEOINT Leaflet surface. */
export function GeointMap({
  investigationId,
  points,
  onViewEvidence,
}: GeointMapProps): ReactElement {
  const { t } = useTranslation("geoint");
  const viewport = useMemo(
    () =>
      geointViewport(
        points.map((point) => ({ latitude: point.lat, longitude: point.lng })),
      ),
    [points],
  );
  const entries = useMemo(() => plottablePoints(points), [points]);

  if (viewport.kind === "none" || entries.length === 0) {
    // The page renders the non-map/empty state instead of an empty world
    // map with no authoritative points.
    return <></>;
  }

  return (
    <Box
      role="region"
      aria-label={t("map.ariaLabel")}
      sx={{ position: "relative", zIndex: 0, height: MAP_HEIGHT_PX, width: "100%" }}
    >
      <MapContainer
        key={investigationId}
        center={viewport.kind === "single" ? viewport.center : [20, 0]}
        zoom={viewport.kind === "single" ? viewport.zoom : 2}
        bounds={viewport.kind === "bounds" ? viewport.bounds : undefined}
        boundsOptions={
          viewport.kind === "bounds"
            ? { padding: [...BOUNDS_PADDING], maxZoom: viewport.maxZoom }
            : undefined
        }
        style={{ height: "100%", width: "100%" }}
      >
        <TileLayer url={TILE_URL} attribution={TILE_ATTRIBUTION} />
        <ViewportController viewport={viewport} />
        {entries.map((point) => (
          <Marker
            key={point.key}
            position={[point.lat, point.lng]}
            keyboard
            alt={point.title}
            title={point.title}
          >
            <Popup>
              <GeointMarkerPopup point={point} onViewEvidence={onViewEvidence} />
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </Box>
  );
}

interface GeointMarkerPopupProps {
  point: GeointMapPoint;
  onViewEvidence?: (evidenceId: string) => void;
}

/** One neutral marker popup with the point's available context. */
function GeointMarkerPopup({
  point,
  onViewEvidence,
}: GeointMarkerPopupProps): ReactElement {
  const { t } = useTranslation("geoint");
  return (
    <Box sx={{ minWidth: 220 }}>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {point.title}
      </Typography>
      {point.locationType !== undefined ? (
        <Typography variant="caption" component="div">
          {t("popup.locationType", {
            type: t(locationTypeKey(point.locationType)),
          })}
        </Typography>
      ) : null}
      {point.precision !== undefined ? (
        <Typography variant="caption" component="div">
          {t("popup.precision", { precision: t(locationPrecisionKey(point.precision)) })}
        </Typography>
      ) : null}
      {point.isCurrent !== undefined ? (
        <Typography variant="caption" component="div" role="note">
          {point.isCurrent
            ? t("popup.currentInInvestigation")
            : t("popup.historicalInInvestigation")}
        </Typography>
      ) : null}
      {point.entityValue !== undefined ? (
        <Typography variant="caption" component="div">
          {t("popup.entity", { entity: point.entityValue })}
        </Typography>
      ) : null}
      {point.context !== undefined ? (
        <Typography variant="caption" component="div">
          {point.context}
        </Typography>
      ) : null}
      {point.observedAt !== undefined && point.observedAt !== null ? (
        <Typography variant="caption" component="div">
          {t("popup.observed", { time: formatDateTime(point.observedAt) })}
        </Typography>
      ) : null}
      {point.retrievedAt !== undefined && point.retrievedAt !== null ? (
        <Typography variant="caption" component="div">
          {t("popup.retrieved", { time: formatDateTime(point.retrievedAt) })}
        </Typography>
      ) : null}
      {point.resolvedAt !== undefined && point.resolvedAt !== null ? (
        <Typography variant="caption" component="div">
          {t("popup.resolved", { time: formatDateTime(point.resolvedAt) })}
        </Typography>
      ) : null}
      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
        {point.evidenceId !== undefined && point.evidenceId !== "" && onViewEvidence !== undefined ? (
          <Button
            size="small"
            variant="outlined"
            onClick={() => onViewEvidence(point.evidenceId as string)}
            sx={{ textTransform: "none" }}
          >
            {t("popup.viewEvidence")}
          </Button>
        ) : null}
        <PivotMenu
          actions={popupActions(point)}
          triggerLabel={t("popup.explore")}
          ariaLabel={t("popup.exploreAria", { location: point.title })}
        />
      </Box>
    </Box>
  );
}

/** The exact bounded popup actions of one point. */
function popupActions(point: GeointMapPoint): PivotAction[] {
  const actions: PivotAction[] = [];
  if (point.actions !== undefined) {
    actions.push(...point.actions);
  }
  if (point.locationId !== undefined && point.locationId !== "") {
    actions.push(
      locationEntitiesAction(point.locationId, point.title, "geoint_location"),
      locationObservationsAction(point.locationId, point.title, "geoint_location"),
    );
  }
  if (point.entityId !== undefined && point.entityId !== "") {
    actions.push(
      ...entityActions(
        point.entityId,
        point.entityValue ?? point.title,
        "geoint_entity",
      ),
    );
  }
  return actions;
}