// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation Leaflet map (PR 25B §21-§28, §38-§40).
//
// React-Leaflet owns the Leaflet lifecycle (no manual map construction in
// an effect, StrictMode-clean, no repeated layout timers). One mappable
// returned item renders one neutral marker with the exact PR 25A
// coordinates; the popup shows exact IP and available approximate context
// (city/region/country, precision, provider, distinct retrieved/observed)
// plus the exact Evidence action. The viewport is derived deterministically
// from server data (map-view model) and applied on dataset change, not on
// every render. No viewport/marker/popup state is persisted anywhere.
//
// Markers carry neutral semantics only: no color/size/icon encodes
// verdict, confidence, severity, maliciousness, or country risk. No
// clustering, heat map, fabricated accuracy radius, polygon, or reverse
// geocoding exists here.

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
import type { InvestigationGeolocation } from "../api/schema-types";
import { formatDateTime } from "../components/Timestamp";
import { GeolocationEntityActions } from "./GeolocationEntityActions";
import { TILE_ATTRIBUTION, TILE_URL, MAP_HEIGHT_PX } from "./map-config";
import {
  BOUNDS_PADDING,
  geoPrecisionKey,
  isPlottableCoordinate,
  locationLabel,
  mapViewport,
  providerLabelKey,
  type MapViewport,
} from "./geolocation-map-model";

// Vite-bundle-safe marker assets: the default Leaflet marker icon URLs are
// relative and resolve nowhere under the hashed bundle, so the resolved
// built assets are configured once. No CDN/hotlinked marker icon is used.
Icon.Default.mergeOptions({
  iconRetinaUrl,
  iconUrl,
  shadowUrl,
});

/** One mappable entry with its exact derived plottable coordinate. */
interface PlottableEntry {
  item: InvestigationGeolocation;
  lat: number;
  lng: number;
}

/**
 * Separate the defensively plottable items for rendering.
 *
 * The pure model already guarantees `mappable` contains only plottable
 * items, but the boundary is re-checked here so malformed runtime data can
 * never produce a Leaflet position.
 */
function plottableEntries(
  items: readonly InvestigationGeolocation[],
): PlottableEntry[] {
  const entries: PlottableEntry[] = [];
  for (const item of items) {
    if (isPlottableCoordinate(item.latitude, item.longitude)) {
      // The guard verified both coordinates are finite in-range numbers.
      entries.push({ item, lat: item.latitude, lng: item.longitude as number });
    }
  }
  return entries;
}

/** Re-apply the deterministic viewport when the dataset changes. */
function ViewportController({ viewport }: { viewport: MapViewport }): ReactElement | null {
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

export interface InvestigationMapProps {
  /** Owns remount identity so a route change never reuses a live map. */
  investigationId: string;
  /** Only plottable (mappable) items reach the map. */
  items: readonly InvestigationGeolocation[];
  /** Exact Evidence provenance action (the exact PR 25A evidence_id). */
  onViewEvidence: (evidenceId: string) => void;
}

/** One Investigation's approximate geolocation Leaflet surface. */
export function InvestigationMap({
  investigationId,
  items,
  onViewEvidence,
}: InvestigationMapProps): ReactElement {
  const { t } = useTranslation("geolocation");
  const viewport = useMemo(() => mapViewport(items), [items]);
  const entries = useMemo(() => plottableEntries(items), [items]);

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
        {entries.map(({ item, lat, lng }) => (
          <Marker
            key={item.evidence_id}
            position={[lat, lng]}
            keyboard
            alt={item.ip_address}
            title={`${item.ip_address} — ${locationLabel(item) ?? t("location.unavailable")}`}
          >
            <Popup>
              <MarkerPopup item={item} onViewEvidence={onViewEvidence} />
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </Box>
  );
}

interface MarkerPopupProps {
  item: InvestigationGeolocation;
  onViewEvidence: (evidenceId: string) => void;
}

/** One marker popup: exact IP and available approximate context. */
function MarkerPopup({ item, onViewEvidence }: MarkerPopupProps): ReactElement {
  const { t } = useTranslation("geolocation");
  const label = locationLabel(item) ?? t("location.unavailable");
  const precisionKey = geoPrecisionKey(item.precision);
  const providerKey = providerLabelKey(item.provider);
  return (
    <Box sx={{ minWidth: 200 }}>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {item.ip_address}
      </Typography>
      <Typography variant="body2">{label}</Typography>
      <Typography variant="caption" component="div" sx={{ mt: 0.25 }}>
        {t("popup.precision", { precision: t(precisionKey) })}
      </Typography>
      <Typography variant="caption" component="div">
        {t("popup.provider", {
          provider: providerKey !== null ? t(providerKey) : item.provider,
        })}
      </Typography>
      <Typography variant="caption" component="div">
        {t("popup.retrieved", { time: formatDateTime(item.retrieved_at) })}
      </Typography>
      {item.observed_at !== null ? (
        <Typography variant="caption" component="div">
          {t("popup.observed", { time: formatDateTime(item.observed_at) })}
        </Typography>
      ) : null}
      <Button
        size="small"
        variant="outlined"
        onClick={() => onViewEvidence(item.evidence_id)}
        sx={{ mt: 0.5, textTransform: "none" }}
      >
        {t("popup.viewEvidence")}
      </Button>
      <Box sx={{ mt: 0.5 }}>
        <GeolocationEntityActions item={item} />
      </Box>
    </Box>
  );
}
