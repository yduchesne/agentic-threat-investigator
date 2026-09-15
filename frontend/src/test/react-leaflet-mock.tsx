// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic react-leaflet rendering mock (PR 25B §43, §49).
//
// Component tests never perform live tile requests and never depend on a
// real layout engine. This module replaces the react-leaflet surface with
// inert labeled elements so tests can assert semantics (marker counts,
// popup content, tile attribution, viewport commands) without Leaflet's
// private DOM. The fake map records the exact deterministic viewport
// commands the application issues. The real Leaflet rendering path is
// exercised by the real-stack browser spec (E24).

import type { ReactElement, ReactNode } from "react";
import { vi } from "vitest";

/** Inert map surface recording viewport commands for assertions. */
export const fakeLeafletMap = {
  fitBounds: vi.fn(),
  setView: vi.fn(),
  invalidateSize: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  remove: vi.fn(),
};

/** Clear every recorded command before one test. */
export function resetFakeLeafletMap(): void {
  for (const spy of Object.values(fakeLeafletMap)) {
    (spy as ReturnType<typeof vi.fn>).mockClear();
  }
}

/** Map container replacement: labeled, inert, children preserved. */
export function MapContainer({
  children,
  bounds,
  center,
  zoom,
}: {
  children?: ReactNode;
  bounds?: unknown;
  center?: unknown;
  zoom?: number;
}): ReactElement {
  return (
    <div
      data-testid="ati-map-container"
      data-bounds={bounds !== undefined ? JSON.stringify(bounds) : undefined}
      data-center={center !== undefined ? JSON.stringify(center) : undefined}
      data-zoom={zoom !== undefined ? String(zoom) : undefined}
    >
      {children}
    </div>
  );
}

/** Tile layer replacement exposing the exact URL/attribution policy. */
export function TileLayer({
  url,
  attribution,
}: {
  url?: string;
  attribution?: string;
}): ReactElement {
  return (
    <div
      data-testid="ati-tile-layer"
      data-url={url ?? ""}
      data-attribution={attribution ?? ""}
    />
  );
}

/** Marker replacement: one labeled element per mappable item. */
export function Marker({
  children,
  position,
  alt,
  title,
}: {
  children?: ReactNode;
  position?: unknown;
  alt?: string;
  title?: string;
}): ReactElement {
  return (
    <div
      data-testid="ati-marker"
      data-position={position !== undefined ? JSON.stringify(position) : undefined}
      data-alt={alt ?? ""}
      data-title={title ?? ""}
    >
      {children}
    </div>
  );
}

/** Popup replacement rendering its children inline. */
export function Popup({ children }: { children?: ReactNode }): ReactElement {
  return <div data-testid="ati-popup">{children}</div>;
}

/** The shared inert map instance. */
export function useMap(): typeof fakeLeafletMap {
  return fakeLeafletMap;
}