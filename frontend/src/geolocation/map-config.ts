// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central basemap tile policy (PR 25B §6).
//
// One map configuration/constants module: the standard OpenStreetMap raster
// tiles are presentation context only — free, credential-free, and never an
// ATI data source. The attribution string is the OSM-required attribution
// and is rendered by Leaflet itself. No secret, proxy, or backend tile
// persistence exists anywhere in the repository.

/** Free OSM raster tile URL template (no API key, no credentials). */
export const TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";

/** The required OSM attribution, rendered by Leaflet's attribution control. */
export const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';

/** Explicit responsive map height within the Investigation workspace. */
export const MAP_HEIGHT_PX = 460;