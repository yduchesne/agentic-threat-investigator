// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation geolocation API boundary (PR 25A / PR 25B).
//
// All traffic funnels through the PR 24A centralized client. The call is
// exactly the PR 25A Investigation-scoped read: no query parameters, no
// cursor, no caller-controlled limit, no Evidence-list request, and no
// provider call. The server owns the projection bound; the browser never
// reconstructs the map from another endpoint.

import { apiGet } from "../api/client";
import type { InvestigationGeolocationCollection } from "../api/schema-types";

/**
 * Load one Investigation's bounded current geolocation projection.
 *
 * The exact PR 25A path is called with no query parameters. The
 * `AbortSignal` (TanStack Query cancellation) is forwarded unchanged and a
 * normal typed `ApiError` propagates on failure.
 */
export async function fetchInvestigationGeolocations(
  investigationId: string,
  signal?: AbortSignal,
): Promise<InvestigationGeolocationCollection> {
  return apiGet<InvestigationGeolocationCollection>(
    `/investigations/${investigationId}/geolocations`,
    signal,
  );
}