// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Routed Location Entities page (PR 31F-8 §10).
//
// ``/investigations/:id/geoint/locations/:locationId/entities`` is the
// canonical Location -> Entities surface. The canonical Location ID is
// path identity; the server-owned containment flag and the opaque cursor
// stay query parameters (N19/N20: toggling containment updates the URL and
// refresh restores it). Reuses the existing LocationEntitiesView — no
// routed copy. Direct deep links reconstruct from path/query alone.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import type { ResourceFilterCodec } from "../analyst-table/resource-page";
import { useResourceTable } from "../analyst-table/resource-page";
import { locationCompactLabel } from "../pivots/pivot-capabilities";
import { GeointBreadcrumbs } from "./GeointBreadcrumbs";
import type { GeointLocationFilters } from "./geoint-filters";
import { parseGeointLocationFilters } from "./geoint-filters";
import { LocationEntitiesView } from "./LocationViews";

/** The canonical routed Location -> Entities surface. */
export function LocationEntitiesPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "", locationId = "" } = useParams();
  const location = useLocation();

  const validLocationId = parseUuidParam(locationId) ?? undefined;
  // The navigated canonical label (presentation only) survives while the
  // page is alive; refresh/deep links fall back to the compact identity.
  const navigatedLabel = (location.state as { locationLabel?: string } | null)
    ?.locationLabel;
  const codec: ResourceFilterCodec<GeointLocationFilters> = {
    parse: (params) => ({
      locationId: validLocationId,
      includeContained: parseGeointLocationFilters(params).includeContained,
    }),
    toParams: (params, filters) => {
      const next = new URLSearchParams(params);
      if (filters.includeContained) {
        next.set("include_contained", "true");
      } else {
        next.delete("include_contained");
      }
      return next;
    },
    empty: () => ({ locationId: validLocationId, includeContained: false }),
  };
  const table = useResourceTable<GeointLocationFilters>(codec);

  return (
    <div>
      <GeointBreadcrumbs
        investigationId={investigationId}
        crumbs={[
          {
            key: "location",
            label:
              navigatedLabel ??
              (validLocationId !== undefined
                ? locationCompactLabel(validLocationId)
                : t("resources.locationUnknown")),
          },
          { key: "entities", label: t("location.entities.title") },
        ]}
      />
      <LocationEntitiesView investigationId={investigationId} table={table} />
    </div>
  );
}
