// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Routed Location Observations page (PR 31F-8 §10).
//
// ``/investigations/:id/geoint/locations/:locationId/observations`` is the
// canonical Location -> observations surface. The canonical Location ID is
// path identity; the server-owned containment flag and the opaque cursor
// stay query parameters. Reuses the existing LocationObservationsView — no
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
import { LocationObservationsView } from "./LocationViews";

/** The canonical routed Location -> observations surface. */
export function LocationObservationsPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "", locationId = "" } = useParams();
  const location = useLocation();

  const validLocationId = parseUuidParam(locationId) ?? undefined;
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
          { key: "observations", label: t("location.observations.title") },
        ]}
      />
      <LocationObservationsView investigationId={investigationId} table={table} />
    </div>
  );
}
