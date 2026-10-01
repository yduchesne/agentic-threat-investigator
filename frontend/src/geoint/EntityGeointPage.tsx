// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Routed Entity GEOINT page (PR 31F-8 §10).
//
// ``/investigations/:id/geoint/entities/:entityId`` is the canonical
// Entity GEOINT surface: current context + pageable history. The canonical
// Entity ID is path identity (labels are presentation only); the opaque
// history cursor stays a query parameter. Direct deep links and refresh
// reconstruct from path/query alone; Back/Forward restores prior routed
// surfaces through the browser history. No local detail replacement exists.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { useParams } from "react-router";

import { parseUuidParam } from "../analyst-table/filters";
import type { ResourceFilterCodec } from "../analyst-table/resource-page";
import { useResourceTable } from "../analyst-table/resource-page";
import { entityCompactLabel } from "../pivots/pivot-capabilities";
import { EntityGeointView } from "./EntityGeointView";
import { GeointBreadcrumbs } from "./GeointBreadcrumbs";
import type { GeointEntityFilters } from "./geoint-filters";
import { emptyGeointEntityFilters } from "./geoint-filters";

/** The canonical routed Entity GEOINT surface. */
export function EntityGeointPage(): ReactElement {
  const { t } = useTranslation("geoint");
  const { investigationId = "", entityId = "" } = useParams();

  // Path-owned identity: the entity_id filter is derived from the route,
  // never from the query; the table controller keeps only the history
  // cursor (and selection bookkeeping) in the URL.
  const validEntityId = parseUuidParam(entityId) ?? undefined;
  const codec: ResourceFilterCodec<GeointEntityFilters> = {
    parse: () => ({ entityId: validEntityId }),
    toParams: (params) => params,
    empty: () => ({ ...emptyGeointEntityFilters(), entityId: validEntityId }),
  };
  const table = useResourceTable<GeointEntityFilters>(codec);

  return (
    <div>
      <GeointBreadcrumbs
        investigationId={investigationId}
        crumbs={[
          {
            key: "entity",
            label:
              validEntityId !== undefined
                ? entityCompactLabel(validEntityId)
                : t("resources.entityUnknown"),
          },
        ]}
      />
      <EntityGeointView investigationId={investigationId} table={table} />
    </div>
  );
}
