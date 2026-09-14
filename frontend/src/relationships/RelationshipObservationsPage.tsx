// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// First-class RelationshipObservation route (PR 24C §9; PR 24D §10).
//
// Route adapter over the shared RelationshipObservations workspace content
// (see RelationshipObservationsWorkspace.tsx); the PR 24D pivot modal
// embeds the same workspace through the pivot-step port.

import type { ReactElement } from "react";
import { useOutletContext, useParams } from "react-router";

import { useResourceTable } from "../analyst-table/resource-page";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import type { ObservationFilters } from "./relationships-filters";
import {
  emptyObservationFilters,
  observationFiltersToParams,
  parseObservationFilters,
} from "./relationships-filters";
import { RelationshipObservationsWorkspace } from "./RelationshipObservationsWorkspace";

/** The first-class RelationshipObservations route. */
export function RelationshipObservationsPage(): ReactElement {
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<ObservationFilters>({
    parse: parseObservationFilters,
    toParams: observationFiltersToParams,
    empty: emptyObservationFilters,
  });

  return (
    <RelationshipObservationsWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
    />
  );
}

export {
  RelationshipObservationsWorkspace,
  ObservationFiltersForm,
  observationColumns,
} from "./RelationshipObservationsWorkspace";