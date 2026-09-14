// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationships workspace route (PR 24C §9; PR 24D §10).
//
// Route adapter over the shared Relationships workspace content: it owns
// the route params/outlet and the live router-backed resource table
// controller. The PR 24D pivot modal embeds the same workspace through
// the pivot-step port.

import type { ReactElement } from "react";
import { useOutletContext, useParams } from "react-router";

import { useResourceTable } from "../analyst-table/resource-page";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import type { RelationshipFilters } from "./relationships-filters";
import {
  emptyRelationshipFilters,
  parseRelationshipFilters,
  relationshipFiltersToParams,
} from "./relationships-filters";
import { RelationshipsWorkspace } from "./RelationshipsWorkspace";

/** The Relationships workspace route. */
export function RelationshipsPage(): ReactElement {
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<RelationshipFilters>({
    parse: parseRelationshipFilters,
    toParams: relationshipFiltersToParams,
    empty: emptyRelationshipFilters,
  });

  return (
    <RelationshipsWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
    />
  );
}

export { RelationshipsWorkspace, RelationshipFiltersForm, relationshipColumns } from "./RelationshipsWorkspace";