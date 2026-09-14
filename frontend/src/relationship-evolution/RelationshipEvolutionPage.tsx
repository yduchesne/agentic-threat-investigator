// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution first-class route (PR 24E §9).
//
//   /investigations/:id/relationships/evolution
//     ?entity_id=<uuid>              required focal entity
//     &direction/relationship_type/counterparty_entity_id/source/
//      observed_from/observed_to     semantic filters (URL-backed)
//     &cursor=<opaque>               bounded keyset continuation
//     &view=evolution|graph          workspace view switch
//
// The route is refreshable and shareable within the deployment; the URL is
// the only owned state. ``view=graph`` shares the same URL space so
// Evolution/Graph switching always preserves focal entity and filters.

import type { ReactElement } from "react";
import { useOutletContext, useParams } from "react-router";

import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import { RelationshipEvolutionWorkspace } from "./RelationshipEvolutionWorkspace";

/** The Relationship Evolution first-class route. */
export function RelationshipEvolutionPage(): ReactElement {
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  return (
    <RelationshipEvolutionWorkspace
      investigationId={investigationId}
      investigation={investigation}
    />
  );
}