// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Research workspace route (PR 24C §10; PR 24D §10).
//
// Route adapter over the shared Research workspace content (see
// ResearchWorkspace.tsx); the PR 24D pivot modal embeds the same workspace
// through the pivot-step port.

import type { ReactElement } from "react";
import { useOutletContext, useParams } from "react-router";

import { useResourceTable } from "../analyst-table/resource-page";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import type { ResearchFilters } from "./research-filters";
import {
  emptyResearchFilters,
  parseResearchFilters,
  researchFiltersToParams,
} from "./research-filters";
import { ResearchWorkspace } from "./ResearchWorkspace";

/** The Research workspace. */
export function ResearchPage(): ReactElement {
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<ResearchFilters>({
    parse: parseResearchFilters,
    toParams: researchFiltersToParams,
    empty: emptyResearchFilters,
  });

  return (
    <ResearchWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
    />
  );
}

export { ResearchWorkspace, ResearchFiltersForm, researchColumns } from "./ResearchWorkspace";