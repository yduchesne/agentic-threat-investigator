// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence workspace route (PR 24C §2, §8, §14-§17; PR 24D §10).
//
// Route adapter over the shared Evidence workspace content: it owns the
// route params/outlet and the live router-backed resource table controller.
// The PR 24D pivot modal embeds the same EvidenceWorkspace through the
// pivot-step port, so no second Evidence table/query architecture exists.

import type { ReactElement } from "react";
import { useOutletContext, useParams } from "react-router";

import { useResourceTable } from "../analyst-table/resource-page";
import type { WorkspaceOutletContext } from "../investigations/InvestigationWorkspace";
import type { EvidenceFilters } from "./evidence-filters";
import {
  emptyEvidenceFilters,
  evidenceFiltersToParams,
  parseEvidenceFilters,
} from "./evidence-filters";
import { EvidenceWorkspace } from "./EvidenceWorkspace";

/** The Evidence workspace route. */
export function EvidencePage(): ReactElement {
  const { investigationId = "" } = useParams();
  const { investigation } = useOutletContext<WorkspaceOutletContext>();

  const table = useResourceTable<EvidenceFilters>({
    parse: parseEvidenceFilters,
    toParams: evidenceFiltersToParams,
    empty: emptyEvidenceFilters,
  });

  return (
    <EvidenceWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
    />
  );
}

export { EvidenceWorkspace, EvidenceFiltersForm, evidenceColumns } from "./EvidenceWorkspace";