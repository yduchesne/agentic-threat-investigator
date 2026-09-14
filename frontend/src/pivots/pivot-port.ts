// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot step <-> resource table port (PR 24D §1.1, §7, §9, §10).
//
// The pivot modal reuses the exact PR 24C ``useResourceTable`` controller
// by supplying a search-params port projected from the active pivot step:
// filters/cursor/selection read from the step, commits round-trip back
// through the existing resource filter codecs (authoritative validation)
// and update only the active step. The URL remains the single owned state
// source; no second table/query layer is introduced.

import type { ResourceFilterCodec, SearchParamsPort } from "../analyst-table/resource-page";
import { stepFromSearchParams, stepToSearchParams } from "./pivot-url";
import type { PivotStep } from "./pivot-types";

/** Commit the active step after any table/filter/detail change. */
export type CommitPivotStep = (next: PivotStep, replace: boolean) => void;

/**
 * Build the search-params port for one active pivot step.
 *
 * ``commit`` replaces the active step in the URL-backed stack; the step's
 * own resource/filters/cursor/selection project onto the familiar URL
 * surface the rest of the PR 24C machinery already operates on.
 */
export function createPivotStatePort<F>(
  step: PivotStep,
  codec: ResourceFilterCodec<F>,
  commit: CommitPivotStep,
): SearchParamsPort {
  return {
    get searchParams(): URLSearchParams {
      return stepToSearchParams(step);
    },
    setSearchParams(next: URLSearchParams, options?: { replace?: boolean }): void {
      commit(stepFromSearchParams(step, next), options?.replace ?? false);
    },
  };
}