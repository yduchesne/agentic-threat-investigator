// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Support presentation API boundary (PR 31F-5 E2).
//
// One bounded Investigation-scoped batch resolution per loaded artifact:
// the frontend collects the finite support-ID sets of one Report/Assessment
// and asks once. Per-support GET requests are never issued.

import { apiRequest } from "../api/client";
import type { SupportPresentation } from "../api/schema-types";

/**
 * Resolve one bounded set of Finding support IDs into presentation metadata.
 *
 * The body is the exact finite request shape of
 * ``POST /investigations/{id}/support-presentations/resolve``; responses
 * carry semantic descriptions only (never raw provider payloads).
 */
export async function resolveSupportPresentations(
  investigationId: string,
  evidenceObservationIds: readonly string[],
  relationshipObservationIds: readonly string[],
  signal?: AbortSignal,
): Promise<SupportPresentation> {
  return apiRequest<SupportPresentation>(
    `/investigations/${investigationId}/support-presentations/resolve`,
    {
      method: "POST",
      body: {
        evidence_observation_ids: evidenceObservationIds,
        relationship_observation_ids: relationshipObservationIds,
      },
      signal,
    },
  );
}
