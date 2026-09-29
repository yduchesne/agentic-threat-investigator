// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Support presentation query hooks (PR 31F-5 E3).
//
// One loaded Report/Assessment produces exactly ONE bounded resolution
// request: unique support IDs are collected from the artifact's findings,
// resolved once through the batch endpoint, and indexed by ID for the
// presentation layer. There is no per-support HTTP query and no frontend
// N+1.

import { useQuery } from "@tanstack/react-query";

import type { ApiError } from "../api/errors";
import type {
  EvidenceSupportPresentation,
  FindingLike,
  RelationshipObservationSupportPresentation,
  SupportPresentation,
} from "../api/schema-types";
import { resolveSupportPresentations } from "./support-presentations-api";

/** One support presentation indexed by its canonical observation ID. */
export type SupportPresentationLookup = Readonly<
  Record<
    string,
    EvidenceSupportPresentation | RelationshipObservationSupportPresentation
  >
>;

/** Collect the unique support IDs of one loaded artifact's findings. */
export function collectSupportIds(
  findings: readonly FindingLike[],
): { evidenceIds: string[]; relationshipObservationIds: string[] } {
  const evidenceIds = new Set<string>();
  const relationshipObservationIds = new Set<string>();
  for (const finding of findings) {
    for (const support of finding.support) {
      if (support.kind === "evidence" && support.evidence_id !== undefined && support.evidence_id !== null) {
        evidenceIds.add(support.evidence_id);
      } else if (
        support.kind === "relationship_observation" &&
        support.relationship_observation_id !== undefined &&
        support.relationship_observation_id !== null
      ) {
        relationshipObservationIds.add(support.relationship_observation_id);
      }
    }
  }
  return {
    evidenceIds: [...evidenceIds],
    relationshipObservationIds: [...relationshipObservationIds],
  };
}

/** Index a resolved presentation result by canonical observation ID. */
export function indexSupportPresentations(
  result: SupportPresentation,
): SupportPresentationLookup {
  const lookup: Record<
    string,
    EvidenceSupportPresentation | RelationshipObservationSupportPresentation
  > = {};
  for (const item of result.evidence) {
    lookup[item.evidence_observation_id] = item;
  }
  for (const item of result.relationship_observations) {
    lookup[item.relationship_observation_id] = item;
  }
  return lookup as SupportPresentationLookup;
}

/**
 * Read the support presentations of one loaded artifact through exactly one
 * bounded request (enabled while the artifact is present and the request
 * carries at least one ID; an artifact without supports needs no request).
 */
export function useSupportPresentations(
  investigationId: string,
  findings: readonly FindingLike[],
  enabled: boolean,
): {
  presentation: SupportPresentationLookup | null;
  isLoading: boolean;
  isError: boolean;
  error: ApiError | null;
  refetch: () => void;
} {
  const { evidenceIds, relationshipObservationIds } = collectSupportIds(findings);
  const requestEnabled =
    enabled && (evidenceIds.length > 0 || relationshipObservationIds.length > 0);
  const result = useQuery<SupportPresentation, ApiError>({
    queryKey: ["support-presentations", investigationId, evidenceIds, relationshipObservationIds],
    queryFn: () =>
      resolveSupportPresentations(
        investigationId,
        evidenceIds,
        relationshipObservationIds,
      ),
    enabled: requestEnabled,
    staleTime: 60_000,
  });
  const presentation =
    result.data === undefined || result.data === null
      ? null
      : indexSupportPresentations(result.data);
  return {
    presentation,
    isLoading: result.isLoading,
    isError: result.isError,
    error: result.error ?? null,
    refetch: () => void result.refetch(),
  };
}
