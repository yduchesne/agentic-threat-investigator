// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Routed exact-detail helpers (PR 31F-8 §10).
//
// The exact detail routes (``/evidence/:evidenceId``, ``/relationships/
// :relationshipId``, ``/relationships/observations/:observationId``) carry
// the reconstructible list query state so the semantic Back link restores
// the same filter/cursor context without any in-memory survival. Only the
// allowlisted resource filter keys (plus the opaque cursor) are preserved;
// selection/other bookkeeping never round-trips through the list URL.

/** The opaque cursor parameter preserved on routed Back links. */
export const ROUTE_LIST_PARAMS = {
  evidence: [
    "source",
    "subject_entity_id",
    "type",
    "retrieved_from",
    "retrieved_to",
    "cursor",
  ] as const,
  relationships: [
    "source_entity_id",
    "target_entity_id",
    "relationship_type",
    "cursor",
  ] as const,
  observations: [
    "relationship_id",
    "source",
    "observed_from",
    "observed_to",
    "retrieved_from",
    "retrieved_to",
    "entity_id",
    "direction",
    "relationship_type",
    "counterparty_entity_id",
    "cursor",
  ] as const,
  research: ["subject_entity_id", "created_from", "created_to", "cursor"] as const,
} as const;

/** Preserve only the listed query keys (canonical order, safe encoding). */
export function preserveListQuery(
  params: URLSearchParams,
  keys: readonly string[],
): URLSearchParams {
  const next = new URLSearchParams();
  for (const key of keys) {
    const value = params.get(key);
    if (value !== null) {
      next.set(key, value);
    }
  }
  return next;
}

/** The canonical list Back destination with preserved query state. */
export function listBackPath(
  base: string,
  params: URLSearchParams,
  keys: readonly string[],
): string {
  const query = preserveListQuery(params, keys).toString();
  return query === "" ? base : `${base}?${query}`;
}
