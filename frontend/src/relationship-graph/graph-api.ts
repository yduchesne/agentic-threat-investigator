// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph-neighborhood API boundary (PR 31D).
//
// The Graph view is a faithful, read-only client of the PR 31C endpoint:
//
//   GET /investigations/{investigation_id}/graph/entities/{entity_id}/neighborhood
//
// Only the directed one-hop neighborhood is requested: ``direction``,
// ``relationship_type`` and ``limit`` map exactly onto the canonical query
// parameters. No cursor, depth, observed/retrieved dates, source, or
// counterparty filters are ever sent, and topology is never reconstructed
// from a Relationships page. The request is Investigation- and
// Entity-scoped, bounded at the browser with an explicit limit, and
// funneled through the centralized api client with AbortSignal support.

import { apiGet } from "../api/client";
import type {
  GraphNeighborhood,
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";

/** Explicit bounded browser graph-neighborhood limit (PR 24E graph-era bound). */
export const GRAPH_NEIGHBORHOOD_LIMIT = 25;

/**
 * Load the bounded one-hop neighborhood of one focal Entity.
 *
 * ``direction`` is relative to the focal Entity and always sent (the
 * backend defaults to ``either``); ``relationship_type`` is sent only when
 * defined; ``limit`` keeps the browser request bounded. The response is one
 * atomic ``GraphNeighborhood`` with a truthful ``truncated`` flag and never
 * a cursor page.
 */
export async function fetchGraphNeighborhood(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  relationshipType: RelationshipTypeName | undefined,
  limit: number = GRAPH_NEIGHBORHOOD_LIMIT,
  signal?: AbortSignal,
): Promise<GraphNeighborhood> {
  const query = new URLSearchParams();
  query.set("direction", direction);
  if (relationshipType !== undefined) {
    query.set("relationship_type", relationshipType);
  }
  query.set("limit", String(limit));
  const qs = query.toString();
  return apiGet<GraphNeighborhood>(
    `/investigations/${investigationId}/graph/entities/${entityId}/neighborhood${qs ? `?${qs}` : ""}`,
    signal,
  );
}
