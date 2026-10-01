// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph-neighborhood API boundary (PR 31D; PR 31G).
//
// The Graph view is a faithful, read-only client of the PR 31C endpoint:
//
//   GET /investigations/{investigation_id}/graph/entities/{entity_id}/neighborhood
//
// Only the directed one-hop neighborhood is requested: ``direction``,
// ``scope``, the canonical filters (connected Entity type, Relationship
// type, exact observation source, half-open observed interval) and the
// bounded ``limit`` map exactly onto the canonical query parameters. No
// cursor, depth, retrieval-time, or counterparty-identity filters are ever
// sent, and topology is never reconstructed from a Relationships page. The
// request is Investigation- and Entity-scoped, bounded at the browser, and
// funneled through the centralized api client with AbortSignal support.

import { apiGet } from "../api/client";
import type {
  EntityTypeName,
  GraphNeighborhood,
  GraphScopeName,
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";

/** Explicit bounded browser graph-neighborhood limit (PR 24E graph-era bound). */
export const GRAPH_NEIGHBORHOOD_LIMIT = 25;

/** Every semantic graph-request input except direction and bound. */
export interface GraphRequestContext {
  scope: GraphScopeName;
  entityType: EntityTypeName | undefined;
  relationshipType: RelationshipTypeName | undefined;
  source: string | undefined;
  observedFrom: string | undefined;
  observedTo: string | undefined;
}

/**
 * Load the bounded one-hop neighborhood of one focal Entity.
 *
 * ``direction`` is relative to the focal Entity and always sent (the
 * backend defaults to ``either``); ``context`` carries the committed graph
 * scope and every optional filter (only defined values are sent);
 * ``limit`` keeps the browser request bounded. The response is one atomic
 * ``GraphNeighborhood`` with a truthful ``truncated`` flag and never a
 * cursor page.
 */
export async function fetchGraphNeighborhood(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  context: GraphRequestContext,
  limit: number = GRAPH_NEIGHBORHOOD_LIMIT,
  signal?: AbortSignal,
): Promise<GraphNeighborhood> {
  const query = new URLSearchParams();
  query.set("direction", direction);
  query.set("scope", context.scope);
  if (context.entityType !== undefined) {
    query.set("entity_type", context.entityType);
  }
  if (context.relationshipType !== undefined) {
    query.set("relationship_type", context.relationshipType);
  }
  if (context.source !== undefined) {
    query.set("source", context.source);
  }
  if (context.observedFrom !== undefined) {
    query.set("observed_from", context.observedFrom);
  }
  if (context.observedTo !== undefined) {
    query.set("observed_to", context.observedTo);
  }
  query.set("limit", String(limit));
  const qs = query.toString();
  return apiGet<GraphNeighborhood>(
    `/investigations/${investigationId}/graph/entities/${entityId}/neighborhood${qs ? `?${qs}` : ""}`,
    signal,
  );
}
