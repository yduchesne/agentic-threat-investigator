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
  GraphPathResult,
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

/** Every semantic traversal input except direction and bound. */
export interface GraphTraversalContext extends GraphRequestContext {
  maxDepth: 1 | 2 | 3;
}

/** Every semantic path input: committed context + path-owned bounds. */
export interface GraphPathRequestContext extends GraphRequestContext {
  maxDepth: number;
  maxPaths: number;
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

/**
 * Load the bounded multi-hop traversal of one focal Entity (PR 31H).
 *
 * The dedicated traversal endpoint returns the same atomic
 * ``GraphNeighborhood`` wire vocabulary (canonical nodes/edges and a
 * truthful ``truncated`` flag) with ``max_depth`` hops from the focal
 * Entity. ``context`` carries the committed scope, every optional filter and
 * the committed depth (2 or 3); ``direction`` is relative to the focal
 * Entity and always sent. The request is Investigation- and Entity-scoped,
 * bounded at the browser and funneled through the centralized api client
 * with AbortSignal support.
 */
export async function fetchGraphTraversal(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  context: GraphTraversalContext,
  limit: number = GRAPH_NEIGHBORHOOD_LIMIT,
  signal?: AbortSignal,
): Promise<GraphNeighborhood> {
  const query = new URLSearchParams();
  query.set("direction", direction);
  query.set("scope", context.scope);
  query.set("max_depth", String(context.maxDepth));
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
    `/investigations/${investigationId}/graph/entities/${entityId}/traversal${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** Frontend default path depth/count sent when the analyst chose no bound. */
export const GRAPH_PATH_DEFAULT_MAX_DEPTH = 4;
export const GRAPH_PATH_DEFAULT_MAX_PATHS = 10;

export const GRAPH_PATH_MAX_DEPTH = 6;
export const GRAPH_PATH_MAX_PATHS = 25;

/**
 * Request bounded deterministic simple paths between two Entities (PR 31I).
 *
 * ``sourceEntityId`` / ``targetEntityId`` are canonical Entity IDs from the
 * graph UI (never free-form UUID input); ``context`` carries the committed
 * graph scope/filters plus the path-owned bounded depth/path count; every
 * optional filter and the bounds are sent explicitly and the response reuses
 * the canonical node/edge vocabulary plus reference-only ordered paths.
 * ``paths`` is empty for a visible-but-unconnected pair; a 404 means an
 * endpoint is not visible to the Investigation. The request is
 * Investigation-scoped, bounded at the browser and funneled through the
 * centralized api client with AbortSignal support.
 */
export async function fetchGraphPaths(
  investigationId: string,
  sourceEntityId: string,
  targetEntityId: string,
  direction: RelationshipDirectionName,
  context: GraphPathRequestContext,
  signal?: AbortSignal,
): Promise<GraphPathResult> {
  const query = new URLSearchParams();
  query.set("direction", direction);
  query.set("scope", context.scope);
  query.set("source_entity_id", sourceEntityId);
  query.set("target_entity_id", targetEntityId);
  query.set("max_depth", String(context.maxDepth));
  query.set("max_paths", String(context.maxPaths));
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
  const qs = query.toString();
  return apiGet<GraphPathResult>(
    `/investigations/${investigationId}/graph/paths${qs ? `?${qs}` : ""}`,
    signal,
  );
}
