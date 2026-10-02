// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph query keys (PR 31D; PR 31G; PR 31H).
//
// The keys contain every semantic input of the graph request (investigation,
// focal Entity, direction, scope, connected Entity type, Relationship type,
// observation source, observed interval, committed depth, limit) and never
// layout or selection state: coordinates, drag positions and the current
// node/edge selection are browser-only presentation and must not affect
// server-state caching. The traversal key is deliberately distinct from the
// one-hop neighborhood key so the two server operations can never share a
// cache entry.

import type { RelationshipDirectionName } from "../api/schema-types";
import type { GraphContext } from "./graph-context-url";

/** Query key for one bounded scoped one-hop neighborhood (depth 1). */
export function graphNeighborhoodKey(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  context: GraphContext,
  limit: number,
): unknown[] {
  return [
    "graph",
    investigationId,
    "neighborhood",
    entityId,
    direction,
    context.scope,
    context.entityType ?? null,
    context.relationshipType ?? null,
    context.source ?? null,
    context.observedFrom ?? null,
    context.observedTo ?? null,
    context.depth,
    limit,
  ];
}

/** Query key for one bounded multi-hop traversal (PR 31H, depth 2/3). */
export function graphTraversalKey(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  context: GraphContext,
  limit: number,
): unknown[] {
  return [
    "graph",
    investigationId,
    "traversal",
    entityId,
    direction,
    context.scope,
    context.entityType ?? null,
    context.relationshipType ?? null,
    context.source ?? null,
    context.observedFrom ?? null,
    context.observedTo ?? null,
    context.depth,
    limit,
  ];
}

/**
 * Query key for one bounded path-finding result (PR 31I).
 *
 * The key contains every semantic input of the path request: Investigation
 * ID, both canonical endpoint Entity IDs, direction, the committed graph
 * context (scope + every optional filter, but NOT the committed traversal
 * depth: path finding has its own bounded max depth/path count) and both
 * path-owned bounds. It is deliberately distinct from the neighborhood and
 * traversal keys so a path result can never share a cache entry with either
 * topology request.
 */
export function graphPathKey(
  investigationId: string,
  sourceEntityId: string,
  targetEntityId: string,
  direction: RelationshipDirectionName,
  context: GraphContext,
  maxDepth: number,
  maxPaths: number,
): unknown[] {
  return [
    "graph",
    investigationId,
    "paths",
    sourceEntityId,
    targetEntityId,
    direction,
    context.scope,
    context.entityType ?? null,
    context.relationshipType ?? null,
    context.source ?? null,
    context.observedFrom ?? null,
    context.observedTo ?? null,
    maxDepth,
    maxPaths,
  ];
}
