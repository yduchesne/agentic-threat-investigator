// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical graph-neighborhood query keys (PR 31D).
//
// The key contains every semantic input of the graph request
// (investigation, focal Entity, direction, relationship type, limit) and
// never layout or selection state: coordinates, drag positions and the
// current node/edge selection are browser-only presentation and must not
// affect server-state caching.

import type {
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";

/** Query key for one bounded investigation-scoped one-hop neighborhood. */
export function graphNeighborhoodKey(
  investigationId: string,
  entityId: string,
  direction: RelationshipDirectionName,
  relationshipType: RelationshipTypeName | undefined,
  limit: number,
): unknown[] {
  return [
    "graph",
    investigationId,
    "neighborhood",
    entityId,
    direction,
    relationshipType ?? null,
    limit,
  ];
}
