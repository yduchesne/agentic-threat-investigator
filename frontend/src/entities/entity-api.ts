// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical Investigation-scoped Entity exact-read boundary (PR 35-8).
//
// ATI already exposes exactly one Investigation-scoped, canonical Entity
// projection: the focal node of the PR 31C graph neighborhood. The endpoint
// returns the request Entity as a node whenever it is valid/visible for the
// Investigation (including an isolated focal Entity with zero edges), so the
// focal indicator and the generic Entity details surface reuse it instead of
// inferring a value/type from graph/list/observation rows. The request is
// deliberately minimal and context-free: Investigation scope, ``either``
// direction and a one-edge bound, because focal presentation must not depend
// on any graph filter or on the graph view being active.

import { ApiError } from "../api/errors";
import type { EntityTypeName, GraphNeighborhood } from "../api/schema-types";
import { isNotFound404 } from "../analyst-table/detail-error";
import { fetchGraphNeighborhood } from "../relationship-graph/graph-api";

/** The bounded edge limit for the exact focal Entity read (focal always included). */
export const ENTITY_DETAIL_LIMIT = 1;

/** One canonical Entity projection (value/type/display name, exact UUID). */
export interface EntityDetail {
  entityId: string;
  entityType: EntityTypeName;
  value: string;
  displayName: string | null;
}

/**
 * Project the canonical focal Entity out of one graph-neighborhood payload.
 *
 * The server guarantees the request Entity as a node on every successful
 * response (including an isolated focal Entity with zero edges), so a graph
 * view that already holds the neighborhood can present the focal Entity
 * without a second read; the projection is a direct server copy and never an
 * inference from edges. Returns ``null`` when no node matches (which the
 * server contract never produces for a successful scoped read).
 */
export function entityDetailFromNeighborhood(
  neighborhood: GraphNeighborhood,
  entityId: string,
): EntityDetail | null {
  const node = neighborhood.nodes.find(
    (candidate) => candidate.entity_id === entityId,
  );
  if (node === undefined) {
    return null;
  }
  return {
    entityId: node.entity_id,
    entityType: node.entity_type,
    value: node.value,
    displayName: node.display_name ?? null,
  };
}

/**
 * Load one canonical Investigation-scoped Entity by its UUID.
 *
 * Returns the exact server Entity projection, or ``null`` when the scoped
 * read reports the Entity as not found/not accessible (a bounded outcome,
 * never a fabricated value). Transport, server and unexpected failures keep
 * propagating as typed :class:`ApiError` values so callers can offer a
 * bounded retry.
 */
export async function fetchEntityDetail(
  investigationId: string,
  entityId: string,
  signal?: AbortSignal,
): Promise<EntityDetail | null> {
  try {
    const neighborhood = await fetchGraphNeighborhood(
      investigationId,
      entityId,
      "either",
      {
        scope: "investigation",
        entityType: undefined,
        relationshipType: undefined,
        source: undefined,
        observedFrom: undefined,
        observedTo: undefined,
      },
      ENTITY_DETAIL_LIMIT,
      signal,
    );
    const node = entityDetailFromNeighborhood(neighborhood, entityId);
    return node;
  } catch (error) {
    if (error instanceof ApiError && isNotFound404(error)) {
      return null;
    }
    throw error;
  }
}
