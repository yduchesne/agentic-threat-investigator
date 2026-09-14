// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Graph pure derived model (PR 24E §22, §24, §63-73).
//
// The graph is a bounded one-hop visualization of stable Relationships
// currently known to ATI for one focal entity in one Investigation. Nodes
// and edges are navigation aids backed by exact Entity/Relationship IDs;
// nothing here discovers edges, infers hidden relationships, scores
// maliciousness, or represents temporal validity.

import type {
  Relationship,
  RelationshipTypeName,
} from "../api/schema-types";

/** One graph node backed by an exact Entity ID. */
export interface RelationshipGraphNode {
  entityId: string;
  role: "focal" | "counterparty";
  /** Bounded analyst-facing label (compact ID unless a free value is
   * already present in the DTO — never an N+1 Entity resolution). */
  label: string;
}

/** One graph edge backed by an exact Relationship ID. */
export interface RelationshipGraphEdge {
  relationshipId: string;
  sourceEntityId: string;
  targetEntityId: string;
  relationshipType: RelationshipTypeName;
}

/** The bounded one-hop graph model of one loaded Relationships page. */
export interface RelationshipGraphModel {
  focal: RelationshipGraphNode;
  counterparties: readonly RelationshipGraphNode[];
  edges: readonly RelationshipGraphEdge[];
  /** True when a self-loop edge exists (focal -> focal). */
  hasSelfEdge: boolean;
}

/** Short stable compact entity label ("Entity a1b2c3d4…"). */
export function graphEntityLabel(entityId: string): string {
  return `Entity ${entityId.slice(0, 8)}`;
}

/**
 * Build the one-hop graph model from one bounded page.
 *
 * Counterparties are deduplicated by exact Entity ID (deterministically
 * sorted); a self-relationship produces exactly one self-loop edge and
 * never duplicates the focal node. Multiple relationship types between the
 * same entity pair stay distinct edges.
 */
export function buildGraphModel(
  focalEntityId: string,
  relationships: readonly Relationship[],
): RelationshipGraphModel {
  const counterpartyIds = new Map<string, RelationshipGraphNode>();
  const edges: RelationshipGraphEdge[] = [];
  let hasSelfEdge = false;

  for (const relationship of relationships) {
    edges.push({
      relationshipId: relationship.id,
      sourceEntityId: relationship.source_entity_id,
      targetEntityId: relationship.target_entity_id,
      relationshipType: relationship.type,
    });
    if (
      relationship.source_entity_id === focalEntityId &&
      relationship.target_entity_id === focalEntityId
    ) {
      hasSelfEdge = true;
      continue;
    }
    const counterparty =
      relationship.source_entity_id === focalEntityId
        ? relationship.target_entity_id
        : relationship.source_entity_id;
    if (counterparty === focalEntityId) {
      continue;
    }
    if (!counterpartyIds.has(counterparty)) {
      counterpartyIds.set(counterparty, {
        entityId: counterparty,
        role: "counterparty",
        label: graphEntityLabel(counterparty),
      });
    }
  }

  const counterparties = [...counterpartyIds.values()].sort((a, b) =>
    a.entityId < b.entityId ? -1 : a.entityId > b.entityId ? 1 : 0,
  );

  return {
    focal: {
      entityId: focalEntityId,
      role: "focal",
      label: graphEntityLabel(focalEntityId),
    },
    counterparties,
    edges,
    hasSelfEdge,
  };
}