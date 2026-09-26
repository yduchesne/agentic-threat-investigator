// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Canonical Relationship Graph presentation model (PR 31D).
//
// The graph is a bounded one-hop visualization of the PR 31C
// ``GraphNeighborhoodResponse``: Entity nodes and Relationship edges are
// copied exactly from the server (canonical identities, type/value/display
// name for nodes, observation summaries for edges) and rendered without
// inventing missing, reverse, or transitive edges; one Relationship is one
// rendered edge; RelationshipObservations are provenance/temporal support,
// never graph edges. Nothing here infers topology, lifetimes,
// maliciousness, or ownership, and no N+1 Entity resolution happens.

import type {
  EntityTypeName,
  GraphEdge,
  GraphNeighborhood,
  GraphNode,
  RelationshipTypeName,
} from "../api/schema-types";
import type { AccumulatedGraph } from "./graph-expansion-model";

/** One canonical Entity projected as a graph node. */
export interface RelationshipGraphNode {
  entityId: string;
  entityType: EntityTypeName;
  value: string;
  displayName: string | null;
  /** Analyst-facing label: non-empty ``display_name``, else ``value``. */
  label: string;
  /** Focal/counterparty role determined by the request Entity ID. */
  role: "focal" | "counterparty";
}

/** One canonical Relationship projected as a graph edge. */
export interface RelationshipGraphEdge {
  relationshipId: string;
  sourceEntityId: string;
  targetEntityId: string;
  relationshipType: RelationshipTypeName;
  /** Copied exactly from the server; never recomputed client-side. */
  observationCount: number;
  firstObservedAt: string | null;
  lastObservedAt: string | null;
}

/** The bounded one-hop graph model over one GraphNeighborhood. */
export interface RelationshipGraphModel {
  /** Focal node (server node with the request Entity ID). */
  focal: RelationshipGraphNode;
  /** All server nodes, in server order (focal first in practice). */
  nodes: readonly RelationshipGraphNode[];
  /** Non-focal server nodes, in server order. */
  counterparties: readonly RelationshipGraphNode[];
  /** All server edges, in server order (one Relationship = one edge). */
  edges: readonly RelationshipGraphEdge[];
  /** True when a self-loop edge exists (source === target). */
  hasSelfEdge: boolean;
  /** Truthful boundedness flag copied from the server payload. */
  truncated: boolean;
}

/**
 * Build the one-hop graph model from one canonical neighborhood.
 *
 * Every node/edge is copied exactly from the server payload: canonical
 * Entity/Relationship IDs, Entity metadata, edge summaries, server ordering
 * and the ``truncated`` flag are preserved. The focal node is the server
 * node whose ``entity_id`` equals the request Entity ID (never inferred
 * from edge direction); a self-loop contributes one node/one edge and never
 * duplicates the focal node.
 */
export function buildGraphModel(
  focalEntityId: string,
  neighborhood: GraphNeighborhood,
): RelationshipGraphModel {
  const nodes: RelationshipGraphNode[] = neighborhood.nodes.map((node) =>
    projectNode(focalEntityId, node),
  );
  const edges: RelationshipGraphEdge[] = neighborhood.edges.map(projectEdge);
  return assembleGraphModel(focalEntityId, nodes, edges, neighborhood.truncated);
}

/**
 * Build the presentation model from the accumulated expansion graph.
 *
 * The accumulated graph is server-canonical state (PR 31E): the workspace
 * focal Entity stays ``accumulated.rootEntityId`` (expansion never changes
 * the root), accumulated nodes/edges are overlaid in canonical order, and
 * the root truncation flag drives the bounded notice. Per-expansion
 * truncation and success state live in the graph expansion controller, not
 * in this presentation model.
 */
export function buildGraphModelFromAccumulated(
  accumulated: AccumulatedGraph,
): RelationshipGraphModel {
  const nodes: RelationshipGraphNode[] = accumulated.nodes.map((node) =>
    projectNode(accumulated.rootEntityId, node),
  );
  const edges: RelationshipGraphEdge[] = accumulated.edges.map(projectEdge);
  return assembleGraphModel(
    accumulated.rootEntityId,
    nodes,
    edges,
    accumulated.rootTruncated,
  );
}

function projectNode(
  focalEntityId: string,
  node: GraphNode,
): RelationshipGraphNode {
  return {
    entityId: node.entity_id,
    entityType: node.entity_type,
    value: node.value,
    displayName: node.display_name ?? null,
    label: nodeLabel(node.display_name ?? null, node.value),
    role: node.entity_id === focalEntityId ? "focal" : "counterparty",
  };
}

function projectEdge(
  edge: GraphEdge,
): RelationshipGraphEdge {
  return {
    relationshipId: edge.relationship_id,
    sourceEntityId: edge.source_entity_id,
    targetEntityId: edge.target_entity_id,
    relationshipType: edge.relationship_type,
    observationCount: edge.observation_count,
    firstObservedAt: edge.first_observed_at ?? null,
    lastObservedAt: edge.last_observed_at ?? null,
  };
}

function assembleGraphModel(
  focalEntityId: string,
  nodes: readonly RelationshipGraphNode[],
  edges: readonly RelationshipGraphEdge[],
  truncated: boolean,
): RelationshipGraphModel {
  const focal =
    nodes.find((node) => node.entityId === focalEntityId) ??
    // The server guarantees the focal node; this fallback keeps the model
    // total without inventing topology.
    nodes[0];
  const counterparties = nodes.filter((node) => node.entityId !== focalEntityId);
  return {
    focal,
    nodes,
    counterparties,
    edges,
    hasSelfEdge: edges.some(
      (edge) => edge.sourceEntityId === edge.targetEntityId,
    ),
    truncated,
  };
}

/** Analyst-facing node label: non-empty display name, else canonical value. */
export function nodeLabel(displayName: string | null, value: string): string {
  return displayName !== null && displayName.trim() !== "" ? displayName : value;
}
