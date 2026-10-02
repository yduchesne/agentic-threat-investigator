// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph-route context codec (PR 31G).
//
// The committed graph context has exactly one authority: the Graph route's
// URL search parameters. Scope/filter state is reconstructible from the URL
// so refresh and browser Back/Forward reproduce the same request; no second
// durable filter store exists. Draft form state is browser-local only and
// never drives graph requests before Apply. The graph uses its own
// ``graph_*`` query parameters so it never collides with the Evolution view's
// observation filters that share the same focused route.
//
//   graph_scope=investigation|known            (absent = investigation)
//   graph_entity_type=<EntityType>
//   graph_relationship_type=<RelationshipType>
//   graph_source=<exact RelationshipObservation source>
//   graph_observed_from=<ISO>&graph_observed_to=<ISO>
//   graph_depth=2|3                              (absent/1 = depth 1)
//
// Unrelated URL parameters are preserved; a malformed enum/timestamp value
// is canonicalized away rather than sent to the API.

import type {
  EntityTypeName,
  GraphScopeName,
  RelationshipTypeName,
} from "../api/schema-types";
import {
  applyFilterParams,
  parseEnumParam,
  parseTimestampParam,
} from "../analyst-table/filters";
import { RELATIONSHIP_TYPES } from "../relationships/labels";

/** The exactly-two graph scopes (Investigation default). */
export const GRAPH_SCOPES: readonly GraphScopeName[] = ["investigation", "known"];

/** The exactly three committed traversal depths (1 = one-hop default). */
export const GRAPH_DEPTHS: readonly [1, 2, 3] = [1, 2, 3];

/** The canonical committed graph depth (hop distance from the focal). */
export type GraphDepth = 1 | 2 | 3;

/** The canonical connected/counterparty Entity types offered as filters. */
export const GRAPH_ENTITY_TYPES: readonly EntityTypeName[] = [
  "domain",
  "ip_address",
  "url",
  "network_prefix",
  "asn",
  "organization",
  "malware",
  "attack_technique",
  "vulnerability",
];

/** The graph-owned URL search parameters (all ``graph_*`` except none else). */
export const GRAPH_CONTEXT_PARAMS = [
  "graph_scope",
  "graph_entity_type",
  "graph_relationship_type",
  "graph_source",
  "graph_observed_from",
  "graph_observed_to",
  "graph_depth",
] as const;

/** The committed graph context (Investigation + no filters + depth 1 = default). */
export interface GraphContext {
  scope: GraphScopeName;
  entityType: EntityTypeName | undefined;
  relationshipType: RelationshipTypeName | undefined;
  source: string | undefined;
  observedFrom: string | undefined;
  observedTo: string | undefined;
  /** PR 31H: hop distance from the focal; 1 = the one-hop neighborhood. */
  depth: GraphDepth;
}

/** The neutral graph context: Investigation scope, no optional filters. */
export function emptyGraphContext(): GraphContext {
  return {
    scope: "investigation",
    entityType: undefined,
    relationshipType: undefined,
    source: undefined,
    observedFrom: undefined,
    observedTo: undefined,
    depth: 1,
  };
}

/** Parse one committed depth; absent/malformed/out-of-range values are 1. */
export function parseGraphDepth(value: string | null): GraphDepth {
  if (value === null) {
    return 1;
  }
  const parsed = parseInt(value, 10);
  return parsed === 2 || parsed === 3 ? (parsed as GraphDepth) : 1;
}

/**
 * Parse the committed graph context off one URL parameter set.
 *
 * An absent scope is Investigation; a malformed enum/timestamp value
 * canonicalizes to absence so it is never presented or sent as a valid API
 * value. Whitespace-only sources normalize to absence.
 */
export function parseGraphContext(params: URLSearchParams): GraphContext {
  return {
    scope: parseEnumParam(params.get("graph_scope"), GRAPH_SCOPES) ?? "investigation",
    entityType: parseEnumParam(params.get("graph_entity_type"), GRAPH_ENTITY_TYPES),
    relationshipType: parseEnumParam(
      params.get("graph_relationship_type"),
      RELATIONSHIP_TYPES,
    ),
    source: nonBlank(params.get("graph_source")),
    observedFrom: parseTimestampParam(params.get("graph_observed_from")),
    observedTo: parseTimestampParam(params.get("graph_observed_to")),
    depth: parseGraphDepth(params.get("graph_depth")),
  };
}

/**
 * Apply one committed graph context over the URL parameter set.
 *
 * The default Investigation scope is omitted for canonical URL minimalism
 * (parsing restores it); every absent optional filter removes its
 * parameter; all unrelated URL parameters are preserved.
 */
export function applyGraphContext(
  params: URLSearchParams,
  context: GraphContext,
): URLSearchParams {
  return applyFilterParams(params, GRAPH_CONTEXT_PARAMS, {
    graph_scope: context.scope === "investigation" ? undefined : context.scope,
    graph_entity_type: context.entityType,
    graph_relationship_type: context.relationshipType,
    graph_source: context.source,
    graph_observed_from: context.observedFrom,
    graph_observed_to: context.observedTo,
    graph_depth: context.depth === 1 ? undefined : String(context.depth),
  });
}

/** Whether any optional graph filter beyond the scope is active. */
export function graphContextActive(context: GraphContext): boolean {
  return (
    context.entityType !== undefined ||
    context.relationshipType !== undefined ||
    context.source !== undefined ||
    context.observedFrom !== undefined ||
    context.observedTo !== undefined
  );
}

/** Whether the committed depth is beyond the default one-hop (PR 31H). */
export function graphDepthActive(context: GraphContext): boolean {
  return context.depth !== 1;
}

/** Canonical committed-context identity (URL resync + expansion reset). */
export function graphContextKey(context: GraphContext): string {
  return JSON.stringify([
    context.scope,
    context.entityType ?? null,
    context.relationshipType ?? null,
    context.source ?? null,
    context.observedFrom ?? null,
    context.observedTo ?? null,
    context.depth,
  ]);
}

/** Whether two committed graph contexts are identical. */
export function graphContextEqual(a: GraphContext, b: GraphContext): boolean {
  return graphContextKey(a) === graphContextKey(b);
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string | null): string | undefined {
  if (value === null) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}
