// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Analyst-driven incremental graph expansion controller (PR 31E).
//
// Owns accumulated graph topology, successful/truncated expansion keys,
// one in-flight expansion, failure/retry state, and the root-semantic
// synchronization rules. Every expansion reuses the existing PR 31C
// one-hop graph fetch (``fetchGraphNeighborhood``): no new API
// abstraction, no cursor iteration, no recursive traversal, no provider
// or Coordinator work. Expansion is read-only exploration of topology
// already admitted to the current Investigation.
//
// Rules (PR 31E §4, §15-§18):
// - one explicit action produces at most one bounded request;
// - one in-flight expansion at a time;
// - an already-completed ``(entity_id, direction)`` expansion never
//   refetches;
// - a successful response merges by canonical Entity/Relationship ID;
// - a failure leaves the accumulated graph untouched and records a retry
//   target;
// - cancellation is not a semantic failure;
// - a root semantic change (investigation/focal/direction/relationship
//   type) aborts and resets accumulated state, and stale late results can
//   never cross into a new root context (generation token + abort).

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  GraphNeighborhood,
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";
import { isAbortError } from "../api/errors";
import { GRAPH_NEIGHBORHOOD_LIMIT, fetchGraphNeighborhood } from "./graph-api";
import {
  emptyAccumulatedGraph,
  expansionKeyMatches,
  mergeNeighborhood,
  overlayRootNeighborhood,
  type AccumulatedGraph,
  type ExpandedNeighborhoodKey,
} from "./graph-expansion-model";

export interface GraphExpansionInputs {
  investigationId: string;
  /** The workspace focal Entity (undefined when no valid focal exists). */
  rootEntityId: string | undefined;
  rootDirection: RelationshipDirectionName;
  relationshipType: RelationshipTypeName | undefined;
  /** The TanStack Query-owned root neighborhood (null while loading). */
  rootNeighborhood: GraphNeighborhood | null;
}

/** The controller surface the graph component consumes. */
export interface GraphExpansionController {
  /** Accumulated canonical topology (null until the root neighborhood loads). */
  graph: AccumulatedGraph | null;
  /** The exact single in-flight expansion key, or null. */
  inFlight: ExpandedNeighborhoodKey | null;
  /** The last failed expansion key (Retry target), or null. */
  failed: ExpandedNeighborhoodKey | null;
  /** Successful expansion keys, in completion order. */
  expanded: readonly ExpandedNeighborhoodKey[];
  /** Successful expansion keys whose response carried ``truncated=true``. */
  truncated: readonly ExpandedNeighborhoodKey[];
  /** The most recent successful expansion (new-node placement anchor). */
  lastExpansion: ExpandedNeighborhoodKey | null;
  /** Explicit analyst action: expand one selected Entity and direction. */
  expand: (entityId: string, direction: RelationshipDirectionName) => void;
  /** Repeat the exact last failed expansion (failure can never be partial). */
  retry: () => void;
  /** Whether an ``(entity_id, direction)`` expansion already completed. */
  isExpanded: (entityId: string, direction: RelationshipDirectionName) => boolean;
}

const EMPTY_EXPANSIONS: readonly ExpandedNeighborhoodKey[] = [];

/** Root semantic context identity (expansion state resets on any change). */
function rootContextKey(
  investigationId: string,
  rootEntityId: string | undefined,
  rootDirection: RelationshipDirectionName,
  relationshipType: RelationshipTypeName | undefined,
): string | null {
  return rootEntityId === undefined
    ? null
    : `${investigationId}\u0000${rootEntityId}\u0000${rootDirection}\u0000${relationshipType ?? ""}`;
}

/** The bounded one-hop expansion orchestrator (PR 31E Part 4). */
export function useGraphExpansion({
  investigationId,
  rootEntityId,
  rootDirection,
  relationshipType,
  rootNeighborhood,
}: GraphExpansionInputs): GraphExpansionController {
  const [graph, setGraph] = useState<AccumulatedGraph | null>(null);
  const [inFlight, setInFlight] = useState<ExpandedNeighborhoodKey | null>(null);
  const [failed, setFailed] = useState<ExpandedNeighborhoodKey | null>(null);

  const graphRef = useRef<AccumulatedGraph | null>(null);
  const inFlightRef = useRef<ExpandedNeighborhoodKey | null>(null);
  const failedRef = useRef<ExpandedNeighborhoodKey | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);
  const contextKeyRef = useRef<string | null>(null);
  const inputsRef = useRef({
    investigationId,
    rootEntityId,
    rootDirection,
    relationshipType,
  });
  inputsRef.current = { investigationId, rootEntityId, rootDirection, relationshipType };

  const contextKey = rootContextKey(
    investigationId,
    rootEntityId,
    rootDirection,
    relationshipType,
  );

  // Root synchronization: a root semantic change resets accumulated state
  // (aborting any in-flight expansion); the same semantic context with a
  // refreshed root response overlays refreshed server data without
  // discarding successful expansions (PR 31E I14/I15).
  useEffect(() => {
    if (contextKeyRef.current !== contextKey) {
      contextKeyRef.current = contextKey;
      // Abort + stale-result exclusion for the old root context.
      generationRef.current += 1;
      abortRef.current?.abort();
      abortRef.current = null;
      inFlightRef.current = null;
      failedRef.current = null;
      setInFlight(null);
      setFailed(null);
      if (contextKey === null || rootNeighborhood === null) {
        graphRef.current = null;
        setGraph(null);
        return;
      }
      const next = emptyAccumulatedGraph(
        inputsRef.current.rootEntityId as string,
        rootNeighborhood,
      );
      graphRef.current = next;
      setGraph(next);
      return;
    }
    if (contextKey !== null && rootNeighborhood !== null) {
      const next =
        graphRef.current === null
          ? emptyAccumulatedGraph(
              inputsRef.current.rootEntityId as string,
              rootNeighborhood,
            )
          : overlayRootNeighborhood(graphRef.current, rootNeighborhood);
      graphRef.current = next;
      setGraph(next);
    }
  }, [contextKey, rootNeighborhood]);

  const runExpansion = useCallback(
    (entityId: string, direction: RelationshipDirectionName): void => {
      if (inFlightRef.current !== null) {
        return; // one in-flight expansion at a time (PR 31E I11/Q12)
      }
      const current = graphRef.current;
      if (
        current !== null &&
        current.expanded.some((key) => expansionKeyMatches(key, entityId, direction))
      ) {
        return; // already completed: idempotent, never a normal refetch
      }
      if (contextKeyRef.current === null) {
        return; // no root context loaded yet
      }
      const { investigationId: investigation, relationshipType: type } =
        inputsRef.current;
      const key: ExpandedNeighborhoodKey = { entityId, direction };
      const generation = generationRef.current;
      const controller = new AbortController();
      abortRef.current = controller;
      inFlightRef.current = key;
      setInFlight(key);
      failedRef.current = null;
      setFailed(null);
      void fetchGraphNeighborhood(
        investigation,
        entityId,
        direction,
        type,
        GRAPH_NEIGHBORHOOD_LIMIT,
        controller.signal,
      )
        .then((neighborhood) => {
          if (
            generationRef.current !== generation ||
            abortRef.current !== controller
          ) {
            return; // stale/cancelled result cannot contaminate another root
          }
          const base = graphRef.current;
          if (base === null) {
            return;
          }
          const next = mergeNeighborhood(base, { key, neighborhood });
          graphRef.current = next;
          setGraph(next);
          inFlightRef.current = null;
          abortRef.current = null;
          setInFlight(null);
        })
        .catch((error: unknown) => {
          if (
            generationRef.current !== generation ||
            abortRef.current !== controller
          ) {
            return; // cancellation is not a semantic failure (PR 31E I13)
          }
          if (isAbortError(error)) {
            inFlightRef.current = null;
            abortRef.current = null;
            setInFlight(null);
            return;
          }
          // Real failure: accumulated graph unchanged, bounded Retry.
          failedRef.current = key;
          setFailed(key);
          inFlightRef.current = null;
          abortRef.current = null;
          setInFlight(null);
        });
    },
    [],
  );

  const retry = useCallback((): void => {
    const target = failedRef.current;
    if (target === null) {
      return;
    }
    runExpansion(target.entityId, target.direction);
  }, [runExpansion]);

  const isExpanded = useCallback(
    (entityId: string, direction: RelationshipDirectionName): boolean =>
      graphRef.current?.expanded.some((key) =>
        expansionKeyMatches(key, entityId, direction),
      ) ?? false,
    [],
  );

  // Unmount: abort the in-flight request and invalidate any late result.
  useEffect(() => {
    return () => {
      generationRef.current += 1;
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  const lastExpansion =
    graph === null || graph.expanded.length === 0
      ? null
      : graph.expanded[graph.expanded.length - 1];

  return {
    graph,
    inFlight,
    failed,
    expanded: graph?.expanded ?? EMPTY_EXPANSIONS,
    truncated: graph?.truncatedExpansions ?? EMPTY_EXPANSIONS,
    lastExpansion,
    expand: runExpansion,
    retry,
    isExpanded,
  };
}
