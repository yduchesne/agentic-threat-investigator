// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Typed Pivot target -> canonical Investigation-scoped route
// (PR 31F-8 §7 Step 1.2).
//
// The generic URL-encoded PivotWorkspace stack is replaced by ordinary
// React Router navigation. This module is the ONE pure translation layer
// between the explicit capability registry (``PivotTarget``) and the
// canonical resource routes: the Investigation shell stays mounted, one
// routed content surface is active at a time, and every filter that the
// existing PR 24C codecs understand round-trips as an equivalent validated
// query parameter.
//
// The mapper is exhaustive over ``PivotResource`` (no permissive default)
// and fail-closed: a target whose canonical identity is missing or not a
// v0.1 UUID never produces a destination, so malformed capability data can
// never drive arbitrary navigation (R12). Path identity is always the
// canonical ID; human-readable labels never enter a route.

import { isUuidValue } from "../analyst-table/filters";
import {
  PIVOT_BOOLEAN_FILTER_KEYS,
  PIVOT_FILTER_KEYS,
  type PivotResource,
} from "./pivot-types";
import type { PivotTarget } from "./pivot-capabilities";

/** One canonical Investigation-scoped route destination. */
export interface PivotRouteDestination {
  /** Absolute path under the Investigation (e.g. ``/evidence/:id``). */
  pathname: string;
  /** Serialized query string without ``?``; absent when empty. */
  search?: string;
}

/** The canonical route prefix of one Investigation. */
function investigationBase(investigationId: string): string {
  // encodeURIComponent guards unusual IDs without breaking UUID form.
  return `/investigations/${encodeURIComponent(investigationId)}`;
}

/** The filter keys that own PATH identity for one resource (never query). */
const PATH_IDENTITY_KEYS: Readonly<Record<PivotResource, readonly string[]>> = {
  evidence: [],
  relationships: [],
  "relationship-observations": [],
  research: [],
  "geoint-entity": ["entity_id"],
  "geoint-location-entities": ["location_id"],
  "geoint-location-observations": ["location_id"],
  "geoint-observation": ["observation_id"],
};

/**
 * Serialize one validated filter set onto the resource query surface
 * (allowlisted keys only; booleans serialize exactly like the codecs;
 * path-owned identities never duplicate into the query).
 */
function filtersToSearch(resource: PivotResource, filters: PivotTarget["filters"]): URLSearchParams {
  const params = new URLSearchParams();
  const pathOwned = PATH_IDENTITY_KEYS[resource] as readonly string[];
  for (const key of PIVOT_FILTER_KEYS[resource]) {
    if (pathOwned.includes(key)) {
      continue;
    }
    const value = (filters as Record<string, unknown>)[key];
    if ((PIVOT_BOOLEAN_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (value === true) {
        params.set(key, "true");
      }
      continue;
    }
    if (typeof value === "string" && value !== "") {
      params.set(key, value);
    }
  }
  return params;
}

/** One validated UUID identity, or null when missing/malformed. */
function uuidIdentity(value: string | undefined | null): string | null {
  if (typeof value !== "string" || value === "" || !isUuidValue(value)) {
    return null;
  }
  return value.toLowerCase();
}

/**
 * Translate one explicit capability target into its canonical route.
 *
 * Returns null (never a navigation) when the target's canonical identity
 * is absent or not a well-formed UUID. Every ``PivotResource`` is handled
 * exhaustively; a future resource added to ``PIVOT_RESOURCES`` without a
 * case here is a compile-time failure (R13).
 */
export function pivotTargetToRoute(
  investigationId: string,
  target: PivotTarget,
): PivotRouteDestination | null {
  const base = investigationBase(investigationId);
  switch (target.resource) {
    case "evidence": {
      const params = filtersToSearch(target.resource, target.filters);
      if (target.selectedId !== null) {
        const evidenceId = uuidIdentity(target.selectedId);
        if (evidenceId === null) {
          return null;
        }
        return {
          pathname: `${base}/evidence/${evidenceId}`,
          search: params.toString() === "" ? undefined : params.toString(),
        };
      }
      return {
        pathname: `${base}/evidence`,
        search: params.toString() === "" ? undefined : params.toString(),
      };
    }
    case "relationships": {
      const params = filtersToSearch(target.resource, target.filters);
      if (target.selectedId !== null) {
        const relationshipId = uuidIdentity(target.selectedId);
        if (relationshipId === null) {
          return null;
        }
        return {
          pathname: `${base}/relationships/${relationshipId}`,
          search: params.toString() === "" ? undefined : params.toString(),
        };
      }
      return {
        pathname: `${base}/relationships`,
        search: params.toString() === "" ? undefined : params.toString(),
      };
    }
    case "relationship-observations": {
      const params = filtersToSearch(target.resource, target.filters);
      if (target.selectedId !== null) {
        const observationId = uuidIdentity(target.selectedId);
        if (observationId === null) {
          return null;
        }
        return {
          pathname: `${base}/relationships/observations/${observationId}`,
          search: params.toString() === "" ? undefined : params.toString(),
        };
      }
      return {
        pathname: `${base}/relationships/observations`,
        search: params.toString() === "" ? undefined : params.toString(),
      };
    }
    case "research": {
      const params = filtersToSearch(target.resource, target.filters);
      if (target.selectedId !== null) {
        const researchId = uuidIdentity(target.selectedId);
        if (researchId === null) {
          return null;
        }
        params.set("selected", researchId);
      }
      return {
        pathname: `${base}/research`,
        search: params.toString() === "" ? undefined : params.toString(),
      };
    }
    case "geoint-entity": {
      const entityId = uuidIdentity(
        (target.filters as { entity_id?: string }).entity_id,
      );
      if (entityId === null) {
        return null;
      }
      // The Entity identity is the canonical path; no query remains.
      return { pathname: `${base}/geoint/entities/${entityId}` };
    }
    case "geoint-location-entities":
    case "geoint-location-observations": {
      const locationId = uuidIdentity(
        (target.filters as { location_id?: string }).location_id,
      );
      if (locationId === null) {
        return null;
      }
      const params = filtersToSearch(target.resource, target.filters);
      const surface = target.resource === "geoint-location-entities" ? "entities" : "observations";
      return {
        pathname: `${base}/geoint/locations/${locationId}/${surface}`,
        search: params.toString() === "" ? undefined : params.toString(),
      };
    }
    case "geoint-observation": {
      const observationId = uuidIdentity(
        (target.filters as { observation_id?: string }).observation_id,
      );
      if (observationId === null) {
        return null;
      }
      return { pathname: `${base}/geoint/observations/${observationId}` };
    }
  }
}
