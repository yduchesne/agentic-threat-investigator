// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Pivot domain model (PR 24D §1.2, §4, §5, §11).
//
// One pivot step is an explicit typed identity: an allowlisted target
// resource, an exact resource-specific filter set (wire-form keys matching
// the existing PR 24C filter codecs), an optional exact detail selection,
// a bounded analyst-facing label, a bounded opaque cursor (never decoded),
// and navigation provenance. No arbitrary dictionaries are authoritative;
// the parser in ``pivot-url.ts`` validates every field against this model.

import type {
  EvidenceTypeName,
  RelationshipTypeName,
} from "../api/schema-types";

/** The resources reachable through a PR 24D pivot workspace. */
export const PIVOT_RESOURCES = [
  "evidence",
  "relationships",
  "relationship-observations",
  "research",
] as const;

/** One allowlisted pivot target resource. */
export type PivotResource = (typeof PIVOT_RESOURCES)[number];

/** Whether one value is an allowlisted pivot resource. */
export function isPivotResource(value: string): value is PivotResource {
  return (PIVOT_RESOURCES as readonly string[]).includes(value);
}

/** Bounded navigation provenance of one pivot step (frontend-only). */
export const PIVOT_SOURCE_KINDS = [
  "table_cell",
  "detail_field",
  "report_support",
  "assessment_support",
  "research_reference",
  "relationship_observation_reference",
] as const;

/** One bounded pivot source kind. */
export type PivotSourceKind = (typeof PIVOT_SOURCE_KINDS)[number];

/** Evidence list filters expressible through one legal pivot step. */
export interface PivotEvidenceFilters {
  source?: string;
  subject_entity_id?: string;
  type?: EvidenceTypeName;
  retrieved_from?: string;
  retrieved_to?: string;
}

/** Relationship list filters expressible through one legal pivot step. */
export interface PivotRelationshipFilters {
  source_entity_id?: string;
  target_entity_id?: string;
  relationship_type?: RelationshipTypeName;
}

/** RelationshipObservation list filters reachable from a pivot step. */
export interface PivotObservationFilters {
  relationship_id?: string;
  source?: string;
  observed_from?: string;
  observed_to?: string;
  retrieved_from?: string;
  retrieved_to?: string;
}

/** ResearchResult list filters expressible through one legal pivot step. */
export interface PivotResearchFilters {
  subject_entity_id?: string;
  created_from?: string;
  created_to?: string;
}

/** The typed filter set of one pivot step, correlated with its resource. */
export type PivotFilterSet =
  | PivotEvidenceFilters
  | PivotRelationshipFilters
  | PivotObservationFilters
  | PivotResearchFilters;

export interface PivotEvidenceStep {
  resource: "evidence";
  filters: PivotEvidenceFilters;
  selectedId: string | null;
  label: string;
  sourceKind: PivotSourceKind;
  /** Opaque bounded cursor; never decoded, kept out of the serialized envelope. */
  cursor?: string;
}

export interface PivotRelationshipStep {
  resource: "relationships";
  filters: PivotRelationshipFilters;
  selectedId: string | null;
  label: string;
  sourceKind: PivotSourceKind;
  cursor?: string;
}

export interface PivotObservationStep {
  resource: "relationship-observations";
  filters: PivotObservationFilters;
  selectedId: string | null;
  label: string;
  sourceKind: PivotSourceKind;
  cursor?: string;
}

export interface PivotResearchStep {
  resource: "research";
  filters: PivotResearchFilters;
  selectedId: string | null;
  label: string;
  sourceKind: PivotSourceKind;
  cursor?: string;
}

/** One explicit typed pivot step (the authoritative stack element). */
export type PivotStep =
  | PivotEvidenceStep
  | PivotRelationshipStep
  | PivotObservationStep
  | PivotResearchStep;

/** The bounded pivot stack. */
export interface PivotState {
  steps: readonly PivotStep[];
}

/** Maximum pivot depth; the base Investigation route is not counted. */
export const MAX_PIVOT_STEPS = 5;

/** Maximum label length persisted in the pivot URL (bounded state). */
export const MAX_PIVOT_LABEL_CHARS = 128;

/** Maximum opaque cursor length persisted per step (bounded state). */
export const MAX_PIVOT_CURSOR_CHARS = 512;

/** Maximum raw filter string value length (bounded state). */
export const MAX_PIVOT_FILTER_VALUE_CHARS = 200;

/** The exact URL/filter keys one resource accepts inside pivot state. */
export const PIVOT_FILTER_KEYS: Readonly<Record<PivotResource, readonly string[]>> = {
  evidence: ["source", "subject_entity_id", "type", "retrieved_from", "retrieved_to"],
  relationships: ["source_entity_id", "target_entity_id", "relationship_type"],
  "relationship-observations": [
    "relationship_id",
    "source",
    "observed_from",
    "observed_to",
    "retrieved_from",
    "retrieved_to",
  ],
  research: ["subject_entity_id", "created_from", "created_to"],
};

/** The filter keys that must hold a canonical UUID value. */
export const PIVOT_UUID_FILTER_KEYS: Readonly<Record<PivotResource, readonly string[]>> = {
  evidence: ["subject_entity_id"],
  relationships: ["source_entity_id", "target_entity_id"],
  "relationship-observations": ["relationship_id"],
  research: ["subject_entity_id"],
};

/** The filter keys that must hold a UTC ISO-8601 timestamp value. */
export const PIVOT_TIMESTAMP_FILTER_KEYS: Readonly<Record<PivotResource, readonly string[]>> = {
  evidence: ["retrieved_from", "retrieved_to"],
  relationships: [],
  "relationship-observations": [
    "observed_from",
    "observed_to",
    "retrieved_from",
    "retrieved_to",
  ],
  research: ["created_from", "created_to"],
};

/** The neutral filter set of one resource (validated shape only). */
export function emptyPivotFilters(resource: PivotResource): PivotFilterSet {
  switch (resource) {
    case "evidence":
      return {};
    case "relationships":
      return {};
    case "relationship-observations":
      return {};
    case "research":
      return {};
  }
}

/**
 * Canonical identity of one filter set (no-op suppression and URL
 * round-trip identity). Only allowlisted keys are considered.
 */
export function pivotFiltersKey(
  resource: PivotResource,
  filters: PivotFilterSet,
): string {
  const parts: string[] = [];
  for (const key of PIVOT_FILTER_KEYS[resource]) {
    const value = (filters as Record<string, unknown>)[key];
    parts.push(value === undefined ? "" : String(value));
  }
  return parts.join("\u0000");
}

/** Whether two filter sets are identical for the same resource. */
export function pivotFiltersEqual(
  resource: PivotResource,
  a: PivotFilterSet,
  b: PivotFilterSet,
): boolean {
  return pivotFiltersKey(resource, a) === pivotFiltersKey(resource, b);
}