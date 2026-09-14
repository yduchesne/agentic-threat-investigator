// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Explicit pivot capability registry (PR 24D §1.3, §4, §6, §8; PR 24F §14).
//
// Every legal pivot is declared here as an explicit typed capability:
// source identity -> exact target resource + exact existing server filter
// (and/or exact scoped selection) + analyst-facing label. Nothing is ever
// inferred from matching property names, string similarity, or
// client-side OR semantics. Targets not expressible through the existing
// PR 24C filter codecs or exact scoped detail endpoints have no
// capability.

import type {
  Evidence,
  Relationship,
  RelationshipObservation,
  ResearchResult,
} from "../api/schema-types";
import { shortUuid } from "../analyst-table/present";
import {
  pivotFiltersEqual,
  type PivotFilterSet,
  type PivotResource,
  type PivotSourceKind,
  type PivotStep,
} from "./pivot-types";

/** One exact pivot target: resource + filters + optional selection. */
export interface PivotTarget {
  resource: PivotResource;
  /** Exact existing server filters (wire-form; allowlisted per resource). */
  filters: PivotFilterSet;
  /** Exact scoped detail selection when a single-item endpoint exists. */
  selectedId: string | null;
  /** Bounded analyst-facing label (breadcrumb identity). */
  label: string;
}

/** Stable machine identities of the legal pivot actions. */
export const PIVOT_ACTION_KINDS = [
  "evidenceForEntity",
  "relationshipsSource",
  "relationshipsTarget",
  "researchForEntity",
  "observationsForRelationship",
  "evidenceExact",
  "researchExact",
  "observationExact",
] as const;

/** One stable pivot action identity. */
export type PivotActionKind = (typeof PIVOT_ACTION_KINDS)[number];

/** One explicit registered pivot action. */
export interface PivotAction {
  readonly key: PivotActionKind;
  /** i18n key inside the ``pivots`` namespace. */
  readonly labelKey: string;
  readonly sourceKind: PivotSourceKind;
  readonly target: PivotTarget;
}

/** Bounded compact labels (PR 24D §17 preference order 3). */
export function entityCompactLabel(entityId: string): string {
  return `Entity ${shortUuid(entityId)}`;
}

export function evidenceCompactLabel(evidenceId: string): string {
  return `Evidence ${shortUuid(evidenceId)}`;
}

export function relationshipCompactLabel(relationshipId: string): string {
  return `Relationship ${shortUuid(relationshipId)}`;
}

export function observationCompactLabel(observationId: string): string {
  return `RelationshipObservation ${shortUuid(observationId)}`;
}

export function researchCompactLabel(researchResultId: string): string {
  return `Research ${shortUuid(researchResultId)}`;
}

/**
 * The four entity-identity actions: Evidence by subject, Relationships by
 * source/target, Research by subject. The Relationship API separates
 * source and target filters, so two distinct actions exist — no
 * client-side source-or-target merge is ever simulated.
 */
export function entityActions(
  entityId: string,
  label: string,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return [
    {
      key: "evidenceForEntity",
      labelKey: "actions.evidenceForEntity",
      sourceKind,
      target: {
        resource: "evidence",
        filters: { subject_entity_id: entityId },
        selectedId: null,
        label,
      },
    },
    {
      key: "relationshipsSource",
      labelKey: "actions.relationshipsSource",
      sourceKind,
      target: {
        resource: "relationships",
        filters: { source_entity_id: entityId },
        selectedId: null,
        label,
      },
    },
    {
      key: "relationshipsTarget",
      labelKey: "actions.relationshipsTarget",
      sourceKind,
      target: {
        resource: "relationships",
        filters: { target_entity_id: entityId },
        selectedId: null,
        label,
      },
    },
    {
      key: "researchForEntity",
      labelKey: "actions.researchForEntity",
      sourceKind,
      target: {
        resource: "research",
        filters: { subject_entity_id: entityId },
        selectedId: null,
        label,
      },
    },
  ];
}

/** Evidence subject identity -> the entity actions (value as label). */
export function evidenceSubjectActions(
  evidence: Pick<Evidence, "subject_entity_id" | "subject_value">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return entityActions(
    evidence.subject_entity_id,
    evidence.subject_value,
    sourceKind,
  );
}

/** Relationship identity -> all observations for that relationship. */
export function relationshipObservationsAction(
  relationshipId: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "observationsForRelationship",
    labelKey: "actions.observationsForRelationship",
    sourceKind,
    target: {
      resource: "relationship-observations",
      filters: { relationship_id: relationshipId },
      selectedId: null,
      label: relationshipCompactLabel(relationshipId),
    },
  };
}

/** Relationship source identity -> the entity actions. */
export function relationshipSourceActions(
  relationship: Pick<Relationship, "source_entity_id">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return entityActions(
    relationship.source_entity_id,
    entityCompactLabel(relationship.source_entity_id),
    sourceKind,
  );
}

/** Relationship target identity -> the entity actions. */
export function relationshipTargetActions(
  relationship: Pick<Relationship, "target_entity_id">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return entityActions(
    relationship.target_entity_id,
    entityCompactLabel(relationship.target_entity_id),
    sourceKind,
  );
}

/**
 * RelationshipObservation identity actions: the typed relationship id opens
 * the relationship-filtered observations workspace; the typed evidence id
 * opens the exact scoped Evidence selection. The DTO exposes no entity
 * ids, so no entity pivots are offered and nothing is derived by parsing.
 */
export function observationActions(
  observation: Pick<RelationshipObservation, "relationship_id" | "evidence_id">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return [
    relationshipObservationsAction(observation.relationship_id, sourceKind),
    {
      key: "evidenceExact",
      labelKey: "actions.evidenceExact",
      sourceKind,
      target: {
        resource: "evidence",
        filters: {},
        selectedId: observation.evidence_id,
        label: evidenceCompactLabel(observation.evidence_id),
      },
    },
  ];
}

/** Research subject identity -> the entity actions (compact label only). */
export function researchSubjectActions(
  research: Pick<ResearchResult, "subject_entity_id">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return entityActions(
    research.subject_entity_id,
    entityCompactLabel(research.subject_entity_id),
    sourceKind,
  );
}

/** Report/Assessment Evidence support -> the exact scoped Evidence. */
export function evidenceSupportAction(
  evidenceId: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "evidenceExact",
    labelKey: "actions.evidenceExact",
    sourceKind,
    target: {
      resource: "evidence",
      filters: {},
      selectedId: evidenceId,
      label: evidenceCompactLabel(evidenceId),
    },
  };
}

/** Report Research claim support -> the exact scoped ResearchResult. */
export function researchSupportAction(
  researchResultId: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "researchExact",
    labelKey: "actions.researchExact",
    sourceKind,
    target: {
      resource: "research",
      filters: {},
      selectedId: researchResultId,
      label: researchCompactLabel(researchResultId),
    },
  };
}

/**
 * RelationshipObservation support identity -> the exact scoped observation.
 *
 * PR 24F: the persisted observation id resolves through the exact
 * Investigation-scoped observation GET (never a list scan, never a
 * substitute observation, never a guessed relationship id). The bounded
 * breadcrumb label is the compact observation id; no raw Report text or
 * free form ever enters the pivot state.
 */
export function observationSupportAction(
  observationId: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "observationExact",
    labelKey: "actions.observationExact",
    sourceKind,
    target: {
      resource: "relationship-observations",
      filters: {},
      selectedId: observationId,
      label: observationCompactLabel(observationId),
    },
  };
}

/**
 * Remove actions whose target equals the active step's resource + filter
 * context (no-op suppression, PR 24D §8: "Avoid no-op pivots to the same
 * resource/filter context"). Exact-id selections are never suppressed.
 */
export function suppressNoOps(
  actions: readonly PivotAction[],
  active: PivotStep | null,
): PivotAction[] {
  if (active === null || actions.length === 0) {
    return [...actions];
  }
  return actions.filter((action) => {
    if (action.target.selectedId !== null) {
      return true;
    }
    if (action.target.resource !== active.resource) {
      return true;
    }
    return !pivotFiltersEqual(active.resource, action.target.filters, active.filters);
  });
}