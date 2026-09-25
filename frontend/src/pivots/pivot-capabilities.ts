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
  GeointEntityLocation,
  GeointObservation,
  Relationship,
  RelationshipObservation,
  ResearchResult,
} from "../api/schema-types";
import { shortUuid } from "../analyst-table/present";
import { locationCanonicalLabel } from "../geoint/geoint-model";
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
  // PR 26E: canonical GEOINT surfaces (Step 11).
  "geointEntity",
  "geointLocationEntities",
  "geointLocationObservations",
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

export function locationCompactLabel(locationId: string): string {
  return `Location ${shortUuid(locationId)}`;
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

/**
 * Evidence subject identity -> the entity actions (value as label).
 *
 * PR 28B association semantics make the subject fields presentation
 * compatibility only: when the exact observation has no associated Entity,
 * there is no subject to pivot from and the action list is empty.
 */
export function evidenceSubjectActions(
  evidence: Pick<Evidence, "subject_entity_id" | "subject_value">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return evidence.subject_entity_id === undefined || evidence.subject_entity_id === null
    ? []
    : entityActions(
        evidence.subject_entity_id,
        evidence.subject_value ?? evidence.subject_entity_id,
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

// PR 26E GEOINT pivot capabilities (Step 11) ------------------------------

/**
 * Entity identity -> the canonical GEOINT current/history surface.
 *
 * The label is the persisted entity display value; the exact Entity ID is
 * the pivot identity. Never derived from coordinates or Evidence payload.
 */
export function entityGeointAction(
  entity: Pick<GeointEntityLocation, "entity_id" | "entity_value">,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "geointEntity",
    labelKey: "actions.geointEntity",
    sourceKind,
    target: {
      resource: "geoint-entity",
      filters: { entity_id: entity.entity_id },
      selectedId: null,
      label: entity.entity_value,
    },
  };
}

/** Location identity -> the scoped Entities surface (exact default). */
export function locationEntitiesAction(
  locationId: string,
  label: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "geointLocationEntities",
    labelKey: "actions.geointLocationEntities",
    sourceKind,
    target: {
      resource: "geoint-location-entities",
      filters: { location_id: locationId },
      selectedId: null,
      label,
    },
  };
}

/** Location identity -> the scoped observations surface (exact default). */
export function locationObservationsAction(
  locationId: string,
  label: string,
  sourceKind: PivotSourceKind,
): PivotAction {
  return {
    key: "geointLocationObservations",
    labelKey: "actions.geointLocationObservations",
    sourceKind,
    target: {
      resource: "geoint-location-observations",
      filters: { location_id: locationId },
      selectedId: null,
      label,
    },
  };
}

/** The two Location exploration surfaces of one GEOINT observation. */
export function geointObservationLocationActions(
  observation: Pick<GeointObservation, "location">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  const location = observation.location;
  const label = locationCanonicalLabel(location) ?? locationCompactLabel(location.location_id);
  return [
    locationEntitiesAction(location.location_id, label, sourceKind),
    locationObservationsAction(location.location_id, label, sourceKind),
  ];
}

/** Entity identity -> existing valid Entity exploration (reused actions). */
export function geointEntityActions(
  entity: Pick<GeointEntityLocation, "entity_id" | "entity_value">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return entityActions(entity.entity_id, entity.entity_value, sourceKind);
}

/** One GEOINT observation -> the exact Evidence surface (no substitution). */
export function geointObservationEvidenceAction(
  observation: Pick<GeointObservation, "evidence_id">,
  sourceKind: PivotSourceKind,
): PivotAction[] {
  return [evidenceSupportAction(observation.evidence_id, sourceKind)];
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
