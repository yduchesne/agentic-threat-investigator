// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship type label mapping (PR 24C §17).
//
// RelationshipType URNs map to translated analyst labels such as
// ``Resolves to`` / ``CNAME of``. Unknown/future values fall back to the
// raw URN so rendering never crashes.

import type { RelationshipTypeName } from "../api/schema-types";

/** i18n key per known RelationshipType URN. */
export const RELATIONSHIP_TYPE_KEYS: Readonly<Record<RelationshipTypeName, string>> = {
  "urn:ati:relationship:dns:resolves_to": "types.resolvesTo",
  "urn:ati:relationship:dns:cname_of": "types.cnameOf",
  "urn:ati:relationship:dns:uses_name_server": "types.usesNameServer",
  "urn:ati:relationship:dns:uses_mail_server": "types.usesMailServer",
  "urn:ati:relationship:network:belongs_to": "types.belongsTo",
  "urn:ati:relationship:routing:announced_by": "types.announcedBy",
  "urn:ati:relationship:registration:registered_to": "types.registeredTo",
  "urn:ati:relationship:organization:operated_by": "types.operatedBy",
  "urn:ati:relationship:threat:associated_with": "types.associatedWith",
  "urn:ati:relationship:attack:uses_technique": "types.usesTechnique",
  "urn:ati:relationship:vulnerability:exploits": "types.exploits",
};

/**
 * Resolve one RelationshipType to its i18n key.
 *
 * Unknown values return the raw URN (i18next renders the key itself as
 * the safe fallback).
 */
export function relationshipTypeKey(type: RelationshipTypeName | string): string {
  return RELATIONSHIP_TYPE_KEYS[type as RelationshipTypeName] ?? type;
}

/** The exact v0.1 RelationshipType values accepted as list filters. */
export const RELATIONSHIP_TYPES: readonly RelationshipTypeName[] = [
  "urn:ati:relationship:dns:resolves_to",
  "urn:ati:relationship:dns:cname_of",
  "urn:ati:relationship:dns:uses_name_server",
  "urn:ati:relationship:dns:uses_mail_server",
  "urn:ati:relationship:network:belongs_to",
  "urn:ati:relationship:routing:announced_by",
  "urn:ati:relationship:registration:registered_to",
  "urn:ati:relationship:organization:operated_by",
  "urn:ati:relationship:threat:associated_with",
  "urn:ati:relationship:attack:uses_technique",
  "urn:ati:relationship:vulnerability:exploits",
];