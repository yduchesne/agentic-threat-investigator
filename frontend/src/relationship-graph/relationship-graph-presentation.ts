// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic Entity-type presentation (PR 31D §18).
//
// Entity-type differentiation must never rely on color alone: every graph
// node renders the exact translated type text through this helper. Known
// v0.1 EntityType values map to i18n keys inside the relationshipEvolution
// namespace; unexpected/future values fail safely by returning the raw
// type URN so rendering never assigns a false semantic.

import type { EntityTypeName } from "../api/schema-types";

/** i18n key per known EntityType value (inside ``relationshipEvolution``). */
export const ENTITY_TYPE_LABEL_KEYS: Readonly<Record<EntityTypeName, string>> = {
  domain: "graph.entityTypes.domain",
  ip_address: "graph.entityTypes.ip_address",
  url: "graph.entityTypes.url",
  network_prefix: "graph.entityTypes.network_prefix",
  asn: "graph.entityTypes.asn",
  organization: "graph.entityTypes.organization",
  malware: "graph.entityTypes.malware",
  attack_technique: "graph.entityTypes.attack_technique",
  vulnerability: "graph.entityTypes.vulnerability",
};

/**
 * Resolve one EntityType to its i18n label key.
 *
 * Unknown values return the raw type value (i18next renders the key itself
 * as the safe fallback, so no unknown type is ever mapped to a false
 * semantic).
 */
export function entityTypeLabelKey(type: EntityTypeName | string): string {
  return ENTITY_TYPE_LABEL_KEYS[type as EntityTypeName] ?? type;
}
