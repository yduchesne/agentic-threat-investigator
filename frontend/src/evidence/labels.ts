// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Evidence type label mapping (PR 24C §17).
//
// Stable EvidenceType URNs map to translated analyst labels. Unknown/
// future enum values fall back to their raw value so rendering never
// crashes and never fabricates semantics.

import type { EvidenceTypeName } from "../api/schema-types";

/** i18n key per known EvidenceType URN. */
export const EVIDENCE_TYPE_KEYS: Readonly<Record<EvidenceTypeName, string>> = {
  "urn:ati:evidence:dns": "types.dns",
  "urn:ati:evidence:registration": "types.registration",
  "urn:ati:evidence:network": "types.network",
  "urn:ati:evidence:geolocation": "types.geolocation",
  "urn:ati:evidence:reputation": "types.reputation",
  "urn:ati:evidence:threat_intelligence": "types.threatIntelligence",
  "urn:ati:evidence:vulnerability": "types.vulnerability",
  "urn:ati:evidence:threat_research": "types.threatResearch",
};

/**
 * Resolve one EvidenceType to its i18n key.
 *
 * Unknown values return the raw URN (i18next renders the key itself as
 * the safe fallback).
 */
export function evidenceTypeKey(type: EvidenceTypeName | string): string {
  return EVIDENCE_TYPE_KEYS[type as EvidenceTypeName] ?? type;
}

/** The exact v0.1 EvidenceType values accepted as list filters. */
export const EVIDENCE_TYPES: readonly EvidenceTypeName[] = [
  "urn:ati:evidence:dns",
  "urn:ati:evidence:registration",
  "urn:ati:evidence:network",
  "urn:ati:evidence:geolocation",
  "urn:ati:evidence:reputation",
  "urn:ati:evidence:threat_intelligence",
  "urn:ati:evidence:vulnerability",
  "urn:ati:evidence:threat_research",
];