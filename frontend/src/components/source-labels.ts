// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared analyst-facing labels for stable ATI source URNs.
//
// Source URNs remain the durable machine identity. List/table surfaces use
// these localized labels; technical detail surfaces may show both the label
// and raw URN. Unknown/future source identifiers safely fall back to the raw
// value rather than fabricating a name.

export const SOURCE_LABEL_KEYS: Readonly<Record<string, string>> = {
  "urn:ati:source:ipinfo_lite": "sources.ipinfoLite",
  "urn:ati:source:rdap": "sources.rdap",
  "urn:ati:source:google_public_dns": "sources.googlePublicDns",
  "urn:ati:source:dbip_city_lite": "sources.dbipCityLite",
  "urn:ati:source:abuseipdb": "sources.abuseIpDb",
  "urn:ati:source:threatfox": "sources.threatFox",
  "urn:ati:source:urlhaus": "sources.urlHaus",
  "urn:ati:source:mitre_attack": "sources.mitreAttack",
  "urn:ati:source:cisa_kev": "sources.cisaKev",
  "urn:ati:source:misp": "sources.misp",
  "urn:ati:source:opencti": "sources.openCti",
};

/** Resolve a stable source identifier to a localized label with raw fallback. */
export function sourceLabel(
  source: string,
  t: (key: string) => string,
): string {
  const key = SOURCE_LABEL_KEYS[source];
  return key === undefined ? source : t(key);
}

/** Detail presentation: human label first, durable technical URN second. */
export function sourceLabelWithUrn(
  source: string,
  t: (key: string) => string,
): string {
  const label = sourceLabel(source, t);
  return label === source ? source : `${label} (${source})`;
}
