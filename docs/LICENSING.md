# Agentic Threat Investigator — Licensing and Attribution

## Table of contents

- [ATI license](#ati-license)
- [Source headers](#source-headers)
- [Repository licensing files](#repository-licensing-files)
- [Third-party code](#third-party-code)
- [External data and service terms](#external-data-and-service-terms)
- [Data bundling](#data-bundling)
- [Runtime attribution](#runtime-attribution)
- [Evidence provenance](#evidence-provenance)
- [Dependencies](#dependencies)
- [Network-use notice](#network-use-notice)
- [Contributions](#contributions)
- [CI checks](#ci-checks)

## ATI license

Agentic Threat Investigator source code is licensed under:

`AGPL-3.0-only`

The repository root contains the complete GNU Affero General Public License v3.0 text in `LICENSE`.

Project-authored documentation is distributed under the same license unless explicitly stated otherwise.

## Source headers

ATI-authored source files use concise SPDX headers where the file format supports comments.

Python:

```python
# SPDX-FileCopyrightText: 2026 <copyright holder>
# SPDX-License-Identifier: AGPL-3.0-only
```

TypeScript:

```typescript
// SPDX-FileCopyrightText: 2026 <copyright holder>
// SPDX-License-Identifier: AGPL-3.0-only
```

SQL:

```sql
-- SPDX-FileCopyrightText: 2026 <copyright holder>
-- SPDX-License-Identifier: AGPL-3.0-only
```

The copyright-holder form must be chosen once and used consistently.

Do not blindly add ATI SPDX headers to generated files, lockfiles, third-party files, downloaded datasets, or material governed by another license.

## Repository licensing files

Root:

- `LICENSE` — full AGPLv3 text.
- `NOTICE` — human-readable ATI and third-party attribution pointer.
- `README.md` — concise licensing statement.
- `docs/LICENSING.md` — detailed third-party/data-source licensing and attribution.

## Third-party code

Vendored third-party code retains its original copyright and licensing notices.

ATI must not relabel third-party code as AGPL-owned ATI code.

Prefer normal package dependencies over vendoring where reasonable.

## External data and service terms

ATI integrates with external sources including:

- DB-IP City Lite;
- MITRE ATT&CK;
- CISA KEV/advisories;
- ThreatFox;
- URLhaus;
- IPinfo Lite;
- AbuseIPDB;
- Google Public DNS;
- RDAP services.

Before a release, current terms for each source must be verified for:

- access conditions;
- attribution;
- redistribution;
- caching/persistence;
- API usage limits;
- any restrictions relevant to the open-source product.

The fact that a source is free to access does not imply that ATI may bundle or redistribute it.

### IPinfo Lite license and attribution

IPinfo publishes the IPinfo Lite database and Lite API under the Creative
Commons Attribution-ShareAlike 4.0 International license (CC BY-SA 4.0),
and attribution is required when using IPinfo Lite:

- IPinfo Lite product and license terms:
  <https://ipinfo.io/lite>
- IPinfo attribution guidance:
  <https://ipinfo.io/attribution>
- CC BY-SA 4.0 license text:
  <https://creativecommons.org/licenses/by-sa/4.0/>

Compliance handling for ATI:

- ATI consumes the Lite API live, stores only normalized facts as evidence
  provenance (`raw_payload=None`), never redistributes or bundles IPinfo
  data, and applies ATI-configured concurrency/rate bounds.
- Distribution or sharing of IPinfo-licensed material, or of material
  adapted from it, must follow the applicable CC BY-SA 4.0 attribution,
  change-indication, and ShareAlike requirements.
- Use-specific classification of ATI's normalized evidence under CC BY-SA
  4.0 requires legal review; that review must be complete before general
  availability of any release that exposes IPinfo-derived data.
- IPinfo's suggested credit form is "IP address data powered by IPinfo"
  with a link to <https://ipinfo.io>, together with a CC BY-SA 4.0
  pointer. That attribution is recorded in the repository `NOTICE` file
  and `docs/LICENSING.md`. Runtime attribution must be added before
  IPinfo-derived data is exposed through a future UI; Evidence
  `source_url` provenance alone does not satisfy this attribution
  obligation.
- Current IPinfo terms must be re-verified before each release.

### DB-IP City Lite license and attribution

DB-IP publishes the IP to City Lite database under the Creative Commons
Attribution 4.0 International license (CC BY 4.0), and DB-IP attribution is
required when using the database:

- DB-IP City Lite product and download page:
  <https://db-ip.com/db/lite.php>
- DB-IP license terms:
  <https://db-ip.com/db/lite.php#license>
- CC BY 4.0 license text:
  <https://creativecommons.org/licenses/by/4.0/>

Compliance handling for ATI:

- ATI consumes only the downloadable local MMDB database; it never calls a
  DB-IP API. The provider reads an operator-supplied local MMDB artifact;
  this repository does not bundle, commit, or distribute the DB-IP dataset,
  and external display or distribution of DB-IP-derived data must satisfy
  the applicable attribution and license terms.
- Operators obtain the City Lite MMDB from the authoritative DB-IP source
  and comply with the applicable attribution/license terms (see
  `docs/DEPLOYMENT.md`).
- Web applications displaying or using DB-IP-derived geolocation results
  must display DB-IP attribution with a link to <https://db-ip.com>, as
  required by the DB-IP Lite license. This runtime attribution must be
  implemented in the future frontend/map work before DB-IP-derived
  geolocation is exposed through a UI; Evidence `source_url` provenance
  alone does not satisfy this obligation.
- Current DB-IP terms must be re-verified before each release.

## Data bundling

Third-party datasets are generally not committed or bundled with ATI.

ATI distributes:

- source code;
- ingestion/download tooling;
- configuration;
- ATI-authored synthetic tests.

Users obtain applicable external datasets from their authoritative sources through setup/ingestion mechanisms.

## Runtime attribution

Where a source requires attribution, ATI should provide attribution in the running product as well as repository documentation.

The frontend should provide an About/Data Sources & Licenses view.

Source metadata should be centralized where practical so UI and documentation do not drift.

## Evidence provenance

Evidence exposes stable source identifiers and source URLs where appropriate.

Provenance supports analyst verification but is not automatically a substitute for legally required attribution.

## AbuseIPDB API terms

The AbuseIPDB provider uses only the official API v2 `check` endpoint.
Authoritative references (must be re-verified before every release):

- <https://docs.abuseipdb.com/>
- <https://www.abuseipdb.com/pricing>
- <https://www.abuseipdb.com/legal>

Terms relevant to ATI operators (as documented at the references above at
the time of writing; the authoritative pages prevail):

1. Operators must choose and comply with an AbuseIPDB plan appropriate
   for their use.
2. Free/Individual use is currently restricted to evaluation,
   contribution, and non-commercial personal projects; commercial or
   organization use requires the appropriate paid plan under current
   terms.
3. Plan quotas are finite and can change. ATI does not hard-code a daily
   quota policy; it safely handles HTTP 429 responses through the shared
   retry policy and `Retry-After` handling.
4. ATI performs lookups only and never submits abuse reports.
5. ATI does not bundle or redistribute AbuseIPDB data; evidence facts are
   retained as investigation observations, not as a redistributable
   dataset.

This section describes source terms for operator awareness and is not
legal advice.

## ThreatFox API terms

The ThreatFox provider uses only the official ThreatFox Community API v1
`search_ioc` query. Authoritative references (must be re-verified before
every release):

- <https://threatfox.abuse.ch/api/>
- <https://threatfox.abuse.ch/faq/>
- <https://abuse.ch/terms-of-use/>

Terms relevant to ATI operators (as documented at the references above at
the time of writing; the authoritative pages prevail):

1. The Community API is available free of charge under the abuse.ch fair
   use principles. Use by companies, networks, or individuals with
   commercial or for-profit needs may require a paid subscription for the
   enhanced abuse.ch commercial API.
2. An Auth-Key (free via the abuse.ch authentication portal) is required
   for API interaction and is sent only in the `Auth-Key` header.
3. IOCs older than six months expire from API and export visibility
   (since 2025-05-01); a no-result never proves historical absence.
4. ATI performs lookups only. It never submits IOCs, retrieves malware
   samples, or consumes MalwareBazaar payloads.
5. ATI does not bundle or redistribute ThreatFox data; evidence facts are
   retained as investigation observations, not as a redistributable
   dataset.

This section describes source terms for operator awareness and is not
legal advice.

## Dependencies

Python and frontend dependencies receive an automated license inventory/check before release.

A dependency with licensing incompatible with ATI distribution requires explicit review.

Base images/system packages retain their own licenses. ATI licensing does not relabel all container contents.

## Network-use notice

The README should make the AGPL network-use source-availability obligation visible and direct users to the authoritative `LICENSE` text.

ATI documentation should not attempt to replace the license with custom legal interpretation.

## Contributions

Until a contributor-IP policy is explicitly established, substantial external contributions should not be accepted casually.

`CONTRIBUTING.md` should state the repository's applicable contribution terms once they are formally selected.

## CI checks

Licensing quality gates should include:

- SPDX-header validation for applicable ATI-authored files;
- dependency-license inventory/check;
- required third-party attribution metadata validation.

Exceptions must be deliberate rather than achieved by disabling the licensing checks.
