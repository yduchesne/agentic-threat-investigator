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

Approved handling for ATI:

- ATI consumes the Lite API live, stores only normalized facts as evidence
  provenance (`raw_payload=None`), never redistributes or bundles IPinfo
  data, and applies ATI-configured concurrency/rate bounds.
- Under CC BY-SA 4.0, normalized or otherwise adapted IPinfo Lite material
  that is shared onward is adapted material and must carry the same
  CC BY-SA 4.0 license plus attribution. ATI's local persistence of
  investigation evidence within a deployment is use, not distribution;
  if a deployment shares IPinfo-derived evidence or reports outside the
  deployment, that shared material carries the CC BY-SA 4.0 obligation.
- The approved attribution is IPinfo's suggested credit form:
  "IP address data powered by IPinfo" with a link to
  <https://ipinfo.io>, together with a CC BY-SA 4.0 pointer. It is
  recorded in the repository `NOTICE` file and `docs/LICENSING.md`, and
  runtime attribution is provided with the frontend data-sources view.
  Evidence `source_url` provenance alone does not satisfy this
  attribution obligation.
- Current IPinfo terms must be re-verified before each release, and formal
  legal review of the ShareAlike handling above should confirm this
  decision before v0.1 general availability.

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
