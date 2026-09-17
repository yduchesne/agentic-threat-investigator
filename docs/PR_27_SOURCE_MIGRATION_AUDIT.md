# PR 27 Source Migration Audit

Fresh-main source audit recorded for PR 27E
(baseline SHA `42c961d3fbf7580babe05d55525f552fe2df9868`).

This audit records the PR 27 architectural status of every ATI source that
produces normalized data, as of the PR 27E landing. Statuses are honest,
source-by-source decisions; a `LEGACY_NOT_SEMANTICALLY_MODELED` row means
the source's production runtime remains the pre-27 Evidence path and is
**not** PR27-compliant. PR 27 closure does not claim otherwise; remaining
migrations are source-specific follow-ups.

## Status vocabulary

| Status | Meaning |
| ------ | ------- |
| `MIGRATED` | Production runtime runs the full PR 27A-D stack: configured `DatasourceDefinition` -> acquisition execution -> serialization -> semantic source objects -> semantic-format-selected `ToEvidenceConverter` -> existing Evidence persistence/Investigation runtime. |
| `SEMANTIC_BOUNDARY_ONLY` | The source has an approved semantic parser boundary (PR 27C) but its production product is not Investigation Evidence through the PR 27D converter path. |
| `LEGACY_NOT_SEMANTICALLY_MODELED` | The source still uses the legacy direct-to-Evidence provider path; no approved PR 27 semantic format/parser/converter contracts exist for it. |
| `NOT_EVIDENCE_SOURCE` | The source produces corpus/reference products that are intentionally not converted to Investigation Evidence. |
| `BLOCKED` | Migration is blocked by an open architectural or contract decision. |

## Migration status by source

| Source | Runtime product | Semantic format | Status |
| ------ | --------------- | --------------- | ------ |
| ThreatFox | Investigation Evidence | `urn:ati:datasource:semanticformat:threatfox` | `MIGRATED` |
| MITRE ATT&CK | SourceRecord corpus / RAG documents | `urn:ati:datasource:semanticformat:stix21` | `SEMANTIC_BOUNDARY_ONLY` + `NOT_EVIDENCE_SOURCE` |
| Google Public DNS | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |
| RDAP | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |
| IPinfo Lite | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |
| AbuseIPDB | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |
| URLhaus | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |
| DB-IP City Lite | Investigation Evidence | none approved | `LEGACY_NOT_SEMANTICALLY_MODELED` |

## ThreatFox — `MIGRATED`

The production Investigation runtime migrates through the PR 27A-D stack:

```text
Settings.datasources (threatfox-live definition)
 -> DatasourceProvider (app/datasource_provider.py)
 -> ThreatFoxDatasource / ProviderHttpClient (Auth-Key header only)
 -> ThreatFox semantic parser -> ThreatFoxRecord
 -> EvidenceConversionContext
 -> ToEvidenceConverterRegistry (semantic_format only)
 -> ThreatFoxToEvidenceConverter
 -> one Evidence per source record (exact source_record_id)
 -> existing ProviderWorkExecutor binding/extraction
 -> ProviderObservationPersistenceService (one atomic UoW per observation)
 -> execution lifecycle terminal (COMPLETED/FAILED/CANCELLED)
```

Why `MIGRATED` and not `PARTIAL`:

- the whole production composition (worker bootstrap registry through the
  runner) serves ThreatFox from the migrated provider;
- acquisition, semantic parsing, conversion, extraction, observation
  persistence, the UnitOfWork recorder, `datasource_log`, and PostgreSQL
  are real in the vertical slices;
- per-record Evidence is the adopted representation, matched against the
  existing extractor and persistence boundaries;
- typed datasource failures map deterministically into the legacy
  `ProviderErrorCode` vocabulary with no message-text parsing;
- the terminal `COMPLETED` is deferred until required Evidence runtime
  processing succeeds; runtime failures append bounded FAILED lifecycle
  codes; cancellation stays CANCELLED and propagates;
- no UoW spans acquisition/parse/conversion/extraction; lifecycle events
  are execution-level; `datasource_log` is never a checkpoint/outbox.

Retained transitional artifacts: the legacy grouped-Evidence
`ThreatFoxProvider` class remains importable and is pinned by its
pre-27E contract tests, but production bootstrap no longer composes it
(`infrastructure/providers/threatfox.py` documents this status). The PR 27D
in-memory reference runner (`acquire_and_convert_threatfox_execution`)
remains the D27D test seam; production terminal ownership lives in the
executor.

## MITRE ATT&CK — `SEMANTIC_BOUNDARY_ONLY` + `NOT_EVIDENCE_SOURCE`

MITRE ATT&CK ingestion remains a SourceRecord corpus path: the STIX 2.1
semantic parser (`infrastructure/datasources/stix21_semantics.py`) is a
delivered PR 27C boundary consumed by `MitreAttackBatchSource`, but the
approved product is normalized `SourceRecord`s plus RAG corpus documents —
not Investigation Evidence. PR 27E does **not** invent a generic
STIX-to-Evidence mapping and does not migrate MITRE away from SourceRecord.
Identity/content-hash/normalization/checkpoint behavior is unchanged and
pinned by the unit/integration suites.

## Google Public DNS / RDAP / IPinfo Lite / AbuseIPDB / URLhaus / DB-IP City Lite — `LEGACY_NOT_SEMANTICALLY_MODELED`

These live Investigation Evidence sources keep the pre-27 direct-to-Evidence
provider path. None has an approved PR 27 semantic format, parser, or
`ToEvidenceConverter` contract on `main`; inventing those semantic models is
source-specific follow-up work and is explicitly out of PR 27E scope. Each
would migrate through its own semantic format URN following the ThreatFox
reference (typed semantic-format parser -> converter registry entry ->
datasource-backed provider composition) with its own test matrices.

## PR 27 closure statement

PR 27A-E delivered the datasource vocabulary, the acquisition-execution/log
substrate, the acquisition-to-semantic boundary, the semantic-format
`ToEvidenceConverter` boundary, and one production migration (ThreatFox)
proving the target runtime end to end. PR 27 is **closed as an incremental
series**, not as a claim that every provider is migrated: the remaining
live sources are tracked above as `LEGACY_NOT_SEMANTICALLY_MODELED`
follow-ups. PR 28 consumes the deterministic datasource fixtures/invariants
from this series for its evaluator/release platform.