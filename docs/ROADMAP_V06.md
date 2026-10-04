# ATI — v0.6 Roadmap

> **Planning status — PROPOSED TARGET / PR 32–33 SERIES**
>
> This document is authoritative for the planned ATI v0.6 MISP, STIX 2.1,
> and TAXII 2.1 datasource-integration series. The v0.5 graph-exploration
> series is preserved in `ROADMAP_V05.md`.

## Purpose

ATI v0.6 expands the datasource architecture delivered by PR 27/28 with two
widely used CTI integration paths:

1. native MISP REST/API ingestion using MISP's own semantic model; and
2. reusable STIX 2.1 Evidence semantics followed by TAXII 2.1 acquisition.

The series preserves ATI's existing separation of provider, datasource
instance, protocol, serialization format, and semantic format. Acquisition
retrieves and decodes source material; semantic adapters validate source-native
objects; `ToEvidenceConverter` implementations convert supported source
semantics into zero or more ATI `ConvertedEvidence` values; the existing
Evidence/extraction/persistence architecture remains authoritative.

The series must also follow ATI's bounded asynchronous-I/O principle:
independent I/O is executed concurrently where doing so preserves semantics,
with explicit bounds and without violating ordering, transaction, lease,
checkpoint, rate-limit, budget, or orchestration invariants.

## Ordering decision

MISP is implemented before TAXII.

This is intentional. Native MISP support can exercise ATI's existing
semantic-format-driven conversion architecture with relatively direct IOC
mappings before ATI expands its general CTI semantics. TAXII is primarily an
acquisition protocol for STIX content; useful TAXII support therefore follows
the reusable STIX 2.1 semantic/conversion work rather than embedding STIX
interpretation inside a TAXII adapter.

The target progression is:

```text
PR 32 — native MISP
        |
        | proves another native semantic format
        v
PR 33A-D — reusable STIX/CTI semantics
        |
        v
PR 33E — TAXII 2.1 acquisition
```

MISP and TAXII must not introduce parallel Evidence persistence,
relationship-persistence, investigation-orchestration, or datasource lifecycle
architectures.

## Series decomposition

| PR | Scope | Principal result |
|---|---|---|
| **32A** | MISP semantic model and parser | Validated, immutable MISP semantic records with exact source/Event context and no Evidence construction |
| **32B** | MISP-to-Evidence conversion | Native MISP semantic-format registration and deterministic IOC-focused `MispToEvidenceConverter` |
| **32C** | MISP acquisition | Bounded MISP REST acquisition, authentication, pagination/filtering, safe errors, provenance, and deterministic fake boundary |
| **32D** | MISP runtime integration and closure | Production composition, datasource lifecycle, real-stack vertical slices, documentation, and source audit |
| **33A** | STIX 2.1 semantic refactoring | Reusable single-object STIX validation independent of Bundle/TAXII envelopes; explicit ATI STIX Evidence profile |
| **33B** | STIX IOC Evidence conversion | `Stix21ToEvidenceConverter` for supported SCOs and bounded Indicator-pattern semantics |
| **33C** | Source-neutral CTI Entity expansion | Selected CTI Entity types required for useful STIX/MISP intelligence and graph exploration |
| **33D** | Source-asserted relationships and STIX sightings | Evidence-backed deterministic relationship assertions and STIX Relationship/Sighting mappings without direct converter persistence |
| **33E** | TAXII 2.1 acquisition and runtime integration | TAXII discovery/collections/envelopes/pagination/incremental retrieval feeding the reusable STIX 2.1 pipeline |

## Cross-series architectural invariants

The following rules apply to every PR in v0.6:

- acquisition and semantic conversion remain separate;
- converter selection is based only on `semantic_format`, never provider,
  protocol, endpoint, or object shape;
- one semantic source object may produce zero, one, or multiple
  `ConvertedEvidence` values;
- valid but unsupported source semantics may deterministically produce zero
  Evidence; unsupported is not equivalent to malformed;
- converters are deterministic and perform no network I/O, persistence,
  orchestration, pivot selection, verdict assignment, or unrestricted
  relationship mutation;
- exact source identity, source observation/version information, retrieval
  provenance, and applicable handling/distribution metadata are preserved;
- source restrictions such as MISP distribution/sharing metadata and STIX
  markings are not silently discarded; preservation does not imply policy
  enforcement unless ATI explicitly implements it;
- source assertions become ATI Relationships only through the existing
  Evidence-backed deterministic extraction/persistence boundary;
- `RelationshipObservation` remains immutable temporal/provenance evidence;
  source timestamps never imply unsupported relationship lifetime semantics;
- datasource lifecycle logging remains operational metadata, not Evidence,
  checkpoint state, or a distributed transaction;
- secrets use the existing `SecretsResolver` composition boundary and are
  never logged or persisted in source references;
- automated tests use ATI-authored deterministic fixtures/fakes and require no
  live MISP or TAXII service;
- real persistence/runtime behavior is proven through the repository's normal
  PostgreSQL/Redpanda integration infrastructure where applicable;
- independent I/O must be evaluated for bounded structured concurrency, while
  semantically ordered work remains sequential.

# PR 32 series — Native MISP integration

## PR 32A — MISP semantic model and parser `[DONE]`

Delivered: durable `SourceId.MISP = urn:ati:source:misp` and
`SemanticFormatId.MISP = urn:ati:datasource:semanticformat:misp`;
`infrastructure/datasources/misp_semantics.py` parses one decoded native
MISP `{"Event": {...}}` envelope into immutable `MispAttributeRecord` /
`MispObjectRecord` records (Event context, Attributes, Objects with nested
Attributes/ObjectReferences, tags, strict UTC timestamps, `deleted`,
distribution/sharing-group state preserved; UUID is upstream identity;
malformed modeled content fails closed with a bounded
`SEMANTIC_VALIDATION` error and zero records); synthetic ATI-authored
fixtures and the deterministic M32A-01..50 matrix; docs. No acquisition,
Evidence conversion (PR 32B), or runtime composition (PR 32C/32D).

Original planning description: introduce the MISP semantic-format identity
and the smallest typed, immutable semantic representation required by ATI.
Preserve MISP source data needed for exact provenance while validating the
fields ATI consumes.

The parser should flatten an acquired MISP Event response into bounded semantic
records suitable for independent conversion rather than requiring one giant
Event conversion. Candidate records include Attribute- and Object-oriented
records carrying the enclosing Event identity/context required for provenance,
tags, timestamps, and applicable distribution/sharing metadata.

Do not construct ATI Evidence in the parser. Do not attempt to model every
MISP schema field as a first-class ATI type. Unsupported valid constructs must
remain distinguishable from malformed source data.

Initial semantic coverage should prioritize common IOC-bearing Attributes,
including domain/hostname, IPv4/IPv6 source/destination forms, and compound
forms such as `domain|ip`. File/hash, URL, certificate, Galaxy, and richer
Object semantics may be added only where the detailed plan can map them to
existing approved ATI concepts without inventing ontology.

## PR 32B — MISP-to-Evidence conversion `[DONE]`

Delivered: `infrastructure/datasources/misp_evidence.py` owns the pure
`MispToEvidenceConverter` (selected exclusively by
`SemanticFormatId.MISP`) plus MISP fact builders and the explicit
side-effect-free `build_misp_conversion_registry()`. Exact five-type IOC
profile (`domain`/`hostname` -> DOMAIN, `ip-src`/`ip-dst` -> IP_ADDRESS
IPv4+IPv6, `domain|ip` -> one Evidence with two ordered IOC facts),
reusing the existing `validate_dns_name`/`canonicalize_ip_address`
canonicalizers; stable global Evidence identity from the exact Attribute
UUID; normalized Event/Attribute/IOC fact shape (preserved `deleted`/
`to_ids`/distribution/sharing/tags/published metadata, `raw_payload=None`,
no verdict/relationship synthesis); zero Evidence for valid unsupported
Attributes and every `MispObjectRecord`; deterministic parser-to-converter
tests (M32B-01..57 + V01..V05) with synthetic ATI fixtures; docs. No
acquisition (PR 32C), runtime composition (PR 32D), or live MISP claim.

Original planning description: add `MispToEvidenceConverter`, registered exclusively under the MISP semantic
format. Convert the approved PR 32A semantic records into deterministic global
Evidence with exact MISP/Event/record provenance.

The initial vertical slice is IOC-focused:

- domain/hostname -> supported DOMAIN semantics;
- IP source/destination forms -> supported IP semantics;
- approved compound attributes -> zero-to-many Evidence in deterministic
  source order;
- valid unsupported Attribute/Object types -> zero Evidence;
- malformed required semantics -> bounded typed conversion failure.

MISP Event metadata, tags, timestamps, and preserved distribution/sharing
metadata remain source facts/provenance. The converter must not assign
maliciousness, directly persist Entities/Relationships, or infer semantics
from arbitrary MISP type names.

## PR 32C — MISP acquisition `[DONE]`

Implement native MISP REST/API acquisition behind ATI's existing datasource
acquisition boundary. Cover endpoint/configuration composition,
`SecretsResolver`-supplied credentials, bounded request/response handling,
pagination or bounded result windows, typed safe errors, cancellation, and
credential-free source references.

Where independent page/detail requests are semantically independent, evaluate
and use bounded structured async I/O according to `ARCHITECTURE.md`; reuse an
existing authoritative HTTP/rate limiter when applicable rather than stacking
unrelated concurrency controls. Ordering required for deterministic conversion,
checkpointing, or source pagination semantics must remain explicit.

Automated tests use deterministic ATI-authored MISP response fixtures and fake
the external HTTP boundary only. No ordinary test contacts a live MISP server.

Delivered by this PR:

- `MispDatasource` + the `extract_misp_event_envelopes()` REST-envelope adapter
  + the `acquire_misp_execution` runner in
  `infrastructure/datasources/misp.py`: dimensions validated fail-closed before
  any I/O, `SecretsResolver`-resolved API key kept header-only, bounded
  sequential pagination against `POST {misp_base_url}/events/restSearch` with
  explicit `page`/`limit` within a validated page-size/max-pages window, real
  `parse_misp_event()` reuse, one credential-free `SemanticSourceContext`,
  bounded typed `DatasourceStageError` outcomes, later-page-failure atomicity,
  cancellation propagation, and no Evidence construction or MISP persistence;
- MISP acquisition settings (`misp_base_url`, `misp_api_key_secret`,
  `misp_max_concurrency`, `misp_requests_per_second`, `misp_page_size`,
  `misp_max_pages`) with documented defaults (`100`/`10`/`4`) and bounds, the
  `.env.example` entries, and `ProviderComposition.misp_datasource`
  composition only when a base URL is configured (an unset URL keeps ordinary
  fake/local startup legal; MISP is **not** registered as a production
  `EvidenceProvider`);
- deterministic unit matrix M32C-01..60 + M32C-C01..C10 + acquisition vertical
  slices M32C-V01..V05 with ATI-authored REST fixtures in
  `tests/support/misp_fixtures.py`; only the external HTTP boundary is faked;
- architecture/configuration/testing documentation and road-map status.

PR 32D remains responsible for production runtime composition and the
semantic acquisition -> conversion -> publication/persistence closure.

## PR 32D — MISP runtime integration and closure `[DONE]`

Compose the MISP datasource through the existing datasource runtime and
converter registry, preserving the PR 27/28 lifecycle and Evidence
publication/persistence boundaries. Add real-stack vertical slices proving
semantic acquisition -> conversion -> Evidence pipeline behavior and exact
provenance without introducing a MISP-specific persistence path.

Reconcile configuration documentation, datasource architecture/source audit,
testing documentation, and v0.6 roadmap status. The closure PR must state
exactly which MISP constructs are supported, preserved-but-not-interpreted,
and unsupported.

# PR 33 series — STIX 2.1 and TAXII 2.1

## PR 33A — Reusable STIX 2.1 semantic refactoring `[DONE]`

Refactor the existing STIX 2.1 semantic parser so individual STIX objects can
be validated independently of a STIX Bundle envelope. Introduce a reusable
single-object validation seam conceptually equivalent to
`parse_stix21_object()`; keep `parse_stix21_bundle()` as an envelope adapter
over that same object contract.

Preserve the existing lossless `Stix21Object` behavior: validate only the
approved common contract while retaining extension/custom fields as immutable
source data. Do not replace it with a universal Pydantic model of the entire
STIX specification.

Define and document an explicit ATI STIX 2.1 Evidence Profile distinguishing:

- valid STIX;
- ATI-supported Evidence-producing STIX;
- valid but currently unsupported STIX;
- malformed STIX.

This PR is semantic refactoring only and must preserve existing MITRE ATT&CK
corpus behavior.

Delivered by this PR:

- `parse_stix21_object()` in
  `infrastructure/datasources/stix21_semantics.py`: ATI's one reusable STIX
  2.1 object semantic boundary — decoded Mapping only, nonblank `type`/`id`,
  optional string `spec_version`, Bundle rejected as "not a STIX object",
  bounded `Stix21SemanticError` (never echoing source values), deep immutable
  lossless snapshots via the existing frozen `Stix21Object` reuse;
- `parse_stix21_bundle()` refactored as an envelope adapter that owns only
  the Bundle container (mapping, `type == "bundle"`, list `objects`, member
  source order, member-index error context) and delegates every member to
  `parse_stix21_object()`; no fake Bundle adaptation and no
  relationship/graph semantics from co-membership;
- the documented ATI STIX 2.1 Evidence Profile vocabulary
  (semantic-valid / Evidence-supported / semantic-valid-but-
  Evidence-unsupported / semantic-malformed) in
  `docs/DATASOURCE_ARCHITECTURE.md`; no Evidence conversion or converter
  registration (PR 33B owns that);
- deterministic matrix M33A-01..30 extending
  `tests/unit/infrastructure/datasources/test_stix21_semantics.py` (direct
  seam, Bundle rejection, lossless nested preservation, bounded
  non-echoing errors, re-parse equality, Bundle delegation proven by
  parity and source inspection, member-index context, module isolation
  from Evidence/provider/HTTP/persistence/TAXII imports), with D27C-S01..12
  and ATT&CK compatibility (`tests/unit/infrastructure/
  test_mitre_attack_source.py` and repository integration suites) kept
  green; no `pyproject.toml`/`uv.lock` change;
- `docs/TESTING.md` and `docs/ROADMAP_V06.md` status documentation.

## PR 33B — STIX IOC Evidence conversion `[DONE]`

Add `Stix21ToEvidenceConverter`, registered under the STIX 2.1 semantic
format independently of TAXII.

Initial support should include approved IOC-oriented Cyber-observable Objects
that map to existing ATI Entity semantics, starting with domain names and
IPv4/IPv6 addresses. Add bounded STIX Indicator-pattern interpretation for the
approved observable/value forms.

Use a standards-compliant STIX pattern parser/AST if a maintained dependency
satisfies ATI's security/licensing requirements; do not implement STIX
patterning with regular expressions. ATI interprets only an explicit whitelist
of pattern constructs/operators. Valid unsupported patterns produce zero
Evidence or another explicitly documented unsupported disposition; they are
never guessed.

Preserve STIX object identity and version information so repeated versions of
one logical STIX object do not lose source provenance.

Delivered by this PR:

- `Stix21ToEvidenceConverter` in
  `infrastructure/datasources/stix21_evidence.py`: registered exclusively by
  `SemanticFormatId.STIX_21`, consumes only already-validated PR 33A
  `Stix21Object` values, maps one supported object to exactly one
  `THREAT_INTELLIGENCE` `ConvertedEvidence` (identity =
  `evidence_id_for_source_record(STIX_21, context source, exact STIX id)`;
  `created`/`modified`/retrieval time never participate), with
  `observed_at=None`, `retrieved_at`/`source_url` from the semantic
  context, and `raw_payload=None`;
- direct SCO profile `domain-name`/`ipv4-addr`/`ipv6-addr` reusing
  `validate_dns_name`/`canonicalize_ip_address` with enforced IP family
  (an `ipv4-addr` carrying IPv6 and an `ipv6-addr` carrying IPv4 each fail
  closed), plus bounded Indicator conversion for the approved
  equality-only whole-pattern whitelist (left-to-right ordered leaves,
  duplicates preserved, never partially extracted);
- `stix21_pattern.py`: the ATI-owned structural pattern adapter over the
  maintained OASIS `stix2-patterns` dependency (` >=2.1.2,<3`, the first
  Python-3.14-capable line; only transitive dependency is the
  BSD-3-Clause antlr4 runtime), distinguishing SUPPORTED /
  VALID_BUT_UNSUPPORTED / MALFORMED with bounded content-safe error
  classification; no regex/string-splitting grammar exists;
- deterministic M33B-01..78 matrix and M33B-V01..V06 vertical slices
  (real PR 33A seam, real pattern parser, real registry, real generic
  conversion) in
  `tests/unit/infrastructure/datasources/test_stix21_evidence.py` and
  `test_stix21_pattern.py`, with ATI-authored synthetic fixtures in
  `tests/support/stix21_fixtures.py`;
- `pyproject.toml` + `uv.lock` bounded dependency, `docs/` status
  documentation (`DATASOURCE_ARCHITECTURE.md`, `DATA_SOURCES.md`,
  `TESTING.md`, `ROADMAP_V06.md`);
- mandatory gates green on final head: `./build.sh --qa` (5993 unit tests,
  87.52% coverage, Ruff/Mypy/frontend), `./build.sh --intg` (1011 passed,
  27 skipped), `./build.sh --sec` (Bandit/Semgrep/Safety/pip-audit); PR 33A
  semantic, MITRE batch, generic conversion, and MISP conversion
  regressions stay green; no TAXII, Entity expansion, relationship/
  sighting persistence, or runtime acquisition change.

## PR 33C — Source-neutral CTI Entity expansion `[DONE]`

Add exactly five source-neutral CTI Entity types — `THREAT_ACTOR`,
`CAMPAIGN`, `INTRUSION_SET`, `TOOL`, and `INFRASTRUCTURE` (wire values
`threat_actor`, `campaign`, `intrusion_set`, `tool`, `infrastructure`) —
to close the actor/tool/campaign/infrastructure gap for the STIX/MISP
roadmap and PR 33D graph endpoints. `MALWARE`, `VULNERABILITY`, and
`ATTACK_TECHNIQUE` already exist and were **not** introduced by 33C. A
generic `ATTACK_PATTERN` is deliberately not added: ATI already owns the
narrower `ATTACK_TECHNIQUE` ATT&CK-identity contract, and blindly equating
arbitrary STIX `attack-pattern` identity with ATT&CK identity would be
semantically wrong.

This is an ATI domain expansion, not a STIX-specific mirror of every SDO.
Each admitted Entity type has explicit canonicalization, display,
query/graph, extraction, seed-exclusion, persistence, API/frontend, and
test semantics where those surfaces apply. MISP may reuse these types in
later enrichment without gaining a parallel MISP ontology; no MISP↔STIX
identity merge occurs without an explicit future equivalence mechanism.

Delivered by this PR:

- domain: five `EntityType` members plus one shared strict machine-ID
  canonicalization mechanism (`canonicalize_cti_object_id` and the five
  registered `_CANONICALIZERS`): STIX-derived canonical values are the
  **exact validated STIX 2.1 object `id`** (`<type>--<canonical uuid>`),
  validated (never normalized/alised/slugified) and returned
  byte-for-byte; wrong/mutated prefixes, missing `--`, non-canonical
  UUID spellings, surrounding whitespace, blank values, human `name`
  values, and aliases fail closed; `CTI_ENTITY_DISPLAY_NAME_MAX_LENGTH =
  512` bounds display metadata, which never participates in identity;
- converter: `stix21_evidence.py` (still the **only** STIX converter,
  keyed solely by `SemanticFormatId.STIX_21`) admits exactly
  `threat-actor`, `campaign`, `intrusion-set`, `tool`, and
  `infrastructure`, each mapping to exactly one `THREAT_INTELLIGENCE`
  Evidence whose normalized facts carry one explicit `cti_entity` block
  (`type` ATI wire value / exact machine value / verbatim `display_name`)
  and `iocs: []`; PR 33B IOC/Indicator Evidence keeps `cti_entity:
  null`; malformed required identity/name is a bounded `ConversionError`;
  valid unsupported objects (including `relationship`, `sighting`,
  generic `attack-pattern`/`malware`/`vulnerability`) return zero
  Evidence; reference fields, aliases, markings, and descriptions stay
  unconsumed source facts;
- extraction: source-neutral `app/extraction/stix.py` consumed through the
  durable message seam (`message_context.py` reconstructs the STIX
  invocation from the `cti_entity` fact or the first ordered `iocs` entry
  — source-fact-derived, never a fabricated semantic owner), dispatched
  by semantic format with deliberately no fixed `SourceId` guard;
  `EvidenceExtractionView` gained an optional `semantic_format`;
  deterministic extraction produces one canonical CTI Entity (or every
  represented PR 33B IOC identity, first-seen deduplicated) and zero
  relationships; malformed durable facts fail closed with
  `EvidenceExtractionError(MALFORMED_FACTS)` without echoing content;
- persistence: reuses the global Evidence batch path unchanged
  (`ati.persist_evidence_batch`; `entity_type` is generic text with no
  DB enum/CHECK, so **no migration** was needed); Evidence +
  `EvidenceObservation` + `EvidenceObservationEntity` per existing
  version/upsert semantics; CTI SDOs create zero Relationship and zero
  RelationshipObservation rows; source namespace is part of Evidence
  identity while Entity identity stays `(EntityType, canonical value)`;
- seeds: `INVESTIGATION_SEED_TYPES` is an explicit allowlist of the nine
  established seed types; the five CTI types are rejected at the
  application validation boundary so provider/research orchestration is
  never invented for them (graphability never implies seedability);
- API/frontend: OpenAPI snapshot and generated TypeScript expose the five
  wire values through the existing `EntityType` enum; the exhaustive
  `ENTITY_TYPE_LABEL_KEYS` registry, English `relationshipEvolution`
  i18n labels (Threat actor / Campaign / Intrusion set / Tool /
  Infrastructure), and `GRAPH_ENTITY_TYPES` filter accept the new types
  textually; the Investigation-seed form (`ENTITY_TYPE_OPTIONS`) is
  intentionally unchanged; generic entity-ID pivot actions work for CTI
  nodes with no CTI-specific endpoint;
- deterministic M33C-D01..D25, M33C-S01..S35, M33C-X01..X34, and
  M33C-U01..U15 matrices plus M33C-V01..V07 real-PostgreSQL vertical
  slices (one threat-actor Entity persistence, all five types,
  same-name/different-ID anti-merge, version/display-name continuity,
  source-namespace separation, multi-leaf Indicator association, and
  generic graph/API projection with test-only relationship fixtures),
  with ATI-authored synthetic fixtures in `tests/support/stix21_fixtures.py`;
- `docs/` status updates (`DATASOURCE_ARCHITECTURE.md`, `DATA_SOURCES.md`,
  `TESTING.md`, `DOMAIN_MODEL.md`, `ROADMAP_V06.md`);
- mandatory gates green on final head: `./build.sh --qa`
  (Ruff/Mypy/frontend + 6092 unit tests at 87.54% coverage ≥ 85),
  `./build.sh --intg` (1018 passed, 27 skipped on real PostgreSQL +
  Redpanda, plus the frontend production bundle), `./build.sh --sec`
  (Bandit/Semgrep/Safety/pip-audit); PR 33A/33B,
  MISP, ThreatFox, generic conversion, and Investigation regressions stay
  green.

No relationship/sighting semantics (PR 33D), TAXII acquisition (PR 33E),
MISP Galaxy/cluster conversion, cross-source entity resolution, new
persistence path, second STIX converter, or generic STIX ontology mirror
was introduced.

## PR 33D — Source-asserted relationships and STIX sightings [DONE]

Introduced source-neutral deterministic handling for external intelligence that
asserts relationships, then mapped the approved bounded STIX Relationship and
Sighting profile through that mechanism.

A STIX converter preserves the source assertion as Evidence facts; the
existing deterministic extraction/application persistence boundary owns
canonical ATI Relationship and immutable RelationshipObservation creation.
No `StixRelationshipPersistenceService` was created and converters never
write graph state directly.

Delivered scope:

- four source-neutral RelationshipType URNs (`USES`, `TARGETS`,
  `ATTRIBUTED_TO`, `CONTROLS`) with all pre-existing relationship URNs
  unchanged;
- the stable `source_assertion` normalized-fact key (never conditionally
  absent; `null` for PR 33B/33C Evidence) and the source-neutral
  normalized-fact validation seam (`app/extraction/source_assertion.py`)
  reusable by a future MISP Object Reference adapter;
- supported STIX Relationships: the exact §5.3 profile (admitted
  relationship string + five-CTI endpoint type pairs) -> exactly one
  Evidence with pinned assertion facts, canonical endpoint machine
  identities, normalized `start_time`/`stop_time`, and
  `observed_at=None`; valid-but-unsupported Relationships yield zero
  Evidence; malformed consumed fields of admitted-profile candidates raise
  bounded `ConversionError` without echoing source content;
- supported STIX Sightings: `sighting_of_ref` canonical to one of the five
  CTI Entity types -> exactly one Evidence preserving
  `first_seen`/`last_seen`/`count`/`summary` and bounded ordered
  `where_sighted_refs`/`observed_data_refs` (maximum 256) with
  `observed_at=None`; Sighting conversion creates zero graph edges;
- durable message reconstruction derives only safe transient invocation
  identities (a Relationship's source endpoint, a Sighting's
  `sighting_of`) and fails closed on contradictory durable shapes;
- deterministic extraction revalidates the full durable assertion,
  cross-checks the STIX/ATI/endpoint profile mapping (tampered messages
  fail closed), and yields the endpoint Entities plus exactly one approved
  RelationshipAssertion (Sightings yield the sighted Entity only);
- reuse of the existing global Evidence batch persistence path with exact
  `EvidenceObservation` -> `RelationshipObservation` provenance:
  repeated assertions of the same semantic edge reuse one Relationship
  with per-Evidence observations, material version updates append
  observations, and a semantic-edge change under one stable Evidence
  identity preserves historical edges without deletion or end inference;
- real PostgreSQL vertical slices (M33D-V01..V10) and real
  Redpanda + PostgreSQL distributed-ingestion acceptance (M33D-K01..K03);
- no migration, no STIX-specific persistence path/repository/table/topic,
  no new converter, no Investigation admission expansion, and no TAXII
  code (PR 33E keeps ownership).

Preserved `observed_at`, source first/last-seen fields, retrieval time, and
source assertion timestamps as distinct concepts. No relationship
start/end, continuity, currentness, or absence-after-`stop_time` is ever
inferred, and no Sighting `where_sighted_refs`/`observed_data_refs` edge or
placeholder Identity/Location/ObservedData Entity is fabricated.

The source-neutral assertion seam is reusable by MISP Object References
when/if their richer relationship semantics are enabled.

## PR 33E — TAXII 2.1 acquisition and runtime integration

Implement TAXII 2.1 as an acquisition/protocol integration that feeds the
existing STIX 2.1 semantic pipeline.

Support the bounded subset required for production-quality collection
ingestion: server/API-root discovery as needed by ATI configuration,
collection selection, TAXII envelopes, authentication, pagination, supported
server filtering, incremental retrieval (including `added_after` where
applicable), typed safe errors, cancellation, datasource lifecycle/provenance,
and production composition.

A TAXII envelope is not rewritten into a fake STIX Bundle. The TAXII adapter
validates its own envelope and passes each contained STIX object through the
PR 33A single-object STIX semantic boundary.

Apply bounded structured async I/O only where TAXII operations are independent.
Pagination/incremental checkpoint semantics that depend on previous responses
remain ordered. Reuse subsystem-owned HTTP concurrency/rate limiting rather
than introducing competing limiters.

Add deterministic fake TAXII fixtures/server-boundary behavior plus real ATI
runtime/persistence vertical slices. Automated tests must not require a live
public TAXII service.

## Deferred beyond v0.6

The following are not implied by this roadmap and require separate approval:

- exhaustive support for every MISP Attribute/Object/Galaxy construct;
- full MISP distribution-policy enforcement;
- exhaustive STIX 2.1 SDO/SCO/SRO coverage;
- a home-grown STIX Patterning implementation;
- arbitrary custom STIX relationship semantics without an explicit ATI
  mapping;
- STIX marking-policy enforcement beyond preservation;
- TAXII server implementation (ATI is a TAXII client/consumer here);
- unbounded TAXII collection mirroring;
- replacement of PostgreSQL with a graph database;
- MISP/TAXII-specific Evidence persistence paths;
- changes to Coordinator investigative decision semantics merely to ingest a
  datasource.

## v0.6 completion criteria

v0.6 is complete when:

1. MISP is a production-composed datasource using its native semantic format
   and the standard ATI Evidence pipeline.
2. The supported MISP Evidence profile is explicit, deterministic, and proven
   without live external services.
3. STIX individual-object validation is reusable independently of Bundle and
   TAXII envelopes while existing MITRE behavior remains compatible.
4. STIX 2.1 has a registered Evidence converter with an explicit supported
   profile and deterministic unsupported-object behavior.
5. Approved CTI Entity and source-asserted relationship semantics are
   source-neutral rather than STIX/MISP persistence special cases.
6. TAXII 2.1 acquisition feeds the reusable STIX semantic/conversion pipeline
   without fabricating STIX Bundle envelopes.
7. MISP/TAXII authentication and source references preserve ATI's secrets and
   safe-error rules.
8. Independent I/O uses bounded concurrency where semantically appropriate,
   and ordered/transactional/checkpointed work remains sequential.
9. Unit tests are deterministic and ordinary CI requires no live MISP/TAXII
   endpoints or API keys.
10. Applicable real PostgreSQL/Redpanda integration gates and the repository
    canonical quality/security gates pass.
11. Architecture, configuration, testing, datasource/source-audit, and roadmap
    documentation accurately describe the delivered behavior and limitations.
