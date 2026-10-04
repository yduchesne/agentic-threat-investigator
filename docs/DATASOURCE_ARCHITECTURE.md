# Agentic Threat Investigator — Datasource Architecture

## Status

This document defines the target datasource architecture for the PR 27 series. It is a forward design contract: existing PR 18/19 provider behavior remains authoritative until the corresponding PR 27 slice lands. PR 27 must migrate incrementally without breaking Investigation execution or Evidence provenance.

PR 27A (vocabulary), PR 27B (execution/logging), PR 27C
(acquisition-to-semantic boundary), PR 27D
(`ToEvidenceConverter`), and PR 27E (existing-source migration
and series closure) have landed. PR 27E migrated the ThreatFox
production Investigation runtime onto the PR 27A-D stack and closed
the series with a source-by-source migration audit. PR 28C later
delivered the pure `EvidenceMessage` v1 wire contract between
conversion and the distributed-log boundary, PR 28D the broker-neutral
publisher/consumer/log abstraction, and PR 28F-2 the generic datasource
Evidence producer seam: one execution's flattened output becomes one
ordered `EvidencePublisher` publication with the non-terminal
`PUBLISHED` lifecycle stage, and producer `COMPLETED` means successful
publication — never consumer/PostgreSQL persistence. The producer path
is delivered and proven at the application boundary; production
Investigation execution still runs synchronously through the PR 27E
compatibility path, which remains transitional. PR 28G delivered the
production Kafka/Redpanda adapters behind the unchanged PR 28D contracts,
and PR 28H closed the full producer -> log -> consumer -> PostgreSQL path
with real-stack integration coverage (H28H-01..21).

### PR 27A landed vocabulary

PR 27A established the typed datasource vocabulary and configuration contract on
`main` without migrating any runtime behavior:

- `DatasourceId` (`src/agentic_threat_investigator/domain/datasource.py`): typed
  identity of one configured datasource instance. It identifies configuration,
  not provider and not execution; multiple datasource instances may share one
  `SourceId`. Canonical lowercase kebab form, bounded to 64 characters.
- `DatasourceProtocol`: typed acquisition protocol vocabulary. Current values
  are `https` and `file` only. **TAXII is a protocol concept, never a semantic
  format**; a `taxii` protocol value will be added when the first
  TAXII-capable datasource is introduced.
- `SerializationFormat`: typed physical serialization vocabulary. Current value
  is `json` only. **JSON is serialization, never semantics**; STIX, ThreatFox,
  MISP, and TAXII are never serialization formats.
- `SemanticFormatId` (`src/agentic_threat_investigator/domain/identifiers.py`):
  stable durable semantic-format URNs
  `urn:ati:datasource:semanticformat:stix21` and
  `urn:ati:datasource:semanticformat:threatfox`. **STIX 2.1 is a semantic
  format, not a protocol or serialization**; ThreatFox has its own
  provider-specific semantic format under its own durable URN.
- `DatasourceDefinition` (`domain/datasource.py`): one immutable typed
  five-dimension model `(datasource_id, source_id, protocol,
  serialization_format, semantic_format)`. Every dimension is explicit and
  independent; none is inferred from another and unknown typed values fail
  closed.
- `Settings.datasources` (`config/settings.py`): typed tuple exposing the
  canonical `DatasourceDefinition` collection, with unique datasource IDs
  enforced and multiple datasource instances allowed to share one `SourceId`.
  The repository-owned representative defaults are `threatfox-live`
  (HTTPS + JSON + ThreatFox semantics) and `mitre-attack-enterprise`
  (FILE + JSON + STIX 2.1 semantics).

A datasource definition describes configuration, not acquisition execution:
PR 27A does **not** implement `execution_id`, per-execution datasource logging,
`ToEvidenceConverter`, a converter registry, or any change to the existing
`EvidenceProvider`/`BatchSource` runtime paths. `semantic_format` is the
converter-selection dimension used by the PR 27D `ToEvidenceConverter`;
PR 27A itself added no converter.

## Objective

ATI must separate **where/how data is acquired** from **what the acquired data means** and from **how source semantics become ATI Evidence**.

The target pipeline is:

```text
Datasource definition
  -> acquisition execution
  -> protocol transport / local read
  -> serialization decoding
  -> source semantic objects
  -> ToEvidenceConverter selected by semantic_format
  -> 0..N ATI Evidence
  -> existing Evidence persistence / extraction / investigation pipeline
```

Acquisition is not Evidence construction. Serialization is not semantics. A provider identity is not a semantic-format identity.

## Vocabulary and independent dimensions

A configured datasource has independent dimensions:

```text
Datasource
  provider
  protocol
  serialization_format
  semantic_format
  location / endpoint / artifact configuration
  acquisition policy
```

## Other documents

- [Data Sources](DATA_SOURCES.md)

### Datasource

A **Datasource** is one configured acquisition source. It is the runtime/configuration unit ATI can execute. Two datasource instances may use the same provider and semantic format while differing in endpoint, local artifact, schedule, credentials, or acquisition policy.

### Provider

A **Provider** identifies the upstream producer/operator or ATI integration family. Provider identity is useful for configuration, attribution, credentials, source policy, and operational behavior. It does not select semantic conversion by itself.

### Protocol

A **Protocol** identifies how ATI obtains the source material, for example HTTPS, TAXII, or local file access. Protocol determines acquisition mechanics, not the meaning of records.

### Serialization format

A **SerializationFormat** identifies the physical encoding/representation, for example JSON, JSON Lines, CSV, XML, or a binary database/file representation. Serialization decoding yields values/records that can then be interpreted according to the semantic format. The JSON engine is infrastructure (v0.2 uses `orjson` for provider response parsing, PR 28F-1): it never owns semantic validation, which remains defined by each source's semantic-format module.

### Semantic format

A **SemanticFormat** identifies the meaning/schema of source objects. Converter selection is based on this value.

Examples:

```text
urn:ati:datasource:semanticformat:stix21
urn:ati:datasource:semanticformat:threatfox
urn:ati:datasource:semanticformat:misp
```

Provider-specific/proprietary semantic models receive their own ATI URNs. ThreatFox therefore uses `urn:ati:datasource:semanticformat:threatfox` even though its transport is HTTPS and its serialization is JSON. MISP (PR 32A) is a native semantic format — `urn:ati:datasource:semanticformat:misp` with `SourceId.MISP = urn:ati:source:misp` — and is deliberately **not** translated through STIX/TAXII.

Semantic format is independent of provider, protocol, serialization format, and datasource instance.

## Why the dimensions must remain separate

These combinations are all valid:

- two providers can publish the same semantic format;
- one provider can publish more than one semantic format;
- the same semantic format can be transported over different protocols;
- the same semantic format can use different serializations;
- multiple configured datasource instances can share all four classifications but differ operationally.

Therefore ATI must not infer semantic conversion from provider, protocol, filename extension, MIME type, or JSON shape alone.

## Acquisition execution (PR 27B, delivered)

Every datasource acquisition execution receives a new `execution_id` UUID,
generated once at the application execution boundary and passed unchanged to
every operational event of that execution.

All operational log events belonging to that execution carry the same
`execution_id` and the same `datasource_id`.

Conceptually:

```text
execution_id = X
  started
  acquired
  decoded
  converted
  completed
```

or:

```text
execution_id = Y
  started
  failed
```

or:

```text
execution_id = Z
  started
  cancelled
```

`execution_id` correlates one execution; it is not datasource identity,
Investigation identity, Evidence identity, source-record identity, artifact
identity, or a durable execution entity.

PR 27B delivered the smallest durable append-only datasource log
(`ati.datasource_log`, SQL API v0025, migration 0030) rather than a separate
durable execution table. The landed contract:

- the closed lifecycle vocabulary is `STARTED`, `ACQUIRED`, `DECODED`,
  `CONVERTED`, `COMPLETED`, `FAILED`, `CANCELLED`, with terminal outcomes
  exactly `COMPLETED`/`FAILED`/`CANCELLED`;
- STARTED is first and unique per execution; at most one terminal outcome
  exists; no event may follow a terminal outcome; all events of one
  execution share one `datasource_id`; omitted intermediate stages are legal;
- lifecycle/concurrency invariants are owned by the versioned stored
  function (`ati.append_datasource_log_event`) under a per-execution
  transaction-scoped advisory lock, with partial unique indexes as the
  STARTED/terminal backstop;
- durable events carry only bounded operational metadata: stage-local
  non-negative `item_count`/`byte_count` and a bounded safe `error_code`
  bound to `FAILED`; source bodies, decoded objects, Evidence bodies,
  credentials, tokens, and raw exception text are excluded by the schema;
- `DatasourceExecutionRecorder` (`app/datasource_execution.py`) centralizes
  event creation and one execution identity, appending each event in a short
  committed UnitOfWork transaction so no database transaction is held across
  acquisition/decode/conversion work; cancellation stays cancellation
  (`CancelledError` propagates after a best-effort CANCELLED append).

Later PR 27C–27E reuse this execution identity and append lifecycle events
at the actual acquisition/decoding boundaries. They must not create a second
execution/logging concept. Existing providers remained on the transitional
pre-27C path until PR 27E (ThreatFox now runs the migrated datasource path;
see `PR_27_SOURCE_MIGRATION_AUDIT.md`).

## Acquisition-to-semantic boundary (PR 27C, delivered)

PR 27C landed the boundary between decoded external data and ATI-owned
downstream products, without implementing conversion (PR 27D) or migrating
existing sources (PR 27E):

```text
DatasourceDefinition
 -> acquisition execution (PR 27B recorder)
 -> protocol transport / local artifact read
 -> serialization decode
 -> decoded external value
 -> semantic-format-specific parser/validator
 -> typed semantic source objects + bounded provenance context
 ---------------- PR 27D boundary ----------------
 -> semantic-format registry -> ToEvidenceConverter
 -> 0..N Evidence
```

Cross-cutting contracts (`src/agentic_threat_investigator/app/datasource_semantics.py`):

- `SemanticSourceContext`: an immutable cross-cutting provenance context
  whose datasource/source/semantic-format identities are derived from one
  `DatasourceDefinition`, with timezone-aware UTC-normalized retrieval
  time and optional credential-free source/artifact references. It carries
  no union of source-specific fields, no Investigation/Evidence ID, no
  verdict/risk/relationship, and no credentials or headers.
- `DatasourceStage` + `DatasourceStageError`: a stage-aware datasource
  failure contract (ACQUISITION / SERIALIZATION / SEMANTIC_VALIDATION /
  CONVERSION) with bounded safe error codes from the PR 27B grammar.
  Stage values never overload lifecycle event types.
- `SemanticAcquisitionResult[T]`: a small generic result
  (context + typed objects + optional bounded stage error) whose
  invariant is success/empty-semantics vs failure with no objects.

Format-specific parsers (`src/agentic_threat_investigator/infrastructure/datasources/`):

- `threatfox_semantics.py` owns the ThreatFox semantic contract (strict
  record model, official UTC timestamp form, URL validation, IOC
  parsing/matching, response-envelope/query-status validation, duplicate-ID
  rules, unrelated-record rejection) and `parse_threatfox_response` for
  decoded values. The legacy `ThreatFoxProvider` reuses this parser and
  keeps only Evidence-specific construction (`_build_match_facts`) locally;
  its public behavior is unchanged.
- `stix21_semantics.py` owns a narrow STIX 2.1 decoded-value parser with
  one reusable object boundary and one envelope adapter (PR 27C + PR 33A):
  `parse_stix21_object` validates exactly one decoded non-Bundle STIX
  object (`Stix21Object`): mapping, nonblank `type`/`id`, optional string
  `spec_version`, and deeply immutable snapshots that preserve every
  extension field (`x_mitre_*`, unknown valid types, nested
  extensions/custom members) as data. `parse_stix21_bundle` is an envelope
  adapter only: it validates the Bundle container (mapping, `type ==
  "bundle"`, list `objects`, member source order, member-index error
  context) and delegates every member to `parse_stix21_object`. Future
  TAXII 2.1 acquisition reuses the same object seam without manufacturing a
  Bundle envelope. A Bundle passed to the object parser is rejected: a
  Bundle is not a STIX object, and Bundle membership never implies
  relationship/graph semantics. The parser is independent of MITRE ATT&CK
  `SourceRecord` normalization, ATI Evidence, and TAXII; it deliberately
  does not reimplement the full STIX 2.1 standard. `MitreAttackBatchSource`
  consumes it as its decoded-value boundary with `SourceRecord` identity,
  content-hash, checkpoint, batch, and ingestion behavior unchanged.
- `misp_semantics.py` owns the PR 32A native MISP semantic boundary
  (`parse_misp_event` -> `MispAttributeRecord` / `MispObjectRecord`): one
  decoded `{"Event": {...}}` envelope validates to immutable source records
  preserving UUID identity, UTC timestamps, Attribute
  `category`/`type`/`value`, `deleted`, tags, and
  distribution/sharing-group state; Event-level Attributes are returned
  before Objects in source order, and Object-owned Attributes/
  ObjectReferences stay nested (never duplicated top level) for future
  0..N conversion in PR 32B. It performs no acquisition, Evidence
  construction, or persistence; MISP REST acquisition is PR 32C and
  runtime composition is PR 32D, and converter selection remains
  semantic-format-driven.
- `threatfox.py` is the narrow production ThreatFox acquisition-to-semantic
  reference path (`ThreatFoxDatasource` + tiny runner): it validates the
  explicit datasource dimensions (THREATFOX + HTTPS + JSON + THREATFOX)
  fail-closed before any I/O, reuses `ProviderHttpClient` (Auth-Key stays
  header-only) and the PR 27B `DatasourceExecutionRecorder`, classifies
  failures by typed stage (never by matching free-form message text), and
  persists only bounded safe terminal codes.
- `misp.py` is the bounded native MISP REST acquisition path
  (`MispDatasource` + `extract_misp_event_envelopes` + tiny runner): it
  validates the explicit datasource dimensions (MISP + HTTPS + JSON +
  MISP) fail-closed before any I/O, authenticates with a
  `SecretsResolver`-resolved key kept header-only, paginates strictly
  sequentially within a validated page-size/max-pages window through the
  existing `ProviderHttpClient` (which owns every HTTP admission/bound),
  adapts each `events/restSearch` response member into the exact
  `{"Event": {...}}` envelope PR 32A accepts, and returns typed
  `MispSemanticRecord` values under one credential-free
  `SemanticSourceContext`; a later-page failure fails the whole bounded
  acquisition with zero objects. It performs no Evidence construction and
  no MISP persistence.

Semantic modules construct no ATI Evidence/`SourceRecord`, perform no
network/DB/persistence I/O, and never log full source objects. There is no
universal mega-schema (ThreatFox and STIX objects remain source-native),
no semantic-object persistence table, and no migration in this slice.

### ATI STIX 2.1 Evidence Profile vocabulary (PR 33A)

PR 33A documents the vocabulary that separates semantic validity from
Evidence production and from malformed input. It implements no Evidence
conversion (PR 33B owns that). The four categories are:

- **Semantic-valid** — the object satisfies ATI's reusable `Stix21Object`
  boundary (mapping, nonblank `type`/`id`, optional string
  `spec_version`). This does not claim complete normative STIX validation
  and does not imply Evidence production.
- **Evidence-supported** — ATI has an explicit deterministic
  `Stix21ToEvidenceConverter` mapping. PR 33A implemented none; PR 33B
  delivered the initial approved profile: `domain-name`, `ipv4-addr`,
  `ipv6-addr` direct SCOs and bounded equality-only Indicator patterns;
  PR 33C adds the five CTI SDO types `threat-actor`, `campaign`,
  `intrusion-set`, `tool`, and `infrastructure` (see the PR 33B/PR 33C
  sections below).
- **Semantic-valid but Evidence-unsupported** — acceptable at the semantic
  boundary but no approved Evidence mapping exists yet. Examples include
  malware, relationship, sighting, identity, location, course-of-action,
  and custom objects until their owning PRs land. Unsupported is not
  malformed.
- **Semantic-malformed** — violates the boundary ATI owns: non-Mapping,
  missing/blank/non-string type or id, invalid current-contract
  `spec_version` type, or a Bundle passed to the object parser.

## Semantic-format Evidence conversion (PR 27D + PR 28A, delivered)

PR 27D landed the pure semantic-object -> Evidence conversion boundary in
`app/evidence_conversion.py` and the ThreatFox reference converter in
`infrastructure/datasources/threatfox_evidence.py`. PR 28A made the
boundary global and Investigation-independent:

- `EvidenceConversionContext`: an immutable dataclass carrying **only** one
  reused `SemanticSourceContext` (PR 28A removed the ATI Investigation
  identity and the canonical subject binding — global Evidence conversion
  has no Investigation/subject context). It carries no transport objects,
  secrets, repositories, callbacks, verdicts, or relationships;
- `ToEvidenceConverter(ABC, Generic[TSource])`: stateless, deterministic,
  synchronous pure mapping from **one** already-validated source object
  plus the explicit context to a `tuple[ConvertedEvidence, ...]`
  (zero/one/many), where each `ConvertedEvidence` is a stable global
  `Evidence` (deterministic PR 28A identity) plus its
  `EvidenceObservationCandidate` (material state with no fabricated
  observation ID/version/diff);
- `ToEvidenceConverterRegistry`: immutable, keyed only by
  `SemanticFormatId` — never SourceId/DatasourceId/provider/protocol/
  serialization/object shape. Duplicate registration fails closed; an
  unknown format raises the narrow typed `UnknownSemanticFormatError`;
  there is no default/fallback converter and no global mutable or
  import-time registration;
- `convert_semantic_source_objects`: deterministic flattening of bounded
  semantic tuples in source-object-then-converter-return order;
- `DatasourceStage.CONVERSION`: typed conversion-stage failure ownership;
  the durable lifecycle reuses the PR 27B recorder and the existing
  `CONVERTED` event (no new lifecycle event);
- `ThreatFoxToEvidenceConverter` (`semantic_format == THREATFOX`, input
  `ThreatFoxRecord`): one record -> one `ConvertedEvidence` whose Evidence
  identity is pinned to `(THREATFOX, THREATFOX, ThreatFoxRecord.id)` via
  `evidence_id_for_source_record`, sharing
  `build_threatfox_match_facts`/`format_threatfox_fact_timestamp` with
  the legacy `ThreatFoxProvider` (no longer composed by production
  bootstrap as of PR 27E), and a tiny lifecycle runner
  (`acquire_and_convert_threatfox_execution`) exercising
  STARTED/ACQUIRED/DECODED/CONVERTED/COMPLETED, `CONVERTED(0)`
  success, bounded `conversion_failed`, and cancellation semantics.

The context carries only cross-cutting provenance:

```text
SemanticSourceContext
    acquisition/source provenance (datasource, source, semantic format,
    retrieval time, credential-free reference/artifact)

EvidenceConversionContext (PR 28A)
    exactly one SemanticSourceContext; no Investigation, no subject
```

Converters assign the deterministic global Evidence identity but never
allocate observation versions (authoritative version allocation is PR 28B
persistence), perform no I/O/persistence/clock/random/secret reads, and
synthesize no verdicts, confidence weights, attribution, relationships,
pivots, or Investigation control flow. Since PR 28B the runtime carries
the `ConvertedEvidence` values unchanged — there is no `LegacyEvidence`
rebind at the runtime/persistence boundary; PostgreSQL owns observation
identity, versioning, and material no-op detection. The pure
`EvidenceMessage` v1 wire contract is delivered in PR 28C below
(`ToEvidenceConverter` -> `ConvertedEvidence` -> `EvidenceMessage` v1)
and the broker-neutral `EvidencePublisher`/`EvidenceConsumer`
contracts plus deterministic `InMemoryEvidenceLog` are delivered in
PR 28D (`app/evidence_log.py`). PR 28F-2 delivers the datasource
Evidence producer seam (`app/datasource_evidence_producer.py`): one
execution's flattened `ConvertedEvidence` tuple becomes an ordered
`EvidenceMessage` tuple with execution-local zero-based sequence and
the exact `datasource_execution_id`, published with exactly one
`EvidencePublisher.publish(...)` call, followed by the non-terminal
`PUBLISHED` stage (`item_count` = accepted message count) and
`COMPLETED`. The producer completes on successful publication and
never waits for the PR 28E consumer. No production Investigation
runtime is rerouted through the log: the PR 27E compatibility path
remains synchronous/transitional (PR 28G delivered the Kafka/Redpanda
adapters; PR 28H delivered the real-stack producer -> log -> consumer ->
PostgreSQL closure as integration coverage, without wiring a production
runner that would require Investigation orchestration redesign).

## Native MISP Evidence conversion (PR 32B, delivered)

PR 32B lands the MISP IOC Evidence profile as the second native
semantic-format converter: `infrastructure/datasources/misp_evidence.py`
owns `MispToEvidenceConverter` (selected exclusively by
`SemanticFormatId.MISP`), the MISP fact builders, and the explicit
side-effect-free `build_misp_conversion_registry()`. It consumes only
already-validated PR 32A records and constructs no Evidence inside
`misp_semantics.py` (which remains source validation only). Conversion is
synchronous, pure, and performs no acquisition, I/O, persistence, clock/
random reads, or secret lookup.

The explicitly supported IOC profile is exactly five MISP Attribute types
(no substring/similarity/fallback inference):

| MISP Attribute type | Normalized IOC(s) | Output |
|---|---|---|
| `domain` / `hostname` | DOMAIN | 1 Evidence |
| `ip-src` / `ip-dst` | IP_ADDRESS (IPv4 + IPv6) | 1 Evidence |
| `domain\|ip` | DOMAIN then IP_ADDRESS | 1 Evidence |
| anything else | unsupported | 0 Evidence |

DOMAIN uses the existing `validate_dns_name(value)` and IP uses the
existing `canonicalize_ip_address(value)`; canonicalization failure for an
already supported type is a bounded `ConversionError`. `domain|ip` requires
exactly two nonempty components separated by one literal `|` and is **one
Evidence with two ordered IOC facts** — no `<uuid>#domain`/`<uuid>#ip`
component identities are ever fabricated (invariant 8).

Evidence identity/provenance:

- `Evidence.type = THREAT_INTELLIGENCE`;
- `Evidence.source = context.semantic_source.source_id.value`;
- `Evidence.source_record_id = str(attribute.uuid)` (exact upstream
  Attribute UUID — value/Event UUID/retrieval time/datasource ID never
  participate);
- `Evidence.id = evidence_id_for_source_record(SemanticFormatId.MISP,
  context.semantic_source.source_id, str(attribute.uuid))`;
- candidate `observed_at` is the exact Attribute source timestamp (never
  Event/publish/retrieval time), `retrieved_at` and `source_reference` come
  from the semantic context, and `raw_payload = None`.

Normalized facts use one stable pinned shape per supported Attribute:
`event` (UUID, info, UTC `Z` timestamp, published, publish_timestamp,
extends_uuid, distribution, sharing_group_id, ordered tags), `attribute`
(UUID, type, category, **original source value**, timestamp, to_ids,
deleted, distribution, sharing_group_id, comment, object_relation,
ordered tags), and `iocs` (only canonical entity-eligible values as
ordered `{"type", "value"}` objects). Optional modeled fields use stable
explicit `None`; local MISP numeric IDs and binary `data` never appear.

Source facts are preserved, never interpreted: `to_ids`, tags, category,
comment, distribution (including Attribute `5` = inherit Event), sharing
group, and `deleted` are material facts — a supported `deleted=True`
Attribute still converts so the same Evidence identity can later reflect
`false -> true`. No verdict, ATI confidence, risk, attribution,
relationship, pivot, campaign, or analyst disposition is synthesized.
Distribution/sharing is never resolved to an effective value and never
treated as ATI authorization. MISP Objects and ObjectReferences remain
unsupported for Evidence production: a valid `MispObjectRecord` returns
zero Evidence even when it nests supported domain/IP Attributes, and no
ObjectReference relationship is created.

Defense-in-depth provenance guards fail closed: a non-MISP source object,
a context whose semantic format is not MISP, and a context whose source
identity is not `SourceId.MISP` each raise a bounded `ConversionError`
with no IOC value/Event info/comment/URL interpolation. A valid
unsupported Attribute type returns zero Evidence deterministically.
Acquisition (REST/auth/pagination) is PR 32C; production runtime
composition and real-stack closure are PR 32D — nothing in PR 32B claims
live MISP integration.

## STIX 2.1 IOC Evidence conversion (PR 33B, delivered)

PR 33B lands ATI's first STIX 2.1 `ToEvidenceConverter` over the reusable
PR 33A single-object semantic seam:
`infrastructure/datasources/stix21_evidence.py` owns
`Stix21ToEvidenceConverter` (selected exclusively by
`SemanticFormatId.STIX_21`), the STIX fact builders, and the explicit
side-effect-free `build_stix21_conversion_registry()`. It consumes only
already-validated `Stix21Object` values — never raw JSON, Bundle
envelopes, or fabricated Bundles — and `stix21_semantics.py` remains
Evidence-independent (PR 33A semantics unchanged). Conversion is
synchronous, pure, and performs no acquisition, I/O, persistence,
clock/random reads, or secret lookup.

### Approved Evidence profile

The exact supported profile (everything else valid is unsupported and
yields zero Evidence):

| STIX type | Required member | Normalized IOC(s) | Output |
|---|---|---|---|
| `domain-name` | string `value` | DOMAIN | 1 Evidence |
| `ipv4-addr` | string `value`, actually IPv4 | IP_ADDRESS | 1 Evidence |
| `ipv6-addr` | string `value`, actually IPv6 | IP_ADDRESS | 1 Evidence |
| `indicator` | approved whole-pattern (below) | ordered approved IOCs | 1 Evidence |
| any other valid object | n/a | unsupported | 0 Evidence |

IP family is enforced: an `ipv4-addr` containing IPv6 and an `ipv6-addr`
containing IPv4 are each a bounded `ConversionError`; DOMAIN reuses
`validate_dns_name(value)` and IP reuses `canonicalize_ip_address(value)`
(no STIX-specific normalization exists).

An `indicator` SDO is Evidence-supported only when
`pattern_type == "stix"`, the `pattern` member is a nonblank
string, any present `pattern_version` is a string, the pattern is
syntactically valid STIX Patterning, the **entire** pattern belongs to the
approved whitelist, at least one approved leaf exists, and every approved
leaf canonicalizes. Only three equality leaves are approved:
`domain-name:value = '<string>'`, `ipv4-addr:value = '<string>'`,
`ipv6-addr:value = '<string>'`; approved composition is exactly those
leaves combined with `AND`/`OR` and parentheses (both within one bracket
and across `[a] OR [b]` brackets). Anything else — `FOLLOWEDBY`,
`WITHIN`/`START ... STOP`/`REPEATS`, `MATCHES`/`LIKE`/`ISSUBSET`/
`ISSUPERSET`, inequalities/ranges, `!=`, `NOT`-prefixed operators,
sets, `EXISTS`, extra object-path steps, indexes, wildcards, or
non-string comparison literals — makes the whole pattern unsupported and
produces zero Evidence. A mixed approved/unsupported pattern is **never**
partially extracted. A syntactically valid pattern outside the whitelist
returns `()` (valid unsupported, not a failure); a syntactically malformed
approved-context pattern raises a bounded `ConversionError`.

Indicator pattern interpretation is delegated to the ATI-owned structural
adapter `stix21_pattern.py`, which parses through the maintained OASIS
`stix2-patterns` dependency (bounded to `>=2.1.2,<3`, the first line with
a Python 3.14 classifier) and whitelists the parsed tree with an
ATI-owned walker. ATI never regex-parses or string-splits STIX
Patterning, and the third-party parser's error text (which may echo input)
is never propagated — malformed syntax maps to a fixed safe label.

### Identity, observation, and facts

For every supported object the Evidence identity is pinned to
`evidence_id_for_source_record(SemanticFormatId.STIX_21, source, source.id)`
where **the exact STIX `id` is `source_record_id`**:

```text
Evidence(id=evidence_id_for_source_record(STIX_21, ctx.source, stix_id),
         type=THREAT_INTELLIGENCE,
         source=ctx.source_id.value,
         source_record_id=stix_id)
```

`created`, `modified`, `valid_from`, retrieval time, IOC values, pattern
content, Bundle IDs, datasource IDs, and Investigation IDs never
participate in Evidence identity: a later version of the same STIX object
under the same ATI source namespace resolves to the same Evidence
identity. Cardinality is 0..1 per STIX object: a supported indicator with
multiple approved leaves is still exactly **one** Evidence whose `iocs`
preserve the left-to-right pattern leaf order (duplicates included, never
sorted or deduplicated).

The observation candidate carries `observed_at=None` (STIX timestamps are
normalized source facts, never ATI observation time), `retrieved_at` and
`source_reference` from the semantic context, and `raw_payload=None`.
Normalized facts use one stable pinned shape (the ``cti_entity`` block is
added by PR 33C and is always present, ``null`` for IOC/Indicator
Evidence):

```json
{
  "stix": {
    "id": "domain-name--...", "type": "domain-name",
    "spec_version": "2.1", "created": null, "modified": null,
    "revoked": null, "labels": [], "confidence": null, "lang": null,
    "external_references": [], "object_marking_refs": [],
    "granular_markings": [], "defanged": null
  },
  "indicator": null,
  "iocs": [{"type": "domain", "value": "example.test"}],
  "cti_entity": null,
  "source_assertion": null
}
```

For an `indicator` source, `indicator` carries only `pattern` (preserved
exactly), `pattern_type`, `pattern_version`, `valid_from`/`valid_until`
(normalized UTC `Z`), and ordered `indicator_types`. Optional scalars use
explicit `None`; modeled list fields use `[]` when absent; list source
order is preserved; approved STIX metadata/marking fields are preserved
as source facts and never dereferenced, interpreted, or enforced (no TLP
inference, no marking-policy enforcement, no confidence interpretation).
No verdict, risk, attribution, relationship, pivot, or ATT&CK semantics
is synthesized.

### Guards and no-SourceId guard

Defense-in-depth provenance guards fail closed: a non-`Stix21Object`
source and a context whose semantic format is not STIX 2.1 each raise a
bounded `ConversionError` with no IOC value, pattern, source URL, or
marking content interpolation. There is deliberately **no** fixed
`SourceId` guard (contrast with MISP): STIX is a shared open semantic
model, and future TAXII sources may carry it under any ATI source
namespace. A valid unsupported object and a valid-but-unsupported pattern
each return zero Evidence deterministically.

TAXII discovery/collections/pagination/authentication, URL/file/hash/email/certificate
IOC support, exhaustive STIX SCO support, exhaustive STIX relationship/
sighting coverage, and full STIX Patterning are explicitly out of scope
(PR 33B/33C): a bounded Relationship/Sighting profile lands in PR 33D and
TAXII acquisition/runtime integration in PR 33E. `DATA_SOURCES.md` does
not claim TAXII support and no all-STIX-objects-produce-Evidence claim is
made.

## Source-neutral CTI Entity expansion (PR 33C, delivered)

PR 33C adds exactly five source-neutral (not STIX-alias) Entity types:
`THREAT_ACTOR`, `CAMPAIGN`, `INTRUSION_SET`, `TOOL`, and
`INFRASTRUCTURE`. `MALWARE`, `VULNERABILITY`, and `ATTACK_TECHNIQUE` were
**not** introduced by 33C — they already exist and their identity
contracts are unchanged. No generic `ATTACK_PATTERN`, `IDENTITY`,
`LOCATION`, `COURSE_OF_ACTION`, or other STIX SDO mirror was added.

### Identity and display contract

Entity type is source-neutral; the current STIX adapter supplies a STIX
machine identifier as the Entity value. For these five types the canonical
value is a **strict opaque machine identifier**, initially the exact
validated STIX 2.1 object `id`. `canonicalize_cti_object_id`/the
registered `_CANONICALIZERS` entries validate rather than normalize: the
exact lowercase STIX type prefix, the `--` delimiter, and a canonical
textual UUID suffix are required, and accepted input is returned
byte-for-byte. Wrong or mutated prefixes, non-canonical UUID spellings,
surrounding whitespace, blank values, human `name` values, and aliases fail
closed with `ValueError`.

`name` is required (nonblank, bounded to 512 characters) but is **display
metadata only**; the exact source spelling is preserved as
`display_name` and never participates in canonical identity. Same-name
STIX objects with different IDs remain distinct Entities, and no
cross-source equivalence is inferred: a future MISP Galaxy/cluster may
reuse the same ATI Entity type, but no MISP↔STIX identity merge occurs
without an explicit future equivalence mechanism.

### Converter extension (PR 33B converter extended, not duplicated)

`stix21_evidence.py` (still the one STIX `ToEvidenceConverter`, keyed only
by `SemanticFormatId.STIX_21`) now admits exactly five CTI SDO types:

| STIX type | ATI Entity type | Required members | Evidence representation |
|---|---|---|---|
| `threat-actor` | `threat_actor` | exact validated `id` + nonblank bounded `name` | 1 Evidence, `iocs: []`, one `cti_entity` block |
| `campaign` | `campaign` | exact validated `id` + nonblank bounded `name` | 1 Evidence, `iocs: []`, one `cti_entity` block |
| `intrusion-set` | `intrusion_set` | exact validated `id` + nonblank bounded `name` | 1 Evidence, `iocs: []`, one `cti_entity` block |
| `tool` | `tool` | exact validated `id` + nonblank bounded `name` | 1 Evidence, `iocs: []`, one `cti_entity` block |
| `infrastructure` | `infrastructure` | exact validated `id` + nonblank bounded `name` | 1 Evidence, `iocs: []`, one `cti_entity` block |

A selected CTI type with a malformed required identity/name raises a
bounded `ConversionError` (zero converted output for the batch call); a
valid unsupported object still yields zero Evidence. The normalized facts
now use one stable five-key shape shared by every supported object:

```json
{
  "stix": { "...": "common facts unchanged" },
  "indicator": null,
  "iocs": [],
  "cti_entity": {
    "type": "threat_actor",
    "value": "threat-actor--11111111-1111-1111-1111-111111111111",
    "display_name": "Example Group"
  },
  "source_assertion": null
}
```

IOC/Indicator Evidence keeps `cti_entity: null`; CTI SDO Evidence keeps
`iocs: []` and `indicator: null`. `type` is the ATI Entity wire value,
`value` the exact validated machine ID, and `display_name` the exact source
name. `relationship`/`sighting` objects, `created_by_ref`, `object_refs`,
`aliases`, `labels`, `external_references`, and `object_marking_refs` stay
unconsumed source facts in PR 33C (PR 33D later consumes the bounded
Relationship/Sighting profiles while every other reference stays a fact) —
never Entity or edge state. Generic STIX
`attack-pattern`/`malware`/`vulnerability` remain unsupported because ATI's
`ATTACK_TECHNIQUE`/`MALWARE`/`VULNERABILITY` contracts are narrower
canonical identity contracts and name-based mapping would be unsafe.

### Durable extraction and persistence

The PR 28E durable seam (`app/extraction/message_context.py`) reconstructs
the STIX invocation target from normalized facts — never a fabricated
semantic owner: a PR 33D source assertion derives it from the normalized
assertion (a Relationship's **source endpoint**, a Sighting's
`sighting_of`), a single `cti_entity` block is the represented subject of
a CTI SDO, otherwise the first ordered `iocs` entry exactly as the MISP
collection solution does. The source-neutral STIX extractor
(`app/extraction/stix.py`) is dispatched by semantic format (STIX 2.1 has
deliberately no fixed `SourceId` guard) and consumes only durable facts. It
produces exactly one canonical CTI Entity per `cti_entity` block (or every
represented IOC identity for PR 33B Evidence, first-seen deduplicated) and
**zero relationships**; the PR 33D assertion path produces the endpoint
Entities plus exactly one approved RelationshipAssertion (or zero for
Sighting). Malformed durable facts fail closed with
`EvidenceExtractionError(MALFORMED_FACTS)` without echoing source values.

Persistence reuses the global Evidence batch path unchanged
(`ati.persist_evidence_batch`, Entity type/value stored as generic text
with no DB enum/CHECK, so **no migration** is required): Evidence +
EvidenceObservation + `EvidenceObservationEntity` association per the
existing version/upsert semantics. CTI SDO Evidence creates zero
`Relationship` and zero `RelationshipObservation` rows. The source
namespace participates in Evidence identity (one STIX ID under two ATI
sources yields two Evidence identities) while Entity identity is
`(EntityType, canonical value)` (the same Entity is associated once).

Graph/query/API projection is entirely generic: `GraphNodeResponse`,
entity-type filters, paths, and the frontend presentation registry accept
the new wire values without CTI-specific endpoints or DTOs. Investigation
seeding is **not** implied by graphability: `INVESTIGATION_SEED_TYPES`
(authoritative in `domain/investigation.py`) explicitly excludes the five
CTI types, so no provider or orchestration capability is invented.

PR 33D owns source-asserted Relationship/Sighting semantics; PR 33E owns
TAXII acquisition. No relationship/sighting/TAXII work happened in 33C.

## Source-asserted CTI relationships and STIX 2.1 Sightings (PR 33D, delivered)

PR 33D adds the first source-neutral durable assertion contract for
external CTI relationships and a deliberately bounded STIX 2.1
`relationship`/`sighting` Evidence profile. The dominant architectural
rule is unchanged: a source assertion becomes ATI graph state **only**
through durable Evidence and deterministic extraction. The converter
preserves source semantics as Evidence facts; it never persists and never
constructs durable graph rows.

### Normalized source-assertion fact contract

Every supported STIX Evidence now carries the stable five-key fact shape
(key order pinned by the regression tests):

```json
{
  "stix": {},
  "indicator": null,
  "iocs": [],
  "cti_entity": null,
  "source_assertion": null
}
```

`source_assertion` is **never conditionally absent**: PR 33B/33C objects
carry explicit `null`; supported Relationship/Sighting objects carry one
`kind`-discriminated block (`"relationship"` or `"sighting"`).

Relationship form:

```json
{
  "kind": "relationship",
  "relationship": {
    "type": "uses",
    "ati_type": "urn:ati:relationship:threat:uses",
    "source": { "type": "threat_actor", "value": "threat-actor--..." },
    "target": { "type": "tool", "value": "tool--..." },
    "start_time": null,
    "stop_time": null
  },
  "sighting": null
}
```

Sighting form:

```json
{
  "kind": "sighting",
  "relationship": null,
  "sighting": {
    "sighting_of": { "type": "threat_actor", "value": "threat-actor--..." },
    "first_seen": null,
    "last_seen": null,
    "count": null,
    "summary": null,
    "where_sighted_refs": [],
    "observed_data_refs": []
  }
}
```

Endpoint identities are canonical machine identities only (no display
names are fabricated); relationship `start_time`/`stop_time` and Sighting
`first_seen`/`last_seen` are normalized UTC `Z` facts that never become
ATI `observed_at`; `where_sighted_refs`/`observed_data_refs` are bounded
ordered provenance lists (single maximum 256, never sorted, never
deduplicated, never interpreted as edges).

### Approved Relationship profile

Only the exact §5.3 matrix produces Evidence (STIX relationship string + endpoint
type pair -> ATI RelationshipType):

| STIX `relationship_type` | allowed source types | allowed target types | ATI URN |
|---|---|---|---|
| `uses` | threat-actor, campaign, intrusion-set | tool, infrastructure | `urn:ati:relationship:threat:uses` |
| `targets` | threat-actor, campaign, intrusion-set | infrastructure | `urn:ati:relationship:threat:targets` |
| `attributed-to` | campaign, intrusion-set | threat-actor | `urn:ati:relationship:threat:attributed_to` |
| `controls` | threat-actor, intrusion-set | infrastructure | `urn:ati:relationship:threat:controls` |

A semantically valid Relationship outside this table — `indicates`,
`related-to`, an admitted string whose endpoint types are outside the
profile, or an endpoint reference to `malware`/`domain-name`/etc. — is
**valid but Evidence-unsupported** and returns zero Evidence. Unsupported
strings are never mapped to `ASSOCIATED_WITH` or any other existing URN.
Once an object claims an admitted profile candidate, a malformed consumed
field (blank `relationship_type`/`source_ref`/`target_ref`, an admitted
endpoint prefix with a non-canonical UUID, malformed/out-of-order
`start_time`/`stop_time`) raises a bounded `ConversionError` that never
echoes source content.

Endpoint identity is the PR 33C CTI machine-ID contract: an endpoint
reference resolves only for the five `threat-actor--`/`campaign--`/
`intrusion-set--`/`tool--`/`infrastructure--` prefixes, and the canonical
value is the exact validated STIX object ID. No cross-message object
lookup, name/alias-derived identity, hidden reference cache, or placeholder
Entity ever exists. Relationship direction follows the source assertion
(`source_ref -> target_ref`); no reciprocal or symmetric edge is inferred.

### Approved Sighting profile

A Sighting is Evidence-supported only when `sighting_of_ref` is an exact
canonical reference to one of the five CTI Entity types; a Sighting of
malware/indicator/domain/IP/attack-pattern/etc. returns zero Evidence.
`where_sighted_refs`/`observed_data_refs` produce **zero** Entities and
**zero** RelationshipAssertions (no `SIGHTED_AT`-style invented edge).
Malformed consumed fields (bad `sighting_of_ref` UUID, out-of-order
`first_seen`/`last_seen`, non-positive/`count`, non-boolean `summary`,
over-bound/malformed reference lists) raise a bounded `ConversionError`.

### Ownership boundaries (unchanged)

- `Stix21ToEvidenceConverter` (still the sole STIX converter, keyed only by
  `SemanticFormatId.STIX_21`) decides whether a validated object produces
  Evidence and preserves normalized source facts; it has no persistence or
  graph imports.
- `app/extraction/source_assertion.py` is the source-neutral normalized-fact
  validation seam (reusable by a future MISP adapter); it imports no STIX
  parser, persistence, broker, or API code, and the STIX→ATI profile
  mapping stays in the STIX adapter.
- `app/extraction/message_context.py` reconstructs only the execution
  identity required by extraction: a Relationship's invocation Entity is
  its **source endpoint**, a Sighting's is `sighting_of`; contradictory
  durable shapes fail closed with `MalformedMessageExtractionError`.
- the STIX extractor deterministically derives the endpoint Entities and
  exactly one approved `RelationshipAssertion` (or zero for Sighting),
  revalidating the full durable fact and the exact profile mapping so a
  tampered message (for example `type: "uses"` paired with
  `ati_type: "...targets"`) fails closed.
- the existing Evidence consumer/batch persistence path persists everything
  unchanged: `Evidence`, `EvidenceObservationEntity` associations for both
  endpoints, the stable `Relationship`, and the immutable
  `RelationshipObservation` backed by the exact authoritative
  `EvidenceObservation`. Distinct assertions of the same semantic edge
  reuse one Relationship while retaining per-Evidence observation
  provenance; a semantic-edge change under one stable Evidence identity
  appends new observations and relationships without mutating or deleting
  the historical edge.

Investigation admission is unchanged: the five CTI Entity types remain
excluded from `INVESTIGATION_SEED_TYPES`, and Relationship/Sighting
Evidence never launches provider or orchestration work. No migration was
introduced (the relationship-type URN stays free text). TAXII remains out
of scope (PR 33E).

## Native MISP REST acquisition (PR 32C, delivered)

PR 32C lands the bounded native MISP acquisition boundary between the MISP
REST API and the PR 32A semantic parser, still without wiring MISP into
the production Evidence runtime (PR 32D owns that closure):

- `infrastructure/datasources/misp.py` owns `MispDatasource`, the narrow
  `extract_misp_event_envelopes()` REST-envelope adapter, and the tiny
  `acquire_misp_execution` runner reusing the PR 27B
  `DatasourceExecutionRecorder` (STARTED -> execution-level ACQUIRED\(total successful page bytes\) -> DECODED\(total semantic records\) -> one
  terminal outcome);
- the endpoint is `POST {misp_base_url}/events/restSearch` with an explicit
  JSON `{"page": N, "limit": L}` body, `Authorization: <resolved key>`
  header, and JSON `Accept`/`Content-Type`; the normal JSON response shape
  `{"response": [{"Event": {...}}, ...]}` is verified against the current
  official MISP/PyMISP contract and is the only supported form;
- every response member is adapted at the acquisition layer into the exact
  `{"Event": {...}}` envelope and parsed by the **real**
  `parse_misp_event()`, so PR 32A remains the sole Event semantic
authority; a malformed search envelope or Event fails the whole bounded
acquisition with zero objects via `semantic_validation_failed`;
- pagination is strictly sequential and explicitly bounded by validated
  `page_size` (1..1000) and `max_pages` (1..1000) settings; an empty page
  stops success, reaching `max_pages` means the bounded acquisition window
  completed (never that the server is exhausted), and no request is issued
  past the bound;
- HTTP admission, retries, response-size bounding, rate limiting, and
  cancellation are owned entirely by `ProviderHttpClient`/`BoundedLimiter`;
  the acquirer stacks no second semaphore/limiter and never prefetches
  pages;
- failures map to bounded typed `DatasourceStageError` outcomes
  (`ACQUISITION`/`timeout`|`rate_limited`|`authentication_failed`|
  `forbidden`|`not_found`|`provider_unavailable`,
  `SERIALIZATION`/`serialization_failed`, and
  `SEMANTIC_VALIDATION`/`semantic_validation_failed`) using
  `HttpOutcome.final_error_stage` and the provider error-code vocabulary;
  `429 Retry-After` is preserved; no raw body/server text/key text is ever
  promoted; `asyncio.CancelledError` always propagates;
- secrets follow the standard contract: `misp_api_key_secret` stores only a
  reference name, composition resolves it through `SecretsResolver` and
  injects the value, and the key travels only in the `Authorization`
  header;
- the composed acquirer is exposed as `ProviderComposition.misp_datasource`
  only when `misp_base_url` is configured (an unset URL keeps ordinary
  fake/local startup legal before PR 32D) and is **not** registered as an
  `EvidenceProvider`.

No database transaction spans HTTP/decoding/parsing, no Evidence is
constructed by acquisition, and there is no MISP-specific persistence path;
PR 32D owns production runtime composition and real-stack Evidence closure.

## Native MISP collection runtime closure (PR 32D, delivered)

PR 32D closes the MISP runtime by wiring the PR 32A semantics, PR 32B
conversion, and PR 32C bounded REST acquisition through ATI's existing
distributed Global Evidence publication and persistence boundaries. MISP
remains a **collection** datasource: it never becomes an Investigation
`EvidenceProvider`, never gains a fake/ignored Entity or
`supports(entity)`, never registers in
`ProviderComposition.provider_registry()`, and never routes through
`ProviderWorkExecutor`.

- **Collection acquisition contract.** `app/datasource_provider.py` now
  defines `CollectionSemanticAcquirer[T]` alongside the entity-triggered
  `SemanticAcquirer[T]`: `acquire(*, definition, recorder)` with no
  Entity and no `supports(entity)`. `MispDatasource.acquire` satisfies it
  structurally without a wrapper. The entity-triggered contract is
  unchanged.
- **Collection Evidence producer.**
  `app/datasource_evidence_producer.py` adds
  `CollectionDatasourceEvidenceProducer[T]`. Its `produce()` takes no
  Entity argument and shares the **same** post-acquisition pipeline as
  `DatasourceEvidenceProducer` through the private
  `_convert_and_publish()` helper (never copied):
  `SemanticAcquisitionResult -> EvidenceConversionContext ->
  convert_semantic_source_objects -> CONVERTED(N) -> EvidenceMessage
  construction -> exactly one EvidencePublisher.publish -> PUBLISHED(N) ->
  COMPLETED`. Zero conversion is valid (`CONVERTED(0)`, `publish(())`,
  `PUBLISHED(0)`, `COMPLETED`); typed acquisition failures record
  `FAILED(code)`, conversion/message-construction/publication failures
  record their bounded codes and propagate, cancellation records
  `CANCELLED` (best effort) and propagates, and a lifecycle append failure
  after a successful publish propagates without republish and without
  `COMPLETED`.
- **Composition.** `infrastructure/providers/composition.py` owns
  `resolve_misp_datasource_definition(settings)` (exactly one MISP
  definition in `Settings.datasources`; zero returns `None`, more than
  one fails closed) and `compose_misp_collection_producer(...)` (blank
  URL -> `None` with no MISP key requirement; configured URL with a
  missing/mismatched definition fails before acquisition; the real
  `build_misp_conversion_registry()` is selected by
  `SemanticFormatId.MISP`; the concrete Kafka publisher is injected
  behind the `EvidencePublisher` ABC via
  `compose_kafka_publisher(settings.evidence_kafka)`). No new CLI or
  scheduler exists: the composition seam is the production entry point.
- **Consumer-side extraction.** `app/extraction/message_context.py`
  dispatches by the exact `(semantic_format, source)` pair (ThreatFox +
  ThreatFox, MISP + MISP; anything else fails closed). MISP
  reconstruction derives the transient invocation Entity from the durable
  normalized `facts.iocs` (first ordered IOC; DOMAIN for `domain|ip`),
  requires canonical values and distinct identities, and never re-parses
  raw payloads. `app/extraction/misp.py` returns the additional
  represented IOC Entities (one for `domain|ip`) with always-empty
  relationships; the dispatcher is registered for
  `(SourceId.MISP, THREAT_INTELLIGENCE)`.
- **Invariants preserved.** Evidence identity remains the exact MISP
  semantic format + MISP source + Attribute UUID; no MISP tables,
  message schema, topic, Observation versioning, or direct
  `MispDatasource -> PostgreSQL` path exists; EvidenceMessage v1, the
  normal Kafka topic, the normal consumer, and the global PostgreSQL
  batch stored functions are reused; `domain|ip` preserves both Entities
  with zero invented relationships; MISP distribution/sharing-group
  metadata remains source fact, never ATI authorization; collection
  ingestion never creates `InvestigationEvidence`.

## TAXII 2.1 acquisition and runtime integration (PR 33E, delivered)

PR 33E adds TAXII 2.1 as a **generic acquisition protocol** and closes
v0.6 by feeding the existing STIX 2.1 semantic/Evidence pipeline through
one configured collection. TAXII only retrieves STIX objects; it never
interprets STIX. The dominant ordering invariant: *a TAXII execution may
advance its durable incremental-retrieval checkpoint only after the
corresponding ordered Evidence publication has succeeded.*

- **Dimensions.** `DatasourceProtocol.TAXII_21 = "taxii21"` joins the
  protocol vocabulary (HTTPS/FILE unchanged); serialization stays JSON;
  `SemanticFormatId.STIX_21` is unchanged; `SourceId.OPENCTI` is added
  for provenance only. OpenCTI has no special semantic path: it is
  consumed through the same generic `Taxii21Datasource`, the same
  `parse_stix21_object()`, and the same `Stix21ToEvidenceConverter`.
- **Protocol module.** `infrastructure/datasources/taxii21.py` owns the
  narrow TAXII contract: the immutable `Taxii21ObjectPage` model
  (`objects` order preserved, `more` + opaque `next`, canonical
  date-added headers), envelope validation (empty envelopes are
  successful empty semantics; `more=true` without a nonblank `next`
  fails closed; malformed pages fail the whole acquisition with zero
  objects), and the bounded `Taxii21Datasource` acquirer. A TAXII
  envelope is never rewritten into a synthetic STIX Bundle; every member
  passes through `parse_stix21_object()` individually.
- **Ordered bounded acquisition.** Pages are strictly sequential
  (`next` is response-dependent); `ProviderHttpClient` owns timeout,
  retries, response-size bounds, content-type verification, concurrency
  admission, optional rate limiting, and cancellation — no second limiter
  or `TaskGroup` is stacked. `added_after` (durable checkpoint or
  configured initial cursor) is sent on the first page only. Reaching
  `max_pages` with `more=true` is successful bounded-window completion.
- **Safe errors.** HTTP/auth failures map to the bounded stage-aware
  codes (timeout, rate_limited, authentication_failed, forbidden,
  not_found, provider_unavailable, serialization_failed,
  protocol_validation_failed, semantic_validation_failed); 401/403/404
  semantics stay intentionally uninterpreted, and raw server bodies are
  never promoted into errors/logs.
- **Durable checkpoint (Part 7).** `ati.datasource_checkpoint` (SQL API
  v0032) stores one row per `(datasource_id, checkpoint_kind)` with a
  bounded canonical value, `updated_at`, and an optimistic-concurrency
  version. The stored functions `ati.get_datasource_checkpoint` /
  `ati.advance_datasource_checkpoint` own row creation, stale
  compare-and-advance rejection (`U32A2`), and equal-value idempotent
  no-ops. The `taxii_added_after` kind interprets values as canonical
  fixed-width UTC date-added timestamps; ordering policy belongs to the
  TAXII kind adapter (never a generic lexical contract). The checkpoint
  is loaded in a short committed UoW **before** any HTTP and committed
  **after** PUBLISHED and **before** COMPLETED. `next` tokens, STIX
  timestamps, and ATI retrieval time never become durable checkpoint
  values.
- **Publication-safe progress seam.**
  `CollectionAcquisitionProgress(kind, previous, candidate)` is an
  optional source-neutral member of `SemanticAcquisitionResult`;
  `CollectionDatasourceEvidenceProducer` invokes an injected
  source-neutral progress committer after PUBLISHED and before COMPLETED.
  Publication-success + checkpoint-failure replays are safe through
  deterministic Evidence identity (at-least-once, never at-most-once); no
  distributed transaction exists between Kafka and PostgreSQL; no
  UnitOfWork is ever held across TAXII HTTP or broker I/O; cancellation
  propagates unchanged and never advances the cursor before its commit
  point (and never rolls it back after).
- **Composition.** `infrastructure/providers/composition.py` owns
  `resolve_taxii_datasource_definition(settings)` (exactly one
  TAXII_21 + JSON + STIX_21 definition; the MITRE ATT&CK FILE definition
  can never match), `build_taxii_checkpoint_committer(uow_factory)`, and
  `compose_taxii_collection_producer(...)`; `ProviderComposition`
  composes `taxii_datasource` only when `taxii_api_root_url` is set
  (resolving the bearer token at composition time, never before HTTP).
  TAXII/OpenCTI stays absent from the Investigation provider registry; no
  scheduler exists.

## Evidence wire boundary (PR 28C, delivered)

PR 28C defines the versioned, broker-independent `EvidenceMessage`
wire contract in `src/agentic_threat_investigator/app/evidence_message.py`
— the durable representation of **one** producer-side
`ConvertedEvidence` candidate plus bounded acquisition provenance:

```text
DatasourceDefinition
 -> acquisition -> serialization -> semantic parsing
 -> SemanticSourceContext
 -> ToEvidenceConverter selected by semantic_format
 -> ConvertedEvidence (global Evidence + observation candidate)
 -> EvidenceMessage v1   (builder + canonical JSON codec, PR 28C)
 -> EvidencePublisher (PR 28D) -> distributed log
    (producer publication delivered: PR 28F-2;
     Kafka/Redpanda adapter delivered: PR 28G)
```

The boundary reuses without modification the PR 28A global Evidence
identity (`evidence_id_for_source_record`) and the PR 27C
`SemanticSourceContext` provenance; it adds deterministic producer-side
`message_id` (UUIDv5 over execution + sequence + Evidence identity) and
`observation_candidate_id` (UUIDv5 over the message identity, explicitly
not a committed `EvidenceObservation.id`) identities. The producer never
allocates an Observation version or diff, and the message carries no
Investigation/subject/graph/broker state and no generic metadata
dictionary. Canonical UTF-8 JSON serialization is byte-deterministic and
deserialization fails closed with typed errors; all codec/builder
operations are pure (no DB/network/UnitOfWork).

The PR 28F-2 producer path is delivered at the application seam
(`app/datasource_evidence_producer.py`): one ordered
`EvidencePublisher` publication per execution and the non-terminal
`PUBLISHED` lifecycle event (`CONVERTED` -> `PUBLISHED` ->
`COMPLETED`), proven by deterministic unit matrices and ThreatFox
real-stack vertical slices. It is **not** wired into a production
runner: the Kafka/Redpanda adapters sit behind the unchanged PR 28D
contracts, and PR 28H proved the full producer -> log -> consumer ->
PostgreSQL path against real Redpanda and real PostgreSQL (H28H-01..21)
without introducing a production runner — replacing the transitional
synchronous Investigation path would require Investigation orchestration
redesign, which is explicitly out of the PR 28 closure scope. Consumer
persistence is PR 28E (delivered). Production Investigation execution
remains synchronous and behaviorally unchanged on the PR 27E
compatibility runtime (provider executor, observation persistence,
`DatasourceProvider`); nothing in that transitional path publishes.

## Runtime datasource migration (PR 27E, delivered)

PR 27E connects the PR 27A-D stack to the existing Investigation runtime
without redesigning the mature executor/persistence architecture. The
migrated production path is:

```text
EvidenceProvider compatibility (app/datasource_provider.py)
 -> DatasourceDefinition (from Settings.datasources)
 -> semantic datasource acquisition (SemanticAcquirer protocol)
 -> SemanticAcquisitionResult[T]
 -> EvidenceConversionContext (global, PR 28A)
 -> ToEvidenceConverterRegistry (selected by semantic_format only)
 -> ConvertedEvidence (global Evidence + observation candidate)
 -> ProviderResult (global model; no v0.1 rebind since PR 28B)
 -> ProviderWorkExecutor binding/extraction/persistence
    (exact EvidenceObservation admission per Investigation)
```

Delivered:

- `DatasourceProvider` (generic adapter over a definition, a PR 27C
  ``SemanticAcquirer``, the converter registry, and the UnitOfWork-
  backed PR 27B recorder): owns STARTED + stage appends + CONVERTED
  (exact Evidence count), returns a lifecycle-aware
  ``DatasourceEvidenceResult`` whose terminal outcome stays open until
  the executor finishes required Evidence processing;
- typed legacy error mapping (timeout/429/auth/forbidden/malformed/
  semantic-invalid -> ``ProviderErrorCode``) with no message-text
  classification and no raw exception/payload/credential persistence;
- generic executor integration in ``ProviderWorkExecutor`` (no provider
  branch): COMPLETED only after per-Evidence extraction/persistence and
  the aggregate completion event succeed; FAILED with bounded
  ``provider_binding_failed``/``extraction_failed``/``persistence_failed``/
  ``timeline_failed`` on runtime failure; CANCELLED (best effort) with
  ``CancelledError`` propagation on cancellation;
- ThreatFox production migration: one validated record -> one Evidence
  (exact ``source_record_id`` provenance retained; the legacy grouped
  shape is superseded), reusing ``ThreatFoxDatasource``/the parser/the
  ``ThreatFoxToEvidenceConverter``/the existing extractor and
  ``ProviderObservationPersistenceService``;
- deterministic transaction-boundary unit tests and real-PostgreSQL
  vertical slices (one-record/two-record/no-result, cross-Investigation
  and subject binding, later-item persistence failure preserving earlier
  commits, extraction failure, acquisition cancellation, lifecycle DB
  invariants);
- batch SourceRecord + checkpoint atomicity regression tests proving the
  ingestion path still commits exactly one UoW per batch with no PR 27
  lifecycle multiplication;
- `docs/PR_27_SOURCE_MIGRATION_AUDIT.md` recording the honest
  source-by-source status: only ThreatFox is MIGRATED; MITRE ATT&CK is a
  SEMANTIC_BOUNDARY_ONLY / NOT_EVIDENCE_SOURCE corpus path; the remaining
  live Investigation Evidence sources remain
  LEGACY_NOT_SEMANTICALLY_MODELED until source-specific follow-ups.

Dominant lifecycle invariants of the PR 27E Investigation compatibility
path (transitional — it stays on the synchronous Investigation runtime and
does not publish):

```text
TX-L1 STARTED
HTTP/decode/semantic parse                       no TX
TX-L2 ACQUIRED
TX-L3 DECODED
conversion                                       no TX
TX-L4 CONVERTED(item_count=N)
extract E1 / persist E1 (observation UoW)  ...  per Evidence
TX-L5 COMPLETED
```

### Current v0.2 Global Evidence producer lifecycle (PR 28F-2, delivered at the application seam)

The `DatasourceEvidenceProducer` (`app/datasource_evidence_producer.py`)
owns the producer-side execution over the same PR 27B recorder. Its target
lifecycle is:

```text
TX-P1 STARTED
HTTP/decode/semantic parse                       no TX
TX-P2 ACQUIRED
TX-P3 DECODED
conversion + message construction                no TX
TX-P4 CONVERTED(item_count=N)
publisher.publish(messages)                      no TX, exactly one ordered call
TX-P5 PUBLISHED(item_count=M)    # M = accepted EvidenceMessage count
TX-P6 COMPLETED
```

`PUBLISHED.item_count` is the count of `EvidenceMessage` values accepted by
that execution's one ordered `EvidencePublisher.publish(...)` call; a valid
zero-output execution records `PUBLISHED(0)` and still calls `publish(())`.
`COMPLETED` means the injected publisher accepted every message — never that
PostgreSQL consumed or persisted them: the producer never waits for the
PR 28E `EvidencePersistenceConsumer`, never holds a UnitOfWork across
HTTP/conversion/message construction/publication, and never falls back to
direct observation persistence. Datasource lifecycle logging and broker
publication are separate durable boundaries (no distributed transaction,
no outbox); after a successful publish a lifecycle-append failure propagates
without republishing. This producer path is tested end-to-end on the
ThreatFox reference datasource (deterministic unit matrices F2-* and real-
PostgreSQL vertical slices V28F2-*) and is now also proven by the PR 32D
collection twin `CollectionDatasourceEvidenceProducer`: the shared
post-acquisition pipeline is exercised by real-stack MISP slices (V01..V05)
and real Redpanda + PostgreSQL closure tests (K01..K06). Publisher
completion still never waits for the PR 28E consumer; a future process or
container may call `process_next_batch()` repeatedly.

One UoW = one real bounded PostgreSQL transaction. No UoW spans
acquisition, parsing, conversion, extraction, retry sleep, or a whole
execution; ``datasource_log`` remains operational lifecycle (never a
checkpoint/outbox/dedup state); the batch SourceRecord + checkpoint
advance stays one atomic UoW per bounded batch; and cancellation stays
cancellation.

## Acquisition boundary

Acquisition owns external/local I/O and the operational result of obtaining source material. It may also invoke the serialization decoder appropriate to the configured source contract.

It does **not** own ATI Evidence semantics.

Target separation:

```text
protocol bytes / source artifact
        -> serialization decode
        -> semantic source objects
        --------------------------- boundary
        -> ATI semantic conversion
```

Existing providers that currently perform retrieval, validation, normalization, and Evidence construction in one component are migrated incrementally in PR 27; their existing security, bounded-I/O, validation, cancellation, provenance, and safe-error contracts must not regress.

## Semantic source objects

A semantic source object represents one object/record in the datasource's own semantic model after transport/serialization concerns have been handled.

The PR 27C implementation must choose the narrowest representation supported by fresh `main`. Prefer typed semantic-format-specific models where ATI needs validation and stable field semantics. Do not create a universal mega-schema for every external source.

Semantic source objects remain untrusted external data until validated by their semantic-format adapter/converter.

## `ToEvidenceConverter`

ATI introduces an application/domain-facing conversion boundary conceptually equivalent to:

```python
class ToEvidenceConverter(ABC):
    def convert(self, source: SourceObject) -> Sequence[Evidence]:
        ...
```

PR 27D landed the concrete contract in `app/evidence_conversion.py`: generic
over one validated source-object type, driven by an explicit
`EvidenceConversionContext` (ATI Investigation + subject + one
`SemanticSourceContext`), returning an immutable `tuple[Evidence, ...]`. The
exact Python type signatures are binding on PR 27E converters, but the
semantic rules are authoritative:

1. converter selection is based on `semantic_format`;
2. conversion is deterministic for a given validated source object and conversion context;
3. one source object may produce **zero, one, or multiple** Evidence records;
4. converters do not perform acquisition/network I/O;
5. converters do not persist Evidence;
6. converters do not decide Investigation orchestration, pivots, verdicts, or attribution;
7. Evidence retains exact datasource/source provenance required by the existing ATI model.

Examples:

```text
ThreatFox semantic object
  -> ThreatFoxToEvidenceConverter
  -> 0..N Evidence

STIX 2.1 semantic object
  -> Stix21ToEvidenceConverter
  -> 0..N Evidence
```

A converter registry/factory must key on semantic-format identity, not provider identity.

## Zero-to-many conversion

Conversion cardinality is deliberately `0..N`.

Zero Evidence is valid when a syntactically/semantically valid source object carries no ATI-supported evidentiary assertion. One Evidence is common. Multiple Evidence records are valid when one source semantic object contains several independently meaningful ATI observations that must retain distinct Evidence semantics/provenance.

The architecture must not force one-to-one conversion merely because current providers often emit one Evidence item per lookup/record.

## Provenance

The conversion boundary must preserve enough acquisition/source context to construct existing Evidence provenance without coupling the converter to transport implementation details.

At minimum the detailed PR must account for the existing concepts that are applicable to a source:

- ATI source/datasource identity;
- source record identity;
- source observation time;
- retrieval time;
- credential-free source location/reference;
- artifact identity/reference where applicable;
- Investigation/subject binding where Evidence construction requires it.

Do not place secrets, authorization headers, unsafe redirect targets, or credential-bearing URLs into provenance.

## Batch and live sources

The architecture is shared by batch and live acquisition; it does not require them to have identical operational mechanics.

### Live/API source

```text
configured datasource
  -> bounded request
  -> response serialization decode
  -> semantic object(s)
  -> semantic-format converter
  -> Evidence
```

### Batch source

```text
configured datasource
  -> artifact acquisition
  -> artifact storage/reference
  -> bounded streaming decode
  -> semantic object(s)
  -> semantic-format converter
  -> Evidence and/or existing corpus/document products as authorized
```

A batch source may have non-Evidence consumers such as the RAG corpus pipeline. PR 27 must not force every semantic object through `ToEvidenceConverter` when the datasource's approved product is a Document/reference corpus rather than Evidence.

## Error boundaries

Errors should remain attributable to the stage that failed:

```text
acquisition error
serialization error
semantic validation error
conversion error
persistence error
```

Do not collapse all failures into a generic provider error if doing so destroys actionable operational meaning. Conversely, preserve existing safe-error rules: external payloads, credentials, and sensitive request material must not leak into logs/errors.

Cancellation propagates unchanged through asynchronous boundaries.

## Observability

PR 27B delivered the durable datasource operational event log (`ati.datasource_log`),
which is structured around:

- datasource identity;
- `execution_id`;
- stage/event;
- bounded counts where useful (objects decoded, converted, Evidence emitted);
- safe error code/classification;
- occurred/created timestamps.

The durable log is a distinct operational layer: it is not the investigation
timeline, not Evidence, and not a replacement for application logs or traces
(see `OBSERVABILITY.md`). Its events never contain source bodies, secrets,
unsafe URLs, unbounded record content, or raw exception text.

## Configuration

The target datasource configuration explicitly represents the independent classification dimensions. Configuration validation must reject unsupported combinations early.

Conceptually:

```yaml
datasources:
  threatfox:
    provider: threatfox
    protocol: https
    serialization_format: json
    semantic_format: urn:ati:datasource:semanticformat:threatfox
```

This is illustrative, not a binding YAML schema. PR 27A reconciled the exact
configuration model with fresh `main`: the canonical typed collection is
`Settings.datasources: tuple[DatasourceDefinition, ...]`
(`config/settings.py`), validated fail-closed through the pydantic boundary,
with provider-specific operational settings (concurrency, secret references,
lookback windows, retry policy, endpoints) deliberately left exactly where
profiles already define them. Existing secret-resolution and profile behavior
is unchanged.

## Compatibility and migration

PR 27 is an incremental migration. Until a datasource is migrated, existing `EvidenceProvider` behavior remains supported.

The end state should avoid two permanent competing ingestion architectures. PR 27E removed obsolete ThreatFox compatibility composition only after the migrated runtime gained equivalent deterministic coverage; the legacy grouped-Evidence `ThreatFoxProvider` remains importable for the pinned pre-27E contract tests but is no longer composed by production bootstrap. The remaining live Investigation Evidence sources stay on the legacy direct-to-Evidence path until their source-specific semantic follow-ups land (see `PR_27_SOURCE_MIGRATION_AUDIT.md`).

Security and semantic behavior already documented for individual sources remain requirements during migration. PR 27 changes ownership boundaries; it does not authorize looser upstream validation.

## PR 27 implementation sequence

### PR 27A — Datasource model and contracts

Formalize datasource/provider/protocol/serialization/semantic-format vocabulary, stable semantic-format URNs, configuration/domain contracts, validation, and compatibility boundaries. No wholesale provider migration.

### PR 27B — Acquisition execution and correlated logging

PR 27B delivered the acquisition-execution seam without migrating runtime
sources: one fresh `execution_id` UUID per acquisition execution, the closed
lifecycle vocabulary (`STARTED`/`ACQUIRED`/`DECODED`/`CONVERTED`/`COMPLETED`/
`FAILED`/`CANCELLED` with terminal outcomes exactly
`COMPLETED`/`FAILED`/`CANCELLED`), the immutable `DatasourceLogEvent` model,
the append-only `DatasourceLogRepository` port, the
`DatasourceExecutionRecorder` application helper, and the durable
append-only `ati.datasource_log` (SQL API v0025, migration 0030).
Fresh-main analysis confirmed no datasource log existed, so the smallest
append-only log was added rather than a durable execution table; lifecycle
and concurrency invariants are database-owned. No provider or batch path
was changed.

### PR 27C — Acquisition-to-semantic boundary [DONE]

Delivered: the cross-cutting `SemanticSourceContext`/`DatasourceStage`/
`DatasourceStageError`/`SemanticAcquisitionResult` contracts
(`app/datasource_semantics.py`); the extracted ThreatFox semantic parser
and the production ThreatFox acquisition-to-semantic reference path
(`infrastructure/datasources/threatfox.py`) reusing `ProviderHttpClient`
and the PR 27B recorder; the STIX 2.1 semantic parser consumed by the
MITRE batch source without behavior change; deterministic real-format and
real-PostgreSQL execution-log tests. No `ToEvidenceConverter`, registry,
converter, new persistence, or migration was added.

### PR 27D — Semantic-format-driven `ToEvidenceConverter` [DONE] [DONE]

Delivered the pure semantic-object -> Evidence conversion boundary:
`EvidenceConversionContext`, `ToEvidenceConverter` (0..N, deterministic,
no I/O/persistence/verdict/relationship ownership), the
`SemanticFormatId`-keyed `ToEvidenceConverterRegistry` (duplicate/unknown
fail closed), the flattening seam, `DatasourceStage.CONVERSION`, the
ThreatFox reference converter sharing its Evidence mapping with the
legacy provider (`infrastructure/datasources/threatfox_evidence.py`),
the lifecycle runner reusing the PR 27B recorder and `CONVERTED` event,
and unit/real-PostgreSQL conversion-lifecycle tests. No provider was
migrated, no Evidence is persisted, and no migration/schema change was
added.

### PR 27E — Existing-source migration and closure [DONE]

Delivered: the generic datasource-backed ``EvidenceProvider`` seam
(``app/datasource_provider.py``), the ThreatFox production runtime
migration (per-record Evidence through ``ThreatFoxDatasource`` +
``ThreatFoxToEvidenceConverter`` + the existing executor/persistence
paths with deferred terminal ownership), deterministic unit matrices and
real-PostgreSQL vertical slices (D27E-P01..P09), batch
SourceRecord/checkpoint transaction regression coverage, removal of
obsolete ThreatFox production composition with equivalent coverage, the
honest source-by-source migration audit
(``docs/PR_27_SOURCE_MIGRATION_AUDIT.md``), and architecture/
documentation reconciliation. ThreatFox is the migrated proprietary-
semantic reference slice proving the design is not STIX-centric;
unmigrated Investigation sources are tracked as
LEGACY_NOT_SEMANTICALLY_MODELED follow-up work rather than falsely
labelled PR27-compliant.

## Testing requirements

Each PR 27 slice requires deterministic unit tests and real integration tests where persistence/runtime behavior is involved.

The final series must prove:

- classification dimensions are independent;
- semantic-format URNs are stable;
- unsupported configuration combinations fail closed;
- execution events correlate by one `execution_id`;
- separate executions never share an execution ID;
- acquisition does not silently construct ATI Evidence in the target path;
- converter selection uses semantic format, not provider/protocol/serialization;
- `convert()` supports zero, one, and multiple Evidence outputs;
- exact Evidence provenance survives conversion;
- malformed source semantics fail closed;
- cancellation and safe-error behavior survive migration;
- existing provider security/validation behavior does not regress;
- existing extraction/persistence/Investigation behavior remains compatible;
- no live Internet is required by automated tests.

## Non-goals

PR 27 does not introduce:

- distributed task brokers;
- arbitrary plugin loading;
- a universal external-data ontology;
- automatic semantic-format inference from JSON shape;
- LLM-based source normalization;
- new attribution semantics;
- new maliciousness semantics;
- automatic relationship creation beyond existing approved extraction rules;
- unbounded artifact/record loading;
- commercial-only datasource behavior in the open-source documentation;
- the evaluation/release-hardening work formerly numbered PR 27.

That evaluation/release-hardening work is renumbered to **PR 28**.

## Relationship to PR 28

PR 28 expands ATI's evaluation and release-hardening layer: curated scenarios, deterministic invariants, agent and end-to-end trajectory evaluation, adversarial content, canonical malicious-domain/IP/malware trajectories, release gates, stability, performance/cost/latency reporting, licensing/source-term checks, and release documentation.

PR 27 should provide deterministic datasource fixtures and invariants that PR 28 can consume, but must not absorb the generic PR 28 evaluator/release platform.
