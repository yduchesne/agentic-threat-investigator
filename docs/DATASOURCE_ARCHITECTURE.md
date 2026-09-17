# Agentic Threat Investigator — Datasource Architecture

## Status

This document defines the target datasource architecture for the PR 27 series. It is a forward design contract: existing PR 18/19 provider behavior remains authoritative until the corresponding PR 27 slice lands. PR 27 must migrate incrementally without breaking Investigation execution or Evidence provenance.

PR 27A (vocabulary), PR 27B (execution/logging), PR 27C
(acquisition-to-semantic boundary), PR 27D
(`ToEvidenceConverter`), and PR 27E (existing-source migration
and series closure) have landed. PR 27E migrated the ThreatFox
production Investigation runtime onto the PR 27A-D stack and closed
the series with a source-by-source migration audit.

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

A **SerializationFormat** identifies the physical encoding/representation, for example JSON, JSON Lines, CSV, XML, or a binary database/file representation. Serialization decoding yields values/records that can then be interpreted according to the semantic format.

### Semantic format

A **SemanticFormat** identifies the meaning/schema of source objects. Converter selection is based on this value.

Examples:

```text
urn:ati:datasource:semanticformat:stix21
urn:ati:datasource:semanticformat:threatfox
```

Provider-specific/proprietary semantic models receive their own ATI URNs. ThreatFox therefore uses `urn:ati:datasource:semanticformat:threatfox` even though its transport is HTTPS and its serialization is JSON.

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
- `stix21_semantics.py` owns a narrow STIX 2.1 decoded-value parser
  (`parse_stix21_bundle` -> `Stix21Object`): mapping bundle, nonblank
  `type`/`id`, optional string `spec_version`, and deeply immutable
  snapshots that preserve every extension field (`x_mitre_*`, unknown valid
  types) as data. It is independent of MITRE ATT&CK `SourceRecord`
  normalization and deliberately does not reimplement the full STIX 2.1
  standard. `MitreAttackBatchSource` consumes it as its decoded-value
  boundary with `SourceRecord` identity, content-hash, checkpoint, batch,
  and ingestion behavior unchanged.
- `threatfox.py` is the narrow production ThreatFox acquisition-to-semantic
  reference path (`ThreatFoxDatasource` + tiny runner): it validates the
  explicit datasource dimensions (THREATFOX + HTTPS + JSON + THREATFOX)
  fail-closed before any I/O, reuses `ProviderHttpClient` (Auth-Key stays
  header-only) and the PR 27B `DatasourceExecutionRecorder`, classifies
  failures by typed stage (never by matching free-form message text), and
  persists only bounded safe terminal codes.

Semantic modules construct no ATI Evidence/`SourceRecord`, perform no
network/DB/persistence I/O, and never log full source objects. There is no
universal mega-schema (ThreatFox and STIX objects remain source-native),
no semantic-object persistence table, and no migration in this slice.

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
identity, versioning, and material no-op detection. This document makes no
claim of `EvidenceMessage`/log publication, which stays PR 28C+.

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

Dominant lifecycle invariants:

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
