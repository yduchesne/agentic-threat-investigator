# Agentic Threat Investigator — Datasource Architecture

## Status

This document defines the target datasource architecture for the PR 27 series. It is a forward design contract: existing PR 18/19 provider behavior remains authoritative until the corresponding PR 27 slice lands. PR 27 must migrate incrementally without breaking Investigation execution or Evidence provenance.

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
`EvidenceProvider`/`BatchSource` runtime paths. `semantic_format` is the later
converter-selection dimension; the converter itself does not exist yet and is
owned by PR 27D.

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
execution/logging concept. Existing providers remain on the transitional
pre-27C path until PR 27E.

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

The exact Python type signatures are determined by the detailed implementation plan and fresh source, but the semantic rules are binding:

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

The end state should avoid two permanent competing ingestion architectures. PR 27E removes obsolete compatibility seams only after all currently supported Evidence-producing sources have equivalent deterministic coverage on the new path.

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

### PR 27C — Acquisition-to-semantic boundary

Separate acquisition/serialization from semantic source objects. Establish semantic-format-specific parsing/validation contracts without yet requiring all source semantics to become ATI Evidence.

### PR 27D — Semantic-format-driven `ToEvidenceConverter`

Introduce zero-to-many conversion, registry/selection by `semantic_format`, deterministic provenance-bearing conversion tests, and no acquisition/persistence ownership in converters.

### PR 27E — Existing-source migration and closure

Migrate existing Evidence-producing sources to the new path, remove obsolete compatibility seams, and prove an end-to-end path:

```text
source fixture
 -> acquisition execution/logging
 -> serialization
 -> semantic object
 -> semantic-format-selected converter
 -> 0..N Evidence
 -> existing persistence/extraction/Investigation behavior
```

ThreatFox should be used as an important proprietary-semantic reference slice so the architecture is demonstrably not STIX-centric.

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
