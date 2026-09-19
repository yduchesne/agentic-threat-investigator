# ATI — v0.2 Roadmap

## Status

ATI v0.1 implementation is complete for roadmap purposes. v0.2 begins with the PR 28 series and focuses on **global Evidence plus a distributed Evidence-ingestion architecture**. Detailed PR plans remain subject to fresh-`main` analysis under `DETAILED_PR_PLAN_AUTHORING_GUIDE.md`.

## Architectural objective

v0.2 separates durable source intelligence from the Investigation that happens to discover or use it, then introduces a durable Evidence integration boundary between datasource producers and PostgreSQL consumers.

```text
Datasource
  -> acquisition
  -> serialization decode
  -> semantic validation
  -> ToEvidenceConverter
  -> EvidenceMessage
  -> EvidencePublisher
  -> distributed log
  -> EvidenceConsumer
  -> extraction
  -> bounded PostgreSQL persistence
```

The log boundary carries authoritative source Evidence observations. It does not carry derived graph state as the primary contract, and it is not the Investigation task-dispatch queue.

## Global Evidence model

### Evidence and EvidenceObservation

`Evidence` becomes a stable global intelligence object identified from semantic-format-specific stable upstream identity. It is no longer owned by an Investigation and has no privileged `subject`.

Mutable source state is represented by immutable `EvidenceObservation` rows:

```text
Evidence
    |
    +--< EvidenceObservation
             |
             +--< EvidenceObservationEntity >-- Entity
             +--< RelationshipObservation >---- Relationship
             +--< InvestigationEvidence >------ Investigation
```

`EvidenceObservation` has a per-Evidence monotonically increasing version. A materially changed upstream state creates a new immutable observation. Re-retrieving semantically unchanged source state is a no-op for Evidence history; `retrieved_at` changing by itself does not create a new semantic version.

Each observation stores a diff from the immediately preceding observation, using ATI's established JSONB-diff semantics where practical.

`Evidence` no longer participates in `domain_object_history`. `EvidenceObservation` is first-class intelligence data with its own retention semantics. This avoids coupling generic partitioned/purgeable audit history to foreign keys from intelligence records.

### Evidence identity

Evidence identity is based on the stable identity supplied by the semantic source model, not on retrieval time and not on a broker offset. The exact identity tuple is semantic-format-specific and should produce a deterministic ATI Evidence UUID when the upstream format provides stable identity. A semantic format that cannot provide an approved stable identity must fail closed rather than silently inventing unstable identity semantics.

Source-record identity and Evidence-observation identity are distinct. The same upstream item can evolve through multiple EvidenceObservations while retaining one Evidence identity.

### Evidence and Entity

`Evidence.subject` is removed entirely. Entity association is many-to-many at the observation level:

```text
EvidenceObservation --< EvidenceObservationEntity >-- Entity
```

The initial association is structural (`evidence_observation_id`, `entity_id`) and does not introduce redundant subject/object/indicator roles. Specific semantic assertions remain represented by `Relationship` and `RelationshipObservation`.

### RelationshipObservation

`RelationshipObservation` is global and references the exact `EvidenceObservation` that supports the relationship observation. It does not carry Investigation ownership.

```text
EvidenceObservation -> RelationshipObservation -> Relationship
```

This preserves exact evidentiary provenance even as a stable Evidence item acquires newer observations.

### InvestigationEvidence and reproducibility

An Investigation admits exact immutable EvidenceObservations, never an implicit "latest Evidence" state:

```python
class InvestigationEvidence:
    investigation_id: UUID
    evidence_observation_id: UUID
    inclusion_reason: InvestigationEvidenceReason
    discovered_from_evidence_observation_id: UUID | None
    added_at: datetime
    added_by: InvestigationEvidenceActor
```

Logical identity is `(investigation_id, evidence_observation_id)`. The same Investigation may admit multiple observations of the same stable Evidence at different times. A newer global EvidenceObservation does not retroactively alter an Investigation.

This is the basis for Investigation/report reproducibility. Analyst drill-down can navigate from the admitted EvidenceObservation to its stable Evidence and inspect the complete EvidenceObservation history, including states not admitted to that Investigation.

## Delivery and persistence semantics

ATI v0.2 assumes **at-least-once delivery plus idempotent PostgreSQL persistence**. Every durable Evidence message has stable producer-assigned identity. Consumer offsets are acknowledged only after the corresponding PostgreSQL transaction commits.

```text
receive bounded message batch
    -> validate / deserialize
    -> extract derived state
    -> BEGIN PostgreSQL transaction
       -> idempotently persist Evidence
       -> idempotently persist EvidenceObservation
       -> idempotently persist Entities
       -> idempotently persist EvidenceObservationEntity
       -> idempotently persist Relationships
       -> idempotently persist RelationshipObservations
       -> persist any DB-side ingestion state
    -> COMMIT
    -> acknowledge / commit log offsets
```

A crash after PostgreSQL commit but before offset acknowledgement causes normal redelivery. PostgreSQL replay must therefore be harmless. ATI does not require distributed exactly-once transactions between PostgreSQL and the log.

Broker offsets are transport topology, not Evidence identity or domain idempotency keys.

## Evidence message contract

The distributed boundary uses an explicit, stable, versioned `EvidenceMessage` contract. It must not be a direct serialization of an internal Pydantic/domain model. Producer-assigned stable `message_id`, `evidence_id`, and observation identity/provenance must support replay and future schema evolution. PR 28C defines the exact V1 wire fields, identities, canonical JSON codec, and fail-closed validation **(delivered)**; PR 28D delivered the publisher/consumer/log abstraction over that contract.

## Distributed-log abstraction

The application architecture is defined before Kafka/Redpanda infrastructure is introduced. PR 28D provides publisher/consumer contracts and an ATI-owned deterministic in-process append-only `InMemoryEvidenceLog` using Python standard-library concurrency primitives **(delivered)**.

The in-memory implementation models log semantics rather than destructive queue semantics: records remain ordered, consumer position is separate, commit occurs explicitly after successful processing, and tests can deterministically simulate redelivery and failures. It is for development and architecture validation and is not durable across process restart.

A Kafka/Redpanda-compatible adapter later implements the same application contracts.

## Datasource execution semantics

Producer-side datasource execution owns acquisition, decoding, semantic validation, conversion, and durable publication. A likely lifecycle extension is:

```text
STARTED -> ACQUIRED -> DECODED -> CONVERTED -> PUBLISHED -> COMPLETED
```

Producer `COMPLETED` means durable publication succeeded; it does not mean PostgreSQL consumption completed. `datasource_execution_id` travels with Evidence-message provenance for correlation. Consumer processing uses separate operational telemetry rather than emitting one datasource lifecycle event per consumed Evidence.

Reference-corpus ingestion remains distinct. Sources such as MITRE ATT&CK that feed `SourceRecord`/RAG corpora are not automatically converted into Evidence merely because a distributed log exists.

## PR 28 series

| PR | Scope | Principal result |
|---|---|---|
| **28A** | Global Evidence domain model | Stable global `Evidence`; immutable versioned `EvidenceObservation`; observation-level Entity, Relationship and Investigation provenance **(delivered)** |
| **28B** | Persistence and query migration | PostgreSQL schema/functions/repositories plus migration of Investigation-scoped reads to the new observation model **(delivered)** |
| **28C** | Evidence wire contract | Explicit versioned `EvidenceMessage` with stable producer-side identity and replay-safe provenance **(delivered)** |
| **28D** | Distributed-log abstraction | `EvidencePublisher`/consumer contracts plus deterministic `InMemoryEvidenceLog` **(delivered)** |
| **28E** | Batch Evidence consumer | At-least-once/idempotent bounded-batch extraction and PostgreSQL persistence; offsets committed only after DB commit |
| **28F-1** | `orjson` integration | behavior-compatible JSON performance implementation |
| **28F-2** | Datasource producer migration | datasource path publishes deterministic EvidenceMessages |
| **28G** | Kafka-compatible infrastructure | Kafka/Redpanda adapter, partitioning, consumer groups, retry/recovery and configuration |
| **28H** | End-to-end closure | Real-stack producer -> log -> consumer -> PostgreSQL crash/replay/recovery tests and compliance documentation |

### PR 28A — Global Evidence domain model **`[DONE]`**

Define the domain contracts and invariants above without absorbing broker infrastructure. Remove Investigation and subject ownership from Evidence, introduce stable Evidence plus immutable EvidenceObservation, observation-level Entity association, global RelationshipObservation provenance, and exact InvestigationEvidence admission semantics. Detailed implementation scope must be generated from fresh `main`.

**Delivered:** stable global `Evidence` with deterministic `evidence_id_for_source_record` identity; immutable per-Evidence `EvidenceObservation` with pure create/no-change/append material-state transitions and the canonical shallow `{old, new}` diff contract; `EvidenceObservationEntity`; exact `InvestigationEvidence` admission with bounded reason/actor vocabularies; `RelationshipObservation` referencing the exact `evidence_observation_id` (no Investigation field); Investigation-independent `EvidenceConversionContext`/`ConvertedEvidence`; ThreatFox converter migration; and the transitional `LegacyEvidence` v0.1 runtime boundary (removed in 28B). Unit matrix E28A-01..75 and vertical slices D28A-V01..V04 pass; PostgreSQL persistence, log, message, and consumer work remain 28B+.

### PR 28B — Persistence and Investigation-scoped query migration

Make the new model authoritative in PostgreSQL using versioned stored-function APIs and thin repositories. Migrate existing Evidence and relationship-observation persistence, remove Evidence from generic domain-object history, preserve referential integrity, and update Investigation-scoped reads to traverse admitted EvidenceObservations. Audit GEOINT, reports, RAG/analysis, API and UI consumers for reproducibility. Split into a corrective/sub-PR if fresh-main analysis shows this is too broad for one reviewable change.

### PR 28C — Evidence message contract **`[DONE]`**

Define the durable, versioned wire contract and stable producer-assigned message/Evidence/observation identities. Pin serialization, compatibility, validation, provenance, and deterministic replay semantics. No broker-specific API should leak into the contract.

**Delivered:** immutable V1 `EvidenceMessage` in `app/evidence_message.py` with explicit wire mapping (never an internal-model dump); deterministic producer-side `message_id` (UUIDv5 over datasource-execution + flattened sequence + Evidence identity) and `observation_candidate_id` (UUIDv5 over the message identity, explicitly not a committed Observation identity); reuse and validation of the PR 28A global Evidence identity; bounded datasource/source/format/retrieval provenance; pure builder/reconstruction between `ConvertedEvidence` and the message; canonical byte-deterministic UTF-8 JSON codec with pinned UTC timestamps; strict typed fail-closed decode (malformed JSON/UTF-8, unsupported versions, extra fields, malformed values, identity mismatches); and deterministic ThreatFox/replay/later-unchanged-acquisition slices. No publisher, consumer, log, broker infrastructure, DB migration, lifecycle event, or datasource runtime reroute was added; production remains synchronous until PR 28F-2.

### PR 28D — Distributed-log abstraction **`[DONE]`**

Introduce application publisher/consumer contracts and deterministic local implementation. Model ordered append, polling, explicit consumer-position commit, replay/redelivery, bounded batches, and deterministic failure injection. Do not introduce Kafka, Redis, RabbitMQ, NATS, or another infrastructure product in this slice.

**Delivered:** broker-neutral `EvidencePublisher`/`EvidenceConsumer` ABCs and immutable log position/record/batch/consumer-identity contracts in `app/evidence_log.py`; the deterministic append-only `InMemoryEvidenceLog` (one ordered stream, contiguous publication, `asyncio.Lock` serialization within one event loop, records retained after commit, independent per-consumer committed cursors, bounded non-destructive `poll(max_messages)`, exact explicit `commit(batch)` with fail-closed foreign/skipped/stale/forged/reversed/non-contiguous validation, natural redelivery of uncommitted batches, same-ID handle recreation, and narrow one-shot `fail_next_publish`/`fail_next_poll`/`fail_next_commit` faults); real PR 28C `EvidenceMessage` values throughout. Unit matrix E28D-C/P/R/K/G/F passes and vertical slices D28D-V01..V05 pass. No Kafka/Redpanda/Redis, no PostgreSQL consumer, no broker fields, no datasource producer reroute, no `PUBLISHED`, and no lifecycle change were added; production remains synchronous, and the in-memory log is not durable across process restart.

### PR 28E — Batch Evidence persistence consumer **`[DONE]`**

Implement bounded consumer processing and set-oriented PostgreSQL persistence. Extraction remains consumer-side so the durable log stores source Evidence rather than derived graph state. Pin crash-before-commit, rollback, commit-before-offset, duplicate, replay, and partial/failure semantics with deterministic and real-PostgreSQL tests.

**Delivered:** the bounded one-iteration `EvidencePersistenceConsumer` in `app/evidence_consumer.py` (poll -> prepare -> one atomic PostgreSQL transaction -> only-then consumer commit; empty polls open no transaction); consumer-side extraction input reconstructed from durable message content for ThreatFox (`app/extraction/message_context.py`: canonical `DOMAIN`/`IP_ADDRESS` invocation contexts from `matches[].ioc`/`ioc_type`, typed fail-closed unsupported/malformed handling, no `subject`/Investigation field added to `EvidenceMessage`); the prepared global batch contract (`PreparedEvidenceRecord`/`PreparedEvidenceBatch` — no transport position, no Investigation identity); `EvidenceBatchPersistenceService` (default 100, hard ceiling 500 enforced by the service, adapter, and SQL API v0027); the one-call PostgreSQL batch API `ati.persist_evidence_batch` (SQL API v0027, migration 0032) reusing the authoritative PR 28B/18C transition functions in input order, returning ordered CREATED/UNCHANGED/APPENDED results with authoritative observation IDs (chosen Option A — `observation_candidate_id` is never required to become the APPENDED observation ID); the narrow `ati.evidence_message_receipt` idempotency table keyed by the stable PR 28C `message_id` (the approved PR 28E amendment to STOP #16 — transactional at-least-once idempotency only, no log/consumer/Investigation semantics); deterministic and real-PostgreSQL tests for the E28E-C/X/P matrices, I28E-01..15 (including the required same-Evidence multi-state `[A,B,C]` replay and the distinct-message recurrence `[M1:A, M2:B, M3:A]` — the second A is APPENDED, never mistaken for replay), and V28E-01..05 vertical slices over the real in-memory log. No datasource producer migration, no `PUBLISHED` lifecycle state, no Kafka/Redpanda, no retry/DLQ policy, and no Investigation admission were added; production datasource execution remains synchronous until PR 28F-2.

### PR 28F-1 — `orjson` integration and JSON performance hardening **`[DONE]`**

Introduce `orjson` as ATI's preferred high-performance JSON
implementation at behavior-compatible runtime JSON boundaries before
producer rerouting. Preserve ATI-owned semantic validation and durable
wire contracts; migrate provider response parsing and other safe
production call sites, and migrate the EvidenceMessage codec only
where canonical compatibility is proven. Do not redesign serialization
models, replace Pydantic, or introduce `msgspec`.

**Delivered:** direct bounded runtime dependency `orjson>=3.11.1,<4`
(regenerated lockfile, Python 3.14 resolution, no `msgspec`, no unrelated
upgrades); the bounded accepted-response parse in
`infrastructure/providers/http.py` now uses `orjson.loads(body)` directly
on bounded bytes (no `str` round trip) with the typed `HttpOutcome`
contracts, `DatasourceStage` classification, retry/size/content-type/
content-encoding behavior, and `response_json` shapes unchanged; invalid
UTF-8, malformed syntax, and the non-standard `NaN`/`Infinity`/`-Infinity`
constants now fail closed through the existing non-retryable
`INVALID_RESPONSE` / `SERIALIZATION` / `"malformed JSON"` outcome with no
raw decoder or payload leakage (documented engine boundary: `orjson`
parses integers beyond the signed-64/unsigned-64 range as `float`; no
supported provider contract emits such integers); the full F1-J01..J15
matrix plus V28F1-01/02 vertical slices; every production stdlib JSON
site inventoried/classified (untrusted runtime parses, canonical
fingerprint/hash and canonical-json-byte contracts, LLM-prompt
`ensure_ascii=True` builders, `object_pairs_hook` duplicate-key loaders,
logging redaction with `default=repr`, and JSONB persistence) with only
the provider HTTP parse migrated; the EvidenceMessage V1 wire mapping
(`_to_wire_dict`) remains authoritative and its codec retained Python's
standard-library `json` in both directions because the encoder probe
proved `orjson` cannot reproduce canonical bytes for finite float
scientific notation (`1.2e-07` vs `1.2e-7`) and cannot parse integers
beyond the 64-bit range exactly, so a frozen golden-bytes oracle now pins
the canonical contract; and the roadmap split below. No `msgspec`, typed
decoder, Pydantic replacement, datasource publication, `PUBLISHED`
lifecycle state, Kafka/Redpanda, DB migration, or global FastAPI
serialization change was made.

### PR 28F-2 — Datasource Evidence producer migration **`[DONE]`**

Move appropriate Evidence-producing datasource executions through
semantic-format-driven `ToEvidenceConverter`, deterministic
`EvidenceMessage` construction, and `EvidencePublisher` publication.
Preserve the PR 27 provider/protocol/serialization/semantic-format
boundaries; flatten zero-to-many conversion results in deterministic
sequence order; carry `datasource_execution_id`; and pin producer
publication lifecycle semantics so `COMPLETED` means durable publication
succeeded, not PostgreSQL consumption. Reference-corpus `SourceRecord`
ingestion remains outside the Evidence log. Do not force reference-corpus
`SourceRecord` ingestion through Evidence.

**Delivered:** the generic producer service `DatasourceEvidenceProducer`
(`app/datasource_evidence_producer.py`) reusing the PR 27B recorder, the
PR 27C `SemanticAcquirer`, the semantic-format-only
`ToEvidenceConverterRegistry` and deterministic 0..N flattening, the
PR 28C `evidence_message_from_converted` builder, and the PR 28D
`EvidencePublisher` ABC; one fresh `datasource_execution_id` per
execution propagated into every message with execution-local zero-based
sequence over the whole flattened output (source order, then converter
return order; no sort/dedup); exactly one ordered `publish(...)` call per
execution (including `publish(())` for valid zero output); the
non-terminal `PUBLISHED` lifecycle stage whose `item_count` is the
accepted message count (SQL API v0028, migration 0033; terminal set
unchanged); producer `COMPLETED` defined as successful publication with
no consumer wait and no direct observation-persistence fallback on
publication failure; cancellation stays cancellation; and the ThreatFox
reference producer proof (deterministic F2-M/L/P/S unit matrices plus
real-PostgreSQL V28F2-01..07 vertical slices: success, multi-record
order, zero result, publisher failure, publisher-boundary cancellation,
DB lifecycle acceptance/post-terminal rejection, and producer/consumer
separation). No Kafka/Redpanda, no retry/DLQ, no outbox, no
Investigation/broker fields in messages, and no publish-plus-direct-
persist dual write were added. Composition is deliberately limited to
the application seam: no production runner routes datasource executions
to the producer yet, so the PR 27E Investigation compatibility path
remains the active synchronous production Investigation path and is
documented as transitional (producer runner wiring stays PR 28G/H).

### PR 28G — Kafka-compatible infrastructure

Add the production-style Kafka/Redpanda adapter behind PR 28D contracts. Define topic/partition key strategy, consumer groups, configuration, retry/recovery, startup/shutdown and observability without changing application correctness semantics.

### PR 28H — End-to-end closure

Exercise producer -> log -> consumer -> PostgreSQL through real-stack trajectories, including redelivery, duplicate messages, consumer crashes at transaction boundaries, producer/consumer restart, unchanged source state, changed source state, multiple Investigations sharing observations, multiple observations of one Evidence in an Investigation, and exact RelationshipObservation provenance. Reconcile documentation and close the PR 28 series.

## Non-goals for the PR 28 series

PR 28 does not implement v0.3 monitor/findings functionality, make Kafka offsets domain identities, use the Evidence log as the Investigation task queue, make all reference corpora Evidence, introduce distributed exactly-once PostgreSQL/broker transactions, or allow newer EvidenceObservations to silently alter completed Investigation provenance.

## After PR 28

Former release-hardening/evaluation work moves after the PR 28 architecture and should be renumbered/replanned against the resulting v0.2 codebase. Monitor/diff/finding/job-administration work is retained in `ROADMAP_V03.md`.
