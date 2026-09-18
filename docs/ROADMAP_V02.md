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

The distributed boundary uses an explicit, stable, versioned `EvidenceMessage` contract. It must not be a direct serialization of an internal Pydantic/domain model. Producer-assigned stable `message_id`, `evidence_id`, and observation identity/provenance must support replay and future schema evolution. PR 28C defines the exact V1 wire fields, identities, canonical JSON codec, and fail-closed validation **(delivered)**; PR 28D+ builds the publisher/consumer/log abstraction over that contract.

## Distributed-log abstraction

The application architecture is defined before Kafka/Redpanda infrastructure is introduced. PR 28D provides publisher/consumer contracts and an ATI-owned deterministic in-process append-only `InMemoryEvidenceLog` using Python standard-library concurrency primitives.

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
| **28D** | Distributed-log abstraction | `EvidencePublisher`/consumer contracts plus deterministic `InMemoryEvidenceLog` |
| **28E** | Batch Evidence consumer | At-least-once/idempotent bounded-batch extraction and PostgreSQL persistence; offsets committed only after DB commit |
| **28F** | Datasource producer migration | Appropriate Evidence-producing datasource pipelines publish converted Evidence through the log boundary |
| **28G** | Kafka-compatible infrastructure | Kafka/Redpanda adapter, partitioning, consumer groups, retry/recovery and configuration |
| **28H** | End-to-end closure | Real-stack producer -> log -> consumer -> PostgreSQL crash/replay/recovery tests and compliance documentation |

### PR 28A — Global Evidence domain model **`[DONE]`**

Define the domain contracts and invariants above without absorbing broker infrastructure. Remove Investigation and subject ownership from Evidence, introduce stable Evidence plus immutable EvidenceObservation, observation-level Entity association, global RelationshipObservation provenance, and exact InvestigationEvidence admission semantics. Detailed implementation scope must be generated from fresh `main`.

**Delivered:** stable global `Evidence` with deterministic `evidence_id_for_source_record` identity; immutable per-Evidence `EvidenceObservation` with pure create/no-change/append material-state transitions and the canonical shallow `{old, new}` diff contract; `EvidenceObservationEntity`; exact `InvestigationEvidence` admission with bounded reason/actor vocabularies; `RelationshipObservation` referencing the exact `evidence_observation_id` (no Investigation field); Investigation-independent `EvidenceConversionContext`/`ConvertedEvidence`; ThreatFox converter migration; and the transitional `LegacyEvidence` v0.1 runtime boundary (removed in 28B). Unit matrix E28A-01..75 and vertical slices D28A-V01..V04 pass; PostgreSQL persistence, log, message, and consumer work remain 28B+.

### PR 28B — Persistence and Investigation-scoped query migration

Make the new model authoritative in PostgreSQL using versioned stored-function APIs and thin repositories. Migrate existing Evidence and relationship-observation persistence, remove Evidence from generic domain-object history, preserve referential integrity, and update Investigation-scoped reads to traverse admitted EvidenceObservations. Audit GEOINT, reports, RAG/analysis, API and UI consumers for reproducibility. Split into a corrective/sub-PR if fresh-main analysis shows this is too broad for one reviewable change.

### PR 28C — Evidence message contract **`[DONE]`**

Define the durable, versioned wire contract and stable producer-assigned message/Evidence/observation identities. Pin serialization, compatibility, validation, provenance, and deterministic replay semantics. No broker-specific API should leak into the contract.

**Delivered:** immutable V1 `EvidenceMessage` in `app/evidence_message.py` with explicit wire mapping (never an internal-model dump); deterministic producer-side `message_id` (UUIDv5 over datasource-execution + flattened sequence + Evidence identity) and `observation_candidate_id` (UUIDv5 over the message identity, explicitly not a committed Observation identity); reuse and validation of the PR 28A global Evidence identity; bounded datasource/source/format/retrieval provenance; pure builder/reconstruction between `ConvertedEvidence` and the message; canonical byte-deterministic UTF-8 JSON codec with pinned UTC timestamps; strict typed fail-closed decode (malformed JSON/UTF-8, unsupported versions, extra fields, malformed values, identity mismatches); and deterministic ThreatFox/replay/later-unchanged-acquisition slices. No publisher, consumer, log, broker infrastructure, DB migration, lifecycle event, or datasource runtime reroute was added; production remains synchronous until PR 28F.

### PR 28D — Distributed-log abstraction

Introduce application publisher/consumer contracts and deterministic local implementation. Model ordered append, polling, explicit consumer-position commit, replay/redelivery, bounded batches, and deterministic failure injection. Do not introduce Kafka, Redis, RabbitMQ, NATS, or another infrastructure product in this slice.

### PR 28E — Batch Evidence persistence consumer

Implement bounded consumer processing and set-oriented PostgreSQL persistence. Extraction remains consumer-side so the durable log stores source Evidence rather than derived graph state. Pin crash-before-commit, rollback, commit-before-offset, duplicate, replay, and partial/failure semantics with deterministic and real-PostgreSQL tests.

### PR 28F — Datasource producer migration

Move appropriate Evidence-producing datasource processing through semantic conversion to EvidenceMessage publication. Preserve the PR 27 provider/protocol/serialization/semantic-format boundaries and semantic-format-driven `ToEvidenceConverter` selection. Do not force reference-corpus `SourceRecord` ingestion through Evidence.

### PR 28G — Kafka-compatible infrastructure

Add the production-style Kafka/Redpanda adapter behind PR 28D contracts. Define topic/partition key strategy, consumer groups, configuration, retry/recovery, startup/shutdown and observability without changing application correctness semantics.

### PR 28H — End-to-end closure

Exercise producer -> log -> consumer -> PostgreSQL through real-stack trajectories, including redelivery, duplicate messages, consumer crashes at transaction boundaries, producer/consumer restart, unchanged source state, changed source state, multiple Investigations sharing observations, multiple observations of one Evidence in an Investigation, and exact RelationshipObservation provenance. Reconcile documentation and close the PR 28 series.

## Non-goals for the PR 28 series

PR 28 does not implement v0.3 monitor/findings functionality, make Kafka offsets domain identities, use the Evidence log as the Investigation task queue, make all reference corpora Evidence, introduce distributed exactly-once PostgreSQL/broker transactions, or allow newer EvidenceObservations to silently alter completed Investigation provenance.

## After PR 28

Former release-hardening/evaluation work moves after the PR 28 architecture and should be renumbered/replanned against the resulting v0.2 codebase. Monitor/diff/finding/job-administration work is retained in `ROADMAP_V03.md`.
