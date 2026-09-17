# ATI — v0.2 Global Evidence and Distributed Ingestion Architecture

> **Status: approved v0.2 target architecture; PR 28A contracts delivered, PR 28B persistence/Investigation-scoped reads delivered.**
>
> This document records the architectural decisions that govern the PR 28 series. `ROADMAP_V02.md` defines the delivery sequence. Delivered v0.1 behavior remains authoritative until the corresponding PR 28 slice lands.
>
> **PR 28A delivered scope:** the Python/domain contracts below — stable global `Evidence`, immutable `EvidenceObservation` with per-Evidence versions and material-state transitions, `EvidenceObservationEntity`, global `RelationshipObservation` provenance, exact `InvestigationEvidence` admission, deterministic semantic-format/source-record Evidence identity, and the Investigation-independent `ToEvidenceConverter` boundary producing `ConvertedEvidence` (global Evidence + observation candidate).
>
> **PR 28B delivered scope:** PostgreSQL tables/migrations for `Evidence`/`EvidenceObservation`/`EvidenceObservationEntity`/`InvestigationEvidence` (SQL API v0026, migration 0031), DB-owned race-safe per-Evidence version allocation with material no-op detection and canonical diffs, exact `RelationshipObservation`→`EvidenceObservation` provenance, exact Investigation admission, Investigation-scoped Evidence/Relationship/Analyst/GEOINT reads through admission, GEOINT provenance on `EvidenceObservation`, the synchronous datasource (ThreatFox) write path on the global model without any `LegacyEvidence` rebind, and exact-observation Assessment/report/coordinator/timeline provenance. The distributed log, `EvidenceMessage`, and consumer processing remain PR 28C–28H.

## PR 28B persistence and Investigation-scoped reads

```text
ConvertedEvidence
  -> ati.persist_evidence_observation   (CREATED | UNCHANGED | APPENDED;
                                        PostgreSQL owns versions/diff/no-op)
  -> EvidenceObservationEntity          (idempotent association)
  -> RelationshipObservation -> EvidenceObservation
  -> InvestigationEvidence              (exact, append-only, idempotent admission)
  -> Investigation-scoped reads (evidence / relationships / analyst / GEOINT)
```

PostgreSQL is authoritative for: stable Evidence metadata validation, atomic
Evidence + observation v1, per-Evidence serialization (transaction-scoped
advisory lock) and next-version allocation, material-state comparison,
canonical shallow `{key: {old, new}}` diffs, idempotent associations,
exact admission (including discovered-from validation), and
`RelationshipObservation` provenance. Evidence/EvidenceObservation never use
`domain_object_history`; the observation row is authoritative intelligence
history. Newer global observations never leak into an Investigation:
scope comes exclusively from `ati.investigation_evidence`.

## Domain model

```text
Evidence
   │
   └──< EvidenceObservation
            │
            ├──< EvidenceObservationEntity >── Entity
            ├──< RelationshipObservation >──── Relationship
            └──< InvestigationEvidence >────── Investigation
```

### Evidence

`Evidence` is a global stable external-intelligence item. It is not owned by an Investigation and does not have a single subject. Stable identity is derived deterministically from the semantic-format/source namespace plus an approved stable upstream source-record identity. Retrieval time is never part of Evidence identity. If a semantic format cannot provide a stable identity, the integration must stop/fail closed until an explicit identity contract exists.

Evidence does not participate in `domain_object_history` in v0.2. Its temporal states are first-class `EvidenceObservation` rows.

### EvidenceObservation

`EvidenceObservation` is an immutable state of one Evidence item as observed by ATI. Versions are monotonically increasing per Evidence and `(evidence_id, version)` is unique. Version 1 is the first material state. A later retrieval whose semantic state is unchanged does not create another observation merely because retrieval time changed. A material change appends the next version with a deterministic diff from the immediately preceding observation.

Operational acquisition telemetry such as datasource execution identity must not manufacture a semantic version. `EvidenceObservation` is authoritative intelligence history and is retained independently from generic `domain_object_history` purge/partition policy.

### EvidenceObservationEntity

The v0.1 one-subject Evidence association is replaced by observation-level many-to-many association:

```text
EvidenceObservationEntity
    evidence_observation_id
    entity_id
```

It records which canonical Entities are materially represented in the exact observation. It is structural provenance; semantic assertions remain RelationshipObservations.

### RelationshipObservation

`RelationshipObservation` becomes global and references the exact supporting `EvidenceObservation`, not Evidence, Investigation, or InvestigationEvidence. Extraction is therefore global per EvidenceObservation. Reusing an observation in multiple Investigations does not duplicate the relationship observation merely because another Investigation admitted it.

### InvestigationEvidence

Investigations admit exact immutable observations:

```text
InvestigationEvidence
    investigation_id
    evidence_observation_id
    inclusion_reason
    discovered_from_evidence_observation_id (nullable)
    added_at
    added_by
```

Logical identity is `(investigation_id, evidence_observation_id)`. Admission is append-only/idempotent. `inclusion_reason` and `added_by` are bounded mechanism/actor vocabularies, not free-form LLM prose. `discovered_from_evidence_observation_id` is workflow provenance, not a threat relationship.

An Investigation may admit several observations of the same stable Evidence over time. A newer global observation never silently replaces or augments the observations admitted to an Investigation. Analysis and reporting operate on the exact admitted observations. Analyst drill-down may navigate from an admitted observation to its stable Evidence and all global observation history while distinguishing admitted from non-admitted states.

## Datasource-to-Evidence boundary

PR 27 established:

```text
DatasourceDefinition
 -> acquisition
 -> serialization decoding
 -> semantic parsing / validation
 -> ToEvidenceConverter selected only by semantic_format
```

PR 28 changes what follows conversion. The v0.2 target is:

```text
                    PRODUCER SIDE
DatasourceDefinition
      ↓
Acquisition
      ↓
Serialization decoding
      ↓
Semantic parsing / validation
      ↓
ToEvidenceConverter
      ↓
versioned EvidenceMessage
      ↓
EvidencePublisher
      ↓
Distributed log
      ↓
                    CONSUMER SIDE
EvidenceConsumer
      ↓
message validation / deserialization
      ↓
bounded batch
      ↓
extraction / derived graph state
      ↓
PostgreSQL idempotent batch persistence
```

The log boundary is Evidence, not provider-native data and not derived Entity/Relationship graph state. The wire contract is an explicit versioned `EvidenceMessage`; it is not an accidental serialization of an internal Pydantic/domain object.

## Delivery and transaction semantics

ATI v0.2 assumes **at-least-once delivery with idempotent PostgreSQL persistence**. Stable producer-side Evidence/message identity exists before publication. Kafka/log offsets are transport position, never Evidence identity or a database idempotency key.

```text
poll bounded batch
      ↓
validate / extract
      ↓
BEGIN PostgreSQL transaction
      ↓
idempotently persist Evidence / EvidenceObservation
Entities / EvidenceObservationEntity
Relationships / RelationshipObservations
      ↓
COMMIT
      ↓
acknowledge / commit consumer position
```

If the process fails after PostgreSQL commit but before consumer-position commit, the batch is redelivered and PostgreSQL processing must be a harmless idempotent replay. ATI does not require a distributed exactly-once transaction between PostgreSQL and the log.

No database UnitOfWork spans network acquisition, semantic parsing, conversion, publication, consumer wait/poll, retry sleep, or offset acknowledgement.

## Broker abstraction and local implementation

Application code targets publisher/consumer contracts rather than Kafka APIs. Before Kafka/Redpanda is introduced, ATI uses an owned deterministic `InMemoryEvidenceLog` implementation. It is an append-only/replayable log abstraction rather than a destructive `asyncio.Queue` contract: records and committed consumer position are separate so tests can model redelivery after a failed/uncommitted batch.

The in-memory implementation may use Python standard-library concurrency primitives and supports deterministic failure/replay injection. It is for local development, architecture validation, and tests; it is not durable across process restart and is not a production substitute for Kafka/Redpanda.

PR 28G adds a Kafka-compatible infrastructure adapter without changing the application contracts or correctness semantics.

## Datasource lifecycle semantics

PR 27 datasource execution lifecycle remains operational provenance. With durable publication, producer completion means the Evidence messages were durably accepted by the configured log, not that PostgreSQL consumer persistence has completed. The detailed PR 28 producer plan will define the exact event vocabulary (including whether an explicit `PUBLISHED` stage is added) without using `datasource_log` as consumer offset, checkpoint, or deduplication state.

`datasource_execution_id` may travel with EvidenceMessage provenance for correlation, but a repeated retrieval/execution identifier does not define stable Evidence identity and does not force a new EvidenceObservation.

## SourceRecord boundary

Distributed Evidence ingestion does not force every datasource into Evidence. Reference-corpus ingestion such as MITRE ATT&CK may continue to produce `SourceRecord`/RAG corpus state when that is the correct semantic role. PR 28 migrates appropriate Evidence-producing datasources; it does not erase the distinction between intelligence Evidence and reference corpus material.

## Migration rule

This is a target contract. Until each PR 28 slice lands, existing v0.1 runtime/schema behavior remains authoritative. Implementations must migrate incrementally and keep tests/builds coherent rather than editing documentation as though global Evidence, EvidenceObservation, or the distributed log already exists in production code.
