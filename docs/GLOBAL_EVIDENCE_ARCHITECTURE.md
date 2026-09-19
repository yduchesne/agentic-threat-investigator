# ATI — v0.2 Global Evidence and Distributed Ingestion Architecture

> **Status: approved v0.2 target architecture; PR 28A contracts delivered, PR 28B persistence/Investigation-scoped reads delivered, PR 28C EvidenceMessage wire contract delivered, PR 28D publisher/consumer contracts and deterministic in-memory log delivered, PR 28E bounded Evidence persistence consumer delivered, PR 28F-2 datasource Evidence producer path delivered at the application seam.**
>
> This document records the architectural decisions that govern the PR 28 series. `ROADMAP_V02.md` defines the delivery sequence. Delivered v0.1 behavior remains authoritative until the corresponding PR 28 slice lands.
>
> **PR 28A delivered scope:** the Python/domain contracts below — stable global `Evidence`, immutable `EvidenceObservation` with per-Evidence versions and material-state transitions, `EvidenceObservationEntity`, global `RelationshipObservation` provenance, exact `InvestigationEvidence` admission, deterministic semantic-format/source-record Evidence identity, and the Investigation-independent `ToEvidenceConverter` boundary producing `ConvertedEvidence` (global Evidence + observation candidate).
>
> **PR 28B delivered scope:** PostgreSQL tables/migrations for `Evidence`/`EvidenceObservation`/`EvidenceObservationEntity`/`InvestigationEvidence` (SQL API v0026, migration 0031), DB-owned race-safe per-Evidence version allocation with material no-op detection and canonical diffs, exact `RelationshipObservation`→`EvidenceObservation` provenance, exact Investigation admission, Investigation-scoped Evidence/Relationship/Analyst/GEOINT reads through admission, GEOINT provenance on `EvidenceObservation`, the synchronous datasource (ThreatFox) write path on the global model without any `LegacyEvidence` rebind, and exact-observation Assessment/report/coordinator/timeline provenance. The
`EvidenceMessage` wire contract is delivered in PR 28C below; the
distributed log publisher/consumer contracts and deterministic in-memory
log are delivered in PR 28D below; PostgreSQL-backed consumer persistence
processing remains PR 28E–28H.

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

## PR 28C EvidenceMessage wire contract (delivered)

PR 28C defines the explicit, versioned, broker-independent `EvidenceMessage`
wire contract between semantic conversion and the future distributed-log
boundary (`src/agentic_threat_investigator/app/evidence_message.py`). It
publishes nothing, consumes nothing, opens no UnitOfWork, and leaves the
synchronous datasource runtime behaviorally unchanged. The wire form is
**never** a direct serialization of `ConvertedEvidence`, `Evidence`,
`EvidenceObservation`, `EvidenceObservationCandidate`, or
`SemanticSourceContext`.

```text
ConvertedEvidence + SemanticSourceContext
  + datasource_execution_id + sequence
  -> EvidenceMessage v1          (evidence_message_from_converted)
  -> canonical UTF-8 JSON bytes  (encode_evidence_message)
  -> strict decode               (decode_evidence_message)
  -> ConvertedEvidence           (converted_evidence_from_message)
```

### V1 fields (exact)

| Field | Type | Semantics |
|---|---|---|
| `schema_version` | int = 1 | explicit wire version; exactly `1` |
| `message_id` | UUID | producer-side replay-stable UUIDv5 identity |
| `observation_candidate_id` | UUID | proposed/replay candidate identity |
| `datasource_execution_id` | UUID | one producer acquisition execution |
| `datasource_id` | `DatasourceId` | bounded datasource-instance identity |
| `source_id` | `SourceId` | source namespace URN |
| `semantic_format` | `SemanticFormatId` | semantic-format URN |
| `sequence` | int >= 0 | zero-based flattened `ConvertedEvidence` order |
| `evidence_id` | UUID | existing global Evidence identity |
| `evidence_type` | `EvidenceType` | stable evidence-type URN |
| `source_record_id` | non-empty str | exact upstream record identity (never normalized) |
| `retrieved_at` | aware UTC datetime | acquisition provenance (operational only) |
| `observed_at` | aware UTC datetime or null | material state |
| `source_url` | str or null | material state (credential-free source reference) |
| `facts` | JSON object | material state |
| `raw_payload` | JSON object or null | material state (source intelligence payload only) |

### Identity distinctions

- `evidence_id` reuses `evidence_id_for_source_record(semantic_format,
  source_id, source_record_id)`; it is recomputed and validated on every
  construction and decode. Schema representation and producer slot never
  participate.
- `message_id` is an ATI-owned UUIDv5 over the exact
  `(datasource_execution_id, sequence, evidence_id)` producer execution
  slot. It is replay-stable per slot: a new datasource execution is a new
  acquisition event and may carry a new `message_id` even when the semantic
  state is unchanged. Retrieval time, broker metadata, Investigation/Entity
  identity, Python hash, and `uuid4` never participate.
- `observation_candidate_id` is an ATI-owned UUIDv5 derived from
  `message_id`. It is the producer/replay identity of the **proposed**
  material state — explicitly **not** the committed `EvidenceObservation.id`
  and not proof that a new observation exists. A future CREATED/APPENDED
  consumer may propose this ID to PostgreSQL; for an UNCHANGED outcome
  PostgreSQL returns the existing observation ID and the candidate ID is
  unused.
- The producer never allocates `EvidenceObservation.version` or `diff`;
  PostgreSQL owns create/no-change/append, version, and diff (PR 28B).

### Bounded provenance and exclusions

Provenance is bounded to the datasource execution, datasource/source/
semantic-format identities, and the candidate's source/retrieval
provenance. Absent by construction: Investigation ownership, subject
Entity, pivot/work-item state, reports, agent state, derived
Entity/Relationship/GEOINT/Assessment state, broker topic/partition/offset/
group/delivery metadata, and any generic `metadata`/`headers`/`config`/
`credentials`/`extra` dictionary. No credentials, auth headers, cookies,
secret references, or exception text enter the contract.

### Canonical JSON and versioning

The codec is explicitly owned (never `model_dump_json()`): canonical UTF-8
JSON with sorted keys, compact fixed separators, `allow_nan=False`,
canonical lowercase UUID strings, stable enum URN values, and `Z`-pinned
UTC timestamps with fixed microseconds — structurally equal messages encode
to byte-identical output. `decode_evidence_message` fails closed with typed
bounded errors: malformed UTF-8/JSON is a decode error, any version other
than `1` is an unsupported-version error, and unknown fields, malformed
values, negative sequences, empty record identities, NaN/Infinity, and
identity mismatches are validation errors. V1 accepts exactly
`schema_version == 1`; future versions must explicitly define reader
compatibility, writer selection, migration/default rules, and identity
stability.

## PR 28D distributed-log contracts and in-memory log (delivered)

PR 28D delivers the broker-neutral application log seam over PR 28C
(`src/agentic_threat_investigator/app/evidence_log.py`):
`EvidencePublisher`, `EvidenceConsumer`, immutable log position/record/
batch contracts, and the deterministic append-only `InMemoryEvidenceLog`
with independent per-consumer committed cursors. The log carries exactly
PR 28C `EvidenceMessage` values; it carries no `ConvertedEvidence`,
semantic source objects, committed `EvidenceObservation` rows, graph
state, Investigation work, or arbitrary bytes.

Invariants pinning this seam:

- **Append-only, non-destructive polling.** Records remain present for the
  entire log-instance lifetime — even after every consumer commits them —
  and `poll(max_messages)` never removes or acknowledges them. An
  uncommitted batch is always redeliverable.
- **Explicit commit.** Polling never advances anything; only
  `commit(batch)` advances one consumer's committed cursor, and only for
  an exact, contiguous, ordered batch starting at that cursor. Foreign,
  forged, skipped, reversed, or stale/stale-repeat batches fail closed;
  a failed commit changes no cursor and the next poll naturally redelivers.
- **At-least-once and independent cursors.** Each `EvidenceConsumerId`
  owns one committed cursor; different consumers are fully independent and
  the same identity resumes its cursor within one log instance. Duplicate
  `EvidenceMessage` publication creates distinct records — the log never
  deduplicates.
- **Transport-only positions.** `EvidenceLogPosition` is a per-instance
  ordering index, never an Evidence ID, message ID, observation-candidate
  ID, or PostgreSQL idempotency key, and never appears inside a message.
- **Deterministic one-shot faults.** `fail_next_publish()` /
  `fail_next_poll()` / `fail_next_commit()` simulate the next
  publish/poll/commit failure (optionally per consumer) with no random
  probabilities or sleeps; publish faults use no position, poll faults
  change no cursor, and commit faults leave redelivery intact.
- **In-process, non-durable.** The in-memory log models restart only
  within one log instance (handle recreation with the same identity
  resumes the cursor); it provides no durability across process restart
  and no cross-process guarantees. Kafka/Redpanda behind the same
  contracts remain PR 28G.

PR 28E builds bounded PostgreSQL consumer persistence on this seam
(delivered). PR 28F-2 delivers the producer side at the application seam:
`DatasourceEvidenceProducer` flattens one datasource execution's
`ConvertedEvidence` tuple into an ordered `EvidenceMessage` tuple
(execution-local zero-based sequence, exact `datasource_execution_id`),
publishes it with exactly one ordered `EvidencePublisher.publish(...)`
call, and records the non-terminal `PUBLISHED` lifecycle stage before
`COMPLETED`; producer `COMPLETED` means successful publication, never
consumer/PostgreSQL persistence, and the producer never waits for the
PR 28E consumer. The production Investigation datasource runtime is
still not routed through the log — the PR 27E Investigation
compatibility path remains synchronous and transitional. Kafka/Redpanda
behind the unchanged PR 28D contracts remain PR 28G, and full
producer -> log -> consumer -> PostgreSQL closure is PR 28H.

## PR 28E bounded Evidence persistence consumer (delivered)

PR 28E connects the PR 28D consumer seam to the PR 28B global Evidence
PostgreSQL model.

### Consumer processing boundary

- `app/evidence_consumer.py::EvidencePersistenceConsumer` polls **one
  bounded batch** (`poll(max_messages)`, default 100, hard ceiling 500),
  prepares every record (PR 28C message reconstruction + consumer-side
  deterministic extraction) **before** the transaction, persists the whole
  prepared batch through one atomic PostgreSQL transaction, and only then
  commits the consumer batch. One non-empty polled batch is one
  PostgreSQL transaction; no `finally`-block acknowledgement and never a
  consumer commit before the DB commit.
- `EvidenceConsumerRunResult` carries only bounded counts
  (polled/persisted/created/unchanged/appended/committed); an empty poll
  returns `committed=False` with no transaction.
- Extraction is consumer-side: the durable log stores source Evidence,
  never derived graph state. `app/extraction/message_context.py`
  reconstructs the smallest `EvidenceExtractionView` from durable message
  content for the currently supported ThreatFox semantic format
  (`matches[].ioc`/`ioc_type` map exactly to canonical `DOMAIN`/
  `IP_ADDRESS` invocation context); unsupported sources, URL IOCs, and
  malformed/non-canonical facts fail closed with typed errors. The
  reconstructed invocation Entity is execution context only — no subject
  field is added to `EvidenceMessage`.

### Prepared batch contract

`PreparedEvidenceRecord`/`PreparedEvidenceBatch` carry the already-
validated, already-extracted persistence work of one polled batch
(message_id, observation_candidate_id, ConvertedEvidence, invocation
Entity, extraction). No Investigation identity, no transport position, and
no broker metadata cross the persistence boundary.

### PostgreSQL batch API (SQL API v0027, migration 0032)

- `ati.persist_evidence_batch(p_items jsonb)` stages one bounded prepared
  batch in input (log) order, reuses the authoritative PR 28B Evidence
  transition per record, resolves Entities and Relationships through the
  established functions, appends one RelationshipObservation per unique
  assertion **only** for CREATED/APPENDED observations, and returns one
  ordered outcome row per input record.
- `ati.evidence_message_receipt` is the narrow durable receipt keyed by
  the stable PR 28C `message_id` (the approved PR 28E amendment to STOP
  #16): transactional at-least-once idempotency only — no Kafka/log
  position, partition, consumer-group, or Investigation semantics. The
  receipt lookup/insert happens in the same PostgreSQL transaction as the
  persistence it records; a previously committed `message_id` returns its
  previously established authoritative result without invoking the
  Evidence transition or recreating derived graph state.
- Observation identity (Option A): PostgreSQL's returned
  `evidence_observation_id` is authoritative; `observation_candidate_id`
  is proposed to the PR 28B transition (used by its CREATED branch) but
  is never required to become the persisted ID on APPENDED.
- Receipts are keyed by message identity, never by material state: a NEW
  message carrying an OLD material state runs the authoritative transition
  (UNCHANGED against the latest, never a historical-state search).
- Replay safety: exact redelivery, duplicate messages inside one batch,
  and the PostgreSQL-commit / consumer-commit-failure boundary are all
  idempotent; a same-Evidence multi-state batch `[A,B,C]` redelivered
  after a DB-commit/log-commit failure adds no observation and no derived
  row.

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

Application code targets publisher/consumer contracts rather than Kafka APIs.
Before Kafka/Redpanda is introduced, ATI uses an owned deterministic
`InMemoryEvidenceLog` implementation (PR 28D, delivered). It is an
append-only/replayable log abstraction rather than a destructive
`asyncio.Queue` contract: records and committed consumer position are
separate so tests can model redelivery after a failed/uncommitted batch.

The in-memory implementation may use Python standard-library concurrency primitives and supports deterministic failure/replay injection. It is for local development, architecture validation, and tests; it is not durable across process restart and is not a production substitute for Kafka/Redpanda.

PR 28G adds a Kafka-compatible infrastructure adapter without changing the application contracts or correctness semantics.

## Datasource lifecycle semantics

PR 27 datasource execution lifecycle remains operational provenance. With durable publication, producer completion means the Evidence messages were durably accepted by the configured log, not that PostgreSQL consumer persistence has completed. The detailed PR 28 producer plan will define the exact event vocabulary (including whether an explicit `PUBLISHED` stage is added) without using `datasource_log` as consumer offset, checkpoint, or deduplication state.

`datasource_execution_id` may travel with EvidenceMessage provenance for correlation, but a repeated retrieval/execution identifier does not define stable Evidence identity and does not force a new EvidenceObservation.

## SourceRecord boundary

Distributed Evidence ingestion does not force every datasource into Evidence. Reference-corpus ingestion such as MITRE ATT&CK may continue to produce `SourceRecord`/RAG corpus state when that is the correct semantic role. PR 28 migrates appropriate Evidence-producing datasources; it does not erase the distinction between intelligence Evidence and reference corpus material.

## Migration rule

This is a target contract. Until each PR 28 slice lands, existing v0.1 runtime/schema behavior remains authoritative. Implementations must migrate incrementally and keep tests/builds coherent rather than editing documentation as though global Evidence, EvidenceObservation, or the distributed log already exists in production code.
