# ATI — v0.2 Documentation Transition

> **Status: forward documentation map for PR 28; not delivered runtime behavior.**

The delivered v0.1 documents remain accurate descriptions of current `main` until corresponding PR 28 implementation slices land. This file identifies how the approved v0.2 target in `GLOBAL_EVIDENCE_ARCHITECTURE.md` changes the interpretation and eventual migration of the rest of `docs/`.

## ARCHITECTURE.md

Current architecture remains the delivered runtime. PR 28 introduces a new Evidence integration boundary after semantic conversion:

```text
producer: datasource -> semantic object -> ToEvidenceConverter -> EvidenceMessage -> EvidencePublisher -> log
consumer: log -> EvidenceConsumer -> bounded extraction/persistence -> PostgreSQL
```

Application correctness must not depend on Kafka APIs. PR 28D first provides deterministic `InMemoryEvidenceLog`; PR 28G later adds Kafka/Redpanda-compatible infrastructure. At-least-once delivery and idempotent PostgreSQL replay are architectural invariants. Existing Investigation execution remains a consumer of Investigation-scoped admitted observations rather than owning global Evidence identity.

## DOMAIN_MODEL.md

The delivered v0.1 `Evidence(investigation_id, subject, ...)` model is transitional. [CLOSED — PR 28A delivered] the v0.2 domain contracts: `Evidence` is now the stable global source identity, `EvidenceObservation` is the immutable per-Evidence-versioned state with deterministic material-state transitions (`create`/`no change`/`append`), `EvidenceObservationEntity` replaces the single subject association, `RelationshipObservation` references the exact `evidence_observation_id` (no Investigation field), and `InvestigationEvidence` records exact observation admission with bounded reason/actor vocabularies. The v0.1 runtime/persistence boundary keeps a transitional `LegacyEvidence` shape; `DOMAIN_MODEL.md` documents both.

## DATABASE.md

The delivered v0.1 persistence model remains current until PR 28B. Target changes include:

- `Evidence` becomes stable global identity rather than immutable retrieval row;
- immutable `EvidenceObservation` becomes the first-class temporal intelligence record;
- Evidence stops writing `domain_object_history`; EvidenceObservation history is retained directly;
- observation-level Entity association is persisted explicitly;
- RelationshipObservation provenance moves from Evidence to EvidenceObservation and loses Investigation ownership;
- InvestigationEvidence maps an Investigation to exact admitted EvidenceObservations;
- consumer-side bounded batch persistence must be idempotent under arbitrary redelivery;
- consumer position/offset is acknowledged only after the corresponding PostgreSQL transaction commits;
- Kafka offsets are not database/domain idempotency keys.

Exact schema, stored-function, migration, indexing, concurrency-safe per-Evidence version allocation, and legacy-data migration are PR 28B work and must be planned from fresh `main`.

## DATASOURCE_ARCHITECTURE.md

PR 27 remains the delivered acquisition/semantic-conversion foundation. [CLOSED — PR 28A delivered] the post-conversion boundary: the `ToEvidenceConverter` now produces global `ConvertedEvidence` (deterministic stable `Evidence` identity plus an `EvidenceObservationCandidate`) and conversion is Investigation-independent — the context carries no Investigation or subject. Publication (PR 28C+), durable producer boundaries, and consumer-side persistence remain future work; the datasource provider currently rebinds converter output onto the transitional v0.1 `LegacyEvidence` shape only to keep the Investigation executor/persistence coherent until PR 28B.

Converter selection remains based only on `semantic_format`; transport/log infrastructure must not leak into semantic conversion.

Datasource lifecycle logging remains execution-level operational provenance. Durable publication success and database-consumer success are separate facts. The exact PR 28 event vocabulary is intentionally deferred to the relevant detailed plan; `datasource_log` must not become a consumer-offset or deduplication table.

## DATA_SOURCES.md

Existing per-source normalization/extraction semantics remain valid unless a PR 28 source migration explicitly changes them. Evidence-producing semantic formats need an approved stable upstream identity contract before producer-side global Evidence publication. A source without such identity must fail closed rather than synthesize an unstable identity. Reference-corpus sources such as MITRE ATT&CK are not forced through Evidence merely because distributed Evidence ingestion exists.

## AGENT_DESIGN.md / EVALUATION.md

Agents must reason over the exact EvidenceObservations admitted to the Investigation, not silently resolve global Evidence to its latest observation. Provenance-bearing analytical support must ultimately identify the exact observation or an exact RelationshipObservation supported by it. Existing evaluation behavior remains current until the corresponding PR 28 migration lands; PR 28H must add replay/crash/reproducibility closure.

## API.md / FRONTEND.md

No new public endpoint or UI contract is authorized merely by this documentation PR. When PR 28 migrates read models, Investigation views must remain reproducible: admitted observations are distinguishable from newer global history, and analyst drill-down may inspect all observations of the stable Evidence item. Exact API/UI changes require their own implementation-plan delta analysis.

## DEPLOYMENT.md / CONFIGURATION.md

No broker dependency is added by this documentation PR. PR 28D uses an ATI-owned in-process `InMemoryEvidenceLog` for deterministic local/test operation. It is not durable across process restart and is not a production broker. PR 28G owns Kafka/Redpanda-compatible deployment/configuration and must preserve the application-level publisher/consumer contracts.

## TESTING.md

PR 28 tests must eventually pin at least: deterministic Evidence identity, per-Evidence observation versioning, unchanged-retrieval no-op, material-change observation creation/diff, exact Investigation admission, observation-level Entity/Relationship provenance, duplicate/replayed messages, database failure, crash after DB commit before offset commit, redelivery idempotency, and producer/consumer restart behavior. Detailed matrices belong to each coding-agent-ready PR plan. [CLOSED — PR 28A delivered] the domain half of this matrix (E28A-01..75 plus vertical slices D28A-V01..V04): deterministic identity, observation versioning, unchanged/no-op, material-change append/diff, exact admission, and observation-level Entity/Relationship provenance are pinned by the delivered unit suites.

## Documentation authority rule

Until a PR 28 implementation slice lands, a conflict between a delivered-v0.1 statement and the v0.2 target is resolved as follows:

1. fresh `main` source/tests define current behavior;
2. `GLOBAL_EVIDENCE_ARCHITECTURE.md` defines the approved v0.2 target;
3. `ROADMAP_V02.md` defines delivery sequencing;
4. the detailed plan for the active PR defines the permitted migration delta.

Documentation must be reconciled from target language to delivered language as each PR 28 slice lands.
