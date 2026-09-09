# Agentic Threat Investigator — Database and Persistence

## Table of contents

- [Database](#database)
- [Persistence categories](#persistence-categories)
  - [Immutable observations](#immutable-observations)
  - [Stable identities](#stable-identities)
  - [Versioned analytical outputs](#versioned-analytical-outputs)
  - [Mutable operational records](#mutable-operational-records)
- [Soft deletion](#soft-deletion)
- [Historical relationships](#historical-relationships)
- [Evidence](#evidence)
- [Investigation persistence](#investigation-persistence)
- [Transactions and Unit of Work](#transactions-and-unit-of-work)
- [Batch persistence](#batch-persistence)
  - [Composite-array input contract](#composite-array-input-contract)
  - [Reconciliation pipeline](#reconciliation-pipeline)
  - [Domain resource versioning and history](#domain-resource-versioning-and-history)
  - [JSONB diff](#jsonb-diff)
  - [PostgreSQL baseline](#postgresql-baseline)
- [SourceRecord](#sourcerecord)
- [Migrations](#migrations)
- [RAG persistence](#rag-persistence)
- [Authentication persistence](#authentication-persistence)
- [Audit persistence](#audit-persistence)
- [Time](#time)
- [Indexing principles](#indexing-principles)

## Database

PostgreSQL is ATI's authoritative datastore. pgvector provides vector search for the RAG corpus.

PostGIS is not required in v0.1.

## Persistence categories

### Immutable observations

Insert-only:

- Evidence
- RelationshipObservation
- AuditEvent

Normal application code exposes no deletion operation for these records.

### Stable identities

Upserted by canonical identity:

- Entity
- Relationship

Entity uniqueness:

`(entity_type, canonical_value)`

Relationship uniqueness:

`(source_entity_id, relationship_type_urn, target_entity_id)`

Relationship writes route through the versioned SQL API: `ati.upsert_relationship`
resolves the stable three-part identity, returns observed state unchanged for reuse
(no version and no history), makes creation race-safe through the authoritative
unique index, and `ati.append_relationship_observation` appends one immutable
observation with a database-allocated version and its CREATE history in the same
transaction. Python repositories never allocate relationship versions or write
relationship history directly.

### Soft-deleted stable identity rediscovery (PR 18C policy)

Rediscovery of a soft-deleted Entity or Relationship raises the typed
`SoftDeletedIdentityError` and fails closed:

- no second canonical row is ever created;
- the soft-deleted object is never silently restored or reused;
- no new Evidence, observation, or relationship mutation is attached to the
  deleted object, and the surrounding unit of work rolls back.

Recovery requires an explicit, separately reviewed governance action rather than a
persistence-time decision.

The policy is enforced by the database write path, not only by application
pre-checks: `ati.upsert_entity` rejects a soft-deleted canonical identity with the
dedicated `U18C2` SQLSTATE while holding the authoritative row lock, so a soft
deletion committed after the caller's pre-lock read is still rejected before any
version allocation, metadata update, or history write.

Relationship soft deletion uses the versioned SQL API: `ati.soft_delete_relationship`
validates the active row under lock, rejects absent/already-deleted edges and stale
expected versions with dedicated SQLSTATEs, allocates the new version from the
relationship sequence, and writes exactly one immutable DELETE history row with the
canonical JSONB diff in the same transaction.

RelationshipObservation Evidence provenance is enforced relationally by the named,
non-cascading foreign key `relationship_observation_evidence_fk`
(`relationship_observation.evidence_id -> evidence(id)`); a dangling Evidence
reference is rejected at insert time and observations are immutable afterwards.

### Versioned analytical outputs

New version/row rather than silent overwrite:

- Assessment
- InvestigationReport
- ResearchResult where applicable

An Investigation may point to the current/final version.

### Mutable operational records

Updates are permitted with auditing where material:

- Investigation status.
- Monitor configuration.
- Finding workflow metadata.
- User/session state.
- Job state.

## Soft deletion

Persistent application/domain records use soft deletion.

Standard fields:

```python
deleted_at: datetime | None = None
deleted_by_actor_id: UUID | None = None
```

Normal queries exclude deleted rows.

Admin/history queries may explicitly include them.

Applies to persistent entities such as:

- Entity
- Relationship
- Investigation
- Assessment/report records
- Monitor
- Finding
- User

Immutable Evidence, RelationshipObservation, and AuditEvent normally have no delete operation at all.

A future governed retention/purge mechanism is distinct from ordinary deletion semantics.

Replaceable internal artifacts such as regenerated RAG chunks may be physically rebuilt because they are indexing artifacts rather than historical domain observations.

## Historical relationships

Relationships are durable semantic identities.

Repeated source observations create new RelationshipObservation rows.

A DNS relationship is not physically removed because a later lookup no longer observes it. Currentness is a query/view concept based on observations.

## Evidence

Evidence is immutable.

A new provider retrieval creates a new Evidence observation rather than overwriting the prior observation.


Raw payload, when retained, is part of that immutable observation.

`ati.append_evidence(...)` is the canonical persistence path. It requires an
existing visible Investigation parent — validated with a row lock inside the
function so the parent cannot be soft-deleted between validation and
insertion, and additionally enforced by the
`evidence(investigation_id) -> investigation(id)` foreign key, which uses no
delete cascade because Investigation deletion is soft and Evidence is
immutable — inserts the observation with version `1`, writes a single
immutable CREATE `domain_object_history` entry carrying
actor/request/investigation correlation, and rejects a duplicate evidence
identity with a dedicated error state. The INSERT itself is authoritative for
duplicate identities, so a concurrent losing insert raises the dedicated
evidence duplicate error state instead of a raw unique violation; a repeated
identity is a conflict, never an update of the prior observation. The normal
repository surface is insert/read only (`insert`, `get_by_id`,
`list_for_investigation`); there is no evidence update, delete, or upsert
operation. `list_for_investigation` returns observations in deterministic
newest-first order (`retrieved_at DESC`, then evidence `id ASC`), backed by
the `evidence_investigation_listing_idx` index. Evidence timestamps must be
timezone-aware and are normalized to UTC.

Evidence subject identity is resolved by the caller before persistence: the
stored observation references the canonical entity row, and reads rebuild the
subject reference from that canonical identity.

## Investigation persistence

Investigation is a mutable, versioned operational resource persisted in
`ati.investigation`. Its domain representation is `InvestigationState`:
identity, status, trigger, objective, budget, and operational identifiers.
`budget` and the remaining operational fields are stored in the `budget` and
`operational_state` JSONB columns; the resource carries database-assigned
versions, authoritative timestamps, and soft-deletion metadata.

The lifecycle, optional optimistic `expected_version` on status updates, and
Investigation soft deletion are explicitly approved PR 18A contracts
(see `docs/DOMAIN_MODEL.md`).

The lifecycle is approved and narrow:

```text
PENDING  -> RUNNING | FAILED
RUNNING  -> COMPLETED | PARTIAL | FAILED
COMPLETED/PARTIAL/FAILED  (terminal)
```

A same-status request is not a transition; the persistence path classifies it
as an unchanged result without allocating a version or writing history.
Transitioning to a terminal status stamps `completed_at` when absent.

The authoritative write path is the versioned SQL API:

- `ati.create_investigation(...)` allocates the initial version and writes
  CREATE history; the INSERT itself is authoritative for the caller-supplied
  identity, so a concurrent duplicate raises the dedicated investigation
  duplicate error state instead of a raw unique violation, and is never
  upserted;
- `ati.update_investigation_status(...)` validates the current row, supports
  an optional optimistic `expected_version` (a stale expectation raises a
  dedicated error state without mutation), classifies the semantic no-op as
  unchanged, revalidates the approved lifecycle against the locked row, and
  only then allocates a new version, mutates, and writes UPDATE history with
  a JSONB diff. Locked-row validation is required defense in depth: a
  concurrent writer can invalidate a transition that passed the caller's
  pre-lock check, and an invalid locked-row transition raises a dedicated
  error state mapped to the domain transition error;
- `ati.soft_delete_investigation(...)` follows the standard soft-deletion
  conventions and writes DELETE history.

All three accept optional actor/request correlation recorded in the history
entry. Normal reads hide soft-deleted investigations; explicit admin/history
reads may include them. Lifecycle validation additionally runs in the
application layer before any database mutation.

Reads return the authoritative persistence metadata — `version`,
`created_at`, `updated_at`, and, for soft-deleted resources visible through
explicit admin reads, `deleted_at` and `deleted_by_actor_id` — following the
`Entity` persistence-metadata convention. A version obtained by a fresh read
can be supplied as `expected_version` in a later unit of work. Persistence
metadata is never serialized into the stored JSONB documents and caller
values never override database-owned columns. Dedicated investigation
columns are authoritative during deserialization; colliding keys inside
`operational_state` cannot replace identity, lifecycle, budget, timestamps,
version, or deletion metadata.

`started_at` is required and non-null. Investigation timestamps are
timezone-aware UTC: the domain rejects naive values and normalizes accepted
offsets to UTC, and the database stores `timestamptz`.

## Transactions and Unit of Work

Repositories do not self-commit.

Application services use an explicit UnitOfWork ABC.

Provider/LLM calls happen outside database transactions.

Persistence of one normalized provider result should be atomic:

```text
Evidence
+ derived/canonical entities
+ relationships
+ relationship observations
+ required audit changes
```

either commit together or not at all.

Transactions must remain short. PR 18B extraction and provider I/O occur before BEGIN; PR 18C preflight validates without database access (Evidence identity, canonical values, assertion Evidence-ID equality, endpoint coverage, and the deterministic duplicate policy), then resolves canonical identities, inserts immutable Evidence, reuses stable Relationships, appends RelationshipObservations, and commits once. A missing or soft-deleted parent Investigation is a typed error before any graph mutation. Empty extraction never deletes graph history.

## Batch persistence

ATI assumes every batch may be large. Every batch persistence operation therefore follows one canonical PostgreSQL path; there is no alternate small-batch JSONB/CTE path.

- The application enforces a configurable maximum batch size (for example `db_batch_size`) before invoking PostgreSQL.
- The canonical Python-to-PostgreSQL transport is an array of a resource-specific PostgreSQL composite input type.
- Stored functions expand the composite array with `unnest(... ) WITH ORDINALITY` into temporary staging tables.
- Temporary tables are always used for batch input and reconciliation/work state.
- The database performs current-state lookup, INSERT/UPDATE/UNCHANGED/CONFLICT classification, version allocation, diff generation, target mutation, history insertion, and result classification set-wise.
- Python repositories are thin: normalize/serialize the batch, invoke the stored function, and deserialize the result.
- Row-level triggers are not used for versioning or history. PL/pgSQL row loops are not used where set operations suffice.
- The database may enforce a defensive hard ceiling larger than the application-configured batch size.

### Composite-array input contract

Each batch resource defines a dedicated input composite type rather than using the target table row type. Database-owned fields such as `version`, `created_at`, `updated_at`, and deletion metadata are not caller inputs. Parallel arrays are not used because they introduce positional coupling.

Conceptually (the entity contract also carries an optional optimistic-concurrency expectation and caller ordinal):

```sql
CREATE TYPE ati.entity_batch_item AS (
    ordinal bigint,
    id uuid,
    entity_type text,
    canonical_value text,
    display_name text,
    attributes jsonb,
    content_hash bytea,
    expected_version bigint
);

CREATE FUNCTION ati.upsert_entities(
    p_items ati.entity_batch_item[]
) RETURNS TABLE(ordinal bigint, id uuid, version bigint, outcome text) ...;
```

Outcomes are `INSERTED`, `UPDATED`, `UNCHANGED`, and `CONFLICT`. A stale
`expected_version` produces `CONFLICT` without mutation, version allocation, or
history insertion; the caller may roll back the surrounding unit of work.

The stored function immediately stages the input set using `unnest(p_items) WITH ORDINALITY`. Ordinality may be retained for deterministic result/error correlation.

### Reconciliation pipeline

```text
composite[] input
 -> UNNEST WITH ORDINALITY
 -> temporary input table
 -> join current target rows
 -> temporary reconciliation/change table
 -> classify INSERTED / UPDATED / UNCHANGED / CONFLICT
 -> allocate versions for changed rows only
 -> compute old/new state and diff
 -> set-based final target mutation
 -> set-based immutable history insertion
 -> batch result
```

For existing rows, reconciliation captures the observed current version. Final mutation verifies that the target version still equals that observed version; otherwise the row is classified as `CONFLICT` rather than silently overwritten. `UNCHANGED` rows receive no new version and no history record.

### Duplicate input and insert-race semantics (SQL v0003)

Input staging deduplicates on the canonical identity `(entity_type, canonical_value)`, keeping the lowest input ordinal as the primary row. Later duplicates in the same batch are classified `CONFLICT` and reported with the winning row's identity and version; they never trigger a unique violation or abort the transaction. This matches stale-`expected_version` semantics: the caller supplied a redundant, potentially contradictory expectation that was not applied.

Inserts are conflict-aware (`ON CONFLICT ... DO NOTHING` on the canonical identity). A row that loses an insert race against a concurrent transaction is re-classified in a second reconciliation pass against the observed row state, yielding `UNCHANGED`, `UPDATED`, or `CONFLICT` (stale `expected_version`). Raced rows are treated as observed state, matching single-batch semantics, and never silently overwrite the concurrent writer.

Staging tables are dropped before creation so the batch function may execute more than once within the same transaction; `ON COMMIT DROP` still cleans them up at transaction end.

### Domain resource versioning and history

Every persisted ATI domain resource has a database-assigned `version BIGINT`. Versions are allocated from a dedicated sequence per resource table. They are monotonically increasing table-wide revisions, not per-object contiguous counters; sequence gaps are acceptable.

Every successful CREATE, UPDATE, or semantic soft DELETE creates an immutable `domain_object_history` entry in the same transaction containing object type/id/version, operation, complete post-operation `state JSONB`, `diff JSONB`, actor/request/investigation correlation where applicable, and `occurred_at`. Immutable resources normally receive only CREATE history. History/infrastructure tables are not themselves historized.

### JSONB diff

PostgreSQL has JSONB primitives but no native general `jsonb_diff(old,new)` operation. ATI therefore owns a small versioned SQL helper such as `ati_jsonb_diff(old_state, new_state, excluded_keys)`.

The v0.1 diff is shallow/top-level and represented as:

```json
{
  "score": {"old": 20, "new": 30}
}
```

The implementation uses native JSONB expansion/aggregation primitives and a full key comparison so additions and removals are represented. Missing keys versus JSON `null` must be handled deliberately and covered by tests. Nested JSON values are treated atomically at the top-level field: a changed nested object records its complete old/new values rather than recursively diffing it.

The complete post-operation state remains authoritative; the diff is a query/debug convenience. Database-maintained metadata such as `version` and selected timestamps may be excluded from the human-readable diff while remaining present in the complete state snapshot. Diff generation occurs only after a row is already known to have semantically changed (for example through `content_hash` or relational comparisons).

### PostgreSQL baseline

ATI targets PostgreSQL 18 with a compatible pgvector release. PostgreSQL 18 `OLD`/`NEW` support in DML `RETURNING` may be used to capture authoritative pre/post mutation state where appropriate, while stored functions and temporary tables remain the consistency boundary. Exact DML patterns must be integration-tested against the pinned PostgreSQL 18 image.

## SourceRecord

External batch records normalize before persistence.

Identity:

`(source_id, source_record_id)`

Normalization version is stored and participates in semantic hashing, so increasing it deterministically classifies a record as changed.

`ati.upsert_source_records(ati.source_record_batch_item[])` is the canonical persistence path. It uses a bounded composite array, `unnest ... WITH ORDINALITY`, temporary staging/reconciliation tables, and set-oriented mutation. PostgreSQL allocates versions and writes immutable `domain_object_history` entries for inserts and updates. An UNCHANGED result neither mutates current retrieval/metadata state nor allocates a version/history row. Duplicate identities, stale expected versions, and lost update races produce deterministic CONFLICT outcomes.

Any adapter that persists a `SourceRecord` must recompute `source_record_content_hash(record)` at the write boundary and reject the write if it does not match the record's `content_hash`.

`ati.ingestion_checkpoint` is mutable internal operational state rather than a versioned domain record. Its identity is `(source_id, artifact_uri, normalization_version)`. The application stores each post-batch opaque checkpoint and completion marker in the same transaction as the corresponding source-record batch, so failed/conflicted batches never advance progress.

## Migrations

Alembic orchestrates schema migrations.

Substantial PostgreSQL stored functions/objects live in separate immutable versioned SQL files. Versioned SQL API v0008 (`migrations/sql/ati/v0008/relationship_persistence.sql`) owns relationship/observation writes for PR 18C.

Rules:

- migrations reference exact SQL versions;
- shipped function versions are never edited in place;
- new changes create new versioned SQL;
- normal DDL remains in Alembic;
- integration tests execute migrations against real PostgreSQL.

## RAG persistence

Documents retain source provenance.

Document fields include:

- source identifier;
- source record identifier;
- title;
- source URL;
- published/retrieved timestamps;
- content hash;
- normalization version;
- metadata.

Chunks retain:

- parent document ID;
- sequence;
- text;
- token count;
- embedding model/version;
- metadata.

Documents are identified by `(source_id, source_record_id)` and reference the source record through that same composite key. They also retain derived `content`, document type (the source `record_type` vocabulary), and an explicit `chunking_version`; the document semantic hash covers document type, title, source URL, published time, content, normalization/chunking versions, and metadata; source identity, retrieval time, and internal identity are excluded.

Chunks are identified by `(document_id, sequence)`. They are replaceable indexing artifacts: replacement physically rebuilds the complete set, allocates chunk versions, and writes no `domain_object_history` rows or soft-delete state. Each chunk stores embedding provider/model/version/dimension and a semantic hash covering its text, token count, metadata, identity, and embedding metadata (not the vector). The vector column is fixed at dimension 1536 and has an HNSW cosine index.

Embedding configuration stores provider/model/version/dimension sufficiently to support controlled re-embedding.

PR 11 retrieval joins current chunks to visible documents, filters all four
embedding identity fields plus optional source/type predicates, and performs
bounded top-k ordering with the pgvector cosine-distance operator. The database
performs ranking; Python does not load or reorder the corpus. No compatible
rows produces an empty result.

## Authentication persistence

Domain user and credentials are separate.

Credentials store only a strong Argon2id password hash and password-change metadata.

Sessions use opaque high-entropy tokens. The database stores a cryptographic hash of the session token rather than the token itself.

## Audit persistence

AuditEvent is append-only and immutable. It is stored in `ati.audit_event` with a database-assigned table-wide `version`, UTC occurrence time, actor snapshot, optional object/correlation identifiers, and minimized JSONB metadata. `actor_id` intentionally has no foreign key: the reserved SYSTEM actor is not a user row, and audit records must remain readable after user soft deletion. Known lookup paths are indexed by actor/time, action/time, and object/time. The actor column is not a foreign key, and audit rows are not duplicated into `domain_object_history`: audit answers who attempted an action, while history answers how a resource changed.

Security-relevant successful mutations and their audit event should commit transactionally together. Failed or denied operations that do not commit use an independent transaction.

Denied/failed events use an appropriate independent audit transaction when the primary mutation does not commit.

## Time

All persisted timestamps are timezone-aware UTC.

## Indexing principles

Indexes should be introduced based on known query paths, including:

- canonical entity lookup;
- relationship adjacency;
- evidence by investigation/entity/source/type/time;
- relationship observations by relationship/time;
- investigations by status/time;
- jobs by claimable status/schedule;
- monitors by due schedule;
- findings by workflow status;
- vector index appropriate to pgvector retrieval.

Exact index implementation is an implementation-level decision validated by query plans/tests.
