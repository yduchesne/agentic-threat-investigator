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
- [Datasource execution log (PR 27B)](#datasource-execution-log-pr-27b)
- [Migrations](#migrations)
- [PostGIS and GEOINT (PR 26)](#postgis-and-geoint-pr-26)
  - [PR 26D analyst read layer](#pr-26d-analyst-read-layer)
- [RAG persistence](#rag-persistence)
- [Authentication persistence](#authentication-persistence)
- [Audit persistence](#audit-persistence)
- [Investigation timeline persistence](#investigation-timeline-persistence)
- [Task dispatch persistence](#task-dispatch-persistence)
- [Time](#time)
- [Indexing principles](#indexing-principles)

## Database

PostgreSQL is ATI's authoritative datastore. pgvector provides vector search for the RAG corpus.

PR 25 does not require PostGIS. PR 26B introduces PostGIS for canonical geography/spatial operations; PR 26A itself remains non-spatial (see [PostGIS and GEOINT (PR 26)](#postgis-and-geoint-pr-26)).

## Persistence categories

### Immutable observations

Insert-only:

- Evidence
- RelationshipObservation
- EntityLocationObservation
- AuditEvent
- InvestigationTimelineEvent

Normal application code exposes no deletion operation for these records.

RelationshipObservation rows are themselves immutable historical observations
and are not duplicated into `domain_object_history`. EntityLocationObservation
follows the same precedent (see [PostGIS and GEOINT (PR 26)](#postgis-and-geoint-pr-26)).

### Stable identities

Upserted by canonical identity:

- Entity
- Relationship
- Location

Entity uniqueness:

`(entity_type, canonical_value)`

Relationship uniqueness:

`(source_entity_id, relationship_type_urn, target_entity_id)`

Location uniqueness (PR 26A):

`(location_type, country_code, admin1_code, admin2_code, canonical_name)`
with null components normalized by the unique COALESCE expression index
`location_canonical_identity_idx`; `parent_location_id` is reference
hierarchy and is not part of identity.

Relationship writes route through the versioned SQL API: `ati.upsert_relationship`
resolves the stable three-part identity, returns observed state unchanged for reuse
(no version and no history), makes creation race-safe through the authoritative
unique index, and `ati.append_relationship_observation` appends one immutable
observation as a database-allocated immutable observation row in the same
transaction, with no `domain_object_history` row. Python repositories never
allocate relationship versions or write relationship history directly.

Relationship history and RelationshipObservation history are different:

- changes to the stable Relationship resource use `domain_object_history`;
- observations of that Relationship are recorded directly as immutable
  RelationshipObservation rows and are not separately historized.

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

### Append-only immutable contextual analytical artifacts (PR 22A)

ResearchResult persists as one immutable root row per research execution,
with typed ResearchClaim/ResearchCitation JSONB snapshots:

- `ati.research_result` rows are insert-only; there is no update or delete
  routine and no version/history table;
- claims/citations are authoritative Pydantic snapshots validated by the
  application; the database enforces only root integrity (foreign keys,
  duplicate-ID rejection) and does not learn Research Agent semantics;
- repeat research executions append a new result rather than mutating a
  prior one (PR 22C owns execution/deduplication semantics);
- persisted results never create Evidence/Assessment rows.

### Versioned analytical outputs

New version/row rather than silent overwrite:

- Assessment
- InvestigationReport
- ResearchResult where applicable

An Investigation may point to the current/final version. `Assessment` rows are
insert-only: a later analysis appends a new `ati.assessment` row with a
fresh database-allocated version and immutable CREATE history, and the
`Investigation` operational-state pointer (`assessment_id`) moves to the
newest durable output only after that row commits.

### Mutable operational records

Updates are permitted with auditing where material:

- Investigation status.
- Monitor configuration.
- Finding workflow metadata.
- User/session state.
- Job state.
- GeoResolution lifecycle (PR 26C); PR 26A persists initial PENDING rows and PR 26C delivers the full asynchronous lifecycle (SQL API v0024).

`EntityLocation` current materialized state is updated exclusively by the
versioned stored-function reconciliation inside
`ati.append_entity_location_observation`; application code has no direct
mutation path.

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

Repeated source observations create new RelationshipObservation rows. Each
observation row is itself the historical record for that observation and is
not duplicated into `domain_object_history`.

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

## Assessment persistence

Assessment persistence (migration 0014, SQL API v0011) is normalized, not an
opaque JSONB blob, so provenance stays relational:

```text
assessment (verdict, confidence, summary, analyzed_evidence_ids uuid[],
            limitations/unresolved_questions/recommended_next_steps text[],
            version, created_at, deleted_at, deleted_by_actor_id)
  -> investigation(id)
  |- assessment_finding (assessment_id, ordinal, category, disposition,
                         statement, confidence) UNIQUE(assessment_id, ordinal)
      |- assessment_finding_support (finding_id, ordinal, kind,
                                     evidence_id, relationship_observation_id)
         UNIQUE(finding_id, ordinal)

EvidenceSupport -> evidence(id) (FK)
RelationshipSupport -> relationship_observation(id) (FK)
```

The support discriminator is an explicit ``kind`` column
(``'evidence'`` / ``'relationship_observation'``) with an exclusive CHECK,
never inferred from nullable id fields. FKs supplement application
validation; they do not replace cross-investigation validation, which the
stored functions revalidate under the parent Investigation row lock.

``ati.append_assessment`` follows the repository batch-persistence rule:
the resource-specific composite arrays are expanded once into
transaction-local temporary staging tables (analyzed Evidence, Findings,
supports) and every validation/insertion is set-oriented from those tables.
Validation covers the complete analyzed set — every analyzed Evidence ID,
whether or not any Finding cites it, must resolve to persisted Evidence of
this Investigation — plus Finding/support structure (positive unique
contiguous ordinals, nonblank statements, allowed vocabulary, at least one
support per Finding, resolvable finding ordinals, exactly one discriminator
with exactly its matching ID field, no duplicate ``(kind, referenced id)``
within a Finding). Referenced Relationships and both endpoint Entities are
locked in a deterministic UUID order (entities before relationships) with a
lock mode that conflicts with the soft-delete UPDATE row locks, then
revalidated after locking, so a concurrent soft deletion can never
invalidate the eligibility snapshot. Every malformed or ineligible input
fails atomically with a typed SQLSTATE before the Assessment version is
allocated, leaving no parent, child, history, audit, or pointer row.

Authoritative write path (versioned SQL API v0011):

- `ati.append_assessment(...)` locks and validates the visible parent
  Investigation, stages and validates the complete input, allocates the
  Assessment version from `ati.assessment_version_seq`,
  makes the INSERT authoritative for the supplied identity (duplicate is a
  typed conflict), persists Assessment/Finding/support atomically set-wise
  from the staging tables, verifies no staged support row was silently
  dropped, and writes one immutable CREATE history entry with
  actor/request/investigation correlation;
- `ati.set_investigation_assessment(...)` advances `operational_state`'s
  `assessment_id` with database-owned optimistic-concurrency, a no-op for an
  identical pointer (no version/history), and UPDATE history otherwise. It
  acquires row locks in the canonical order — owning Investigation row
  `FOR UPDATE`, then the target Assessment row `FOR UPDATE` — and verifies
  the target belongs to that Investigation and is still visible after the
  lock, so a concurrent soft deletion serializes behind the pointer mutation
  and a visible Investigation is never pointed at a deleted Assessment;
- `ati.soft_delete_assessment(...)` follows the standard soft-deletion
  conventions with DELETE history, but only for superseded Assessments:
  the approved PR 20A policy rejects deletion (dedicated `U20AB` typed
  conflict) while the Assessment's visible owning Investigation still points
  at it as its current analytical output. Deletion first discovers the owning
  Investigation without locking, then locks the owning Investigation row
  `FOR UPDATE` before the Assessment row `FOR UPDATE` (the same canonical
  lock order), revalidates existence/ownership/visibility and the expected
  Assessment version under those locks, and reads the pointer from the
  already-locked Investigation row — so a visible Investigation can never
  point at a deleted Assessment. The application service emits one
  transactional `ASSESSMENT_DELETE` audit event in the same UnitOfWork;
- every Assessment input array is bounded in two places: the application
  service and the repository enforce the configured `db_batch_size` (default
  100) independently against analyzed Evidence, Findings, flattened Finding
  supports, and each ordered string collection before any provenance read or
  SQL, and `ati.append_assessment` rejects any array above the database
  defensive hard ceiling of 10,000 (dedicated `U20AD`) before staging or
  mutation. Oversized aggregates are never truncated, split, deduplicated,
  or silently repaired, and an oversized candidate fails with a message
  containing only the collection name, count, and limit.

Migration 0014 applies the approved legacy-data policy: the v0002 flat
``ati.assessment`` table is treated as guaranteed empty (no repository or
service ever wrote to it), and the migration explicitly counts the old table
and fails with a clear error BEFORE the drop if any row exists, so legacy
Assessment data can never be silently destroyed. A nonempty table requires a
maintainer-approved data-migration mapping before this migration may run.

## InvestigationReport persistence

Report persistence (migration 0023, SQL API v0019) follows the versioned
analytical-output convention: each explicit report generation appends a new
immutable ``ati.investigation_report`` row with a fresh database-allocated
version and one CREATE domain-history entry; a prior report row is never
updated in place.

The write path accepts the composite input arrays (executive summary
statements and their flat narrative-support rows, finding snapshots and their
flat finding-support rows, research snapshots) and stores the nested
presentation structures as authoritative typed JSONB snapshots:

```text
investigation_report (investigation_id, assessment_id,
    verdict, confidence, title,
    executive_summary jsonb, findings jsonb, research_context jsonb,
    limitations/unresolved_questions/recommended_next_steps text[],
    source_evidence_ids/source_relationship_observation_ids/
    source_research_result_ids uuid[],
    version, created_at, deleted_at, deleted_by_actor_id)
  -> investigation(id) FK
  -> assessment(id) FK
  UNIQUE(investigation_id, version)
index (investigation_id, version DESC, id ASC) WHERE deleted_at IS NULL
```

Nested report structures are deliberately NOT normalized into mutable child
tables: the report is an immutable versioned presentation snapshot whose
child structures are never independently mutated or queried, mirroring the
ResearchResult claims/citations JSONB precedent. The Pydantic domain model
remains the contract; the database enforces root integrity, structural
vocabulary, hard ceilings, and the critical current-Assessment invariant.

Authoritative write path (versioned SQL API v0019):

- ``ati.append_investigation_report(...)`` locks the visible parent
  Investigation row ``FOR UPDATE`` first, then the target Assessment row
  ``FOR UPDATE``, and verifies the Assessment is visible, belongs to the
  Investigation, and — critically — is STILL the Investigation's current
  ``assessment_id`` under the lock. A report whose input was materialized
  against an Assessment that ceased to be current is rejected with the
  typed stale-input conflict (``U23A1``) and no report row, history, or
  pointer change commits. The staged composites are validated set-wise
  (finding ordinals positive/unique, allowed vocabulary, nonblank
  statements, at least one unique valid support per finding/statement,
  research selections unique and resolvable to persisted claims of this
  Investigation), the version is allocated from
  ``ati.investigation_report_version_seq``, the authoritative row is
  inserted (duplicate identity is ``U23A4``), the JSONB snapshots are
  assembled set-wise, and one immutable CREATE history entry is written;
- ``ati.set_investigation_report(...)`` advances ``operational_state``'s
  ``report_id`` with database-owned optimistic concurrency, a no-op for an
  identical pointer, and UPDATE history otherwise. Lock order matches the
  Assessment pointer: owning Investigation row ``FOR UPDATE``, then the
  target report row ``FOR UPDATE``;
- ``ati.soft_delete_investigation_report(...)`` mirrors Assessment soft
  deletion: only a superseded report may be deleted (rejected with
  ``U23A7`` while a visible Investigation still points at it), deletion
  allocates the next report version and writes one DELETE history entry,
  and the application emits one transactional ``REPORT_DELETE`` audit event.

The report append + Investigation ``report_id`` pointer update are one
atomic UnitOfWork: the pointer advances only after the report row has been
durably inserted, and any failure rolls both back. The current report is
resolved through the durable ``report_id`` pointer, never ``MAX(version)``.
Input ceilings follow the Assessment convention: the application service and
repository enforce the configured ``db_batch_size`` independently against
every bounded report collection, and the stored function rejects any
collection above the defensive hard ceiling of 10,000 (``U23A8``).

Lock order is documented here once for all report/Assessment pointer
operations: owning Investigation row first, then target Assessment/Report
row. Both directions use this exact order so concurrent pointer assignment
and soft deletion serialize on the Investigation row and can never
interleave into a visible Investigation pointing at a deleted output.

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

Historized domain resources receive immutable `domain_object_history` entries for successful state transitions according to their resource contract: a CREATE, UPDATE, or semantic soft DELETE creates one entry in the same transaction containing object type/id/version, operation, complete post-operation `state JSONB`, `diff JSONB`, actor/request/investigation correlation where applicable, and `occurred_at`.

Append-only resources that are themselves historical/event records are not automatically duplicated into `domain_object_history`. In particular, RelationshipObservation, AuditEvent, and InvestigationTimelineEvent are not historized there. Evidence retains its separately approved CREATE-history contract.

Legacy databases upgraded from versions before PR 22E (SQL API v0018) may contain redundant RelationshipObservation CREATE history rows. These rows are tolerated but no new such rows are produced.

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

`ati.ingestion_checkpoint` is mutable internal operational state rather than a versioned domain record. Its identity is `(source_id, artifact_uri, normalization_version)`. The application stores each post-batch opaque checkpoint and completion marker in the same transaction as the corresponding source-record batch, so failed/conflicted batches never advance progress. PR 27E regression tests pin this atomicity over real PostgreSQL (one UoW per batch; batch-2 failure rolls back both data and checkpoint while batch-1 stays durable; restart resumes from the last committed checkpoint; the ingestion path writes zero `ati.datasource_log` rows).

## Datasource execution log (PR 27B)

PR 27B adds the smallest durable append-only datasource execution log
(`ati.datasource_log`, migration 0030, SQL API v0025). One acquisition
execution receives a fresh application UUID `execution_id`; every operational
event of that execution is appended with the same `execution_id` and the
same `datasource_id`. There is deliberately **no** durable
`datasource_execution` table: the log itself establishes execution existence
(STARTED), datasource correlation, stage history, and the terminal outcome.

Logical columns:

```text
id              bigint IDENTITY          append-event identity/order key
 execution_id    uuid NOT NULL           one acquisition execution
 datasource_id   text NOT NULL           canonical bounded PR 27A identity
 event_type      text NOT NULL           closed seven-value vocabulary
 occurred_at     timestamptz NOT NULL    application event time (UTC)
 item_count      bigint NULL             stage-local non-negative count
 byte_count      bigint NULL             stage-local non-negative count
 error_code      text NULL               bounded safe code, FAILED only
 created_at      timestamptz NOT NULL    DEFAULT transaction_timestamp()
```

Constraints (database-owned backstops, not Python-only rules):

- `datasource_id` must be canonical lowercase kebab, unpadded, at most 64
  characters;
- `event_type` is closed to `started`/`acquired`/`decoded`/`converted`/
  `completed`/`failed`/`cancelled`;
- `item_count`/`byte_count` are nullable and never negative;
- `error_code` matches `^[a-z][a-z0-9_]{0,63}$` (unpadded) and is required
  for `failed` and forbidden on every other event type;
- events are immutable; there is no version column and no soft-delete
  column. Direct owner/admin SQL is outside the application immutability
  boundary; application mutation is append-only through the stored function.

Indexes:

```text
datasource_log_started_uq   UNIQUE (execution_id) WHERE event_type='started'
datasource_log_terminal_uq  UNIQUE (execution_id) WHERE event_type IN
                            ('completed','failed','cancelled')
datasource_log_execution_idx (execution_id, id) deterministic correlation
```

Lifecycle/concurrency enforcement: every normal write routes through the
versioned stored function `ati.append_datasource_log_event`, which
serializes per-execution lifecycle validation with a transaction-scoped
advisory lock derived deterministically from `execution_id`
(`hashtextextended`), then enforces first-event-STARTED, datasource identity
stability, duplicate-STARTED rejection, and append-after-terminal rejection
with typed `U27B*` SQLSTATEs (`U27B1` invalid input, `U27B2` first event
must be STARTED, `U27B3` datasource identity mismatch, `U27B4` duplicate
STARTED, `U27B5` append after terminal). The partial unique indexes remain
constraint backstops for one STARTED and at most one terminal even if the
function is bypassed. Two concurrent terminal (or initial STARTED) writers
for the same execution therefore yield exactly one durable terminal (or
STARTED) row; independent executions use distinct advisory locks and never
block each other.

Transaction rule: each event append participates in the caller's short
UnitOfWork transaction and commits before any external
acquisition/decode/conversion work; no database transaction is held across
external I/O. Migration 0030 is additive with no backfill; its downgrade
drops only the PR 27B function, indexes, constraints, and table in
dependency-safe order and never touches source records, checkpoints,
Evidence, or other authoritative rows.

### PR 27E transaction boundaries

PR 27E wires the datasource execution into the Investigation runtime with
three distinct short-transaction classes (all real bounded PostgreSQL
transactions, never opened across I/O):

```text
lifecycle events (PR 27B recorder)   one short UoW per event append
Evidence observation persistence    one short atomic UoW per Evidence
SourceRecord batch + checkpoint     one short atomic UoW per SourceBatch
```

A successful datasource-backed provider execution therefore appends
STARTED, the acquirer's ACQUIRED/DECODED stages, and CONVERTED(item_count
= Evidence count) during acquisition/conversion, then each preserved
Evidence observation persists through the PR 18C boundary in its own
atomic UoW (Entities + Evidence + RelationshipObservation + audit, or
none), and finally the COMPLETED terminal append — never before every
required extraction/persistence step succeeded. A runtime failure appends
FAILED with a bounded safe code (``provider_binding_failed``/
``extraction_failed``/``persistence_failed``/``timeline_failed``); later
failures never compensate earlier commits; cancellation appends CANCELLED
(best effort) and propagates. Lifecycle events are execution-level and are
never multiplied per Evidence; ``IngestionService`` writes no datasource-
log rows at all. PR 27E adds zero migrations, zero stored-function
changes, zero tables, and zero indexes.

## Migrations

Alembic orchestrates schema migrations.

Substantial PostgreSQL stored functions/objects live in separate immutable versioned SQL files. Versioned SQL API v0018 (`migrations/sql/ati/v0018/relationship_persistence.sql`) owns relationship/observation writes; it supersedes v0008 (PR 18C) by removing the redundant RelationshipObservation `domain_object_history` write while preserving the stable Relationship write path. Versioned SQL API v0021 (`migrations/sql/ati/v0021/geoint_persistence.sql`, migration 0025) owns the PR 26A GEOINT persistence functions; SQL API v0022 (`migrations/sql/ati/v0022/geoint_persistence.sql`, migration 0026, PR 26A-2) redefines only `ati.append_entity_location_observation` to allocate EntityLocation versions from `ati.entity_location_version_seq` on every actual current-state mutation. SQL API v0023 (`migrations/sql/ati/v0023/geoint_reference_spatial.sql`, migration 0027, PR 26B) adds the canonical reference/spatial write path `ati.upsert_reference_location` and the PostGIS extension; it only adds objects and never edits v0021/v0022. SQL API v0024 (`migrations/sql/ati/v0024/geo_resolution_lifecycle.sql`, migration 0028, PR 26C) adds the asynchronous work lifecycle on the same `ati.geo_resolution` table (`ati.claim_geo_resolutions`, `ati.complete_geo_resolution_resolved`, `ati.complete_geo_resolution_unresolvable`, `ati.record_geo_resolution_failure`) plus the claim-support indexes and lifecycle CHECK constraints; it only adds objects and never edits v0021-v0023. SQL API v0025 (`migrations/sql/ati/v0025/datasource_log.sql`, migration 0030, PR 27B) adds the append-only datasource execution log (`ati.datasource_log` plus `ati.append_datasource_log_event`); it only adds objects and never edits v0021-v0024. The shipped files are never edited in place.

Rules:

- migrations reference exact SQL versions;
- shipped function versions are never edited in place;
- new changes create new versioned SQL;
- normal DDL remains in Alembic;
- integration tests execute migrations against real PostgreSQL.

## PostGIS and GEOINT (PR 26)

PR 25 does not require PostGIS. PR 26B introduces PostGIS for canonical
geography/spatial operations; PR 26A itself remains non-spatial. The GEOINT
persistence foundation delivered by PR 26A (migration 0025, SQL API v0021)
is deliberately free of PostGIS, geometry columns, centroids, and spatial
predicates.

### PR 26B: PostGIS runtime and spatial Location state

PR 26B (migration 0027, SQL API v0023) makes PostGIS part of the v0.1
runtime and adds the canonical reference/spatial surface:

- **PostGIS through migrations.** The supported PostgreSQL 18 image
  (`docker/postgres/Dockerfile`) contains both pgvector and PostGIS; the
  migration runs `CREATE EXTENSION IF NOT EXISTS postgis` so an
  already-existing ATI database whose server has PostGIS installed also
  upgrades. Downgrade (0027 -> 0026) drops the spatial function, columns,
  and indexes first, then removes the PostGIS extension only when PR 26B
  introduced it (the extension lives in the `ati` schema), never with
  `CASCADE`.
- **Spatial columns.** `ati.location.geometry geometry(Geometry, 4326)`
  and `ati.location.centroid geometry(Point, 4326)` are optional SRID-4326
  PostGIS `geometry` columns — never `geography`. Geometry is state
  attached to the canonical reference object, never part of canonical
  identity: corrections or corpus upgrades never create a second logical
  Location.
- **Geometry-type rules.** Country/administrative-area geometry must be
  polygonal (`ST_Polygon`/`ST_MultiPolygon`) and valid; city geometry must
  be a `Point`. Empty geometries, SRIDs other than 4326, and coordinates
  outside WGS84 bounds are rejected. `centroid` is always a `Point`. The
  `centroid` column stores an **on-surface representative point** derived
  deterministically with `ST_PointOnSurface` during ingestion when the
  source polygon is present and no explicit point is supplied (documented
  as on-surface, never as a mathematical `ST_Centroid`); a city stores its
  canonical point in both spatial columns.
- **Spatial validation ownership.** CHECK constraints cannot call PostGIS
  functions (they are not immutable), so malformed spatial state is
  rejected fail-closed inside the versioned write function
  (`ati.upsert_reference_location`), the sole mutation path for reference
  spatial state. Typed SQLSTATEs: `U26B1` invalid reference geometry,
  `U26B2` invalid reference hierarchy, `U26B3` canonical location conflict,
  `U26B4` unsupported reference record.
- **Reference enrichment/version semantics.**
  `ati.upsert_reference_location` returns deterministic outcomes:
  `CREATED` (new canonical identity, version from
  `ati.location_version_seq`), `UNCHANGED` (identity and complete supplied
  canonical state semantically identical — no version churn), `ENRICHED`
  (approved previously-missing reference/spatial fields filled or a
  deterministic reference-corpus refresh changed approved spatial state —
  a new sequence version is allocated), and `CONFLICT` (raised as `U26B3`
  when the canonical identity would be rebound with a different display
  name or parent). PR 26A `ati.upsert_location` remains unchanged and
  works on the same table: existing rows stay valid with
  `geometry = NULL`, `centroid = NULL`, and no row is ever rewritten when
  its referenced Location gains spatial state.
- **Reference identity.** Canonical reference ingestion derives
  deterministic UUIDv5 ids (`uuid5(ATI_LOCATION_NAMESPACE, ...)` over the
  canonical identity tuple) so a clean and an existing database resolve the
  same canonical identity to the same UUID; external source record ids
  never participate. Reference data is loaded separately from schema
  migration: `alembic upgrade` never downloads or imports geography; the
  operator runs `ati-geography-import` with local corpus artifacts.
- **Hierarchy and containment are distinct.** `parent_location_id` is
  reference hierarchy supplied by the corpus; PostGIS predicates are
  geometric. A failed/missing spatial predicate never rewrites the
  hierarchy, and spatial containment alone never establishes parentage
  during ordinary reads. `CanonicalGeographyResolver` (PR 26B) performs
  deterministic narrowing (country code -> admin code/name -> city name)
  and uses boundary-inclusive `ST_Covers` containment only to disambiguate
  equally-valued candidates when the claim supplies coordinates; it never
  invents precision, never infers a nearest city, and never mutates
  Entity/EntityLocation/Observation/GeoResolution state (that remains PR
  26C).
- **Spatial indexes.** Two PR 26B indexes are justified by concrete paths:
  `location_geometry_gist_idx` (GiST on non-null `geometry`, used for
  containment/intersection candidate selection) and
  `location_resolution_name_idx` (b-tree on `(location_type,
  country_code, canonical_name)`, used by the deterministic claim
  narrowing path). Containment queries are proven spatial-index eligible by
  EXPLAIN in the G26B-P matrix.

### Delivered PR 26A persistence

Four tables with database-owned versions and the versioned SQL API v0021
(`migrations/sql/ati/v0021/geoint_persistence.sql`):

- `Location`: canonical geographic/reference identity;
- `EntityLocation`: current materialized Entity-to-Location association;
- `EntityLocationObservation`: immutable append-only geographic observation/provenance;
- `GeoResolution`: durable operational geographic-enrichment work.

`Location` is not an ATI Entity and never participates in
Relationship/RelationshipObservation records. Canonical hierarchy and
geometric containment are separate concerns.

### Location (delivered)

`ati.location` is bounded to country, administrative area, and city
(`location_type` vocabulary `country`/`administrative_area`/`city`). Canonical
identity is the deterministic tuple `(location_type, country_code, admin1_code,
admin2_code, canonical_name)` with null components normalized through a unique
COALESCE expression index (`location_canonical_identity_idx`);
`parent_location_id` is reference hierarchy and is **not** part of identity.
Type-specific shape checks enforce country (no parent/admin codes),
administrative-area (parent + admin1 required), and city (parent + admin1
required, admin2 optional) constraints, plus the two-letter uppercase
`country_code` shape and bounded nonblank textual fields.

`ati.upsert_location(...)` creates once or reuses the existing canonical row
(reuse is a semantic no-op with no version/history churn), rejects
incompatible display name or parent for the same canonical identity (`U26A7`),
and allocates the version from `ati.location_version_seq`. Location rows are
not duplicated into `domain_object_history`.

Canonicalization must preserve supported precision. A country-only claim
remains country-level; reference data must not manufacture a city-level
assertion.

### EntityLocationObservation (delivered)

`ati.entity_location_observation` follows the same fundamental historical
principle as `RelationshipObservation`: the observation row is itself history
and is **not** duplicated into `domain_object_history`. It is insert-only and
immutable (no update/delete path). Each observation explicitly preserves its
exact `entity_id`, `location_id`, and `evidence_id`; historical observations
do not derive Location through current `EntityLocation`, and Investigation
scope is derived through the exact Evidence provenance chain (there is no
`investigation_id` column).

`ati.append_entity_location_observation(...)` validates in one transaction
that the Entity exists and is visible, the Location exists, the Evidence
exists, the Evidence type is `GEOLOCATION`, and the Evidence subject is the
exact Entity (typed SQLSTATEs `U26A1`-`U26A5`); rejects a duplicate
observation identity (`U26A6`); appends exactly one immutable observation
with a database-allocated version; and reconciles the current
`EntityLocation` atomically. The bounded per-Entity historical read is
backed by `entity_location_observation_entity_retrieved_idx`
(`(entity_id, retrieved_at DESC, id ASC)`).

### EntityLocation (delivered)

`ati.entity_location` is current materialized state, database-maintained from
observations. Reconciliation is database-owned and versioned; it does not
replace immutable observations. The deterministic currentness ordering is
`(COALESCE(observed_at, retrieved_at), observation_id)` with the greater pair
winning: a later observation advances the current Location/precision/latest
observation and `last_observed_at`, an older observation is still appended as
history but never rewinds current state, and the earliest
`first_observed_at` is preserved. Exactly one row exists per Entity in v0.1,
and `latest_observation_id` points at the observation that currently
determines the materialized association (enforced by a foreign key to
`entity_location_observation(id)`). Application code has no direct mutation
path.

`EntityLocation.version` is a database-issued materialized-state change token
allocated from `ati.entity_location_version_seq` on creation and every actual
current-state mutation (SQL API v0022, migration 0026). It is monotonic for
successive committed mutations of a row but not contiguous; sequence gaps are
valid. An appended historical observation that does not change current state
leaves the persisted version unchanged (a sequence value may still be
consumed internally), and an older observation that extends
`first_observed_at` is a real mutation that receives a new sequence token even
when Location, precision, latest observation, and `last_observed_at` remain
unchanged.

### GeoResolution (delivered: PR 26A initial persistence + PR 26C lifecycle)

`ati.geo_resolution` is the durable operational work record and conceptual
queue for geographic enrichment. It is distinct from Evidence and from
successful immutable geographic observations. `ati.create_geo_resolution(...)`
persists the initial PENDING row (`status = 'pending'`, `attempt_count = 0`,
no claim/lease/outcome metadata) after validating the Entity/Evidence binding
and the GEOLOCATION Evidence type; the unique `(entity_id, evidence_id)`
constraint makes creation race-safe, and an exact duplicate pair reuses the
existing record unchanged only while it still has the initial pending shape
(`U26A8` otherwise). `next_attempt_at` may be null in 26A.

PR 26C (SQL API v0024, migration 0028) delivers the asynchronous work
lifecycle on this same row; there is no second queue table and no broker.

#### State machine

```text
PENDING
  -> PROCESSING on eligible claim
PROCESSING
  -> RESOLVED            (atomic successful completion)
  -> UNRESOLVABLE        (deterministic no-match/ambiguity, never guessed)
  -> PENDING             (retryable failure with attempts remaining)
  -> FAILED              (terminal error or attempt budget exhausted)
  -> PENDING (next attempt, same N) on retry
  -> PROCESSING (next claim, N+1) from an expired lease
  -> FAILED              (expired lease already at the attempt budget)
```

Terminal: RESOLVED, UNRESOLVABLE, FAILED. Terminal rows are never claimed.
Canonical AMBIGUOUS is treated as UNRESOLVABLE in v0.1 with the stable code
`ambiguous_location`; it is never automatically retried and never guessed.

#### Claim eligibility and ordering

`ati.claim_geo_resolutions(p_claimed_by, p_claim_limit, p_lease_seconds,
p_max_attempts)` selects in ONE bounded stored-function transaction:

```text
PENDING and (next_attempt_at IS NULL or <= DB now)
OR
PROCESSING with expired lease (lease_expires_at <= now)
```

Terminal rows, future-scheduled PENDING rows, and unexpired PROCESSING rows
are never claimed. Rows are locked with bounded `FOR UPDATE SKIP LOCKED` and
ordered deterministically by eligibility time ASC (for PENDING,
`COALESCE(next_attempt_at, created_at)`; for PROCESSING, `lease_expires_at`),
then `created_at` ASC, then `id` ASC. Two claim-support partial indexes make
both predicates AND the ordering index-eligible (proven with EXPLAIN in
G26C-P39): `geo_resolution_pending_claim_idx (next_attempt_at, created_at,
id) WHERE status = 'pending'` and `geo_resolution_processing_claim_idx
(lease_expires_at, created_at, id) WHERE status = 'processing'`.

#### Attempts and leases

`attempt_count` counts started processing attempts: a new PENDING row is 0,
the first claim makes it 1, a retry transition retains N, and the next claim
(from either a fresh retry schedule or an expired-lease reclaim) makes it
N+1. Attempt `max_attempts + 1` is never started: expired PROCESSING work
already at the budget becomes FAILED (`attempts_exhausted`) instead of being
reclaimed. PROCESSING requires a non-null claimant and lease expiry; leaving
PROCESSING always clears the lease fields. DB time (`now()`) is authoritative
for eligibility and expiry; the lease duration is bounded configuration.
Repeated claims allocate fresh `ati.geo_resolution_version_seq` versions
(every lifecycle mutation is a database-issued version, never
application `version + 1`).

#### Retry policy

Retryable failures with budget remaining return the row to PENDING with the
deterministic bounded exponential backoff `base * 2^(attempt_count - 1)`
capped at the configured maximum and **no jitter**; the failed attempt's
number drives the delay. At exhaustion, or for a non-retryable condition the
row becomes FAILED with no next attempt. Malformed Evidence, provenance
violations, and deterministic ambiguity/no-match are never transient.
`last_error_code` is always a bounded lowercase machine code; raw exception
text is never persisted.

#### Stale-worker protection and lock ordering

Every completion/failure request supplies `(resolution_id, expected_version,
claimed_by)`; the stored functions lock the row (`SELECT ... FOR UPDATE`) and
verify PROCESSING status, matching version, matching claimant, and a live
lease before any mutation, so a stale worker whose lease expired and whose
row was reclaimed can never create an observation or overwrite the newer
owner (G26C-P17/P18). The deterministic lock order is the work row only; the
versioned append function it composes touches the observation/current-state
rows in the same order as PR 26A, so multi-worker contention stays
deadlock-free under bounded batches.

#### Atomic successful completion

`ati.complete_geo_resolution_resolved(...)` is ONE atomic stored function: it
validates status/version/claimant/live lease and the exact Entity/Evidence/
Location provenance (reusing the `U26A1`-`U26A5`/`U26A2` semantics), appends
exactly one immutable `EntityLocationObservation` (reusing SQL API v0022's
append + EntityLocation reconciliation), records the resolved Location,
clears lease/retry/error state, and allocates a fresh DB version. The
observation identity is deterministic (UUIDv5 of the `GeoResolution.id` under
the fixed ATI observation namespace; `observation_uuid_for_resolution` in the
domain), so an uncertain-commit replay of the exact same successful
completion is an idempotent no-op that can never duplicate an observation; a
terminal replay that disagrees with the settled outcome (for example the same
work resolved to a different Location) is a typed conflict with no mutation
(`U26C7`).

### PR 26 stored-function ownership

All PR 26A/26B GEOINT mutations and current-state reconciliation go through
the versioned SQL API stored functions (`ati.upsert_location`,
`ati.append_entity_location_observation`, `ati.create_geo_resolution`, and
the PR 26B `ati.upsert_reference_location`). SQL API v0021 (migration 0025)
shipped the PR 26A functions; SQL API v0022 (migration 0026, PR 26A-2)
redefines `ati.append_entity_location_observation` so `EntityLocation`
versions are always allocated from `ati.entity_location_version_seq` — never
derived arithmetically from the current row — while `ati.upsert_location`
and `ati.create_geo_resolution` remain v0021. SQL API v0024 (migration 0028,
PR 26C) installs the four lifecycle functions
(`ati.claim_geo_resolutions`, `ati.complete_geo_resolution_resolved`,
`ati.complete_geo_resolution_unresolvable`, `ati.record_geo_resolution_failure`)
on the same table. Python repositories are thin callers and never issue
ad-hoc GEOINT DML.

Bounded read/query services may use direct SQL in the same manner as ATI's
existing dedicated query services; PostGIS-capable spatial projections are
PR 26B+ scope.

### Work claiming and deadlock/lock-duration rule (PR 26C, delivered)

Claiming uses `FOR UPDATE SKIP LOCKED` internally, but only in a short
transaction:

```text
claim rows -> persist lease/ownership/attempt -> commit
```

No row lock or transaction is retained while geographic resolution executes.
Completion occurs in a separate short transaction. Contended records are
processed in deterministic ordering documented above. Leases---not long-lived
database locks---coordinate workers, and expired leases recover deterministically
(a stale worker is rejected by version/claimant/lease validation; its committed
claim simply lapses). 

PR 26C lifecycle SQLSTATE mapping (SQL API v0024):

```text
U26A1..U26A6, U26A9  provenance/input codes reused from PR 26A
U26C1 geo resolution not found       U26C5 geo resolution lease expired
U26C2 invalid transition             U26C6 invalid retry/exhaustion (defensive)
U26C3 stale version                  U26C7 terminal replay conflict
U26C4 claim owner mismatch
```

### Spatial indexing (PR 26B+)

Spatial indexes are introduced only for concrete PR 26 query/canonicalization
paths. Tests should verify query-plan/index eligibility where useful without
asserting unstable planner cost estimates.

PostGIS owns spatial computation. Spatial results do not mutate ATI cyber
relationships merely because entities share or approach a geographic location.

### PR 26D analyst read layer

PR 26D reads are bounded, Investigation-scoped, and read-only; mutations
remain 100% owned by the PR 26A-26C versioned stored functions (SQL APIs
v0021-v0024).

**Scope join.** Every analyst GEOINT read proves the path Investigation
through the exact immutable provenance chain
`ati.entity_location_observation.evidence_id -> ati.evidence,
ati.evidence.investigation_id = <path Investigation>`. Scope is never
inferred from shared Entity or Location identity, and the global
materialized `ati.entity_location` row is never consulted for
Investigation-relative current.

**Read joins.** Purpose-built literal SELECT statements join observation ->
Evidence (scope) -> Entity (display context) -> Location (canonical
reference, `ST_Y`/`ST_X` of the on-surface centroid for the coordinate
pair); the centroid coordinate pair is the only spatial value that leaves
the query layer. Evidence type is not re-filtered by reads: the immutable
append stored function already rejects non-`GEOLOCATION` Evidence (U26A4).

**Currentness.** Entity current within the path Investigation and all
history/observation pages use the exact PR 26A currentness ordering:
`COALESCE(observed_at, retrieved_at)` descending, observation UUID
descending (the greater `(effective time, observation id)` pair wins, in
exact agreement with the persisted reconcile path). Location-Entity pages
use the deterministic Entity ordering `(entity_type, canonical_value,
entity_id)` with each Entity appearing once via its latest qualifying
observation (`DISTINCT ON (entity_id)`).

**Containment.** `include_contained=true` selects the exact canonical
Location plus child canonical Locations whose SRID-4326 `geometry` the
selected boundary covers: `l.geometry && sel.geometry` (GiST bounding-box
pre-filter) then boundary-inclusive `ST_Covers(sel.geometry, l.geometry)`.
City Points never expand; a NULL selected `geometry` degrades to the exact
selection reported honestly via the response `containment_applied` flag.
Containment never writes `parent_location_id` and never creates
Relationships.

**Read indexes (migration 0029).** The PR 26A entity history index
(`entity_location_observation_entity_retrieved_idx`) served only the
Entity dimension. PostgreSQL has no access path for the two PR 26D read
shapes without these b-tree indexes:

- `entity_location_observation_location_idx` `(location_id,
  retrieved_at DESC, id ASC)` — Location reverse lookups
  (Locations -> Entities/observations) filter observation rows by the
  selected Location before the exact Evidence scope join;
- `entity_location_observation_evidence_idx` `(evidence_id)` — the
  observation-side continuation of the exact Evidence scope join for the
  summary and scope-driven reads.

Both are read-only: no data rewrite, no mutation SQL change; downgrade
(0028) drops only the two indexes. The new collections page by the
`COALESCE` currentness expression, which no plain b-tree serves, so the
bounded filtered sort is accepted and proven by the EXPLAIN tests
(`SET LOCAL enable_seqscan = off`; assert index eligibility, never brittle
plans).

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
- the deterministic semantic citation identity (`citation_id`);
- sequence;
- text;
- token count;
- embedding identity (provider/model/version) and the vector;
- content hash;
- metadata.

Documents are identified by `(source_id, source_record_id)` and reference the source record through that same composite key. They also retain derived `content`, document type (the source `record_type` vocabulary), and an explicit `chunking_version`; the document semantic hash covers document type, title, source URL, published time, content, normalization/chunking versions, and metadata; source identity, retrieval time, and internal identity are excluded.

Chunks are identified by `(document_id, sequence)`. They are replaceable indexing artifacts: replacement physically rebuilds the complete set, allocates chunk versions, and writes no `domain_object_history` rows or soft-delete state. Each chunk stores embedding provider/model/version/dimension and a semantic hash covering its text, token count, metadata, identity, and embedding metadata (not the vector). The vector column is fixed at dimension 1536 and has an HNSW cosine index.

`document_chunk.citation_id` is a NOT NULL, globally unique deterministic UUIDv5 derived in the pure domain layer from the chunk's semantic coordinates (document identity, sequence, text, token count, and semantic chunk metadata). It is independent of the replaceable row identity, the vector, and the embedding identity, and it is the durable identity ResearchCitations snapshot. The application supplies citation IDs; PostgreSQL never generates them. The storage guarantee is uniqueness fail-closed: a chunk batch carrying a duplicate citation identity aborts the whole replacement transaction.

Embedding configuration stores provider/model/version/dimension sufficiently to support controlled re-embedding. DocumentIndexingService re-indexes unchanged Documents when their current chunk set is missing or does not exactly match the active embedding identity (provider/model/version/dimension); fully compatible chunk sets remain a true no-op. Re-embedding physically replaces the chunk rows and vectors but preserves each chunk's citation identity, so persisted research citations remain valid across embedding migrations. Embedding I/O always happens outside the persistence transaction.

Migration note (upgrade to 0019): existing derived `document_chunk` rows were
removed by the migration because the application citation algorithm cannot be
reproduced exactly in SQL; Documents and all source/investigation/evidence/
assessment records are preserved, and the corpus must be re-indexed after
upgrade to rebuild chunks and embeddings. Inaccurate historical citation IDs
are never retained to avoid reindexing.

PR 11 retrieval joins current chunks to visible documents, filters all four
embedding identity fields plus optional source/type predicates, and performs
bounded top-k ordering with the pgvector cosine-distance operator. The database
performs ranking; Python does not load or reorder the corpus. No compatible
rows produces an empty result. Each retrieved chunk exposes the full
provenance surface (row chunk_id, stable citation_id, document identity,
source identity/record, document type, chunk sequence, text, document title/
URL/published time, similarity score, and metadata) so a durable
`ResearchCitation` snapshot can be created without reopening the vector index.

## Authentication persistence

Domain user and credentials are separate.

Credentials store only a strong Argon2id password hash and password-change metadata.

Sessions use opaque high-entropy tokens. The database stores a cryptographic hash of the session token rather than the token itself.

## Audit persistence

AuditEvent is append-only and immutable. It is stored in `ati.audit_event` with a database-assigned table-wide `version`, UTC occurrence time, actor snapshot, optional object/correlation identifiers, and minimized JSONB metadata. `actor_id` intentionally has no foreign key: the reserved SYSTEM actor is not a user row, and audit records must remain readable after user soft deletion. Known lookup paths are indexed by actor/time, action/time, and object/time. The actor column is not a foreign key, and audit rows are not duplicated into `domain_object_history`: audit answers who attempted an action, while history answers how a resource changed.

Security-relevant successful mutations and their audit event should commit transactionally together. Failed or denied operations that do not commit use an independent transaction.

Denied/failed events use an appropriate independent audit transaction when the primary mutation does not commit.

## Investigation timeline persistence

`ati.investigation_timeline_event` (migration 0013, SQL API v0010) stores the
append-only, analyst-facing workflow timeline. It is deliberately separate
from `AuditEvent`, `domain_object_history`, application logs, and trace
backends.

Table semantics:

- `id uuid PRIMARY KEY` (caller-supplied event identity);
- `investigation_id uuid NOT NULL REFERENCES ati.investigation(id)`; the
  foreign key rejects events for unknown investigations;
- `event_type text NOT NULL` constrained to the six documented timeline
  event types;
- `occurred_at timestamptz NOT NULL` (timezone-aware UTC);
- optional `provider` (source URN), `target_entity_id`,
  `evidence_ids uuid[]`, `entity_ids uuid[]`, `relationship_ids uuid[]`,
  and `error_code text`;
- `error_code`, when present, is bounded to 64 ASCII characters matching
  `^[a-z][a-z0-9_]{0,63}$` by a CHECK constraint mirroring the domain
  contract, so the database rejects an invalid code even if model
  validation is bypassed;
- `sequence bigint NOT NULL` drawn from
  `ati.investigation_timeline_event_seq`, giving a deterministic
  chronological read order even for events sharing one timestamp. The
  sequence is `OWNED BY` its table column, so the 0013 downgrade drops
  both deterministically.

The repository (`PostgresInvestigationTimelineRepository`) exposes exactly
two operations: `append` (insert and flush inside the caller's UnitOfWork
transaction; it never commits) and `list_by_investigation` (chronological
`occurred_at` then `sequence` order).

Append-only enforcement boundary: normal application code is append-only
through the `InvestigationTimelineRepository` ABC — there is no update,
delete, upsert, soft-delete, or versioning path anywhere in the application
stack, and no ATI routine (function/procedure) mutates timeline events.
Direct owner/admin SQL is outside the application immutability boundary;
deployment-role privilege separation (a restricted runtime role) is future
hardening if required, not a v0.1 guarantee. No row-level triggers or generic
history mechanisms are used. Timeline appends are not transactionally atomic
with PR 18C provider-observation persistence; a failed append never rolls
back already committed domain data.

## Task dispatch persistence

PR 19C makes no schema change. Local in-process dispatch requires no dispatch, delivery, worker, acknowledgement, lease, or broker-outbox tables.

The existing PostgreSQL investigation job mechanism remains the durable investigation-level scheduler; it is separate from `TaskDispatcher`, which hands already-selected work to an executor within a running investigation.

## API asynchronous submission and idempotency (PR 23C, migration 0024, SQL API v0020)

`POST /api/v1/investigations` persists the PENDING Investigation, its
durable investigation job, the mutation audit event, and the actor-scoped
idempotency record in **one transaction** (one commit or nothing), then
returns `202 Accepted`. The request never executes the Investigation; a
worker claims the durable job later.

- `ati.investigation_job` is the minimal durable investigation-level job:
  one row per Investigation (unique `investigation_id`), status
  `pending -> claimed -> succeeded|failed`, with `claimed_at`/`completed_at`
  and a bounded `error_code`. Claiming uses
  `SELECT ... FOR UPDATE SKIP LOCKED` through
  `ati.claim_next_investigation_job`, so concurrent workers claim distinct
  jobs; `ati.complete_investigation_job` only completes a claimed job.
  Job administration/monitoring vocabulary is PR 26 scope and is not added
  here.
- `ati.api_idempotency` stores `(actor_id, operation, key_hash,
  request_fingerprint, resource_type, resource_id, created_at)` with a
  unique `(actor_id, operation, key_hash)` scope. Only the SHA-256 digest
  of the `Idempotency-Key` is stored; the raw key is never persisted. The
  fingerprint is a canonical SHA-256 over the semantic normalized request.
- Race safety is database-owned: the unique scope makes concurrent
  identical submissions resolve to exactly one Investigation and one
  logical job (the losing insert waits on the winner's transaction and
  replays the authoritative resource).
- Equivalent replays return the existing Investigation; the same key with a
  semantically different request is rejected (`409 idempotency_conflict`)
  before any mutation.
- Retention: there is no cleanup scheduler in v0.1. Deployments define
  retention for `ati.api_idempotency` (and exhausted job rows); both tables
  are plain operational infrastructure without versioning, history, or
  triggers.

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

## Query/index inventory (PR 23A)

PR 23A introduces the analyst-facing read/query layer (`app/query/` and
`infrastructure/persistence/query/`). Every collection has exactly one
canonical deterministic ordering, every paginated query uses keyset
continuation (never OFFSET), every cursor is opaque, versioned, and bound to
its query collection and filter fingerprint, and date ranges use UTC
half-open ``[from, to)`` semantics.

Every index below exists because a concrete PR 23A query contract requires
it. Indexes whose access path was fully superseded by a richer composite
(``investigation_status_idx``, ``relationship_observation_time_idx``) were
dropped in migration 0022 rather than duplicated.

### Investigation

| Index | Columns/predicate | Query path |
|---|---|---|
| `investigation_active_created_idx` | `(created_at DESC, id ASC) WHERE deleted_at IS NULL` | global investigation listing (`created_at DESC, id ASC`) |
| `investigation_active_status_created_idx` | `(status, created_at DESC, id ASC) WHERE deleted_at IS NULL` | status-filtered investigation listing |

### Evidence

| Index | Columns/predicate | Query path |
|---|---|---|
| `evidence_investigation_listing_idx` (pre-existing) | `(investigation_id, retrieved_at DESC, id ASC)` | investigation Evidence listing / retrieved-time range |
| `evidence_investigation_source_listing_idx` | `(investigation_id, source, retrieved_at DESC, id ASC)` | investigation + source Evidence listing |
| `evidence_investigation_subject_listing_idx` | `(investigation_id, subject_entity_id, retrieved_at DESC, id ASC)` | investigation + subject-entity Evidence listing |
| `evidence_investigation_type_listing_idx` | `(investigation_id, evidence_type, retrieved_at DESC, id ASC)` | investigation + type Evidence listing |

### Relationship

| Index | Columns/predicate | Query path |
|---|---|---|
| `relationship` canonical UNIQUE (pre-existing) | `(source_entity_id, relationship_type_urn, target_entity_id)` | source-direction adjacency and stable edge identity |
| `relationship_target_adjacency_idx` | `(target_entity_id, relationship_type_urn, source_entity_id) WHERE deleted_at IS NULL` | target-direction adjacency pivots |

Investigation relationship listing derives visibility through
`relationship_observation.investigation_id` (no `investigation_id` column is
added to the stable Relationship resource) and deduplicates by the edge's
primary key; the canonical order is the stable `relationship.id ASC`.

### RelationshipObservation

RelationshipObservation rows are themselves the immutable historical record
and are **not** duplicated into `domain_object_history`. Historical browsing
queries `relationship_observation` directly.

| Index | Columns/predicate | Query path |
|---|---|---|
| `relationship_observation_investigation_retrieved_idx` | `(investigation_id, retrieved_at DESC, id ASC)` | investigation-scoped observation listing and investigation relationship join |
| `relationship_observation_relationship_retrieved_idx` | `(relationship_id, retrieved_at DESC, id ASC)` | relationship-scoped observation listing / retrieved-time range |
| `relationship_observation_relationship_observed_idx` | `(relationship_id, observed_at DESC, id ASC) WHERE observed_at IS NOT NULL` | relationship + observed-at date-range browsing |

Observation cursors always encode `retrieved_at` (mandatory) and the row id;
the nullable `observed_at` is an independent filter and never a cursor key.

### ResearchResult

| Index | Columns/predicate | Query path |
|---|---|---|
| `research_result_investigation_idx` (pre-existing) | `(investigation_id, created_at, id)` | internal execution reconciliation read (`created_at ASC, id ASC`) |
| `research_result_subject_idx` (pre-existing) | `(subject_entity_id, created_at, id)` | execution-time subject reconciliation |
| `research_result_investigation_created_idx` | `(investigation_id, created_at DESC, id ASC)` | analyst listing (`created_at DESC, id ASC`) |
| `research_result_investigation_subject_created_idx` | `(investigation_id, subject_entity_id, created_at DESC, id ASC)` | investigation + subject analyst listing |

### Assessment

| Index | Columns/predicate | Query path |
|---|---|---|
| `assessment_investigation_listing_idx` (pre-existing) | `(investigation_id, created_at DESC, id ASC) WHERE deleted_at IS NULL` | internal newest-created listing |
| `assessment_investigation_version_idx` | `(investigation_id, version DESC, id ASC) WHERE deleted_at IS NULL` | Assessment version list (`version DESC, id ASC`) |

The current/final Assessment is resolved exclusively through the
Investigation's durable `assessment_id` pointer; `MAX(version)` inference is
never used. Assessment version lists are `assessment` rows; generic
state-change history is `domain_object_history`. The two are never conflated.

### Investigation timeline

| Index | Columns/predicate | Query path |
|---|---|---|
| `investigation_timeline_event_chronological_idx` (pre-existing) | `(investigation_id, occurred_at, sequence)` | chronological timeline listing (`occurred_at ASC, sequence ASC`) |

The `sequence` column is a table-wide monotonic sequence and is the stable
cursor tie-breaker; no UUID is required. The event-type filter is a bounded
residual filter in v0.1 (low cardinality).

### Generic domain-object history

Generic resource-state history lives in `domain_object_history` with stable
object identity `object_type + object_id` (the original domain object ID).
No `natural_key` column exists or is introduced. The history row's own
primary key `id` (pre-existing) is the stable pagination tie-breaker under
`occurred_at DESC, id ASC`; nothing is invented for cursor pagination.

| Index | Columns/predicate | Query path |
|---|---|---|
| `domain_object_history_object_idx` (pre-existing) | `(object_type, object_id, version)` | exact `object_type + object_id + version` lookup |
| `domain_history_occurred_idx` | `(occurred_at DESC, id ASC)` | global chronological history browsing |
| `domain_history_type_occurred_idx` | `(object_type, occurred_at DESC, id ASC)` | type-scoped history browsing (including type + occurred range) |
| `domain_history_object_occurred_idx` | `(object_type, object_id, occurred_at DESC, id ASC)` | one object's complete history |
| `domain_history_investigation_occurred_idx` | `(investigation_id, occurred_at DESC, id ASC) WHERE investigation_id IS NOT NULL` | investigation-scoped history browsing |

RelationshipObservation is deliberately excluded from
`domain_object_history`; its historical record is its own immutable rows.

### GEOINT (PR 26D read layer)

| Index | Columns/predicate | Query path |
|---|---|---|
| `entity_location_observation_entity_retrieved_idx` (PR 26A) | `(entity_id, retrieved_at DESC, id ASC)` | PR 26D Entity observation history (Entity dimension) |
| `entity_location_observation_location_idx` (migration 0029) | `(location_id, retrieved_at DESC, id ASC)` | PR 26D Locations -> Entities/observations reverse lookup |
| `entity_location_observation_evidence_idx` (migration 0029) | `(evidence_id)` | exact Evidence scope join for summary/scope-driven reads |
| `location_geometry_gist_idx` (PR 26B) | GiST `(geometry) WHERE geometry IS NOT NULL` | containment `&&` bounding-box pre-filter |

Observation cursors encode the PR 26A effective time
(`COALESCE(observed_at, retrieved_at)`) and the observation UUID; the
`COALESCE` ordering expression is served by a bounded filtered sort proven
by the EXPLAIN tests. Location-Entity cursors encode
`(entity_type, canonical_value, entity_id)`.
