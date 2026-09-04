# Agentic Threat Investigator — Database and Persistence

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

Transactions must remain short.

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
 -> classify INSERT / UPDATE / UNCHANGED / CONFLICT
 -> allocate versions for changed rows only
 -> compute old/new state and diff
 -> set-based final target mutation
 -> set-based immutable history insertion
 -> batch result
```

For existing rows, reconciliation captures the observed current version. Final mutation verifies that the target version still equals that observed version; otherwise the row is classified as `CONFLICT` rather than silently overwritten. `UNCHANGED` rows receive no new version and no history record.

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

Normalization version is stored so records can be reprocessed when ATI normalization changes.

## Migrations

Alembic orchestrates schema migrations.

Substantial PostgreSQL stored functions/objects live in separate immutable versioned SQL files.

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

Embedding configuration stores provider/model/version/dimension sufficiently to support controlled re-embedding.

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
