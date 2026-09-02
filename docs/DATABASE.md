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

## Batch repositories

Batch repositories expose set-oriented `upsert_batch`.

Implementation uses PostgreSQL stored functions.

Small/medium batches:

```text
Python batch
 -> JSONB
 -> stored function
 -> INSERT ... ON CONFLICT / set-based merge
```

Large batches may use:

```text
COPY -> staging table -> merge
```

Batch results distinguish:

- INSERTED
- UPDATED
- UNCHANGED

`content_hash` prevents unnecessary updates and downstream reprocessing.

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

AuditEvent is append-only and immutable.

Security-relevant successful mutations and their audit event should commit transactionally together.

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
