# Agentic Threat Investigator — Architecture

## Table of contents

- [Architectural objective](#architectural-objective)
- [High-level architecture](#high-level-architecture)
- [Layering](#layering)
  - [Domain](#domain)
  - [Application](#application)
  - [Infrastructure](#infrastructure)
  - [Agents](#agents)
  - [API](#api)
  - [Frontend](#frontend)
- [Core architectural rule](#core-architectural-rule)
- [Asynchronous investigation execution](#asynchronous-investigation-execution)
- [LangGraph topology](#langgraph-topology)
- [Agent boundaries](#agent-boundaries)
- [Structured agent results and presentation](#structured-agent-results-and-presentation)
- [Provider architecture](#provider-architecture)
- [Relationship construction](#relationship-construction)
- [RAG](#rag)
- [Persistence](#persistence)
- [Transactions](#transactions)
- [Batch ingestion](#batch-ingestion)
- [Geospatial](#geospatial)
- [Observability](#observability)
- [Technology baseline](#technology-baseline)
- [Configuration architecture](#configuration-architecture)
- [Batch persistence responsibility boundary](#batch-persistence-responsibility-boundary)
- [Batch artifact storage boundary](#batch-artifact-storage-boundary)
- [Secrets boundary](#secrets-boundary)
- [Batch artifact acquisition and storage evolution](#batch-artifact-acquisition-and-storage-evolution)

## Architectural objective

ATI separates domain semantics, application orchestration, infrastructure adapters, persistence, agent behavior, and presentation so that external providers, LLMs, tracing systems, and deployment details can change without altering the core investigation model.

## High-level architecture

```text
React / TypeScript UI
        |
     REST API
        |
  Application Services
        |
  PostgreSQL Job Queue
        |
      Worker
        |
     LangGraph
        |
+-----------------------------+
| Coordinator                 |
| Infrastructure Collector    |
| Threat Intel Collector      |
| Threat Research Agent       |
| Evidence Analyst            |
| Report Writer               |
+-----------------------------+
        |
+-----------------------------+
| Evidence Providers          |
| RAG Retriever               |
| LLM Client                  |
| Repositories / UnitOfWork   |
| Observability Adapter       |
+-----------------------------+
        |
 PostgreSQL + pgvector
```

## Layering

### Domain

Pure Pydantic domain models and enums. The domain must not depend on SQLAlchemy, HTTP clients, FastAPI, LangChain, LangGraph, pgvector, or a specific LLM provider.

### Application

Coordinates use cases, persistence, transactions, policies, jobs, and state transitions. Application services enforce invariants.

### Infrastructure

Contains PostgreSQL repositories, HTTP clients, source/provider implementations, pgvector retrieval, LLM adapters, tracing adapters, and other external integrations.

### Agents

Agents interpret evidence and make typed recommendations within explicit contracts. They do not directly mutate the database or invoke unrestricted infrastructure.

### API

FastAPI request/response DTOs and REST routes. API DTOs are separate from domain and ORM models.

### Frontend

React/TypeScript analyst workbench consuming the stable `/api/v1` contract.

## Core architectural rule

> Providers retrieve. Collectors coordinate retrieval. Repositories persist. Application workflows decide persistence. Agents decide investigative actions within policy.

## Asynchronous investigation execution

Investigation creation is asynchronous.

```text
POST /api/v1/investigations
        |
persist investigation + job
        |
return 202
        |
worker claims job
        |
execute LangGraph
        |
persist state/results
```

Long-running investigation work must not execute as an in-process FastAPI background task.

v0.1 uses a PostgreSQL-backed job queue rather than introducing Redis/Kafka solely for background work.

## LangGraph topology

Conceptually:

```text
START
  |
Initialize
  |
Coordinator
  |
Collectors
  |
Persist Evidence
  |
Extract Relationships
  |
Update Discoveries
  |
Coordinator
  +----> Pivot / Collect More
  |
  +----> Threat Research
  |
Evidence Analyst
  +----> Coordinator if more evidence is justified
  |
Assessment
  |
Report Writer
  |
END
```

The persisted domain objects are authoritative. `InvestigationState` carries identifiers, queues, budgets, status, and outcomes rather than copies of all domain objects.

### Current LangGraph implementation status (PR 19A)

The first LangGraph implementation is a **deterministic orchestration skeleton** (PR 19A) under `app/orchestration/`. It proves typed work can be queued, executed through an injected deterministic `WorkExecutor`, recorded, and terminated on queue exhaustion:

```text
START -> initialize -> select_work -> execute_work -> record_outcome -> select_work
                     ^-- (pending work -> execute_work | no work -> END)
```

The skeleton implements mechanics only: FIFO selection, duplicate suppression for identical work, provider-call counter increments, and serializable operational state. Real provider execution arrived with PR 19B; LLM/Evidence Analyst behavior is PR 20; adaptive coordinator/pivot behavior, budget enforcement, stopping policy, and trajectory evaluation arrive with PR 21. The domain layer does not depend on LangGraph; only `app/orchestration/graph.py` does.

### Real provider execution path (PR 19B)

The production `WorkExecutor` is `ProviderWorkExecutor` (`app/orchestration/provider_executor.py`), composed with explicit injected dependencies: an `EntityReader` (short UnitOfWork-backed target lookup closed before any provider I/O), a typed provider registry (`Mapping[SourceId, EvidenceProvider]` keyed by enum members, built from `ProviderComposition.provider_registry()`), the PR 18B deterministic extractor, the PR 18C `ProviderObservationPersistenceService`, and an `InvestigationTimelineSink`. The public composition seam `build_provider_investigation_graph(uow_factory, provider_registry, context)` in `app/orchestration/composition.py` assembles all production dependencies and returns the compiled PR 19A graph for a later worker entry point; it constructs no HTTP clients, providers, settings, engines, or global registries. The compiled production graph is bound to exactly one `ProviderExecutionContext.investigation_id`: every invocation validates the wrapped `InvestigationState`'s investigation ID in the `initialize` node before work selection or any I/O, and a mismatch raises the typed `InvestigationGraphContextMismatchError` (a fixed safe message with no identifiers) and emits no timeline event. The generic PR 19A graph remains usable with fake executors when no expected ID is passed. Its per-work-item flow:

```text
ProviderWorkItem (provider, entity_id, depth)
  -> resolve persisted target Entity (short transaction, closed)
  -> validate provider applicability (provider.supports)
  -> append PROVIDER_WORK_STARTED timeline event
  -> call the existing EvidenceProvider (outside all transactions)
  -> validate the complete returned ProviderResult against the selected
         provider, owning investigation, and persisted target
  -> for each normalized Evidence, in provider-return order:
         assign the Evidence identity if the provider did not
         PR 18B deterministic extraction (outside transactions)
         PR 18C atomic observation persistence
         append EVIDENCE_PERSISTED timeline event
  -> append PROVIDER_WORK_COMPLETED (aggregate committed IDs)
  -> ProviderExecutionOutcome (evidence/entity/relationship IDs + safe error)
```

Returned provider data is validated before any extraction or persistence. The
persisted Entity resolved for `work_item.entity_id` is authoritative: it must
carry exactly that entity ID and an already-canonical value, or a faulty
reader could substitute another Entity while timeline events retain the
requested target ID. The result provider must equal the registry provider and
the work item source, and every returned Evidence must carry the owning
investigation ID and a subject whose type, canonical value, and (when present)
identifier exactly match the authoritative persisted target. Subject values
must already be canonical and equal the persisted target value exactly:
canonical equivalence after normalization is not accepted. Malformed or
noncanonical provider subjects and reader results that are not the exact
selected Entity become safe `provider_binding` failures before any provider
output is processed, extraction runs, or an observation is written;
canonicalization errors fold into that deterministic failure and never escape
the executor or appear in logs, state, or timeline events. The whole returned
tuple is validated before the first Evidence is processed, so one invalid item
never lets an earlier item commit; a violation fails the work with the stable
`provider_binding` code and no observation is written.

Failure semantics: an unknown provider, provider registry/key identity
mismatch, missing/soft-deleted target, unsupported target, provider error,
extraction failure, or persistence failure yields a failed typed outcome with a
stable error code (`provider_not_configured`, `provider_binding`,
`target_not_found`, `unsupported_indicator`, provider codes,
`extraction_error`, `persistence_error`); already committed Evidence
observations are never compensated. A failed work outcome always retains every
Evidence, discovered Entity, and Relationship ID committed before the failure
so `record_provider_outcome` can merge them into `InvestigationState`, even
when the final failure timeline event cannot be appended.

Mixed evidence-plus-provider results follow the approved PR 19B
partial-result contract: valid Evidence is processed and persisted in
provider-return order; when at least one Evidence observation committed and
no extraction, persistence, or timeline failure followed, the status is
`SUCCEEDED` and only the first provider error (provider-return order) is
retained — its stable code and retryability, never its free-form message. The
retained code is carried on the `PROVIDER_WORK_COMPLETED` event's
`error_code` so the timeline accurately exposes the partial result. If
extraction, persistence, or timeline processing fails after Evidence
commits, `FAILED` takes precedence and all previously committed IDs remain in
the outcome. Errors without Evidence remain `FAILED`; an all-empty result
remains `SUCCEEDED`. No PARTIAL execution status exists in PR 19B. Caught
provider, persistence, and timeline exceptions are never attached to logs: a
bounded fixed-format summary carrying stable identifiers only is emitted
instead. `asyncio.CancelledError` propagates unchanged.
Extracted entities update `discovered_entity_ids` only; PR 21 owns whether
they become pivots. The provider-call counter increments exactly once per
executed work item.

The investigation timeline (`domain/investigation_timeline.py`, table `ati.investigation_timeline_event`) is a distinct, append-only, analyst-facing workflow history. It is separate from AuditEvent (governance/security), domain-object history, structured logs, and trace backends. Events carry typed identifiers, a stable event type, and an optional bounded error code only: no prose reasoning, raw payloads, secrets, stack traces, or chain-of-thought. Timeline appends run in their own short transactions and are deliberately not transactionally atomic with PR 18C persistence; a failed append surfaces a typed `timeline_error` without rolling back committed domain data.

## Agent boundaries

ATI has six logical agent roles:

1. Investigation Coordinator.
2. Infrastructure Collector.
3. Threat Intelligence Collector.
4. Threat Research / Context RAG Agent.
5. Evidence Analyst.
6. Report Writer.

There is not one agent per external API.

## Structured agent results and presentation

ATI separates model reasoning/synthesis from presentation.

Every agent operation that produces a programmatic result crosses the agent
boundary through a concrete Pydantic output model:

```text
Agent / LLM
    |
    v
Pydantic structured result
    |
    v
deterministic semantic validation
    |
    +--> application workflow
    +--> persistence
    +--> API DTO mapping
    |
    v
deterministic presentation
```

Free-form LLM text is never the authoritative representation of an agent
decision or analytical output.

The JSON-compatible serialization of the validated Pydantic model is the
authoritative machine-readable representation. Human-readable documents
are derived views.

### Presentation boundary

Human-readable Markdown, HTML, and plain text are produced by
deterministic formatter/presenter components. Presentation components
belong outside the agent reasoning boundary and do not invoke an LLM.

A formatter may:

- select headings and labels;
- render lists/tables;
- render references/citations;
- apply explicit locale/date-format settings;
- escape content for the target representation.

A formatter may not:

- add or remove material findings;
- alter verdict/confidence;
- reinterpret evidence;
- introduce citations;
- generate recommendations;
- infer facts;
- invoke tools/providers/retrievers;
- mutate persisted/domain state.

This makes structured ATI data the single semantic source for API
responses, frontend rendering, exported reports, and deterministic test
comparisons.

### Report pipeline

The report path is:

```text
Evidence + Relationships + Research + Assessment
                    |
                    v
              Report Writer
                    |
                    v
       InvestigationReport (Pydantic)
                    |
             validate invariants
                    |
                    v
        persist structured report
                    |
          +---------+---------+
          |                   |
          v                   v
       API DTO         deterministic formatter
                              |
                         Markdown / HTML
```

The Report Writer therefore produces structured report content rather
than a finished free-form document.

### Framework boundary

LangChain/LangGraph or an LLM-provider-specific structured-output
mechanism is an infrastructure concern. Domain/application contracts
depend on ATI Pydantic result types, not on a vendor-specific
JSON-schema or tool-call representation.

The LLM adapter is responsible for converting provider/framework
structured output into the requested ATI Pydantic model and reporting
invalid output as the typed LLM failure defined by the agent contract.

## Provider architecture

All live evidence providers implement an `abc.ABC` contract.

Providers:

- determine deterministic applicability via `supports()`;
- retrieve external information;
- normalize it into ATI Evidence;
- return typed errors.

Providers do not:

- persist;
- create relationships;
- assess maliciousness;
- decide pivots.

## Relationship construction

Relationships are derived deterministically from normalized evidence/source records through relationship extractors.

The PR 18B extraction layer (`app/extraction`) is a pure, database-free application package. A dispatcher maps each `(source, evidence type)` pair to a source-specific extractor that converts one normalized, persisted `Evidence` observation into canonical discovered entity identities (`ExtractedEntity`) and evidence-backed relationship assertions (`RelationshipAssertion`, each carrying the supporting Evidence ID). Extraction consumes normalized facts only (never raw payloads), performs no I/O, persistence, provider calls, or LLM calls, re-canonicalizes every identity through the shared domain canonicalizers, fails explicitly on malformed facts (all-or-nothing per Evidence), and deduplicates within one Evidence deterministically. The exact per-source extraction matrix lives in `docs/DOMAIN_MODEL.md` and `docs/DATA_SOURCES.md`.

No LLM is required to infer basic relationships such as DNS resolution or network ownership.

Relationship extraction can discover entities. The Coordinator may then evaluate those entities as possible pivots. PR 18C persists the extraction output atomically (entity upserts, stable relationships, immutable relationship observations). Its narrow application service performs preflight validation before BEGIN — Evidence identity, canonical values, assertion Evidence-ID equality, endpoint coverage, and the deterministic duplicate policy — so provider calls and PR 18B extraction never run inside the UnitOfWork. Rediscovery of a soft-deleted Entity or Relationship is a fail-closed typed error: no second canonical row, no silent restore, and no observation attached to a deleted object. The fail-closed behavior is database-enforced: the authoritative write functions reject soft-deleted identities and dangling Evidence provenance under the row lock, so application pre-checks are defense in depth rather than the guarantee itself.

## RAG

PostgreSQL + pgvector is the v0.1 vector store.

RAG is conditional and concept-driven. It is invoked for entities such as malware, ATT&CK techniques, vulnerabilities, or explicit analyst contextual questions.

Live IOC facts remain evidence-provider responsibility.

## Persistence

PostgreSQL is the authoritative datastore.

Categories:

- append-oriented immutable observations: Evidence, RelationshipObservation, AuditEvent;
- stable identities: Entity, Relationship;
- versioned outputs: Assessment, InvestigationReport;
- mutable operational state: Investigation, Monitor, jobs, users/sessions;
- replaceable derived indexing artifacts: document chunks/embeddings.

All persistent application/domain deletion is soft deletion. Immutable historical observations normally expose no delete operation.

## Transactions

External provider and LLM calls occur outside database transactions.

A normalized provider result is persisted atomically as the relevant evidence, entities, relationships, observations, and audit changes. Evidence is insert-only, stable graph identities are reused, and each assertion receives one immutable Evidence-provenanced observation.

Repositories never self-commit. Application services use an explicit Unit of Work.

The investigation persistence service owns this boundary for the PR 18A seam:
investigation resources and immutable evidence observations persist in one
short transaction each, together with their required audit events. Provider
calls stay outside transactions. Graph persistence (entities, relationships,
relationship observations) joins this seam atomically in a later PR.

## Batch ingestion

Structured batch sources follow:

```text
download
 -> normalize SourceRecord
 -> batch repository
 -> PostgreSQL stored function / set-based merge
 -> inserted/updated/unchanged result
 -> downstream processing only for changed records
```

The canonical path is the bounded resource-specific PostgreSQL composite-array transport described in DATABASE.md; PostgreSQL expands it into temporary staging tables and performs the set-based merge. There is no alternate small-batch path.

## Geospatial

v0.1 uses DB-IP City Lite through a local MMDB database. Latitude/longitude are used for map visualization.

PostGIS is not required until ATI needs actual spatial queries.

## Observability

Product history and operational observability are separate:

- AuditEvent: governance/security history.
- Investigation timeline: analyst-facing workflow history.
- Structured logs: runtime diagnostics.
- LangSmith or future trace backend: agent/LLM development observability.

No observability backend is required for correct execution.

## Technology baseline

- Python managed by `uv`.
- FastAPI.
- Pydantic.
- PostgreSQL + pgvector.
- SQLAlchemy/repository implementations.
- Alembic migrations.
- LangChain/LangGraph.
- LangSmith initially.
- React + TypeScript.
- React Flow.
- Leaflet.
- Podman Compose for local deployment.

## Configuration architecture

Runtime configuration follows `CONFIGURATION.md`. `ATI_CONFIG_PROFILE` selects a source-controlled profile under `ati.config`; `default` is always the base and a selected non-default profile shallowly overrides it. Configuration is loaded once during process bootstrap and injected into application components. Components do not independently read process environment variables. Effective configuration is logged with conservative sensitive-value redaction.

## Batch persistence responsibility boundary

Batch persistence always uses resource-specific PostgreSQL composite arrays as the bounded application-to-database transport and temporary tables inside set-oriented stored functions. ATI assumes batches may be large; there is no small-batch alternate path. The application enforces a configurable maximum batch size. PostgreSQL owns reconciliation, concurrency checks, version allocation, JSONB diff generation, target mutation, immutable history creation, and outcome classification. Python repositories must not duplicate this logic. Row-level history/version triggers are prohibited.

## Batch artifact storage boundary

Batch ingestion separates acquisition, storage, and interpretation. BatchSource consumes an artifact through an abstract ObjectStore using a URI and is unaware of how the artifact was acquired. v0.1 provides filesystem-backed object storage; cloud object-store implementations are future extensions.

A future Downloader is a producer-side acquisition abstraction. A later producer/consumer topology may use a distributed event log to announce artifact availability while retaining the artifact itself in filesystem/object storage.

## Secrets boundary

Secret acquisition is abstracted through `SecretsResolver`. v0.1 uses `EnvVarSecretsResolver`. Secret resolution occurs in the application composition/bootstrap layer; constructed providers receive resolved credentials rather than depending on the resolver itself.


## Batch artifact acquisition and storage evolution

The architectural dependency direction is:

```text
v0.1

manual acquisition
      ↓
FileSystemObjectStore
      ↓
artifact URI
      ↓
BatchSource
      ↓
SourceRecord
      ↓
batch repository
```

A `BatchSource` consumes an already-present artifact. It does not perform HTTP downloads, authenticate to the upstream publisher, or decide where artifacts are stored.

Artifact locations are represented by URIs. Canonical examples are:

```text
file:///var/lib/ati/datasets/mitre-attack/enterprise-attack.json
s3://ati-datasets/mitre-attack/enterprise-attack.json
```

The URI identifies the resource; it never carries credentials. URI-scheme resolution selects the appropriate `ObjectStore` implementation outside the `BatchSource`. The source must not contain `if scheme == "file"` / `if scheme == "s3"` storage branching.

For v0.1 the only required storage implementation is `FileSystemObjectStore`, rooted operationally beneath:

```text
${ATI_DATA_DIR}/datasets/<source>/
```

Resumable progress is scoped by `(source_id, artifact_uri, normalization_version)`. A source owns its opaque checkpoint syntax. The ingestion service commits each bounded source-record batch and its post-batch checkpoint in one short UnitOfWork transaction; it never holds a database transaction while awaiting artifact I/O or the next normalized batch. Earlier committed batches remain resumable if later parsing fails. Completed artifacts return a deterministic no-op unless explicitly restarted, and downstream work receives only INSERTED/UPDATED records.

A future `Downloader` is a producer-side abstraction:

```text
external publisher
      ↓
Downloader
      ↓
ObjectStore
      ↓
artifact URI
```

A still-later distributed topology may introduce a producer/consumer layer and distributed event log such as Kafka:

```text
Downloader
      ↓
ObjectStore
      ↓
ArtifactAvailable event
      ↓
distributed event log
      ↓
consumer
      ↓
BatchSource
```

The event log carries artifact metadata/reference information such as source ID, artifact URI, content hash, and retrieval timestamp. Bulk datasets remain in filesystem/object storage and are not transported as event payloads.

Secret acquisition remains orthogonal to all of the above. `SecretsResolver` resolves credentials during bootstrap/composition; storage implementations, downloaders, and providers receive only the credentials they require.
