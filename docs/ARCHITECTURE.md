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
  - [Current LangGraph implementation status (PR 19A–19C)](#current-langgraph-implementation-status-pr-19a19c)
  - [Real provider execution path (PR 19B–19C)](#real-provider-execution-path-pr-19b19c)
  - [Dispatch versus execution](#dispatch-versus-execution)
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
| Coordinator / orchestration |
|                             |
| Coordinator                 |
| Infrastructure Collector    |
| Threat Intel Collector      |
| Threat Research Agent       |
| Evidence Analyst            |
| Report Writer               |
+-----------------------------+
        |
   TaskDispatcher
        |
 LocalTaskDispatcher
        |
+-----------------------------+
| Execution components        |
|                             |
| WorkExecutor                |
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

> Orchestration selects and authorizes work. Dispatchers route already-selected work. Executors perform it. Dispatchers do not make investigative decisions.

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
LocalTaskDispatcher dispatches selected work
        |
WorkExecutor performs selected work
        |
persist state/results
```

Two separate mechanisms participate:

```text
PostgreSQL job queue
    durable investigation-level background scheduling

TaskDispatcher
    dispatch of already-selected work within a running investigation
```

In v0.1, a worker claims an investigation job, runs LangGraph, and LangGraph hands authorized work to `LocalTaskDispatcher`, which delegates to a local `WorkExecutor`. Long-running investigation work must not execute as an in-process FastAPI background task. PR 19C does not replace the PostgreSQL job queue.

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

### Current LangGraph implementation status (PR 19A–21)

The LangGraph implementation began as a **deterministic orchestration skeleton** in PR 19A under `app/orchestration/`. PR 19C routing already-selected work through an injected deterministic `TaskDispatcher`. PR 21 extends the graph with a coordinator-driven topology that adds pivot authorization, analysis synchronization, and deterministic stopping:

```text
START -> initialize -> coordinator -> { EXECUTE_PROVIDER_WORK
                                       | REQUEST_ANALYSIS
                                       | AUTHORIZE_PIVOT
                                       | STOP }

Provider work path: select_work -> execute_work -> record_outcome -> coordinator
Analysis path:       analyze -> coordinator
Pivot path:          authorize_pivot -> coordinator
Stop path:           finalize_stop -> END
```

The coordinator node applies `CoordinatorPolicy`, a pure deterministic
application-layer policy that decides what action is authorized next. Queue
exhaustion never terminates the production graph: the coordinator decides
whether to pivot, analyze, or stop. The graph fails closed when a transition
node runs without a stored decision or when any coordinator dependency is
partially injected at construction. The legacy queue-exhaustion topology is
available only through the explicitly named `build_legacy_investigation_graph`
test helper; production composition never selects it.

`build_investigation_graph` requires all coordinator dependencies:
`CoordinatorPolicy` (pure policy), `CoordinatorContextLoader` (read-only
policy context), `AnalysisExecutor` (seam around the PR 20B Evidence Analyst),
`CoordinatorTransitionService` (atomic coordinator state writes), and
`InvestigationStatusWriter` (terminal transitions; the database owns
`completed_at`). The policy is stateless and performs no DB, LLM, network,
provider, or clock access; `finalize_stop_state` likewise never reads a
clock.

The production factory `build_provider_investigation_graph` injects a
deterministic planner over the ordered enabled provider registry
(`RegistryProviderWorkPlanner`): applicability is evaluated per candidate
against each enabled provider's own `supports(Entity)` contract using the
exact persisted entity value — never a cached type matrix or canonical-sample
probing — plus the UoW-backed context loader, transition service, status
writer, timeline action service, fatal stop service, and the
bootstrap-supplied analysis executor and provider registry. Discovery depth
is computed from typed `EntityTraversalState` entries (first-discovery
ordinal and minimum depth), never from set/dict iteration or default-zero
fallbacks. A persisted in-progress provider work item (no retry token exists)
fails to a bounded fatal stop rather than re-issuing an external call.

The domain layer does not depend on LangGraph; only `app/orchestration/graph.py` does.

### Real provider execution path (PR 19B–19C)

The production dispatcher is `LocalTaskDispatcher`, which delegates in-process to the production `WorkExecutor`, `ProviderWorkExecutor` (`app/orchestration/provider_executor.py`). `ProviderWorkExecutor` is composed with explicit injected dependencies: an `EntityReader` (short UnitOfWork-backed target lookup closed before any provider I/O), a typed provider registry (`Mapping[SourceId, EvidenceProvider]` keyed by enum members, built from `ProviderComposition.provider_registry()`), the PR 18B deterministic extractor, the PR 18C `ProviderObservationPersistenceService`, and an `InvestigationTimelineSink`. It implements `InvestigationBoundWorkExecutor`, exposing its one authoritative `ProviderExecutionContext.investigation_id` through `bound_investigation_id`.

The public composition seam
`build_provider_investigation_graph(uow_factory, provider_registry, context, analysis_executor, ...)`
in `app/orchestration/composition.py` assembles `ProviderWorkExecutor`, wraps it
with `LocalTaskDispatcher`, injects the PR 21 coordinator policy (with
deterministic `PROVIDER_APPLICABILITY`), the UoW-backed context loader,
transition service, and status writer, plus the bootstrap-supplied analysis
executor, and wires them into the compiled coordinator graph; it constructs
no HTTP clients, providers, settings, engines, or global registries. Investigation binding is preserved across the wrapper: the generic graph builder automatically adopts a bound dispatcher's investigation identity, an explicit conflicting ID fails at graph construction with `InvestigationGraphBindingConflictError`, and every invocation validates the wrapped `InvestigationState` in `initialize` before work selection, dispatch, or I/O. A mismatch raises `InvestigationGraphContextMismatchError` with a fixed safe message and no timeline event. Ordinary unbound dispatchers and explicit expected IDs remain supported. The per-work-item flow is:

```text
ProviderWorkItem (provider, entity_id, depth)
  -> LocalTaskDispatcher
  -> ProviderWorkExecutor
  -> resolve persisted target Entity (short transaction, closed)
  -> validate provider applicability (provider.supports)
  -> append PROVIDER_WORK_STARTED timeline event
  -> call the existing EvidenceProvider (outside all transactions)
  -> validate the complete returned ProviderResult against the selected
         provider, owning investigation, and persisted target
  -> for each normalized Evidence, in provider-return order:
         assign the Evidence identity if the provider did not provide one
         PR 18B deterministic extraction (outside transactions)
         PR 18C atomic observation persistence
         append EVIDENCE_PERSISTED timeline event
  -> append PROVIDER_WORK_COMPLETED (aggregate committed IDs)
  -> ProviderExecutionOutcome (evidence/entity/relationship IDs + safe error)
```

`ProviderWorkExecutor` remains the owner of provider semantics, persistence sequencing, and provider timeline behavior. Returned provider data is validated before any extraction or persistence. The
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

### Dispatch versus execution

```text
Coordinator/LangGraph: WHAT should run?
TaskDispatcher:       HOW/WHERE selected work is handed off?
WorkExecutor:         HOW is concrete work performed?
```

PR 19C's `LocalTaskDispatcher` performs trivial, same-process delegation. A future implementation may replace it without coupling orchestration to transport details, but NATS/JetStream is neither implemented nor a v0.1 dependency. The dispatcher does not select pivots, assess evidence, choose goals, or otherwise make investigative decisions.

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

### Application-level investigation runner (PR 21C)

The application seam that future API and job/monitor entry points call to execute one persisted Investigation is `InvestigationRunner` (`app/orchestration/runner.py`), an `abc.ABC` with a single `run(investigation_id)` operation returning the authoritative durable terminal `InvestigationState`. The in-process production implementation, `LocalInvestigationRunner`, receives only already-composed application/infrastructure seams: a `UnitOfWork` factory, the enabled provider registry, a per-investigation `AnalysisExecutor` factory, an optional clock, and a bound recursion limit. It loads the authoritative persisted Investigation in one short UnitOfWork (closed before any graph/provider/LLM work), treats terminal investigations as idempotent no-ops, fails closed with a typed lifecycle error on any other non-terminal status, creates a fresh investigation-bound analysis executor and a fresh compiled graph per invocation, delegates graph composition to the existing `build_provider_investigation_graph`, invokes the graph outside any enclosing transaction, requires a terminal graph outcome, then reloads and returns the authoritative durable state after validating it against the graph output (`InvestigationRunnerPersistenceMismatchError` on contradiction). Missing investigations raise the existing `InvestigationNotFoundError` (no fatal stop is invented), and `asyncio.CancelledError` propagates unchanged.

### Assessment validation and persistence (PR 20A)

A candidate `Assessment` (produced by the Evidence Analyst in PR 20B) must
pass deterministic provenance validation before it can persist. The seam
keeps repository reads separate from pure rules:

```text
repositories
  -> AssessmentProvenanceContext (immutable snapshot)
  -> AssessmentProvenanceValidator (no provider/network/LLM call)
  -> one short UnitOfWork
       -> persist Assessment (versioned analytical output)
       -> advance Investigation assessment_id pointer
       -> audit event
       -> commit
```

Direct source-fact claims cite Evidence; graph-backed claims cite the exact
RelationshipObservation. Cross-investigation support is rejected, an empty
analyzed set is approved only for INCONCLUSIVE, and a later analysis never
silently overwrites a prior conclusion: it appends a new Assessment version
and moves the Investigation's pointer to it after durable success. The
immutable validation context snapshots every loaded map, and the stored
function revalidates the complete analyzed set, Finding/support structure,
and exact observation chain under deterministic row locks as defense in
depth; Assessment soft deletion is rejected while an Investigation still
points at the Assessment.

Every Assessment-pointer operation (pointer assignment and Assessment soft
deletion) acquires row locks in the canonical order owning Investigation
first, then the target Assessment, so concurrent pointer assignment and
deletion serialize on the Investigation row and can never commit to a
visible Investigation pointing at a deleted Assessment. Assessment
candidate collections (analyzed Evidence, Findings, flattened Finding
supports, and each ordered string collection) are bounded before any
UnitOfWork entry or provenance read by the application service, again by
the repository before SQL, and by the database's larger defensive hard
ceiling before staging; oversized aggregates are rejected with only the
collection name, count, and limit.

### Evidence Analyst execution (PR 20B)

PR 20B establishes the deterministic analyst execution path:

```text
Persisted Investigation
        |
        v
EvidenceAnalystInputLoader (short read-only UnitOfWork, then closed)
        |
        +-> Evidence / RelationshipObservation / Relationship / Entity reads
        v
EvidenceAnalystInput (immutable, bounded DTO; evidence facts only)
        |
        v
EvidenceAnalyst (application service)
        |
        +-> deterministic prompt construction
        v
LlmClient (ABC) --typed, structured-output only--
        |
        v
LangChainLlmClient (infrastructure)
        |   with_structured_output + explicit error mapping
        v
EvidenceAnalystDecision (semantic output only)
        |
        v
Assessment (application stamps investigation_id and analyzed_evidence_ids)
        |
        v
AssessmentPersistenceService (PR 20A validator + atomic persistence)
        |
        v
persisted Assessment + Investigation assessment pointer
```

The Evidence Analyst: assembles its input from persisted authoritative
resources only (``Evidence.raw_payload`` never enters model context),
bounds the context deterministically with typed errors instead of silent
truncation, calls the LLM only through the ATI-owned ``LlmClient``
abstraction, and persists exclusively through the PR 20A
``AssessmentPersistenceService``. **All LLM calls occur strictly outside
database transactions**: the loader's read-only UnitOfWork closes before the
prompt is built, and the PR 20A persistence UnitOfWork opens only after a
candidate has been constructed.

Every actual model invocation, including each structured-output repair
attempt, is durably reserved against the Investigation LLM budget through a
short, versioned Investigation update. Prompt construction for each attempt
happens BEFORE its reservation: a prompt-construction failure consumes no
LLM budget, and a reservation is written only immediately before entering
``LlmClient`` for that attempt — so a failed repair-prompt build never
reserves a nonexistent repair call while the prior real attempt stays
counted. Structured-output attempts are
hard-limited to ``1..2`` (initial attempt plus at most one schema repair),
and a repair happens only for an ``INVALID_STRUCTURED_OUTPUT`` error whose
``retryable`` flag is true — a non-retryable invalid output, or any other
category, fails conservative. Cancellation propagates unchanged. An
Investigation with no Evidence short-circuits to a deterministic
INCONCLUSIVE Assessment with no model call.

The Evidence Analyst input is assembled from persisted authoritative
resources only (``Evidence.raw_payload`` never enters model context); item
counts, the aggregate normalized-facts byte size, and the total serialized
size are each independently bounded with typed errors instead of silent
truncation.

PR 20B does not modify the PR 19C dispatcher or the provider-only LangGraph
topology. Adaptive pivots, stopping, and the general multi-work dispatch
boundary are PR 21.

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

### Document and chunk identity semantics

```text
DocumentChunk.id
    = replaceable persistence row identity

DocumentChunk.citation_id
    = deterministic semantic citation identity

ResearchCitation
    = immutable provenance snapshot

ResearchResult
    = immutable contextual research artifact
    != Evidence
    != Assessment
```

- `DocumentChunk.id` is the operational row identity and changes whenever the chunk set is physically rebuilt (document change or re-embedding).
- `DocumentChunk.citation_id` is a deterministic UUIDv5 derived from the chunk's semantic coordinates (document identity, sequence, text, token count, and semantic chunk metadata) in the pure domain layer. It deliberately excludes the row identity, the vector, and the embedding provider/model/version/dimension: pure re-embedding preserves the citation identity, while a semantic chunk change alters it.
- `DocumentChunk.content_hash` remains the concrete indexed representation digest (including embedding metadata) used for change detection.
- `ResearchCitation` is an immutable self-contained snapshot of one retrieved chunk's full provenance surface, so a persisted research result remains interpretable even when the active chunk row it cited is later replaced or removed.
- `ResearchResult` is an immutable, append-only contextual research synthesis/provenance container. It is deliberately NOT Evidence and NOT Assessment: it never enters Evidence persistence and never carries Assessment verdict/confidence semantics. Repeat research executions create a new result rather than mutating a prior one.

### Research Agent execution boundary (PR 22B)

```text
ResearchAgentRequest
 -> ResearchRetriever
 -> deterministic prompt
 -> LlmClient
 -> citation validation
 -> ResearchResult
 -> ResearchResultPersistenceService
```

The standalone Research Agent executes one bounded request per invocation:
retrieved context enters an immutable `ResearchResult` only after the model's
structured claims pass deterministic citation-membership validation against
the exact chunks supplied to that model execution. Model-visible citations
use the stable `DocumentChunk.citation_id`; the model never sees or returns
`chunk_id`, durable result/claim UUIDs, timestamps, investigation/entity
anchors, verdicts, confidence, or pivot/tool fields. Retrieved context,
`ResearchResult`, Evidence, and Assessment remain distinct: retrieval
produces context, the Research Agent persists contextual synthesis, and only
evidence collection/persistence can create Evidence while only the Evidence
Analyst creates Assessments.

## Persistence

PostgreSQL is the authoritative datastore.

Categories:

- append-oriented immutable observations: Evidence, RelationshipObservation, AuditEvent;
- append-only immutable contextual analytical artifacts: ResearchResult (research claims with self-contained citation snapshots);
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
- Task dispatch: application-layer `TaskDispatcher`; v0.1 implementation: `LocalTaskDispatcher`.
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
