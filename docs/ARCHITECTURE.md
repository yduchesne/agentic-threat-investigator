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
- [Investigation Map frontend (PR 25B)](#investigation-map-frontend-pr-25b)
- [Map analyst workflow and E2E seeding (PR 25C)](#map-analyst-workflow-and-e2e-seeding-pr-25c)
- [GEOINT architecture (PR 26)](#geoint-architecture-pr-26)
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

The v0.1 frontend is a typed, internationalization-ready browser application
(foundation PR 24A) with strict ownership boundaries:

```text
React Router 7            owns navigation/URL state
TanStack Query v5         owns server state (cache, async lifecycle)
local React state         owns transient presentation state
FastAPI /api/v1           authoritative for identity, runtime mode and
                          every analytical resource
```

Server resources live in TanStack Query only — never in React Context or a
custom global store. All browser API traffic flows through one centralized,
ATI-owned fetch boundary (`frontend/src/api/client.ts`) using the
browser-relative `/api/v1` base, `credentials: include`, Abort signals and
exact `ati_csrf` → `X-CSRF-Token` handling. The HttpOnly `ati_session` cookie
is never read by frontend code; `/auth/me` is the authentication authority.
OpenAPI-derived TypeScript types are generated from the committed snapshot
(`tests/fixtures/openapi_v1.json`) with a deterministic drift check.

Component/design system is Material UI + Emotion; user-visible strings are
backed by i18next/react-i18next (English first). Investment in Investigation
workflow (PR 24B), analyst tables (PR 24C), pivots (PR 24D) and relationship
visualization (PR 24E) builds on this foundation.

### Server-driven analyst browsing (PR 24C)

PR 24C adds one reusable server-driven tabular browsing and detail
architecture over the PR 23C read APIs:

```text
workspace route
 -> URL-backed filters
 -> bounded server query
 -> opaque cursor page
 -> analyst table
 -> row selection
 -> authoritative resource detail drawer
```

The backend owns filter semantics, canonical ordering, cursor encoding,
pagination bounds, Investigation scoping, authorization, history
allowlisting/redaction, and resource identity. The frontend owns filter
controls, URL serialization, table presentation, opaque-cursor
Previous/Next navigation, row selection, detail presentation, and
accurately labeled bounded export.

```text
URL                 resource filter values, the opaque cursor, and
                    `selected=<uuid>` for the drawer (never JSON filter
                    blobs or API responses)
TanStack Query      one bounded page per committed filter/cursor, plus
                    detail queries enabled only on selection
TanStack Table v8   the sole table engine, running headless through
                    Material UI primitives in manual/server mode
browser-local state draft filter-form values and the Previous back stack
                    (never persisted to browser storage)
backend             filters/order/pagination/cursor encoding, binding,
                    authorization, history public allowlists and redaction
```

Rules enforced by the architecture:

- cursors are opaque: the browser never decodes, compares, or performs
  arithmetic on them, never shows page numbers/totals, and never fetches
  all pages to simulate a client dataset;
- any semantic filter change resets the cursor and the browser-local back
  stack; a direct URL cursor may load but reload need not reconstruct the
  prior back stack; an invalid/stale cursor offers first-page recovery;
- tables never poll: Evidence/Relationships/Research/Timeline/History load
  one bounded page per committed state. While an Investigation is
  pending/running they display currently persisted rows plus a small
  freshness notice with an explicit Refresh;
- RelationshipObservation is first-class immutable observation history
  (`/relationships/observations`) and is never routed through generic
  History; `observed_at` and `retrieved_at` are visibly independent with
  half-open ranges and no started/ended/removed/continuous-validity
  inference;
- Research is contextual knowledge, never Evidence: claims/citations are
  inspectable and external text is React-escaped, never auto-fetched;
- generic History is secondary (workspace `More -> History`), honors the
  backend public object-type allowlist, and renders backend-redacted
  `state`/`diff` only as escaped data with exact-version detail;
- export means the current page: a bounded RFC 4180 CSV with spreadsheet
  formula-injection neutralization and filenames free of objective/IOC
  text.

Cross-resource pivots and breadcrumb modal workspaces (PR 24D) reuse this
table/detail architecture rather than creating a second one; Relationship
Evolution and the bounded stable-relationship graph are delivered in PR
24E below, and maps remain PR 25.

### Cross-resource pivots and provenance navigation (PR 24D)

PR 24D is a navigation layer over the PR 24C surfaces: an analyst can
pivot from a typed entity/resource value or an Overview/Report provenance
reference into an existing filtered resource view, inspect table/details,
and pivot again — deterministically, bounded, and restorable through
browser navigation.

```text
typed value / provenance reference
 -> explicit capability registry entry
 -> URL-backed pivot step (validated, versioned, bounded stack)
 -> one modal workspace -> active PR 24C resource view
 -> breadcrumbs preserve the exploration sequence
 -> next pivot replaces the modal content (never stacks dialogs)
```

Architectural decisions:

- a typed pivot model and one explicit capability registry
  (`frontend/src/pivots/pivot-types.ts`, `pivot-capabilities.ts`) list
  every legal action; ATI never infers navigation from arbitrary matching
  strings and never merges unsupported query combinations client-side —
  every pivot corresponds to an existing bounded PR 24C filter or exact
  scoped detail endpoint;
- pivot state is a versioned base64url JSON stack in the reserved `pivot`
  search parameter (`pivot-url.ts`), capped at five steps and a 4096-byte
  header budget; pushing replaces the query (removing a prior
  `selected=<uuid>`), truncation and Close restore prior/base state, and
  browser Back/Forward plus refresh restore the active modal from the URL
  — no client-side global pivot store;
- the route-independent workspaces extracted for PR 24D reuse the exact
  PR 24C query/filter/table/detail machinery through a thin search-params
  projection (`analyst-table/resource-page.ts`, `pivots/pivot-port.ts`):
  one modal workspace hosts the active resource view, nested pivots key
  the same modal by resource, and the URL continues to own all state.
  The modal and the multi-target action menus are implemented with MUI
  primitives (fixed paper/backdrop, Portal, WAI-ARIA menu semantics)
  rather than the MUI Dialog/Menu/Modal chain: in material-ui 7 the Modal
  focus trap, with the custom detail drawer mounted inside it, races the
  drawer's unmount on an in-drawer pivot click and permanently
  spins/crashes the Chromium main thread (real-stack E2E, PR 24D). The
  component contracts (accessible dialog semantics, backdrop/Escape
  close, body scroll lock, aria-hiding of the underlying page, roving
  keyboard menus) are identical; jsdom and browser behavior agree;
- the Investigation ID is immutable across the pivot stack, the modally
  hosted tables reuse the identical bounded server queries and detail
  endpoints, and pivoting changes navigation context only — it never
  alters Investigation orchestration, never creates Evidence, and never
  performs downloads;
- provenance navigation uses exact persisted support identifiers where
  bounded API access exists (Evidence support, Research claims/context,
  and RelationshipObservation support); a Report/Assessment
  `relationship_observation` support id resolves through the exact
  Investigation-scoped observation read
  (`GET /api/v1/investigations/{id}/relationship-observations/{observation_id}`,
  PR 24F) inside the pivot workspace — the browser never scans cursor
  pages, never substitutes a related observation, and never falls back to
  generic History. Missing and cross-Investigation ids map to the same
  safe scoped 404;
- Performance bounds enforced by the plan: only the active step is
  mounted (no hidden component trees for prior steps), menus are computed
  from already-loaded row objects and never prefetch resources or issue
  API calls, labels come from the same object graph (no N+1 resolution),
  the depth cap is `MAX_PIVOT_STEPS=5` at which further pivot actions are
  suppressed, and nested pivots replace the single modal's content rather
  than stacking dialogs.

### Relationship Evolution and the bounded relationship graph (PR 24E)

PR 24E delivers the entity-centric temporal view of observed relationships
and a bounded one-hop visualization of the stable Relationship set.

```text
Relationship          = stable semantic edge ATI knows about
RelationshipObservation = immutable observation that the edge was observed
Relationship Evolution  = deterministic read projection of those observations
                          (RelationshipObservation JOIN Relationship)
Investigation Timeline   = what ATI did (distinct, unmodified)
Generic History          = how eligible persisted objects changed (distinct)
Relationship Graph       = bounded one-hop view of the stable Relationship set
```

Architectural decisions:

- **Evolution is a read projection, never a second persistence model**: no
  `relationship_evolution` tables, no materialized timelines, no mutable
  validity records, no frontend-generated historical truth. The existing
  Investigation-scoped RelationshipObservation endpoint remains the source
  of truth;
- the PR 23A observation query is extended narrowly with server-side
  `entity_id`, `direction` (`source`/`target`/`either`),
  `relationship_type`, and `counterparty_entity_id` filters, evaluated in
  SQL through the joined stable Relationship (an inner join on edge
  identity; Investigation isolation stays on the observation's own
  `investigation_id`). The browser never downloads unrelated observations
  and never joins/filters client-side;
- each observation page carries the joined Relationship semantics
  (`relationship_source_entity_id`, `relationship_target_entity_id`,
  `relationship_type`) as public projection fields — there is no N+1
  Relationship detail loading;
- cursor identity includes the new semantic filters; changing any
  Evolution filter resets the cursor, and a cursor from another focal
  entity/direction/type fails with the existing
  `cursor_filter_mismatch` contract;
- `observed_at` is the only temporal axis of Evolution and `retrieved_at`
  remains secondary metadata; null `observed_at` rows render in an
  explicit `Observed time unavailable` group and are never positioned on
  the retrieved timestamp;
- discrete observations never imply continuous validity: ATI does not
  infer started/ended/removed/active intervals from observation gaps and
  never claims global first-observed/frequency facts from one bounded
  cursor page (only page-scoped, deterministic labels such as
  `Earliest shown on this page` are produced);
- the first-class route
  `/investigations/:id/relationships/evolution` owns the URL state
  (`entity_id` required, semantic filters, opaque cursor, `view`);
  `view=evolution|graph` switches views without losing focal entity or
  filter context, and observed-range filters stay in the URL while Graph
  (correctly) does not apply them to stable edges;
- the entry points are explicit typed internal links from the
  Relationships table/detail (source and target entities) and the
  enriched observation detail; PR 24D pivot capabilities are reused for
  Evidence/research/relationships pivots and are not distorted with
  route-only targets;
- the graph is a bounded one-hop neighborhood: one server query using the
  Relationships `entity_id` filter (source-or-target OR on the server),
  deterministic radial layout, React Flow (`@xyflow/react`) as the single
  graph library, exact Entity/Relationship IDs backing nodes/edges, no
  recursive traversal, no inference, no maliciousness scoring, no
  validity reasoning, and an always-available non-spatial edge list with
  exact navigation links;
- Evolution/Graph interactions drill into the existing PR 24C detail
  surfaces and PR 24D pivot/provenance paths. PR 24F closed the
  documented Report -> exact RelationshipObservation residual with a
  narrow Investigation-scoped exact observation GET (Section
  "RelationshipObservation query contracts") and reuses it from the
  Report/Assessment provenance references.

### Async workflow and state ownership (PR 24B)

The PR 24B Investigation workflow treats the Investigation API as a durable
asynchronous resource, never as an RPC that runs an Investigation:

```text
POST /api/v1/investigations  (Idempotency-Key, CSRF-aware client)
  -> 202 Accepted + durable Investigation identity
  -> navigate immediately to /investigations/{id}/overview
  -> GET /investigations/{id}  (bounded 2s polling while pending/running)
  -> terminal status (completed | partial | failed) stops polling
  -> pointer-gated GET .../assessments/current and .../reports/current
  -> Overview presentation (Report when present, Assessment fallback)
```

State ownership is explicit:

```text
URL                 route/tab state and list filters/cursor (never objective,
                    indicators, idempotency keys, or raw errors)
TanStack Query      server resources (list pages, detail, current Assessment,
                    current Report, Report Markdown) with opaque cursors
component state     form controls and the in-memory idempotency attempt
                    (cryptographic key retained for commit-uncertain retry —
                    transport failures and transient HTTP 5xx outcomes — and
                    replaced when the semantic payload changes or the attempt
                    is definitively settled; pre-transport CSRF failures and
                    definitive 4xx responses settle, never persisted or
                    logged; see ``frontend/src/investigations/idempotency.ts``)
backend             lifecycle, idempotency, durable current-resource pointers
```

Polling is bounded to the Investigation detail resource while non-terminal;
it stops on terminal status (never on timestamps or pointer presence), never
runs in the background, propagates AbortSignals, and never invents progress
percentages, ETAs, queue positions, or worker internals. Current Assessment
and Report are queried only through their durable pointers and the `/current`
endpoints — the browser never computes current versions from version lists.
The Overview renders the persisted Report when present, falls back to the
current Assessment otherwise, keeps Research visibly distinct from Evidence,
and renders every support reference in compact form (rich resolution belongs
to PR 24C/24D).

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

The durable worker also owns the confirmed PENDING -> RUNNING lifecycle
transition (PR 24B): the API persists PENDING, the runner executes only
RUNNING investigations, so the worker performs the short versioned
transition through the investigation repository after claiming the job and
before invoking the runner; a missing, terminal, or already-RUNNING
Investigation is a no-op.

The PR 24B `ati-worker` entrypoint adds one bounded post-run step: after a
terminal Investigation owns a current Assessment but no current Report, the
worker invokes the existing production Report Writer (PR 23B composition) and
advances the durable `report_id` pointer. Report generation stays out of the
coordinator graph (PR 23B boundary); a report failure never flips the
already-terminal Investigation — the legitimate Assessment-only state remains
visible. The worker composes the configured `LlmClient` implementation; the
deterministic driver (`ATI_LLM_DRIVER=deterministic`) selects the
repository-owned offline scripted boundary used by the real-stack fake-world
browser tests, so the full worker path (provider execution, coordinator,
runner, Evidence Analyst, Research Agent, Report Writer, persistence) runs
over real PostgreSQL with no live LLM.

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
                                       | REQUEST_RESEARCH
                                       | STOP }

Provider work path: select_work -> execute_work -> record_outcome -> coordinator
Analysis path:       analyze -> coordinator
Pivot path:          authorize_pivot -> coordinator
Research path:       research -> coordinator
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

PR 22C adds one bounded coordinator action, `REQUEST_RESEARCH`, consuming
the persisted `research_required_for_entity_ids` markers: after evidence
synchronization and before any terminal/pivot decision, the Coordinator
selects at most one due research context in deterministic candidate order,
plans a bounded contextual question through the pure
`DeterministicResearchRequestPlanner` (never an LLM), and fingerprints the
exact context with a schema-versioned SHA-256 identity. The `research` graph
node persists the `REQUEST_RESEARCH` transition plus a `RESEARCH_REQUESTED`
timeline event in one short transaction before any Research Agent I/O,
reconciles an already-persisted matching `ResearchResult` (crash recovery
never blindly repeats the model call), otherwise executes the PR 22B
Research Agent through the narrow `ResearchExecutor` seam, reloads the
authoritative Investigation (LLM accounting may have advanced its version),
and records durable COMPLETED or bounded EXHAUSTED state through
`RECORD_RESEARCH_OUTCOME`. Research executions are bounded to two
orchestration attempts per unchanged context; completion always returns to
Coordinator policy and never directly authorizes a pivot. Research remains
contextual knowledge: result identities never enter `evidence_ids` and no
Assessment is created or modified by research.

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

The report path (PR 23B delivered) is:

```text
Investigation
    |
    +--> current Assessment
    |
    +--> Evidence / RelationshipObservation / Relationship
    |
    +--> persisted ResearchResult / ResearchClaim / ResearchCitation
    |
    v
ReportWriterInputLoader        (short read transaction, then closed)
    |
    v
ReportWriterInput              (immutable, bounded, deterministic)
    |
    v
deterministic prompt  ->  Report Writer LLM  ->  ReportWriterOutput
    |
    v
build_investigation_report     (application stamping)
    |
    v
ReportProvenanceValidator      (deterministic closure before persistence)
    |
    v
InvestigationReport (Pydantic)
    |
    v
versioned PostgreSQL persistence (append + CREATE history)
    |
    +--> Investigation.report_id pointer (atomic, revalidated under lock)
    |
    +--> structured API resource [PR 23C]
    |
    +--> deterministic Markdown formatter
```

The Report Writer produces structured report content, never a finished
free-form document. The current persisted Assessment remains the sole
authority for verdict and confidence: those values are application-stamped
into the final :class:`InvestigationReport` and the model output schema
excludes them entirely. Assessment findings are snapshotted application-side
at their stable ordinals, Research context is snapshotted from persisted
ResearchClaims/Citations, and every material model-authored narrative
statement carries at least one typed reference to supplied Assessment or
Research provenance.

Key delivered components:

- :class:`ReportWriterInputLoader` — one short read-only UnitOfWork
  materializes the current Assessment (via the Investigation's durable
  ``assessment_id`` pointer), its analyzed Evidence, the
  RelationshipObservations referenced by its findings, and bounded persisted
  ResearchResults, then closes the transaction. Input collections and
  serialized bytes are independently bounded with typed errors; ``Evidence``
  is minimized through normalized facts only (never ``raw_payload``).
- :class:`ReportWriter` — the application execution service: deterministic
  prompts, existing ``LlmClient.generate_structured``, existing
  investigation-wide LLM accounting, and at most one explicit schema-repair
  attempt. LLM calls happen strictly outside database transactions.
- :class:`ReportProvenanceValidator` — deterministic closure validation
  (Assessment authority, finding closure, narrative support closure,
  research closure, caveat equality, source-set closure) before any report
  becomes authoritative. It proves reference integrity, never semantic
  entailment.
- :class:`InvestigationReportPersistenceService` — one short atomic
  transaction appends the immutable versioned report, advances the
  Investigation ``report_id`` pointer, and emits the ``REPORT_CREATE`` audit
  event. The append revalidates under the locked Investigation row that the
  report's Assessment is still current; a stale input fails atomically.
- deterministic formatter — pure presentation code rendering the validated
  structured report (Markdown in v0.1); it never calls the LLM or the
  database.

Semantic faithfulness of bounded model-authored prose is evaluated by the
repository-owned Report Writer evaluation baseline (deterministic scenarios
with stable failure codes), never by an invented heuristic fact checker or
LLM-as-judge.

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

PR 22C integrates the standalone agent into the production lifecycle as a
bounded, durable Coordinator synchronization point. The Coordinator owns
every decision: whether research runs, which marked entity is researched
next (deterministic root/discovery order, at most one context per decision),
and whether any later pivot occurs. The Research Agent remains an executor of
already-authorized work and never decides orchestration policy. Exact
research contexts are deduplicated by a deterministic, schema-versioned
fingerprint (subject, entity type/value, query, retrieval filters,
`max_results`, and the investigation anchor), so a completed or exhausted
unchanged context is never re-executed while a changed context becomes due
again. Orchestration-level attempts are bounded to two independently of the
agent's internal structured-output repair; a crash between result
persistence and completion recording is reconciled by adopting the
already-persisted matching `ResearchResult` without another model call. The
completion transition always reloads the Investigation after Research Agent
execution so PR 20B LLM accounting version increments are never overwritten.

## Evaluation view (PR 22D)

PR 22D adds a deterministic repository-owned evaluation layer that consumes
the typed outputs the production runtime already persists:

```text
production runtime
 -> persisted ResearchResult / durable timeline + InvestigationState
 -> repository-owned scenario expectations (semantic labels)
 -> deterministic evaluators (no DB/network/LLM/clock)
 -> stable failure codes + denominator-safe metrics
```

Retrieval evaluation consumes ordered `RetrievedChunk` values from the
production pgvector retriever; synthesis evaluation consumes the
repository-read-back `ResearchResult`, the exact citation IDs supplied to
the model invocation (observed at the retrieval boundary, never substituted),
and evaluation-only epistemic snapshots of Evidence / RelationshipObservation
/ Assessment identity-version sets taken immediately before and after an
isolated research interval. Nothing in the evaluation layer is invoked by
the runtime, and nothing here adds runtime fields or behavior.

Epistemic boundaries are final:

```text
Observed source facts
 -> Evidence / RelationshipObservation
 -> Evidence Analyst
 -> Assessment

Corpus knowledge
 -> DocumentChunk
 -> Research Agent
 -> ResearchResult
```

`ResearchResult` does NOT become Evidence, RelationshipObservation, or
Assessment: the PR 22D hard promotion gates prove identity/version set
unchanged across isolated research execution.

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

Within the graph, history semantics are distinct:

```text
Relationship
    stable semantic edge, historized in domain_object_history

RelationshipObservation
    immutable time-stamped historical observation, append-only,
    not duplicated into domain_object_history

domain_object_history
    state history for designated historized resources
```

### Analyst read/query path (PR 23A)

Analyst-facing data browsing is a dedicated read path, separate from the
execution-oriented persistence used by orchestration:

```text
FastAPI (/api/v1, api/)
    -> authentication/authorization (server-side cookie sessions)
    -> DTO mapping (api/dto/, api/mappers.py)
    -> PR 23A query services (app/query/ + infrastructure/persistence/query/)
    -> indexed deterministic keyset queries
    -> InvestigationSubmissionService (app/investigation_submission.py)
         -> PostgreSQL durable investigation job (migration 0024, SQL v0020)
```

Division of responsibility:

- **write repositories / orchestration persistence** own mutation, version
  allocation, history writes, and bounded internal execution reads
  (``list_for_investigation`` and similar); they are unchanged by PR 23A;
- **analyst read/query services** own bounded explicit filters, one
  canonical deterministic ordering per collection, opaque versioned keyset
  cursors, and page contracts (`QueryPage`) — never HTTP semantics, request
  DTOs, or report generation;
- query services return validated domain/read models only; raw SQLAlchemy
  rows and unvalidated dictionaries never cross the application boundary;
- historical RelationshipObservation browsing queries
  `relationship_observation` directly and never `domain_object_history`;
  generic resource-state history uses `object_type + object_id` identity;
- the HTTP layer (PR 23C) consumes these read contracts directly through a
  per-request query bundle (`app/query/services.py`); it does not invent
  SQL or query behavior, and no route imports concrete PostgreSQL
  repositories.

### API and asynchronous submission (PR 23C)

The delivered `/api/v1` boundary is FastAPI
(`src/agentic_threat_investigator/api/`), an HTTP adaptation layer only:

```text
FastAPI request (api/)
    -> request-ID/security-header middleware
    -> stable error envelope + central typed exception mapping
    -> authentication/authorization dependencies
    -> DTO parsing (extra="forbid") -> application seams
    -> PR 23A/23B query/report services for every read
    -> POST /investigations -> InvestigationSubmissionService
         -> atomically: entities + PENDING Investigation + durable job
            + audit + idempotency record (one transaction)
    -> 202 Accepted + Location
```

The API process and the worker process remain distinct: the FastAPI
lifespan composes API services only and never launches LangGraph, provider
polling, or job execution. `InvestigationJobWorker`
(`app/investigation_worker.py`) claims the durable PostgreSQL job and
invokes `InvestigationRunner` outside any transaction; the worker process
composition assembles the provider registry and LLM client from existing
infrastructure seams.

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

The Investigation Map read data (PR 25A) is a read projection derived exclusively from already-persisted immutable `GEOLOCATION` Evidence joined to its canonical IP entity: the API never opens the DB-IP MMDB, never invokes a provider, performs no network I/O, and introduces no new geolocation persistence, spatial materialization, or map-snapshot storage. One deterministic latest observation per IP entity is selected by PostgreSQL and returned as one bounded server-owned collection with explicit truncation, retaining the exact Evidence ID as provenance.

PR 25 does not require PostGIS. PR 26B introduces PostGIS for canonical geography/spatial operations; PR 26A itself remains non-spatial (see [GEOINT architecture (PR 26)](#geoint-architecture-pr-26)).

## Investigation Map frontend (PR 25B)

The Investigation Map is a pure presentation surface over the bounded PR 25A projection (`frontend/src/geolocation/`):

- one first-class `/investigations/:id/map` workspace route/tab consumes `GET /api/v1/investigations/{id}/geolocations` through the centralized API client and TanStack Query (Investigation-scoped key, no polling, no cursor/limit, no Evidence reconstruction);
- Leaflet + react-leaflet are presentation only: one neutral marker per mappable returned item, conservative deterministic viewport (fixed zoom 8 for one point, capped `fitBounds` for many), locally bundled Leaflet CSS and inlined marker assets, standard credential-free OSM raster tiles with visible attribution defined in one `map-config.ts` module;
- the map never reinterprets generic Evidence facts, never performs a geolocation lookup, never geocodes, never manufactures/clamps/centroid-substitutes missing coordinates, and derives no geographic relationship, risk, attribution, or maliciousness — markers carry no risk/confidence/severity coloring and no accuracy radius is fabricated;
- coordinate-less (null/null) and defensively malformed items never reach Leaflet and remain fully visible in an always-available non-map table of every returned item; mixed and truncated states are stated honestly, and the server-owned bound is never bypassed;
- exact Evidence provenance is retained: marker popups and non-map rows both open the shared PR 24C DetailDrawer/EvidenceDetail surface through the exact persisted PR 25A `evidence_id` (no lookup by IP, no list scan, no History substitution);
- a persistent visible disclaimer states that IP geolocation is approximate network-address context and does not establish the physical location of an attacker, user, or device; observed/retrieved timestamps stay distinct.

There is no map-time geolocation lookup, no spatial query, no PostGIS, no clustering/heat map/polygon, no cross-Investigation map, no historical movement, and no map state persisted in the URL, localStorage, or sessionStorage (the Map route's URL state is only the route itself).

## Map analyst workflow and E2E seeding (PR 25C)

PR 25C completes the Map as a bounded analyst exploration surface without turning geography into an inference engine:

- **typed entity pivots from the Map (PR 25C):** every returned Map item — marker popup and non-map row alike — exposes the exact persisted PR 25A `evidence_id` through the existing detail drawer **and** an Explore surface that reuses the PR 24 typed pivot capabilities via the exact `entityActions(item.entity_id, item.ip_address, "map_entity")` registry (`frontend/src/geolocation/GeolocationEntityActions.tsx`). The single new `map_entity` source kind is navigation provenance only: the target resources are the unchanged `evidence`/`relationships`/`research` workspaces with their existing server-backed filters (Evidence by exact subject, Relationships by source and by target as two independent actions, Research by exact subject). The first Map-origin breadcrumb label is the IP display value, never city/country/coordinates; the PivotWorkspace constraint set (typed resources, allowlisted filters, UUID/timestamp validation, bounded labels/cursors, URL serialization, no-op suppression, dead-end behavior, max depth 5, close/back) is untouched, and no Leaflet viewport/marker/popup state enters the pivot URL. Same-coordinate items remain individually inspectable through the accessible non-map rows with no jitter, clustering, or co-location/coordination inference; coordinate-less items stay fully actionable without a marker; empty projections stay honestly empty.
- **deterministic E2E seeding seam (PR 25C):** `tests/e2e_support/seed_geolocation.py` is harness-only test infrastructure. It materializes ordinary canonical IP Entities and immutable `GEOLOCATION` Evidence into the throwaway isolated E2E PostgreSQL through the normal application repositories/UnitOfWork (`investigations.get_by_id`, `entities.upsert`, `evidence.insert`) for an exact browser-created Investigation UUID and an allowlisted scenario name (`single_mappable`, `multi_ioc`, `non_mappable`, `same_location`). It is deterministic (uuid5-derived identities, fixed UTC retrieval epoch), idempotent/bounded (repeated invocation reuses the persisted rows), offline and non-LLM, and fail-closed unless both `ATI_OPERATING_MODE=fake` and the dedicated `ATI_E2E_SEEDING_ENABLED` flag are present. There is no seed HTTP endpoint, no browser database credential, and no product fake-world/DB-IP catalog change; production reads remain exclusively the PR 25A projection through the real `/geolocations` endpoint.

## GEOINT architecture (PR 26)

This section distinguishes **delivered PR 26A/26B/26C/26D** from the planned PR
26E-G architecture.

PR 25 remains the delivered v0.1 geolocation presentation path:

```text
DB-IP provider
  -> persisted GEOLOCATION Evidence
  -> bounded Investigation geolocation projection
  -> Investigation Map
```

PR 26A (delivered) establishes the non-spatial GEOINT persistence
foundation:

```text
Location / EntityLocation / EntityLocationObservation / GeoResolution
        delivered persistence foundation
```

PR 26A delivers:

- `Location` as canonical geographic/reference identity (country,
  administrative area, city) with a deterministic database-enforced
  canonical identity tuple and no geometry;
- immutable append-only `EntityLocationObservation` with exact Entity +
  Location + Evidence provenance;
- database-maintained current `EntityLocation` with deterministic
  reconciliation (`COALESCE(observed_at, retrieved_at)`, observation UUID
  tie-break);
- `GeoResolution` durable operational work with initial PENDING persistence
  only;
- the versioned SQL API v0021 stored functions, thin repositories, and
  UnitOfWork integration;
- no PostGIS, no resolver, no claim/lease/retry, no GEOINT API, and no
  agentic reasoning.

PR 26B (delivered) establishes the deterministic geographic substrate on
that foundation; PR 26B-2 (corrective completion) adds the upstream
reference-data supply path that produces the corpus:

PR 26C (delivered) adds the asynchronous geographic-resolution lifecycle on
the same `GeoResolution` work rows: bounded claim/lease with `FOR UPDATE
SKIP LOCKED`, deterministic attempt/backoff bookkeeping, stale-worker
protection, atomic resolved completion (observation + current-state
reconciliation + terminal transition in one stored function), and a
separate `ati-geo-resolver` process/container. The lifecycle adds no broker,
no second queue table, and no query API.

```text
GeoNames local files       Natural Earth local files
(operator-supplied)        (operator-supplied, GeoJSON)
        |                           |
        v                           v
 GeoNamesReferenceSource      NaturalEarthReferenceSource
 (source-specific adapters; normalized records only; never write PostgreSQL)
        |                           |
        +--------------+------------+
                       |
                       v
              GeographyCorpusBuilder (PR 26B-2)
              deterministic joins, hierarchy, ordering,
              geometry validation; emits source-neutral records
                       |
                       v  ati-geography-build writes the ATI Geography Corpus NDJSON
                 ati-geography-import (CLI)
                       |
                       v  ReferenceIngestionService (validated, ordered)
                ati.upsert_reference_location (SQL API v0023)
                       |
                       v
        +-------------------------------------------+
        |  ati.location                              |
        |  canonical identity (unchanged from 26A)   |
        |  reference hierarchy (parent_location_id)  |
        |  geometry       (SRID 4326, never geography)|
        |  centroid       (on-surface representative) |
        +-------------------------------------------+
                       |
 geographic claim ------+
        |
        v  CanonicalGeographyResolver (PR 26B primitive)
        +--> RESOLVED(location, supported precision)
        +--> AMBIGUOUS(candidates)
        +--> UNRESOLVABLE(reason code)
```

The deliberate boundary (PR 26B-2): the source-specific adapters
(`infrastructure/geoint/geonames.py`, `infrastructure/geoint/natural_earth.py`)
turn upstream files into normalized source records; `GeographyCorpusBuilder`
(`infrastructure/geoint/geography_corpus_builder.py`) joins them into the
source-neutral ATI Geography Corpus; the canonical Location ingestion
(`ReferenceIngestionService` + `ati.upsert_reference_location`) consumes only
that corpus. GeoNames/Natural Earth fields never leak into `Location`,
`GeographicClaim`, canonical identity, resolution results,
`EntityLocation`, or `GeoResolution`, and corpus construction never writes
PostgreSQL.

Key PR 26B properties: PostGIS is installed through the normal
migration/deployment path (the project-owned PostgreSQL 18 image ships both
pgvector and PostGIS); canonical identity stays the PR 26A tuple and is
never rebuilt by geometry or source identifiers; reference identity is a
deterministic UUIDv5; repeated unchanged ingestion is a true no-op;
approved reference/spatial refreshes enrich the same canonical row with a
database-issued version; and hierarchy (reference parentage) and spatial
containment (PostGIS predicates) remain explicitly distinct. No threat
relationship, maliciousness, attribution, or analytical conclusion is ever
inferred from spatial facts.

PR 26 adds a richer, derived GEOINT subsystem without replacing that path:

```text
Persisted Evidence / geographic claim
        |
        v
   GeoResolution
 durable operational work/state
        |
        | short stored-function claim transaction        (PR 26C)
        | lease persisted; transaction committed
        v
 Geo Resolver process
 (no database locks held while resolving)
        |
        v
 canonical Location resolution
 PostgreSQL + PostGIS                                       (PR 26B)
        |
        +--> EntityLocationObservation
        |    immutable historical/provenance observation
        |
        +--> EntityLocation
             current materialized association
```

### Geographic domain separation

`Location` is not an ATI `Entity`. Geographic containment and hierarchy are not modeled as ordinary `Relationship` / `RelationshipObservation` records.

The initial canonical Location vocabulary is deliberately bounded to:

- country;
- administrative area;
- city.

`Location.parent_location_id` represents canonical/reference hierarchy. PostGIS spatial predicates represent geometric containment/intersection. These are distinct semantics.

`EntityLocationObservation` is immutable and append-only. It explicitly preserves the Entity, exact canonical Location resolved/claimed at that time, supporting Evidence/provenance, precision, and relevant observation/retrieval/resolution timestamps. Historical location observations do not inherit their Location through mutable current state.

`EntityLocation` is the current materialized association, maintained by the database from observations under the deterministic ordering `(COALESCE(observed_at, retrieved_at), observation_id)`. It references the most specific canonical Location actually supported by the underlying claim. Canonicalization must never manufacture additional precision.

`GeoResolution` is mutable operational state, not geographic evidence. PR 26C delivers the full asynchronous lifecycle on top of the PR 26A initial PENDING row: processing, resolved, unresolvable, and failed transitions with attempts, bounded leases/claims, retry scheduling, terminal replay protection, and versioned mutations — all database-owned through SQL API v0024.

`GeoResolution` is operational work; the geographic truth it produces lives only in the immutable `EntityLocationObservation` history and the database-maintained `EntityLocation` current state. A work row never becomes geographic evidence, and no geography-derived threat Relationship is ever created.

### PostgreSQL ownership and asynchronous resolution

PR 26A/26B deliver the database-ownership model for GEOINT persistence:

> All PR 26A/26B/26C GEOINT mutations, current-state reconciliation, and versioning are performed through versioned PostgreSQL stored functions (SQL API v0021/v0022; the PR 26B canonical reference/spatial path is SQL API v0023; the PR 26C asynchronous lifecycle is SQL API v0024). Python repositories/processes remain thin callers.

Purpose-built bounded read/query services, including PostGIS spatial projections, may execute SQL directly under ATI's existing query-service pattern.

The Geo Resolver executes PR 26C's committed work-lifecycle transaction split:

```text
claim bounded work  -> ati.claim_geo_resolutions (FOR UPDATE SKIP LOCKED
                       internally, bounded) -> own claimant/lease/attempt
                       -> COMMIT
resolve geographic claim       (no database transaction or row lock held)
complete outcome    -> ati.complete_geo_resolution_resolved (observation +
                       current-state reconciliation + RESOLVED termination
                       in ONE atomic stored function) / unresolvable /
                       failure with bounded backoff  -> COMMIT
```

```text
claim:  ati.claim_geo_resolutions(claimed_by, limit, lease, max_attempts)
  -> bounded eligible rows (PENDING due now / expired PROCESSING)
  -> FOR UPDATE SKIP LOCKED internally; deterministic ordering
     (eligibility time, created_at, id)
  -> persist worker/lease/attempt +1 state, fresh DB version
  -> COMMIT

resolve geographic claim
  -> no database transaction or row lock held

complete: one of ati.complete_geo_resolution_resolved |
               ati.complete_geo_resolution_unresolvable |
               ati.record_geo_resolution_failure
  -> validate ownership/version/live lease (+ exact provenance for RESOLVED)
  -> RESOLVED: append EntityLocationObservation + reconcile EntityLocation
     + transition GeoResolution in ONE atomic stored function
  -> COMMIT
```

Leases coordinate asynchronous processing; long-held row locks do not.
Expired claims are recoverable under a new claimant; stale workers are
rejected by version/claimant/lease validation and never create observations.
Completion/reconciliation uses deterministic update ordering where records
may contend.

### PostGIS responsibility

PR 26B is the point at which PostGIS becomes part of the v0.1 architecture
(delivered): the supported PostgreSQL 18 runtime contains both pgvector and
PostGIS, the migration installs the extension, and canonical reference
spatial state is persisted as SRID-4326 PostGIS `geometry` (never
`geography`).

PostGIS may answer deterministic spatial questions such as containment,
intersection, distance, proximity, and bounding-box queries. It does not
infer threat semantics.

Spatial facts never by themselves establish:

- maliciousness;
- common ownership;
- cyber relationships;
- campaign association;
- coordination;
- targeting;
- attribution.

The PR 26B deterministic resolver (`CanonicalGeographyResolver`, a boundary
for PR 26C's asynchronous `LocationResolver`) narrows semantically first
(country code -> administrative code/name -> city name) and uses PostGIS
containment only as a deterministic disambiguation signal among equally
valued candidates. Coordinates never upgrade claim precision, and there is
no nearest-city or fuzzy geocoding. Resolved/ambiguous/unresolvable are
first-class results, and malformed claims remain errors.

### GEOINT query and analyst layers

Canonical `Location` is global reference data, but analyst operational reads remain bounded and Investigation-scoped.

PR 26D (delivered) establishes the bounded analyst-facing GEOINT read and
API layer over the PR 26A-26C persistence:

```text
PostgresQueryServices (one per-request AsyncSession, PR 23A bundle)
  -> GeointQueryService
     -> PostgresGeointQueryService
        -> purpose-built literal SELECT/PostGIS statements (read-only)
  -> /api/v1/investigations/{I}/geoint/* FastAPI router (AnalystUser)
```

- **Exact Evidence scope join.** Every analyst GEOINT read proves the path
  Investigation through the immutable provenance chain
  `EntityLocationObservation.evidence_id -> Evidence.investigation_id`;
  scope is never inferred from shared Entity or Location identity. The
  read layer executes purpose-built bounded SELECT statements directly in
  the existing query infrastructure; mutations remain 100% PR 26A-26C
  stored-function-owned.
- **Investigation-relative current.** Entity current
  (`GeointEntityLocationItem.current_observation`) is the newest
  qualifying observation **within the path Investigation** under the exact
  PR 26A currentness ordering
  (`COALESCE(observed_at, retrieved_at)` descending, observation UUID
  descending, greater pair wins). The global materialized
  `EntityLocation` row may have been advanced by another Investigation
  and is therefore never exposed as scoped current unless its exact latest
  observation is proven scoped.
- **Location reverse lookup and containment.** Location -> scoped
  Entities/observations page deterministically
  (`(entity_type, canonical_value, entity_id)` for Entities; the PR 26A
  effective-time ordering for observations). `include_contained=true`
  selects the exact canonical Location plus child canonical Locations
  whose SRID-4326 reference geometry the selected boundary covers
  (boundary-inclusive `ST_Covers` with a GiST bounding-box pre-filter).
  City Points never expand, NULL boundary geometry degrades to the exact
  selection (honestly reported via `containment_applied`), and there is no
  radius/nearest/proximity API and no arbitrary PostGIS input contract.
- **Shared boundedness.** Page sizes reuse the PR 23A `QueryLimits`;
  collections reuse the opaque versioned cursor codec with cursors bound
  to the exact query scope (investigation, Entity/Location, containment
  flag); the summary carries a server-owned `top_locations` bound.
  Read models expose only approved fields and the centroid
  latitude/longitude pair; raw EWKT/WKB geometry and provider payloads
  never cross the boundary.

The application query layer owns bounded geographic projections such as:

- current and historical Locations for an Entity;
- Investigation-scoped Entities/observations for a Location;
- exact EntityLocationObservation provenance with exact Evidence drill-down;
- bounded geographic summaries;
- narrowly justified containment reads.

The PR 24 typed pivot/workspace architecture remains the navigation model. PR 26 extends it with semantically valid geographic pivots rather than creating a parallel navigation system.

### Agentic GEOINT

PR 26F introduces agentic reasoning only after deterministic geographic primitives exist. Agents receive bounded GEOINT tools; they do not issue arbitrary SQL/PostGIS, canonicalize Locations, or own persistence reconciliation.

Potential deterministic tools include:

- geographic summary;
- locations for entity;
- entities in location;
- geographic history for entity;
- narrowly bounded nearby/within queries.

Agent output must preserve exact geographic observation/Evidence support. Common geography or proximity remains contextual unless independent Evidence supports a stronger analytical conclusion.

### v0.1 persistence taxonomy update

With PR 26A/26B delivered, the persistence categories are:

- immutable observations: Evidence, RelationshipObservation, **EntityLocationObservation**, AuditEvent, InvestigationTimelineEvent;
- stable/reference identities: Entity, Relationship, **Location** (with optional canonical spatial state since PR 26B);
- current materialized geographic state: **EntityLocation**;
- mutable operational state: Investigation, jobs, users/sessions, **GeoResolution**;
- versioned outputs: Assessment, InvestigationReport;
- replaceable derived indexing: document chunks/embeddings.

`GeoResolution` is durable operational work state in every PR 26A-C
release: PR 26A persists the initial PENDING row, and PR 26C (delivered)
owner of claim/lease/retry/completion lifecycle transitions through SQL API
v0024 stored functions. The application never issues ad-hoc lifecycle DML.

Monitor is no longer a v0.1 persistence requirement. Monitor/scheduler/snapshots/diffs/Findings administration is deferred to v0.2 and tracked in `PR_PLAN_V02.md`.

### Fake runtime and GEOINT

The deterministic fake runtime continues to replace external/non-deterministic intelligence boundaries, not ATI's production application/persistence architecture.

For PR 26, fake GEOINT data should enter as normal deterministic persisted geographic Evidence/claims and then flow through the real PR 26 resolution pipeline:

```text
fake deterministic source data
  -> normal GEOLOCATION Evidence
  -> GeoResolution
  -> real asynchronous Geo Resolver
  -> real canonicalization/PostGIS
  -> Location
  -> EntityLocationObservation
  -> EntityLocation
```

The fake bootstrap must not directly manufacture `Location`, `EntityLocation`, or `EntityLocationObservation` merely to make GEOINT demos pass.

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

## Intelligence-source operating mode (PR 23D)

`ATI_OPERATING_MODE` selects the intelligence-source implementations composed at bootstrap; it never selects the LLM, embeddings, persistence, dispatcher, runner, coordinator policy, report implementation, or API behavior. The mode branch exists only at the bootstrap/composition boundary
(`infrastructure/intelligence_composition.py`):

```text
                         ATI_OPERATING_MODE
                                |
                  +-------------+-------------+
                  |                           |
                fake                     production
                  |                           |
       fake/local intelligence       real intelligence
       source composition            source composition
                  |                           |
                  +-------------+-------------+
                                |
                     existing provider registry
                                |
                     production ATI execution
```

Both branches yield the same existing contracts, above all the `SourceId`-keyed provider registry consumed by the production investigation graph/runner. The Coordinator, graph nodes, `ProviderWorkExecutor`, persistence services, API routers, domain models, and report code are mode-unaware; the composition seam is the single place that knows the mode.

Fake mode fakes the **external intelligence world**, not ATI's architecture:

- deterministic fake live providers implement the existing `EvidenceProvider` contract, preserve the exact `SourceId` identity and `supports(Entity)` applicability, use no HTTP transport, and require no provider secret;
- the versioned synthetic world (`infrastructure/fake_runtime/data/v1/`) models one shared deterministic threat-intelligence world; named scenarios are stable entry points into that world;
- packaged batch fixtures are parsed by the existing production `BatchSource` parsers and persisted through the normal batch persistence path by the explicit idempotent `ati-fake-data-bootstrap` command;
- fake mode never falls back to real intelligence sources and production mode never falls back to fake sources.

Fake evidence is produced through the same normalized fact vocabulary and the same deterministic extractors as real provider evidence. Because the production outcome-provenance stored function requires every newly discovered entity to be backed by a `RelationshipObservation` from this provider outcome, the fake world exercises relationship-backed discovery shapes (DNS A/CNAME/MX/NS, ThreatFox `ASSOCIATED_WITH`, RDAP `BELONGS_TO`) in canonical investigation paths; sources whose discoveries carry no relationship assertion (DNS PTR targets, IPinfo ASN facts, URLhaus URL/host matches) are composed but return deterministic no-results. This is fixture design within the existing production contracts — the production parser/extractor/executor/coordination/stored-function behavior is unchanged.

Runtime `fake` mode uses the configured real `LlmClient`; automated tests inject `FakeLlmClient` at the model boundary independently of operating mode so CI stays deterministic and offline.

`GET /api/v1/runtime` exposes the selected mode (``fake``/``production``) so the future frontend can display a persistent `FAKE DATA` indicator without hard-coding deployment knowledge. The endpoint exposes mode only: never credentials, secret reference names, LLM providers, database URLs, filesystem paths, or the effective configuration.

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
