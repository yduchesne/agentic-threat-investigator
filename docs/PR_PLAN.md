# ATI — PR Plan Update

This update assumes PR 19A and PR 19B are merged and inserts PR 19C before the split PR 20 work.

## PR 19A — Investigation orchestration state and deterministic LangGraph skeleton [DONE]

Established typed provider work, deterministic queue mechanics, operational state/outcomes, injected `WorkExecutor`, serializable LangGraph state, and deterministic execution/termination.

## PR 19B — Provider execution integration and persisted workflow timeline [DONE]

Integrated the orchestration skeleton with real EvidenceProvider execution, PR 18B extraction, PR 18C persistence, provider/result and investigation binding validation, timeline persistence, production composition, and PostgreSQL + synthetic-HTTP vertical-slice coverage.

`ProviderWorkExecutor` remains the component that performs provider work.

## PR 19C — Investigation task dispatcher abstraction [DONE]

Introduce an explicit application-layer dispatch boundary between orchestration and execution without introducing distributed infrastructure.

```text
Coordinator / LangGraph
    decides WHAT authorized work runs
             ↓
TaskDispatcher
    determines HOW/WHERE selected work is handed to execution
             ↓
LocalTaskDispatcher
    dispatches in-process in v0.1
             ↓
WorkExecutor
    performs selected work
```

Deliver:

- `TaskDispatcher` as an `abc.ABC`;
- `LocalTaskDispatcher`;
- preservation of the existing `WorkExecutor` contract;
- LangGraph execution through `TaskDispatcher` rather than directly through `WorkExecutor`;
- preservation of PR 19B investigation binding across the dispatcher;
- production composition wrapping `ProviderWorkExecutor` with `LocalTaskDispatcher`;
- deterministic dispatcher fakes/tests;
- unchanged PR 19B provider-pipeline behavior and vertical-slice results;
- documentation of orchestration/dispatch/execution responsibilities.

`TaskDispatcher` owns routing/execution-location semantics. `WorkExecutor` owns concrete execution semantics. In PR 19C, routing is deliberately trivial: `LocalTaskDispatcher` delegates the already-selected work exactly once to its injected executor in the same process.

PR 19C must preserve FIFO selection, duplicate suppression, provider-call accounting, investigation isolation, provider binding/applicability validation, PR 18B/18C ownership, timeline behavior, cancellation, safe errors, and all current durable results.

PR 19C does **not** introduce NATS, JetStream, Kafka, Redis, broker subjects/topics, ACK/NACK, delivery attempts, broker retry/redelivery, task serialization envelopes, distributed workers, remote execution, worker discovery, load balancing, priorities, durable dispatch queues, LLM execution, Evidence Analyst behavior, or adaptive pivots.

A future `DistributedTaskDispatcher` may replace `LocalTaskDispatcher` without requiring Coordinator/LangGraph code to know transport details. Distributed dispatch is not a v0.1 requirement.

## PR 20A — Assessment model and provenance validation [DONE]

Deliver the deterministic analytical domain/persistence foundation:

- typed `Assessment`;
- `AnalyticalFinding`;
- bounded `FindingCategory`;
- `EvidenceSupport`;
- `RelationshipSupport`;
- deterministic provenance validation;
- Assessment persistence/versioning;
- state update only after successful validated persistence;
- deterministic unit/PostgreSQL tests.

Direct fact provenance:

```text
Finding -> Evidence -> normalized facts
```

Graph provenance:

```text
Finding
 -> RelationshipObservation
      -> Evidence
      -> Relationship
           -> source Entity
           -> target Entity
```

Graph-backed Findings cite `RelationshipObservation`, not a bare Relationship or redundant Evidence+Relationship pair. Evidence may validly support zero Relationships.

No LLM is introduced in PR 20A.

## PR 20B — Evidence Analyst LLM execution [DONE]

Delivered `LlmClient` `abc.ABC`, the LangChain structured-output adapter,
`FakeLlmClient`, typed analyst input, structured Pydantic output, PR 20A
provenance validation/persistence integration, durable LLM-budget
accounting, safe failure behavior, and deterministic fake-LLM unit and
real-PostgreSQL integration coverage.

Deliver `LlmClient` `abc.ABC`, LangChain adapter, `FakeLlmClient`, typed analyst input, structured Pydantic output, PR 20A provenance validation/persistence integration, safe failure behavior, and deterministic fake-LLM tests.

The Evidence Analyst does not collect Evidence, mutate graph objects, decide pivots, invoke PR 22 RAG, or generate reports.

Execution must respect the PR 19C dispatch boundary; do not broaden PR 19C into distributed execution.

## PR 20C — Evidence Analyst evaluation baseline [DONE]

Delivered a narrow, repository-owned, deterministic evaluation baseline for the
Evidence Analyst. PR 20C answers one question about a persisted `Assessment`
produced through the unchanged PR 20B execution path: *was the analyst's
persisted analytical decision acceptable for a known scenario?*

Deliverables:

- `AnalystScenario` DTOs (fixture + `ExpectedAssessment` envelope) under
  `src/agentic_threat_investigator/evaluation/analyst/`;
- deterministic `EvidenceAnalystEvaluator` consuming only persisted
  Assessments with stable bounded failure codes and denominator-safe metrics;
- strict scenario loading (`evals/scenarios/analyst/*.json`) with semantic
  labels resolved to exact persisted UUIDs through
  `AnalystScenarioResolution`;
- deterministic fixture materialization through the application `UnitOfWork`
  seam (`AnalystScenarioMaterializer`);
- 8 repository-owned core scenarios covering direct Evidence support,
  RelationshipObservation support, no-hit-not-BENIGN, cloud-ASN-not-BENIGN,
  shared-ASN-not-MALICIOUS, city/country-contextual-only, conflicting-provider
  contradiction handling, and stale-evidence limitations;
- FakeLlmClient-driven real-PostgreSQL vertical slices proving both the
  passing canonical path and that a structurally valid Assessment can fail
  behavioral evaluation;
- unit coverage of every failure code, model/scenario validation, loader
  fail-closed behavior, deterministic ordering, and label resolution;
- `EVALUATION.md`/`TESTING.md` updates describing the delivered slice.

PR 20C deliberately does **not** implement the generic evaluator platform,
LLM-as-judge evaluation, LangSmith execution, trajectory/pivot/stopping
evaluation, RAG evaluation, or release thresholds. Those remain future
architecture (PR 27) scope; this PR leaves extension seams only.

## PR 21 — Adaptive pivots and stopping [DONE]

Delivered the deterministic coordinator policy, typed traversal state
(first-discovery order, minimum depth, and best investigated depth), the
coordinator-driven production graph, transition-kind-bounded PostgreSQL
persistence with mandatory optimistic concurrency, required typed analyst
disposition persisted as one coherent Investigation transition, durable
provider selection/outcomes, bounded pivot lifecycle, enabled-provider
planning, structured coordinator timeline actions, and the strict
13-scenario coordinator trajectory baseline. Canonical PostgreSQL and layered
scenario trajectories execute offline with measured transition bounds; QA and
PostgreSQL integration gates pass.

**Key deliverables:**
- `CoordinatorPolicy` (`app/orchestration/coordinator.py`): pure deterministic application-layer policy deciding pivot eligibility, depth/budget enforcement, duplicate/cycle suppression, stop reason precedence, and replan semantics.
- `CoordinatorPolicyContext`: read-only entity view and current assessment snapshot materialized from a short UoW before policy execution.
- `RegistryProviderWorkPlanner`: deterministic provider-work planning over enabled providers using each provider's exact persisted entity applicability, with `MappingProviderWorkPlanner` retained for tests.
- `AnalysisExecutor` ABC + `FakeAnalysisExecutor`: typed seam between LangGraph and the PR 20B Evidence Analyst.
- `CoordinatorDecision`: bounded decision (EXECUTE_PROVIDER_WORK, REQUEST_ANALYSIS, AUTHORIZE_PIVOT, STOP) with typed work/pivot/research lists.
- Extended LangGraph topology: coordinator-driven flow replacing queue-exhaustion->END with coordinator->{pivot|analyze|stop} routing.
- New `InvestigationTimelineEventType` values: `PIVOT_ENQUEUED`, `PIVOT_EXECUTED`, `PIVOT_SKIPPED`, `ASSESSMENT_REQUESTED`, `INVESTIGATION_STOPPED`.
- `InvestigationState.analyzed_evidence_ids` and `analysis_disposition` fields for unchanged-evidence guard and disposition tracking.
- `authorize_pivot`, `record_analysis`, `finalize_stop_state` helpers in orchestration models.
- `CoordinatorTrajectoryEvaluator`, `CoordinatorScenario`, and `CoordinatorEvaluationResult` in `evaluation/coordinator.py` with deterministic metrics and hard-gate failure codes.
- `EntityTraversalState`: typed discovery metadata (first-discovery ordinal + minimum depth) with coherence validators.
- `CoordinatorPolicyContextLoader`, `CoordinatorTransitionService`, and `EvidenceAnalystAnalysisExecutor` application services.
- `ati.update_investigation_coordinator_state` stored function (migration 0016) for atomic coordinator transitions with version/history and database-owned `completed_at`.
- Production composition injects the coordinator policy, planner, context loader, transition service, status writer, and analysis executor; the legacy queue-exhaustion graph is available only through the explicitly named `build_legacy_investigation_graph` test helper.
- Unit tests cover eligibility, budgets, duplicate suppression, stop reasons, replan semantics, analysis requests, deterministic ordering, traversal coherence, timeline event shapes, and evaluator failure codes.

**Non-goals preserved:** no LLM-based coordinator, no RAG, no generic task bus, no PR 27 evaluator platform, no dispatch policy, no invented entities.

PR 21 consumes PR 19A queue/state mechanics, PR 19B provider execution, PR 19C dispatch, and PR 20A/20B validated analytical output. PR 20C provides the analyst evaluation baseline.

The dispatcher does not decide investigative policy; it dispatches only work already selected/authorized by orchestration.

### PR 21 completion follow-ups

PR 21 stays `[DONE]`; its delivered state on `main` includes the following
follow-up PRs, which closed the remaining hardening gaps without introducing
new v0.1 feature phases:

- **PR 21B** — admitted-entity budget semantics (exact-capacity pivots of
  already-admitted entities remain legal; only overflow discoveries are
  rejected), investigated-state timing, and fail-closed traversal-metadata
  validation.
- **PR 21C / 21C2** — the production `LocalInvestigationRunner` application
  seam: authoritative load through a short UnitOfWork, graph execution
  outside any enclosing transaction, and an authoritative durable reload as
  the runner result; canonical PostgreSQL execution through the production
  graph; terminal idempotency; investigation binding/isolation; and typed
  malformed-graph-output handling.
- **PR 21D** — the independent per-scenario pivot-policy oracle
  (`allowed_pivots` with semantic entity labels and exact depths),
  evaluator metric hardening (unique-identity policy-invalid counting,
  illegal enqueue detection even when never executed, bounded
  `invalid_pivot_rate`/`policy_invalid_pivot_rate`), and documentation
  reconciliation (`EVALUATION.md`, `TESTING.md`).

PR 22 remains the next feature PR (Threat Research / RAG); PR 27 generic
evaluation-platform scope is not absorbed into PR 21.

## PR 22 — Threat Research / RAG

Deliver investigation-time contextual research as four bounded follow-up PRs. The split preserves ATI's epistemic separation between observed Evidence, retrieved knowledge, research synthesis, and analytical Assessment while keeping each implementation PR narrow enough for deterministic review and testing.

```text
EvidenceProvider
    -> observes investigation facts
    -> Evidence / RelationshipObservation

Research retrieval
    -> retrieves contextual knowledge
    -> DocumentChunk

Research Agent
    -> synthesizes cited contextual claims
    -> persisted structured research result

Evidence Analyst
    -> evaluates investigation evidence
    -> Assessment
```

RAG supplies contextual research, not live IOC facts. Retrieved or synthesized research must not become `Evidence` merely because it was retrieved during an Investigation. The Research Agent does not own verdict/confidence or other Assessment semantics.

### Source realism and deterministic testing

PR 22 production capability targets **real upstream research sources and real production adapters**. Automated tests must not replace those production contracts with invented source formats.

The testing rule is:

```text
Production:
real corpus adapter
    -> real upstream format
    -> real ingestion/chunking/indexing code
    -> PostgreSQL + pgvector
    -> real retrieval implementation
    -> real LLM adapter when configured

Automated tests:
deterministic local fixtures captured/derived from the real upstream format
    -> same production parser/normalizer
    -> same persistence/indexing path
    -> same PostgreSQL + pgvector retrieval path where under test
    -> FakeLlmClient only at the LLM boundary
```

Tests must remain offline and reproducible. They may use small checked-in fixture subsets of MITRE ATT&CK/CISA or synthetic records that conform exactly to the production source contract, but must not introduce a separate "fake source" architecture that bypasses the production parser, repository, indexing, retrieval, or orchestration path being tested. Live Internet access and live LLM calls are not required by CI/integration tests.

### PR 22A — Research storage, corpus ingestion, and retrieval foundation [DONE]

Delivered the deterministic, non-LLM Threat Research/RAG foundation:

- deterministic stable chunk citation identity (`DocumentChunk.citation_id`),
  distinct from the replaceable row identity and embedding identity, computed
  in the pure domain layer and uniquely persisted in PostgreSQL;
- pgvector retrieval provenance extended with citation ID, source-record ID,
  document type, and chunk sequence;
- immutable append-only `ResearchResult`/`ResearchClaim`/`ResearchCitation`
  domain contracts with deterministic citation closure, the `ResearchResultRepository`
  ABC, a PostgreSQL implementation (one immutable root row with typed JSONB
  snapshots), `UnitOfWork` exposure, and a narrow persistence service;
- controlled re-embedding: unchanged Documents re-index only when their
  current chunk set is missing or incompatible with the active embedding
  identity, while pure re-embedding preserves citation identities;
- production semantic embedding adapter (`LangChainEmbeddingClient` wrapping
  the installed LangChain/OpenAI async interface, plus `build_openai_embedding_client`)
  with count/ordinal/dimension/finite validation and a secret-reference config
  seam, while `HashingEmbeddingClient` remains available for deterministic
  offline tests;
- canonical real-format vertical slice: a deterministic local STIX 2.1 fixture
  drives the production `MitreAttackBatchSource` parser, `MitreAttackDocumentBuilder`,
  `DocumentIndexingService`, PostgreSQL persistence, and `PgVectorResearchRetriever`
  offline, proving ingestion, provenance, idempotency, and embedding migration.

PR 22A reuses the existing PR 11 document/RAG abstractions and the existing
MITRE ATT&CK source/document architecture; it adds no Research Agent LLM,
Coordinator/graph behavior, `research_requested` action, Evidence/Assessment
change, report generation, or generic evaluation framework.

**Deliver:**
- finalize the research persistence/domain contracts, including the exact lifecycle and provenance semantics for persisted research results/claims;
- `Document` / `DocumentChunk` storage and stable chunk identifiers suitable for citations;
- embedding/index persistence using PostgreSQL + pgvector behind repository/application abstractions;
- an application-layer retrieval contract using `abc.ABC`, keeping agents and LangGraph independent of pgvector/LangChain storage details;
- deterministic semantic retrieval with explicit filtering, result limits, and stable provenance;
- corpus ingestion/indexing kept separate from investigation-time retrieval;
- one canonical initial free corpus source, preferably MITRE ATT&CK, implemented against its real upstream representation and sufficient to prove the complete ingestion -> chunking -> embedding -> retrieval path;
- deterministic local source fixtures representing that real upstream format for offline tests;
- deterministic unit and PostgreSQL integration tests that exercise the production parser/normalizer and persistence/retrieval path for ingestion, indexing, provenance, idempotency, and no-result behavior.

**Boundaries:**
- no LLM Research Agent;
- no Coordinator/LangGraph research execution;
- no `research_requested` timeline action;
- no Assessment changes;
- no generic evaluation framework;
- no requirement to ingest every planned CISA/ATT&CK source in this PR;
- no test-only source implementation that substitutes a different contract for the production corpus adapter.

The PR must prove that real-format contextual knowledge can be ingested and retrieved through stable application contracts without an LLM or investigation orchestration.

### PR 22B — Structured Research Agent [DONE]

Delivered the standalone structured Threat Research / Context Agent on the PR 22A retrieval and persistence foundation, without modifying Coordinator routing:

- immutable bounded `ResearchAgentRequest` (investigation, subject entity, normalized query, retrieval-context filters, `max_results` 1..100) and semantic-only `ResearchAgentClaim`/`ResearchAgentDecision` LLM output contracts in `domain/research_agent.py`, with `extra="forbid"`, trimmed/deduplicated filters, and no persistence-owned/verdict/confidence/pivot/tool fields;
- deterministic prompt construction (`app/research_agent/prompts.py`, `urn:ati:llm:research_synthesis`) treating retrieved chunk content as untrusted data, with at most one bounded schema-repair attempt;
- standalone execution service (`app/research_agent/agent.py`): one bounded retrieval pass, citation-membership validation against the exact supplied chunk set (fail-closed `ResearchAgentCitationError`, no post-hoc chunk loading), application-stamped result/claim UUIDs and UTC clock, deterministic first-use durable citation snapshots via `research_citation_from_retrieved_chunk`, and persistence through the existing `ResearchResultPersistenceService`;
- LLM accounting reuses the investigation-wide `LlmAccountingService`: exactly one durable reservation per actual model invocation, zero reservations for no-context/prompt-build failures, versions chained across a repair attempt, reservation retained when the call fails or is cancelled;
- deterministic outcomes: empty retrieval short-circuits to a persisted zero-claim/zero-citation result with no model call; retrieved-but-irrelevant context persists `claims=()`; contradictory material is represented as separately cited claims without verdict/confidence;
- production composition seam (`infrastructure/research_agent_composition.py`) wiring the real `PgVectorResearchRetriever`, `LlmClient`, `ResearchResultPersistenceService`, and `LlmAccountingService`; the agent is not added to the Coordinator/LangGraph graph;
- unit tests for contracts, deterministic/injection-safe prompts, and application execution (retry/accounting/cancellation/fail-closed), plus canonical PostgreSQL vertical slices (`tests/integration/test_research_agent.py`) using real-format MITRE STIX ingestion, real pgvector retrieval, real persistence, and `FakeLlmClient` only at the model boundary (including a second real-format STIX fixture for contradictory-context coverage).

**Deliver:**
- bounded immutable Research Agent input DTOs;
- structured-only LLM output through the existing `LlmClient(ABC)` abstraction;
- typed research results/claims whose factual claims cite stable `DocumentChunk` identifiers;
- deterministic validation that citations reference chunks actually supplied to the model;
- explicit relevant-context, irrelevant/no-context, and contradictory-context behavior;
- retrieved documents treated as untrusted data: document content cannot issue instructions, invoke tools, override application/system policy, or expand investigative authority;
- bounded LLM execution and retry semantics consistent with the existing Evidence Analyst pattern;
- short transaction boundaries: retrieve/load -> close transaction -> LLM -> validate -> short persistence transaction;
- persistence through the PR 22A research-result seam;
- tests using real persisted `Document`/`DocumentChunk` records produced through the production research persistence/retrieval path;
- `FakeLlmClient` only at the model boundary for deterministic unit and real-PostgreSQL integration tests covering citation validity, unsupported citations, no-context behavior, contradictory context, persistence, and safe failure.

**Boundaries:**
- no Coordinator/graph changes;
- no `research_requested` timeline action;
- no web-browsing research agent;
- no live IOC collection through RAG;
- no verdict/confidence ownership;
- no report generation;
- no generic PR 27 evaluator platform;
- no mocked retrieval architecture when the integration test is intended to prove the production retrieval/persistence path.

The PR must prove that ATI can produce persisted, structured, provenance-backed contextual research independently of orchestration.

### PR 22B-2 — Research prompt provenance and retrieval-score semantics [DONE]

Narrow prompt-contract fixup inserted before PR 22C Coordinator integration.
Delivered:

- `source_url` is now rendered as model-visible provenance metadata for each
  retrieved chunk; a null URL renders as an empty field and the stored string
  is otherwise rendered verbatim;
- URLs do not authorize browsing or fetching and cannot justify inferring
  content ATI did not supply;
- `similarity_score` is explicitly documented to the model as a retrieval
  relevance/ranking signal only;
- similarity does not mean source credibility, factual correctness,
  evidentiary strength, maliciousness, or research/Assessment confidence;
- similarity does not resolve contradictory sources: it must never be used to
  choose a winner between conflicting supplied chunks;
- `citation_id` remains the sole authoritative model-visible citation token
  and `chunk_id` remains hidden;
- byte-deterministic prompt construction is preserved;
- no retrieval, persistence, LLM execution, LLM accounting, or Coordinator
  behavior changed: only deterministic prompt rendering/instructions, focused
  prompt tests, and documentation were touched.

### PR 22C — Coordinator research execution [DONE]

Integrate the independently working research capability into the production investigation lifecycle.

PR 21 already records `research_required_for_entity_ids`; PR 22C consumes that state.

**Deliver:**
- deterministic Coordinator semantics for deciding when marked entities require research execution;
- bounded request, deduplication, completion, exhaustion, and retry/replan behavior;
- durable state sufficient to prevent repeated research of the same unchanged entity/research context;
- the `research_requested` timeline action and any strictly necessary existing-action metadata;
- a research execution application seam composed into the existing production graph without coupling Coordinator policy to pgvector, LangChain, or concrete LLM infrastructure;
- production LangGraph routing for research execution and return to normal Coordinator decision-making;
- integration with the PR 21C `InvestigationRunner` lifecycle and existing short-UoW execution model;
- research completion must not directly authorize pivots: any subsequent pivot remains subject to normal Coordinator policy;
- canonical PostgreSQL trajectory tests that exercise the real production research execution, persistence, retrieval, and orchestration path using a locally seeded real-format corpus fixture and `FakeLlmClient`;
- no live Internet or live LLM dependency in automated tests.

**Boundaries:**
- do not redesign PR 21 Coordinator policy;
- no LLM-based Coordinator planning;
- no distributed worker/task infrastructure;
- no report generation;
- no attribution;
- no ontology/knowledge-graph inference;
- no unrestricted recursive research;
- no generic evaluation/release framework;
- no alternate fake research provider that bypasses the production PR 22A/22B application path in the canonical trajectory.

The PR must prove that research can execute as a bounded, idempotent part of the production investigation state machine.

### PR 22D — Threat Research / RAG evaluation and documentation hardening [DONE]

Delivered the narrow repository-owned deterministic evaluation baseline for
PR 22 and reconciled the documentation with the delivered research
architecture.

**Delivered:**
- deterministic retrieval evaluation (`evaluation/research/retrieval.py`,
  `ResearchRetrievalEvaluator`) with Recall@k, Precision@k, MRR,
  expected-source rank, filter/rank/gap invariants, stable failure codes,
  and retention of the existing synthetic metric fixture;
- real-format retrieval evaluation through the production
  parser/builder/indexing/pgvector path against repository-owned scenarios
  (`evals/scenarios/research/retrieval/`), including a deliberately failing
  expectation proving a structurally successful retrieval can fail the
  baseline;
- structured synthesis evaluation (`ResearchSynthesisEvaluator`) over the
  persisted `ResearchResult`: exact citation closure, supplied-context
  membership, required/forbidden citation labels, bounded claim counts,
  canonical-phrase claim envelopes, explicit empty/no-context and
  contradictory-context semantics, and safe-failure execution envelopes;
- hard epistemic promotion gates: isolated research leaves Evidence /
  RelationshipObservation / Assessment identity-version sets unchanged;
- strict versioned scenario loaders for retrieval/synthesis corpora
  (`evals/scenarios/research/synthesis/` S01..S06) with duplicate-JSON-key,
  duplicate-identity, and duplicate-label fail-closed loading;
- coordinator-trajectory evaluator extensions recognizing `RESEARCH_REQUESTED`
  with required/forbidden request expectations, bounded request budgets,
  identity-level duplicate detection (post-completion re-request, never mere
  count > 1), and research-termination checks without duplicating
  Coordinator policy, plus repository scenarios C-R01..C-R04;
- fully offline canonical slices exercising the production
  parser/index/pgvector/Coordinator/LangGraph/Research Agent path with
  `FakeLlmClient` only at the model boundary;
- documentation reconciliation across `EVALUATION.md`, `TESTING.md`,
  `ARCHITECTURE.md`, and `AGENT_DESIGN.md`, including the final
  Evidence -> retrieval -> research -> Assessment epistemic boundaries.

**Boundaries honored:** deterministic repository-owned baseline only; no
LLM-as-judge; no LangSmith evaluation dependency; no generic evaluation-run
persistence; no release-threshold framework; no cost/latency/performance
framework; no PR 27 evaluator-platform scope; no research runtime behavior
change; no live source downloads or live LLM calls during evaluation.

### PR 22E — RelationshipObservation history semantics [DONE]

Corrects persistence semantics so `RelationshipObservation` is the historical
record itself and is no longer duplicated into `domain_object_history`.

**Delivered:**
- `RelationshipObservation` remains immutable and append-only; each append
  creates exactly one immutable `relationship_observation` row with its
  database-allocated version and provenance, and no `domain_object_history`
  row (SQL API v0018, migration 0021).
- `append_relationship_observation` no longer writes redundant
  `domain_object_history` CREATE rows.
- Stable `Relationship` history remains unchanged: CREATE history for new
  edges, reuse as a no-op, and soft-delete history.
- Existing legacy observation-history rows are preserved/tolerated; the
  migration is non-destructive.
- PostgreSQL regression coverage locks the boundary (one observation -> one
  row/zero history; multiple observations -> zero observation history;
  Relationship and Evidence history regression; rollback atomicity; legacy
  migration upgrade path).

**Boundaries honored:** PostgreSQL owns the correction; no application-side
suppression, no RelationshipObservation update/delete API, no version
removal, no history/observation browse indexes, no generic history
framework, and no Evidence/Assessment/Investigation historization change.

### PR 22 overall non-goals

Across PR 22A-E, do not add paid intelligence feeds, a general web-browsing research agent, live IOC facts through RAG, threat-actor attribution, ontology inference, unrestricted recursive research, report generation, Assessment ownership by the Research Agent, LLM-based Coordinator policy, or distributed task infrastructure.

Execution must continue to respect the PR 19C dispatch boundary, PR 20B structured-LLM boundary, PR 21 deterministic Coordinator policy, and PR 21C `InvestigationRunner` lifecycle.

The production/test distinction is deliberate: production adapters target real source contracts; automated tests use deterministic local representations of those contracts and fake only true external/non-deterministic boundaries such as the LLM or network transport. Tests must not gain determinism by bypassing the production code path they are intended to verify.

## PR 23 — Report Writer and investigation API

Deliver structured reports, Report Writer, report persistence/versioning, `/api/v1` investigation/subresource endpoints, asynchronous semantics, cursor pagination, stable errors, idempotency, and history/version exposure.

Report Writer cannot alter Evidence Analyst verdict/confidence or introduce unsupported facts.

## PR 24 — Analyst frontend

Deliver React/TypeScript investigation list/create/detail flows, Overview, Evidence, Relationships, Research, Timeline and Report views, React Flow graph visualization, and polling. Keep the UI evidence-centric.

## PR 25 — Geolocation map

Deliver Map tab, Leaflet, approximate IP geolocation, multi-IOC visualization, provenance/precision, disclaimer, and correlation-oriented presentation. General GEOINT/PostGIS remains deferred.

## PR 26 — Monitors, diffs, findings, jobs and administration

Deliver Monitor persistence, scheduler, normal Investigation execution from monitors, snapshots/diffs, material Finding generation, findings inbox, PostgreSQL-backed jobs, administration/system UI, and operational visibility.

The PostgreSQL job queue schedules durable investigation-level work. PR 19C `TaskDispatcher` is the in-investigation execution-dispatch seam. These are separate responsibilities.

## PR 27 — Evaluation and release hardening

Expand to curated scenarios, deterministic invariants, agent evaluations, end-to-end trajectory evaluation, adversarial content, canonical malicious-domain/IP/malware trajectory, release gates, stability, performance/cost/latency reporting, licensing/source-term checks, and release documentation.

## v0.1 dispatch boundary

v0.1 uses `LocalTaskDispatcher`. Distributed task-broker infrastructure is explicitly outside the v0.1 requirement.
