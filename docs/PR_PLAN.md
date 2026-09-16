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

PR 23 is split into bounded follow-up PRs (see the PR 23A execution plan at
`.plans/PR_23A_DETAILED_EXECUTION_PLAN.md` for the full decomposition):

### PR 23A — API query and PostgreSQL read-path foundation [DONE]

Delivered the production analyst-facing read/query foundation the REST API
and Report Writer will consume:

- a dedicated application query/read layer (`app/query/`) with typed,
  immutable query contracts, one canonical deterministic ordering per
  collection, bounded explicit filters, and UTC half-open date ranges;
- versioned opaque keyset cursors bound to their query collection and filter
  fingerprint, with typed fail-closed codec errors; no OFFSET anywhere in
  the API-oriented read path;
- PostgreSQL query implementations for Investigations, Evidence,
  Relationships, RelationshipObservations, ResearchResults, Assessments,
  timeline events, and generic `domain_object_history` browsing, including
  exact `object_type + object_id + version` history lookup;
- RelationshipObservation treated as a first-class historical resource
  (investigation/relationship scopes, retrieved/observed date ranges) and
  never routed through `domain_object_history`, preserving PR 22E semantics;
- Assessment current-version resolution through the durable Investigation
  `assessment_id` pointer, never `MAX(version)`;
- migration 0022 indexes mapping one-to-one to concrete query paths, with
  redundant pre-existing indexes superseded and removed;
- functional pagination integration tests proving no skips/duplicates over
  tied timestamps, plus `EXPLAIN` plan-eligibility tests that never assert
  unstable planner costs;
- `docs/DATABASE.md` index/query inventory and `docs/API.md` cursor/filter/
  date semantics without claiming the HTTP implementation exists.

PR 23A does **not** implement FastAPI routes, HTTP DTOs, authentication,
Report Writer execution, report persistence, investigation submission,
idempotency, or frontend work.

### PR 23B — Structured Report Writer and report persistence [DONE]

Delivered the structured Report Writer LLM execution, typed report domain
model, report persistence/versioning, and report history exposure on the PR
23A persistence foundation. Report Writer cannot alter Evidence Analyst
verdict/confidence or introduce unsupported facts.

Delivered:

- typed report domain contracts (``AssessmentFindingRef`` /
  ``ResearchClaimRef`` / ``ReportNarrativeStatement`` /
  ``ReportWriterOutput`` / ``InvestigationReport``) with strict frozen
  models and ``extra="forbid"``;
- ``ReportWriterInputLoader`` materializing the current Assessment (via the
  Investigation's durable ``assessment_id`` pointer), its analyzed Evidence,
  finding-referenced RelationshipObservations, and bounded persisted
  ResearchResults, with independent input bounds and no raw Evidence
  payloads;
- deterministic prompt builder (``urn:ati:llm:report_writing``), reusing
  ``LlmClient.generate_structured`` and investigation-wide LLM accounting
  with at most one schema-repair attempt and no free-form fallback;
- application stamping and ``ReportProvenanceValidator``: verdict/
  confidence copied from the current Assessment (never model-authored),
  finding/research snapshots application-copied, caveats preserved exactly,
  reference/source-set closure enforced before persistence;
- versioned PostgreSQL persistence (migration 0023, SQL API v0019):
  ``ati.investigation_report`` root table with JSONB presentation snapshots,
  DB-assigned versions, one CREATE history row, the durable Investigation
  ``report_id`` pointer advanced atomically under lock, stale-Assessment
  rejection (``U23A1``), and superseded-only soft deletion;
- report query extension of the PR 23A layer (``QueryKind.REPORTS``,
  keyset pagination ``version DESC, id ASC``, current report via the durable
  pointer, listing index with EXPLAIN eligibility test);
- deterministic Markdown formatter (pure presentation code, no LLM/DB
  access, safe escaping);
- repository-owned Report Writer behavioral baseline (RPT-S01..S08, stable
  failure codes, no LLM-as-judge) and the canonical real-PostgreSQL /
  ``FakeLlmClient`` vertical slice;
- documentation reconciliation (architecture, agent design, database, API,
  testing, evaluation).

PR 23C remains the Investigation REST API.

### PR 23C — Investigation REST API [DONE]

Delivered `/api/v1` investigation and subresource endpoints consuming the PR
23A query contracts (cursor pagination, bounded filters, history/version
exposure), asynchronous investigation creation semantics, stable errors, and
idempotency.

Delivered:

- FastAPI application factory (`api/app.py`) composing CORS, request-ID /
  security-header middleware, the stable error envelope, every /api/v1
  router, health probes, and the cookie-session OpenAPI security scheme;
- explicit request/response DTOs (`api/dto/`) with `extra="forbid"` and
  pure deterministic allowlist mappers (`api/mappers.py`);
- minimal server-side session authentication (`POST /auth/login`, `POST
  /auth/logout`, `GET /auth/me`) reusing the Argon2id credential and
  SHA-256-hashed opaque session tokens (256-bit CSPRNG) behind an HttpOnly
  SameSite=Lax cookie plus double-submit CSRF cookies and same-origin
  checks;
- ANALYST/ADMIN authorization dependencies (``authentication_required`` 401
  / ``forbidden`` 403) and credentialed CORS with explicit configured
  origins (wildcard rejected);
- bounded request IDs echoed in `X-Request-ID` and inside every error
  envelope;
- stable public error envelope (`ErrorResponse{code,message,request_id}`)
  with central typed-exception mapping (cursor, not-found, conflict,
  stale-version, idempotency codes) and FastAPI validation overridden to
  the ATI envelope;
- asynchronous investigation creation: `POST /api/v1/investigations`
  atomically persists the PENDING Investigation, the durable PostgreSQL
  investigation job (`ati.investigation_job`, SQL API v0020), the mutation
  audit event, and the actor-scoped idempotency record
  (`ati.api_idempotency`) in one transaction, then returns `202 Accepted`
  with a `Location` header; the request never invokes `InvestigationRunner`;
- durable idempotency: required bounded `Idempotency-Key` (1..128 visible
  ASCII), SHA-256 key digests only, canonical semantic request fingerprints,
  equivalent replays returning the same Investigation, mismatches returning
  `409 idempotency_conflict`, and database-owned race safety (one
  Investigation + one logical job under concurrency);
- Investigation list/detail, Evidence, Relationships,
  RelationshipObservations (observed/retrieved filters kept distinct),
  Research, Assessment (version list / current via durable
  `assessment_id` / detail), Report (version list / current via durable
  `report_id` / detail / deterministic Markdown), Timeline, and scoped
  generic history — all read paths reuse the PR 23A keyset contracts and
  the PR 23B report query layer, with no OFFSET, no total counts, and no
  raw payloads;
- generic history redaction: public object-type allowlist
  (investigation/entity/relationship/assessment/investigation_report) with
  per-type state/diff projections that never expose operational or auth
  material;
- the minimal durable job worker seam (`InvestigationJobWorker`) claiming
  jobs atomically and invoking `InvestigationRunner` outside any
transaction; no job administration API (PR 26 scope);
- OpenAPI snapshot fixture (`tests/fixtures/openapi_v1.json`) pinning
  explicit operation IDs, public DTOs, error responses, and the cookie
  scheme;
- unit + route contract tests (`tests/unit/api/**`), real-PostgreSQL API
  integration tests (auth, creation transaction, idempotent replay/race/
mismatch, collections, raw-payload exclusion, durable pointers, history
  redaction, deterministic Markdown), the canonical async vertical slice
  (`POST -> job -> worker -> InvestigationRunner -> GET`), and document
  reconciliation.

PR 24/25/26 scope boundaries are retained: no frontend, no geolocation/map
endpoints, no monitors/findings/admin/job-administration APIs, no report
generation/regeneration endpoints, no WebSockets/SSE, and no distributed
broker.

### PR 23D — Runtime operating modes and deterministic fake intelligence environment [DONE]

Added the v0.1 `ATI_OPERATING_MODE` runtime contract with exactly `fake` and
`production` modes. `production` preserves the existing real
intelligence-source composition; `fake` replaces only external batch/live
intelligence sources with deterministic repository-owned fixtures/adapters
while retaining the production `InvestigationRunner`, Coordinator/LangGraph,
provider execution, persistence, Research, Assessment, Report, worker, and
HTTP architecture.

Delivered:

- typed `OperatingMode` (`config/settings.py`) bound to `ATI_OPERATING_MODE`
  with a safe `production` default, fail-closed validation, and documented
  orthogonality with `ATI_CONFIG_PROFILE`;
- the versioned synthetic world and scenario catalog
  (`infrastructure/fake_runtime/data/v1/` + `catalog.py`): one shared
  deterministic world with scenario-defining signal, relevant-but-
  inconclusive data, ambient noise, shared infrastructure, dead-end pivots,
  and F01–F05 named scenario entry points, all strictly validated;
- deterministic fake live providers implementing the existing
  `EvidenceProvider` contract with preserved `SourceId` identities and
  real-provider `supports(Entity)` applicability, no HTTP transport, no
  provider secrets, and explicit no-result/error semantics
  (`infrastructure/fake_runtime/providers.py`);
- the operating-mode composition boundary
  (`infrastructure/intelligence_composition.py`): fake vs production
  branches yielding the same provider-registry contract, wired into the
  worker/runner through existing seams;
- the explicit idempotent fake-data bootstrap (`ati-fake-data-bootstrap`)
  materializing the packaged MITRE STIX fixture into the datasets object
  store and ingesting through the production `MitreAttackBatchSource` /
  `IngestionService` / document-indexing path; API/worker startup never
  ingests fake data;
- the real `ati-worker` entrypoint composing the selected registry, the
  configured real LLM, the real Evidence Analyst, and the real Research
  Agent;
- safe startup observability (`operating_mode=...
  intelligence_source_mode=...`) and the authenticated
  `GET /api/v1/runtime` metadata endpoint for the future frontend
  (OpenAPI snapshot updated);
- local Compose wiring (bootstrap-before-API/worker, `ATI_OPERATING_MODE`
  on API and worker) and documentation reconciliation
  (`CONFIGURATION.md`, `ARCHITECTURE.md`, `TESTING.md`, `API.md`,
  `DEPLOYMENT.md`);
- deterministic offline coverage: configuration unit tests, fixture/catalog
  unit tests, no-network provider tests, composition fail-closed tests,
  batch-bootstrap PostgreSQL integration tests, F03 relationship-evolution
  integration, F04 research-required integration, and the canonical
  fake-mode HTTP -> durable job -> worker -> runner -> HTTP vertical slice
  over real PostgreSQL with `FakeLlmClient` only at the model boundary.

No frontend, new production intelligence sources, distributed
infrastructure, mode switching through HTTP, a third operating mode, or a
generic simulation framework was introduced.

## PR 24 — Analyst frontend

PR 24 is decomposed into five bounded frontend PRs. The original single-PR scope mixed application infrastructure, Investigation workflow, tabular analyst exploration, pivot/navigation semantics, and visualization. These are separate architectural concerns and should not be delegated to one coding-agent change.

The frontend reuses the Vite/React 19 scaffold already present on `main`. The v0.1 frontend stack is:

```text
Vite + React 19 + strict TypeScript
React Router 7                 route/navigation state
TanStack Query v5              server state
Material UI + Emotion          component/design system
i18next + react-i18next        internationalization foundation
OpenAPI-derived TS types       backend DTO contract
Vitest + Testing Library + MSW unit/component tests
Playwright                     browser E2E
```

Future table browsing uses TanStack Table; relationship graph visualization uses React Flow. Do not add either before the PR that owns it.

The product UX remains evidence-centric:

```text
summary
  -> finding
  -> supporting evidence / relationship observations / research
  -> analyst pivot
  -> further exploration
```

The UI must make it easy to move from an AI conclusion to its provenance and from any interesting value to the next investigative pivot. Chat is not the primary application interaction model.

### PR 24A — Frontend foundation and authenticated analyst shell

Establish the browser application platform and prove real authenticated operation against the PR 23C/23D backend.

Deliver:

- evolve the existing `frontend/` Vite/React 19 scaffold rather than replacing it;
- React Router browser/data-router foundation;
- TanStack Query server-state foundation;
- Material UI/Emotion theme and responsive analyst shell;
- i18next/react-i18next foundation with English shell/auth strings;
- TypeScript types generated from committed `tests/fixtures/openapi_v1.json`, with deterministic drift check;
- one ATI-owned fetch/API boundary using relative `/api/v1`, `credentials: include`, stable public `ErrorResponse` mapping, AbortSignal support, and exact `ati_csrf` -> `X-CSRF-Token` handling for unsafe authenticated requests;
- authentication state sourced from `GET /api/v1/auth/me`, plus login/logout flows and protected routing;
- routes `/login`, `/investigations` (bounded placeholder only), and safe not-found behavior;
- safe internal return-to navigation after authentication; no external redirect target;
- authenticated shell showing product/navigation/user identity/logout;
- authenticated `GET /api/v1/runtime` integration and persistent, non-dismissible textual `FAKE DATA` indicator when `operating_mode=fake`; runtime lookup failure must never silently imply production;
- Vite `/api` development proxy and production Nginx `/api` reverse proxy so feature code never hard-codes an API host;
- Nginx SPA history fallback so direct nested browser routes resolve through React Router;
- local public-origin/Compose wiring preserving PR 23C CORS and Origin/Referer CSRF protections;
- frontend unit/component infrastructure with Vitest, jsdom, Testing Library, user-event and centralized MSW;
- Playwright real-browser coverage against real FastAPI/PostgreSQL proving login -> authenticated shell -> runtime indicator, reload/session restore, CSRF-protected logout, and direct SPA navigation;
- frontend architecture/deployment/testing documentation.

**PR 24A boundaries:** no Investigation list data, create form, polling, detail workspace, Overview, Report UI, analyst resource tables, export, pivots, Relationship Evolution, React Flow, or map. No Redux/Zustand/global state store. No refresh-token mechanism or weakening of cookie/CSRF security. [DONE]

### PR 24B — Investigation workflow, Overview and report experience [DONE]

Delivered the first complete analyst workflow:

```text
Investigations
    -> Create Investigation
    -> Investigation workspace
    -> Overview
```

Deliver:

- real Investigation list using PR 23C cursor semantics;
- Create Investigation form using backend-supported indicator types/objective bounds;
- browser-generated cryptographically strong `Idempotency-Key` per logical submission attempt, retained for safe retry of that attempt and replaced for a new semantic request;
- asynchronous `202 Accepted` handling;
- navigate immediately into Investigation workspace;
- bounded polling of Investigation until terminal state, with cancellation on route/unmount/terminal transition;
- persistent Investigation header: subject/indicators, objective, status, timestamps and current assessment/report availability;
- workspace navigation establishing `Overview | Evidence | Relationships | Research | Timeline`, with only Overview substantive in 24B and later routes owned by 24C;
- Overview centered on "What did ATI conclude, why, and what remains uncertain?";
- current Assessment and current Report resolved through durable current-resource endpoints, never `MAX(version)` client-side;
- verdict/confidence, executive summary, findings, caveats/limitations, unresolved questions/recommendations and relevant research references according to delivered DTOs;
- full report presentation as a secondary view/action rather than making Report the only workspace;
- finding support rendered as explicit provenance references ready for PR 24C/24D drill-down;
- robust empty states for running, failed, stopped-without-report, and other legitimate missing-artifact states;
- Playwright real-stack slice using PR 23D fake mode: `login -> create known fake Investigation -> durable job/worker -> poll -> terminal Overview`.

No Evidence/Relationship/Research table implementation, pivot workspace, graph, or map in 24B.

Delivered (PR 24B implementation summary):

- real Investigations landing replacing the PR 24A placeholder, consuming
  the PR 23C cursor API with exact lifecycle-status filtering, opaque
  Previous/Next cursor navigation through a browser-local cursor stack,
  bounded page size, and no total-count/page-number fiction;
- Create Investigation form (objective + typed indicators, friendly labels
  over exact `EntityType` values, exact backend bounds from the committed
  OpenAPI snapshot, no client-side canonicalizer);
- browser idempotency-key lifecycle: cryptographic keys (never
  `Math.random`), transport-uncertain retries reusing the same key,
  changed semantic payloads forcing a new key, explicit
  `409 idempotency_conflict` handling, keys never persisted or logged;
- asynchronous `202 Accepted` handling with immediate workspace
  navigation and list invalidation;
- persistent workspace header + `Overview | Evidence | Relationships |
  Research | Timeline` route links, with placeholder routes issuing no
  collection queries;
- bounded detail polling (2s) while `pending`/`running` only, stopping on
  every terminal status, no interval-in-background, AbortSignal
  propagation and unmount cancellation;
- Overview answering conclusion/why/confidence/uncertainty/next steps
  from the durable pointer-backed `/assessments/current` and
  `/reports/current` endpoints (never `MAX(version)`), Report
  presentation when present, Assessment fallback otherwise, visible
  support references, distinctly labeled Research context, and a
  consistency warning when Report and Assessment disagree;
- secondary full Report route with persisted metadata and an optional
  deterministic Markdown view as plain text;
- MSW lifecycle handlers, polling-behavior component tests, corrupted-key
  and cursor-opacity unit tests, and a real-stack Playwright slice
  (login -> create F02 fake-world Investigation -> 202 -> workspace ->
  poll -> terminal -> current Assessment/Report -> Overview) over
  PostgreSQL, FastAPI, the real durable worker with the deterministic
  offline LLM boundary, and the built Nginx frontend — no live LLM or
  live network;
- narrow backend prerequisite: `ATI_LLM_DRIVER=deterministic` selects the
  repository-owned offline scripted boundary, and the `ati-worker`
  writes the current Report through the existing PR 23B Report Writer
  after terminal Investigation completion (Assessment-only failure state
  remains legitimate).

### PR 24C — Analyst resource tables and drill-down [DONE]

Deliver one reusable server-driven analyst browsing architecture and apply it to:

```text
Evidence
Relationships
RelationshipObservations
Research
Timeline
History
```

Use TanStack Table over Material UI presentation primitives; do not introduce MUI Data Grid as a second table framework.

Common interaction contract:

```text
server-side filters
    -> URL search parameters
    -> API query
    -> opaque cursor page
    -> rows
    -> row selection
    -> detail drawer/panel
```

Deliver:

- resource-specific bounded filters matching PR 23C API capabilities;
- no client-side invention of unsupported filter semantics;
- opaque next-cursor pagination; frontend never decodes cursors and never uses OFFSET/page-number assumptions;
- deterministic loading/empty/error/retry states;
- table density appropriate for analyst work;
- explicit provenance fields where present;
- detail surfaces for Evidence, Relationship, RelationshipObservation, ResearchResult/claims/citations, Timeline events and generic History records;
- RelationshipObservation treated as the first-class historical observation resource, not generic history;
- `observed_at` and `retrieved_at` displayed distinctly;
- Research visually/semantically distinguished from Evidence;
- generic History kept secondary to core analyst views and respecting backend redaction;
- bounded export designed against actually loaded/query-selected server data; never silently claim exhaustive export when only one cursor page is available;
- URLs preserve route/filter state sufficiently for refresh/share within same deployment;
- component tests for reusable table/query machinery and real-stack browser coverage against representative PR 23D noisy fake-world data.

No cross-table popup pivot workspace or breadcrumb chain yet; that is PR 24D. No relationship graph/timeline visualization; that is PR 24E.

Delivered (PR 24C implementation summary):

- TanStack Table v8 as the sole table engine, rendered headless through
  Material UI primitives in manual/server mode (no client sorting, no
  client-side exhaustive filtering, no page-number fiction);
- a reusable analyst-table layer (`frontend/src/analyst-table/`) with
  URL-backed resource filter controllers, opaque-cursor Previous/Next over
  a browser-local back stack, filter-change cursor reset, invalid-cursor
  first-page recovery, row-selection/detail drawers, bounded current-page
  CSV export (RFC 4180 quoting, spreadsheet formula-injection
  neutralization, objective-free filenames), safe structured-data viewer,
  and loading/empty/error/refresh states;
- real Evidence, Relationships, RelationshipObservations, Research and
  Timeline workspaces replacing the PR 24B placeholders, plus secondary
  Investigation History reached through the workspace `More` menu;
- Evidence detail uses the authoritative Investigation-scoped GET;
  Relationship detail shows the stable edge plus a bounded
  relationship-scoped observation preview; RelationshipObservations are
  first-class through `/relationships/observations` with `observed_at` and
  `retrieved_at` visibly independent (never generic History, never
  ended/removed inference); Research keeps contextual claims/citations
  visibly distinct from Evidence with escaped external text; Timeline
  preserves the API canonical order and maps known event enums with safe
  fallback; History honors the backend public object-type allowlist with
  exact-version detail, object-scoped version browsing, and allowlisted
  state/diff rendered as escaped data;
- a backend contract fix discovered by the E2E slice: the generic History
  list now skips non-allowlisted audit rows (such as the immutable
  ``evidence`` rows appended by the stored functions) instead of failing
  with a 500, and explicit requests for non-allowlisted object types still
  fail closed with ``400 invalid_request`` (api/routes/history.py with
  four route-level unit tests);
- component tests covering the full resource matrix (cursor/filter/drawer/
  export mechanics, Evidence epistemics, RelationshipObservation temporal
  semantics, Research contextual separation, Timeline semantics, History
  safety) and real-stack Playwright coverage over the PR 23D fake world
  without live Internet/LLM, including a browser-proven current-page CSV
  download.

No cross-table popup pivot workspace or breadcrumb chain yet; that is PR 24D. No relationship graph/timeline visualization; that is PR 24E.

### PR 24D — Cross-resource pivots, provenance navigation and breadcrumb workspaces [DONE]

Deliver ATI's defining analyst exploration interaction:

> From an interesting value or report finding, move to the relevant supporting data or a filtered target resource without losing exploration context.

Deliver:

- contextual actions on eligible entity/column/reference values;
- user-selected pivot targets where more than one target resource is meaningful;
- target table/workspace opens as a popup/modal analyst workspace with selected value pre-applied as a server-side filter;
- nested pivots preserve breadcrumb path, for example: `Investigation -> 203.0.113.7 -> Relationships -> beta.example -> Evidence`;
- popup/workspace title renders breadcrumb context;
- URL representation of pivot/filter state sufficient for refresh/back-forward without sensitive raw payloads in URL;
- deterministic close/back semantics;
- Report/Assessment finding -> supporting Evidence / RelationshipObservation / Research navigation;
- Relationship -> observation -> Evidence provenance drill-down;
- value pivots never invent entity equivalence or relationship semantics not provided by backend;
- bounded nested-workspace depth or another explicit guard against unbounded modal recursion;
- browser tests covering multi-step pivots against the shared PR 23D synthetic world, including one meaningful path and one benign/dead-end path.

No generic graph visualization or geospatial map.

Delivered (PR 24D implementation summary, completed by PR 24F):

- typed pivot model and one explicit capability registry
  (`frontend/src/pivots/pivot-types.ts`, `pivot-capabilities.ts`): every
  legal action is an explicit source identity -> exact PR 24C
  filter/selection target; nothing is inferred from strings, no
  source-or-target merge, no client-side OR simulation;
- versioned base64url JSON pivot stack in the reserved `pivot` search
  parameter (`pivot-url.ts`), capped at five steps and a 4096-byte
  header budget, with deterministic push/truncate/clear semantics;
- one modal pivot workspace (`PivotWorkspace.tsx`) hosting the active
  PR 24C resource view through a thin search-params projection
  (`pivot-port.ts`), with breadcrumbs, Back/Forward/refresh restore,
  depth cap, and Close to the base route; implemented with MUI
  primitives (fixed paper/backdrop + roving-keyboard menus) because the
  MUI 7 Modal focus trap races the in-drawer pivot unmount and crashes
  the Chromium main thread on the real stack;
- provenance navigation by exact persisted support identity: Report/
  Assessment Evidence support opens the exact scoped Evidence selection,
  Research context/claim references open the exact Research result, and
  RelationshipObservation support resolves through the exact
  Investigation-scoped observation read added by PR 24F (never a list
  scan, never a substitute observation, never generic History);
- Relationship -> observation -> Evidence drill-down through the same
  typed pivot model, and bounded compact breadcrumb labels;
- no entity equivalence or relationship semantics are ever invented by
  the browser; free Report/Research text never enters the pivot URL;
- real-stack E22 covering the meaningful pivot path
  (Evidence support -> subject -> Relationships -> observations ->
  Evidence, breadcrumbs, Back/Forward, truncation, refresh, Close) and
  the real-stack E22-B benign/dead-end path over the F01 fake-world
  Investigation (legal pivot to an honestly empty filtered target, no
  invented fallback, breadcrumb preserved, safe Close) added by PR 24F;
- source-and-test compliance re-audited in PR 24F against the exact PR
  24D deliverable list (bounded/versioned URL state, single workspace,
  depth 5, no graph/map leakage).

### PR 24E — Relationship Evolution and relationship graph `[DONE]`

Delivered:

- server-side entity-centric RelationshipObservation filtering
  (`entity_id`, `direction=source|target|either`, `relationship_type`,
  `counterparty_entity_id`) on the existing Investigation-scoped endpoint,
  evaluated in SQL through the joined stable Relationship; validation
  rules are exact (`direction`/`counterparty_entity_id` require
  `entity_id`; a bare entity behaves as `either`) and cursor fingerprints
  include the new filters;
- joined Relationship semantics shipped on each observation page
  (`relationship_source_entity_id`, `relationship_target_entity_id`,
  `relationship_type`) — no N+1 Relationship loading, no persistence
  duplication;
- the Relationships list gains the one-hop `entity_id` neighborhood
  filter (source-or-target OR on the server) used by the graph;
- first-class `/investigations/:id/relationships/evolution` route with
  URL-backed focal entity + filters + opaque cursor and a
  `view=evolution|graph` switch that preserves entity/filter context;
- Relationship Evolution swimlanes over `observed_at` with `retrieved_at`
  kept distinct, an explicit `Observed time unavailable` group, bounded
  page honesty, page-scoped deterministic labels (`Earliest shown on this
  page`), keyboard-accessible points, observation detail with Evidence
  provenance and exact Relationship navigation, and a tabular
  alternative;
- explicit Evolution entry links from the Relationships table/detail
  (source/target entities) and the enriched observation detail; PR 24D
  pivots reused for Evidence/research/relationships — the pivot model was
  not distorted with route-only targets;
- bounded one-hop stable Relationship graph with React Flow
  (`@xyflow/react`): exact Entity/Relationship IDs, deterministic radial
  layout, honest incomplete-neighborhood notice, and an always-available
  non-spatial edge list; no recursive traversal, no inference, no
  validity semantics, no layout persistence;
- backend unit/route/OpenAPI/PostgreSQL integration tests (E-B01..E-B16 +
  cursor binding + index plan eligibility), frontend derived-model and
  component tests (E-D01..E-D09, E-U01..E-U18, E-G01..E-G11), and the
  real-stack F03 browser slice E23
  (`entity -> Evolution -> observation -> Evidence -> Graph ->
  Relationship/table`, refresh and Back/Forward preservation);
- documentation updated in `docs/API.md`, `docs/ARCHITECTURE.md`, and
  `docs/TESTING.md`.

No PR 24B/24D residual fixups were absorbed; PR 24F owns final series
reconciliation (including the Report -> exact RelationshipObservation
provenance gap, which PR 24E explicitly does not depend on).

Deliver the relationship visualization layer after the table/pivot model is established.

Prioritize **Relationship Evolution** over generic graph polish.

Relationship Evolution answers:

> How has ATI observed this entity's relationships over time?

Deliver:

- entity-centric temporal relationship view sourced from `RelationshipObservation`;
- filters for direction, relationship type, counterparty/source where supported, and observed date range;
- discrete observation points / swimlane-style presentation based on `observed_at`;
- `retrieved_at` remains distinct metadata;
- derived labels such as First observed, Re-observed, observation frequency, new counterparty/type only where deterministically supported;
- never infer started/ended/continuous validity merely from missing observations;
- observation interaction drills into PR 24C detail/provenance and PR 24D pivots;
- React Flow graph for current/stable relationship exploration after temporal view;
- graph nodes/edges are navigation/exploration aids, not a new inference engine;
- graph/table/pivot transitions preserve entity identity and Investigation scope;
- backend prerequisite rule: if current PR 23C RelationshipObservation API cannot support bounded temporal queries, STOP and introduce a narrow backend prerequisite rather than downloading unbounded observations client-side;
- Playwright coverage: `entity -> Relationship Evolution -> observation -> Evidence/provenance`, plus bounded graph-to-table navigation.

No PR 25 map/GEOINT expansion.

### PR 24 overall UI principles

Across PR 24A–E:

- primary landing after authentication becomes Investigations workspace once PR 24B lands;
- Overview answers conclusion/why/uncertainty, not executive SOC KPI dashboards;
- Evidence, Relationships and Research are table-first analyst surfaces;
- Research remains visibly epistemically distinct from Evidence;
- Investigation Timeline (what ATI did) remains distinct from Relationship Evolution (what relationships ATI observed over time) and generic resource History (how persisted state changed);
- Assessment/Report current versions come from durable backend current pointers/endpoints, never browser inference;
- backend opaque cursors remain opaque;
- no client-side reconstruction of unbounded datasets;
- filter/pivot state belongs in routes/search params where appropriate; server resources belong in TanStack Query; transient component state remains local;
- substantive user-visible UI text uses i18n foundation;
- PR 23D fake mode remains visibly labeled during demos;
- component tests may fake HTTP at browser-unit boundary, but every functional PR also proves its principal workflow through a real browser against real FastAPI/PostgreSQL;
- frontend must not weaken PR 23C authentication, CSRF, authorization, idempotency or error contracts.

After PR 24E, PR 25 adds the geolocation map using the established routing/query/pivot architecture.

### PR 24F — PR 24 series hardening and compliance closure [DONE]

PR 24F is a hardening and compliance-closure PR, not a feature PR. It
closes the bounded residual compliance gaps remaining from PR 24A–24E and
reconciles the authoritative documentation with the verified
implementation. No new product capability, agent behavior, persistence
model, graph feature, or GEOINT work was added.

Delivered (PR 24F implementation summary):

- **Create Investigation commit-uncertain retry safety (PR 24B fix):** one
  pure policy helper (`isCreateAttemptOutcomeUncertain` in
  `frontend/src/investigations/idempotency.ts`) classifies create
  outcomes as commit-uncertain only for transport failures and HTTP
  responses with status >= 500 (including malformed 5xx bodies);
  pre-transport CSRF failures and definitive 4xx responses (validation,
  idempotency conflict, auth/permission) settle the attempt. An unchanged
  semantic payload after a transient 5xx retries with the same
  in-memory Idempotency-Key; a changed payload (objective/indicator edit)
  always starts a new logical attempt/key. Keys remain cryptographic,
  memory-only, and never enter URLs, storage, logs, or UI text. Component/
  MSW coverage: F-B01..F-B12.
- **Exact RelationshipObservation read (PR 24D provenance fix):**
  `RelationshipObservationQueryService.get(investigation_id,
  observation_id)` and its PostgreSQL joined exact read (identity +
  Investigation scope; same joined source/target/type projection as the
  list, no cursor, no N+1, no generic History) behind
  `GET /api/v1/investigations/{id}/relationship-observations/{observation_id}`
  (operation id `get_relationship_observation`, public
  `RelationshipObservationResponse`, stable scoped 404 for missing and
  cross-Investigation ids). OpenAPI fixture and generated frontend types
  regenerated. Coverage: F-O01..F-O06 backend contract, real-PostgreSQL
  scope matrix, F-A01..F-A06 API.
- **Report/Assessment -> exact RelationshipObservation provenance:**
  Report finding `relationship_observation` support references are now
  actionable; the persisted observation id drives one Investigation-
  scoped exact GET inside the PR 24D pivot workspace (never a list scan,
  never a substitute observation), reusing the existing observation row
  presentation, and the observation detail keeps exact Evidence
  navigation by `evidence_id`. Coverage: F-P01..F-P10 component.
- **Benign/dead-end real-browser pivot scenario:** E22-B in
  `frontend/e2e/zz-pivots.spec.ts` completes the deterministic F01
  fake-world Investigation and takes a legal typed pivot
  (Evidence subject -> Research for this entity) to an honestly empty
  filtered target: exact filter visible, no invented relationship or
  fallback, breadcrumb context preserved, Close safe, `FAKE DATA`
  visible, clean browser console, real FastAPI/PostgreSQL/built frontend,
  no live Internet/LLM.
- **Final source-and-test compliance sweep:** every PR 24A–24E minimum
  requirement was re-verified against implementation files and
  deterministic tests (COMPLIANT/PARTIAL/MISSING/NOT APPLICABLE mapping);
  only PR-24F-admissible residual fixes were absorbed (the three gaps
  above plus the missing `observations.detail.title` i18n key). No
  material precedent-PR gap was found; no STOP was required.
- **Documentation reconciliation:** `docs/PR_PLAN.md` (24D marked DONE,
  this summary), `docs/ARCHITECTURE.md` (24B commit-uncertain retry
  wording, 24D exact observation provenance wording), `docs/API.md`
  (exact observation GET), `docs/TESTING.md` (5xx uncertainty, exact
  observation provenance, benign/dead-end browser path, final closure
  note, stale non-pivotable wording removed).

## PR 25 — Geolocation map

Deliver the v0.1 Investigation geolocation map as three bounded PRs. PR 25 consumes the already-delivered DB-IP City Lite `GEOLOCATION` Evidence contract; it does not introduce a second geolocation persistence model, runtime map-time provider lookups, PostGIS, or broader GEOINT analysis.

```text
Persisted GEOLOCATION Evidence
        |
        v
PR 25A bounded geolocation read projection/API
        |
        v
PR 25B Investigation Map / Leaflet visualization
        |
        v
PR 25C analyst integration, multi-IOC workflow, and E2E closure
```

### PR 25A — Investigation geolocation read projection and API [DONE]

Deliver the backend/query foundation for the Map:

- dedicated Investigation-scoped geolocation query/read contract;
- projection exclusively from already-persisted `GEOLOCATION` Evidence joined to its canonical IP Entity;
- one deterministic latest geolocation observation per IP entity, preserving the exact Evidence ID as provenance;
- explicit typed country/region/city, optional paired latitude/longitude, provider, precision, and observation/retrieval timestamps;
- coordinate-less valid geographic context retained rather than silently discarded;
- bounded server-owned collection response with explicit truncation rather than browser reconstruction through paginated Evidence;
- PostgreSQL latest-per-entity selection and strict cross-Investigation isolation;
- dedicated public API DTO and `GET /api/v1/investigations/{investigation_id}/geolocations`;
- normal analyst authentication/authorization and generated OpenAPI/client artifacts;
- deterministic unit, real-PostgreSQL, HTTP, scope, truncation, and vertical-slice tests.

PR 25A performs no MMDB/provider lookup at API request time, creates no new geolocation table, and adds no frontend Map behavior. A database migration/index is not expected; if current indexes are demonstrably insufficient, stop and propose a separate narrow prerequisite rather than silently adding schema work.

Delivered (PR 25A implementation summary):

- **Dedicated query read projection:** `app/query/geolocation.py` defines
  the immutable `InvestigationGeolocationItem`/`InvestigationGeolocationResult`
  read models, the Investigation-scoped
  `InvestigationGeolocationQueryService` ABC, and the pure
  `geolocation_item_from_persisted_facts` mapper that consumes only the
  approved normalized facts and fails closed with `GeolocationFactsError`
  on malformed persisted data (never silently dropping or reinterpreting
  corrupt rows);
- **PostgreSQL latest-per-entity selection:**
  `infrastructure/persistence/query/geolocation.py` selects one row per
  subject via `row_number() OVER (PARTITION BY subject_entity_id ORDER BY
  retrieved_at DESC, id ASC)`, scopes to the Investigation GEOLOCATION
  Evidence with IP_ADDRESS subjects, orders the final projection
  `ip_address ASC, entity_id ASC`, and fetches at most `max_items + 1`
  rows so truncation is explicit. The query drives through the existing
  investigation-prefixed evidence listing indexes (verified by the
  test_p13 plan-eligibility test), so no index/migration was required;
- **Service composition:** `QueryServiceBundle.geolocations` is composed
  by `PostgresQueryServices` with the server-owned bound
  `ATI_API_MAX_MAP_GEOLOCATION_ITEMS` (default 500, semantically separate
  from pageable collection sizes);
- **API:** `GET /api/v1/investigations/{id}/geolocations` (operation id
  `list_investigation_geolocations`, tag `geolocation`) returns the
  dedicated allowlisted `InvestigationGeolocationCollectionResponse` DTO
  (`items` + `truncated`, no cursor, no arbitrary facts, no raw payload,
  no artifact paths) with normal analyst cookie-session
  authentication/authorization. Unknown/not-visible Investigations follow
  the established collection convention and return an empty `200`;
- **Coverage:** G-Q01..G-Q10 read-model invariants, G-M01..G-M12 pure
  fact mapping, G-P01..G-P16 real-PostgreSQL matrix (empty, single,
  ordering, latest-per-entity, tie-breaker, type/IP exclusion,
  cross-Investigation isolation, coordinate-less context, truncation
  bound/exact, historical volume, malformed/partial-pair fail-closed,
  nonexistent-Investigation empty, bounded single read),
  G-A01..G-A10 HTTP contract checks, and two real PostgreSQL + FastAPI
  vertical slices (`tests/integration/test_api_geolocation.py`);
- **Artifacts:** OpenAPI fixture regenerated
  (`tests/fixtures/openapi_v1.json`) and frontend generated API types
  regenerated (`frontend/src/api/schema.generated.ts`, verified with
  `npm run api:check`); `docs/API.md` documents the delivered geolocation
  endpoint, `docs/ARCHITECTURE.md` documents projection-from-Evidence
  semantics, and `docs/TESTING.md` records the PR 25A matrices.

No frontend Map/Leaflet feature, PostGIS, spatial query, provider change,
new geolocation persistence, or GEOINT expansion is included.

### PR 25B — Investigation Map and Leaflet visualization [DONE]

**PR 25B closure:** with the PR 25C deterministic real-stack seeding seam in
place, the E24 data prerequisite is closed: `frontend/e2e/zz-geolocation.spec.ts`
now seeds the allowlisted `single_mappable` scenario into the exact
browser-created Investigation and runs the full Map workflow through the real
PR 25A endpoint (disclaimer, seeded IP, real Leaflet marker, exact persisted
GEOLOCATION Evidence provenance, safe return, `FAKE DATA`, clean console) with
no data-path skip. E24 passes end-to-end on the full E2E stack.

Consume the PR 25A endpoint and deliver the first-class Investigation Map frontend:

- Investigation `Map` route/tab using the established PR 24 routing/TanStack Query architecture;
- Leaflet and the minimum required React integration;
- zero-, single-, and multi-point rendering with deterministic fit/zoom behavior;
- markers representing IP entities with approximate city/region/country context;
- visible provider/precision/provenance presentation;
- persistent disclaimer that IP geolocation is approximate network-address context and does not establish attacker, user, or device physical location;
- explicit presentation of valid geolocation context that lacks plottable coordinates;
- exact Evidence drill-down using the PR 25A `evidence_id`;
- loading/error/empty/truncated states and i18n;
- component and real-browser coverage of the principal map rendering workflow.

PR 25B does not add spatial queries, PostGIS, clustering-driven inference, geographic scoring, cross-Investigation maps, historical movement, or broader GEOINT capabilities.

Delivered (PR 25B implementation summary):

- **Dependencies:** `leaflet@1.9`, `react-leaflet@5.0` (peer-compatible with
the repository's React 19 without forced peers), `@types/leaflet`; no Leaflet
plugin; lockfile committed; Leaflet CSS bundled locally and marker assets
inlined by Vite (no production marker 404s, no CDN); standard
credential-free OSM raster tiles with required attribution centralized in
`frontend/src/geolocation/map-config.ts` (no CSP change needed — Nginx ships
no CSP);
- **Transport/server state:** generated PR 25A aliases in `schema-types.ts`
(`InvestigationGeolocation`, `InvestigationGeolocationCollection`,
`GeoPrecisionName`); `geolocation-api.ts` calls the exact
`/investigations/:id/geolocations` path through the centralized `apiGet`
with no query string/cursor/limit and the AbortSignal propagated;
Investigation-scoped query key (`["investigations", id,
"geolocations"]`) with the 30s analytical stale time and no polling;
- **Pure view model** (`geolocation-map-model.ts`, no React/Leaflet
objects): defensive plottable-coordinate policy (finite in-range numbers
only; no clamping/centroid/geocoding/jitter), mappable/unlocated
partition preserving server order without mutating transport objects,
truncation propagated exactly, comma-joined location labels, neutral
precision/provider label keys, and the deterministic viewport policy
(single-point center at fixed zoom 8; multi-point `fitBounds` over every
mappable returned point with `[24,24]` padding and a zoom cap ≤ 8);
- **Route/tab:** `/investigations/:id/map` inside `InvestigationWorkspace`
as a primary route-owned tab (`tabs.map`) in the order Overview | Evidence |
Relationships | Map | Research | Timeline;
- **Page** (`InvestigationMapPage.tsx`): translated loading, error+Retry(
no Evidence fallback, no invented markers), honest empty and
coordinate-less states, explicit mixed-state counts, persistent visible
approximation disclaimer, persistent truncated warning (server bound never
bypassed), the Leaflet surface, the always-available non-map table of all
returned items, and exact Evidence provenance through the shared PR 24C
DetailDrawer/EvidenceDetail/`useEvidenceDetail` surface (exact
`evidence_id`, Investigation-scoped, no IP lookup/list scan/History
substitution); the Map URL state remains only the route itself;
- **Leaflet** (`InvestigationMap.tsx`): React-Leaflet-owned lifecycle
(StrictMode-clean, no manual map construction, no repeating timers),
`MapContainer`/`TileLayer`/`Marker`/`Popup`/`useMap`, one neutral marker
per mappable item (no risk/confidence/severity styling), popup with exact
IP + available city/region/country + precision/provider + distinct
observed/retrieved timestamps + exact `View Evidence` action, no
clustering/heat map/circle/polygon;
- **Coverage:** pure model B-M01..B-M10, labels B-L01..B-L05, viewport
B-V01..B-V07, API/query B-Q01..B-Q08, route page B-U01..B-U17,
Leaflet wrapper B-F01..B-F08 (rendering boundary mocked via
`src/test/react-leaflet-mock.tsx`; no live tile requests), provenance
B-P01..B-P06, accessibility B-A11Y01..B-A11Y08 — all passing under the
repo frontend gate (`api:check`, strict typecheck, ESLint, Vitest,
production build);
- **E24 real-stack browser spec** (`frontend/e2e/zz-geolocation.spec.ts`)
implements the principal Map workflow path (built frontend + Nginx + real
FastAPI + real PostgreSQL + durable worker, real PR 25A endpoint, no
geolocation interception, no dependence on live tile success).

> **E24 data prerequisite STOP (closed by PR 25C):** the PR 25C harness-only
> deterministic geolocation seeding seam (`tests/e2e_support/seed_geolocation.py`
> + `scripts/e2e-seed-geolocation.sh`) persists ordinary canonical IP Entities
> and `GEOLOCATION` Evidence into the throwaway E2E database through the normal
> repositories for an exact browser-created Investigation UUID, with no product
> fake-mode change. E24 now passes end-to-end with a real marker and exact
> Evidence provenance; PR 25B is therefore marked `[DONE]` and the original
> STOP report below is retained as history.

### PR 25C — Map analyst workflow integration and PR 25 closure [DONE]

**Delivered (PR 25C implementation summary):**

- **Deterministic E2E seeding seam (harness-only):**
  `tests/e2e_support/seed_geolocation.py` + `scripts/e2e-seed-geolocation.sh`
  persist normal canonical IP Entities and immutable `GEOLOCATION` Evidence
  into the isolated throwaway E2E PostgreSQL through the normal application
  repositories/UnitOfWork for an exact browser-created Investigation UUID
  and an allowlisted scenario (`single_mappable`, `multi_ioc`,
  `non_mappable`, `same_location`). Deterministic uuid5 identities and a
  fixed UTC retrieval epoch make repeated invocation idempotent/bounded;
  the seam is offline, non-LLM, explicitly invoked, guarded by both
  `ATI_OPERATING_MODE=fake` and the dedicated `ATI_E2E_SEEDING_ENABLED`
  flag, and exposed through **no HTTP endpoint** (no browser DB
  credentials, no seed service);
- **Map-origin typed pivots:** marker popup and non-map rows expose
  `entityActions(item.entity_id, item.ip_address, "map_entity")` through
  `frontend/src/geolocation/GeolocationEntityActions.tsx` (single new
  `map_entity` source kind; existing `Evidence`/`Relationships`/
  `Research` resources, separate source/target Relationship actions,
  IP-identity breadcrumb, unchanged PR 24 PivotWorkspace constraints, no
  viewport state in the URL, no client OR merge, no dead-end broadening);
- **E24 closure:** `zz-geolocation.spec.ts` seeds `single_mappable`, opens
  the Map, consumes the real `/geolocations` endpoint, verifies a real
  marker and exact persisted Evidence provenance, and no longer skips;
- **Real-stack matrix** (`zz-geolocation-workflow.spec.ts`): E25 multi-IOC
  typed pivots, E26 same-coordinate inspectability (no jitter/cluster),
  E27 coordinate-less actionable context, E28 empty/isolation — all
  passing on the full E2E stack;
- **Coverage:** seeder unit C-S01..C-S13, real-PostgreSQL SG01..SG07
  (including an authenticated real `/geolocations` read), map-action
  C-P01..C-P12, pivot URL/model C-V01..C-V08, and the E24-E28 browser
  specs;
- **Docs/compliance:** `ARCHITECTURE.md`, `API.md`, `TESTING.md`, and this
  plan reconciled; the PR 25A-C functional compliance sweep classifies all
  material requirements COMPLIANT, with minor residuals (PR 25A duplicated
  G-P labels, optional stronger statement-count instrumentation, naming/
  test-traceability touches) carried to the dedicated final PR 25-series
  cleanup, which is **not** marked complete here.

Complete the map as an analyst exploration surface without turning geography into an inference engine:

- integrate Map navigation with the existing PR 24 typed pivot/drill-down model where a semantically valid entity/Evidence transition already exists;
- preserve exact Investigation, Entity, and Evidence identity across map/table/detail transitions;
- provide bounded multi-IOC correlation-oriented presentation for the current Investigation without inventing geographic relationships;
- ensure overlapping/same-location entities remain individually inspectable through an accessible non-map representation or bounded location grouping;
- preserve provenance, precision, approximation warnings, and epistemic boundaries through all map interactions;
- add deterministic real-stack E2E coverage for multi-IOC map exploration, exact Evidence provenance, non-mappable context, empty/dead-end behavior, and safe navigation;
- reconcile `API.md`, `ARCHITECTURE.md`, `TESTING.md`, and `PR_PLAN.md` and perform a final PR 25A–C source/test compliance sweep.

PR 25C must not infer co-location, coordination, common ownership, targeting, maliciousness, attribution, or victim geography merely because indicators appear geographically near one another.

### PR 25D — PR 25-series compliance closure [DONE]

PR 25D is the final closure PR for the PR 25 geolocation-map series. It
added no geolocation, Map, API, persistence, pivot, provider, spatial, or
GEOINT functionality; it closes the demonstrated PR 25A-C test-traceability
residuals and verifies the complete geolocation surface.

Delivered (PR 25D implementation summary):

- **Fresh source-level audit of PR 25A-C:** every material requirement was
  re-verified against actual source/tests (not `[DONE]` summaries or
  implementation summaries) and classified COMPLIANT/PARTIAL/MISSING/
  OUT-OF-SCOPE; no material production defect was found and no STOP
  condition fired;
- **G-P matrix normalization:** the three tests that incorrectly reused
  `gp12` were renamed to the distinct `test_gp14_malformed_persisted_facts_fail_closed`,
  `test_gp15_partial_pair_from_raw_facts_fails_closed`, and
  `test_gp16_nonexistent_investigation_empty`; G-P01..G-P13 keep their
  established meanings (G-P12 remains the historical-volume test, G-P13
  the bounded-single-read test) and the module plus `TESTING.md` now
  document G-P01..G-P16; `tests/integration/test_query_geolocation.py`
  and `docs/TESTING.md` updated;
- **G-M matrix normalization:** the duplicated `gm10` unit identifiers
  became `test_gm11_invalid_precision_vocabulary_rejected` and
  `test_gm12_invalid_country_code_rejected`; the module plus
  `TESTING.md`/`PR_PLAN.md` now document G-M01..G-M12;
- **Seeder unit matrix normalization:** the duplicated `cs04` identifier
  became `test_cs13_cli_guard_refuses_without_flag`; the module plus
  `TESTING.md`/`PR_PLAN.md` now document C-S01..C-S13;
- **G-P13 disposition:** existing test support was explicitly inspected
  for SQL statement-counting infrastructure (SQLAlchemy event listeners,
  query counters, statement recorders). The only SQLAlchemy event
  listeners in the repository register batch composite types (the E2E
  seeder) or track UnitOfWork lifecycle phases (the analyst pipeline
  transaction tracker); no reusable lightweight statement-count fixture
  exists. Per the PR 25D decision (STOP condition D03), no generic
  query-count framework was created; the structural verification (one
  `session.execute`, DB-side ranked latest-per-entity selection,
  server-side `max_items + 1`, no per-item repository gets, no Python
  historical grouping) is retained and documented at the test and in
  `TESTING.md`;
- **B/C/SG/E traceability audit:** B-M/B-L/B-V/B-Q/B-U/B-F/B-P/B-A11Y,
  C-P/C-V, SG01..SG07, and E24-E28 were audited for duplicate or
  misleading identifiers and doc mismatches; no demonstrated defect was
  found (the G-A04 gap is documented: no lower-privilege role exists in
  the v0.1 UserRole vocabulary); the E22/E22-B Chromium/MUI wedge remains
  separately classified per `docs/INVESTIGATION_STABILITY.md`;
- **E24-E28 rerun:** all four real-stack browser specs pass on the
  canonical full stack through the real PR 25A read path with assertions
  unweakened;
- **No production/API/schema/persistence change:** the endpoint, operation
  ID, DTO, exact IDs, paired coordinates, provider/precision/timestamps,
  `{items,truncated}`, authentication, Map route, 30s stale time/no
  polling, viewport policy, neutral markers, coordinate-less
  presentation, disclaimer, exact Evidence drill-down, `map_entity`
  behavior, and the deterministic seeder implementation are unchanged;
  no migration, index, provider, package, generated contract, or Leaflet
  file was modified;
- **Documentation reconciliation:** `TESTING.md` and this plan updated;
  `ARCHITECTURE.md` and `API.md` required no change after the fresh
  audit.

PR 25A-C remain `[DONE]`; the PR 25 series is now closed with no known
functional residual. PR 26 remains the next v0.1 feature phase.

### PR 25 overall boundaries

Across PR 25A–C:

- DB-IP City Lite remains the v0.1 geolocation source and uses its already-delivered local MMDB provider path;
- the Map consumes persisted Evidence and never invokes providers directly;
- geolocation remains approximate contextual information, not maliciousness evidence or physical attacker/device location;
- no new geolocation persistence model is introduced;
- no PostGIS is required until ATI needs actual spatial queries;
- no victim geography, targeting geography, infrastructure-to-victim correlation, movement analysis, country-risk scoring, heat-map inference, or broader GEOINT analytics;
- no cross-Investigation/global map in v0.1;
- no client-side reconstruction of unbounded datasets;
- every displayed location retains exact Evidence provenance and the established Evidence/Research/Assessment epistemic boundaries.

## PR 26 — GEOINT

PR 26 delivers ATI's v0.1 infrastructure-focused GEOINT subsystem as seven bounded PRs. It builds on PR 25's persisted `GEOLOCATION` Evidence and Investigation Map without replacing or retrofitting the PR 25 read path.

The Monitor/scheduler/snapshots/diffs/Findings/job-administration scope formerly assigned to PR 26 is deferred to **v0.2** and consigned to `docs/PR_PLAN_V02.md`. `PR_PLAN_V02.md` is not yet effective and does not supersede this active v0.1 plan.

### PR 26 series invariants

Across PR 26A-G:

- **Locations are not Entities.** `Location` is canonical geographic/reference data. Geographic hierarchy, containment, and spatial relationships do not use ordinary ATI `Entity`, `Relationship`, or `RelationshipObservation` records.
- **Historical geographic observations are explicit and immutable.** `EntityLocationObservation` explicitly records the Entity, canonical Location, supporting Evidence/provenance, precision, and relevant timing. It is append-only historical truth.
- **Current state is separate from historical observation.** `EntityLocation` is the materialized current Entity-to-Location association and references the most specific canonical Location actually supported. Historical changes remain in `EntityLocationObservation`.
- **Operational resolution state is separate from geographic truth.** `GeoResolution` owns pending/processing/resolved/unresolvable/failed workflow state, attempts, leases, retries, and resolution outcome metadata. Pending or failed work is not an `EntityLocationObservation`.
- **Canonicalization never invents precision.** Country-level input cannot become city-level truth merely because reference or spatial data makes a more specific Location plausible.
- **PR 25 remains valid and unchanged.** The existing persisted `GEOLOCATION` Evidence -> bounded PR 25A projection/API -> PR 25B/25C Map workflow remains supported. PR 26 derives richer geographic state from persisted Evidence; it does not make `EntityLocation` an alternate PR 25 Map source.
- **PostGIS owns spatial computation, not threat interpretation.** Containment, intersection, distance, proximity, and common geography are geographic facts/signals only. They do not establish cyber relationships, maliciousness, common ownership, campaign association, coordination, targeting, or attribution.
- **Exact provenance remains mandatory.** Analyst-visible geographic observations and derived geographic context remain drillable through `EntityLocationObservation` to exact supporting Evidence/source.
- **Analyst-facing geographic reads remain bounded and appropriately Investigation-scoped.** Global canonical `Location` reference data must never become a route for cross-Investigation data leakage or unbounded client reconstruction.
- **ATI's PostgreSQL ownership model continues.** All GEOINT mutations, reconciliation, current-state maintenance, versioning, asynchronous work claiming, leases/retries, stale-claim recovery, and workflow state transitions are performed through versioned PostgreSQL stored functions. Python repositories remain thin callers. Purpose-built bounded read/query services, including PostGIS spatial projections, may execute SQL directly under ATI's existing query-service pattern.
- **Database locks coordinate only short atomic transitions.** Claiming uses a short stored-function transaction, internally permitted to use `FOR UPDATE SKIP LOCKED`, which persists ownership/lease state and commits before geographic resolution begins. No database transaction or row lock is held while external/application geographic resolution is performed.
- **Leases coordinate asynchronous processing.** Completion occurs in a separate short stored-function transaction with ownership/version/idempotency validation. Expired claims are recoverable and contended updates use deterministic ordering.
- **Infrastructure GEOINT is the v0.1 boundary.** PR 26 does not expand into victim geography, targeting geography, physical-person tracking, generalized movement intelligence, facilities intelligence, country-risk scoring, or attribution.
- **Existing epistemic boundaries remain authoritative.** Evidence, Research, Assessment, and Report semantics are not weakened by geographic enrichment or agentic GEOINT reasoning.

### PR 26A — GEOINT domain and persistence foundation [DONE]

Establish:

- `Location` as canonical geographic/reference data, initially country, administrative-area, and city;
- `EntityLocation` as current materialized Entity-to-Location association;
- immutable append-only `EntityLocationObservation` with explicit Entity, Location, Evidence/provenance, precision, and timing;
- `GeoResolution` as durable operational resolution/work state;
- domain invariants for precision, canonical identity, provenance, current-vs-history separation, and fail-closed malformed state;
- PostgreSQL schema/migrations and versioned stored functions for all mutations/reconciliation;
- thin repositories and UnitOfWork integration;
- deterministic unit and real-PostgreSQL integration tests.

No PostGIS spatial analysis, asynchronous resolver, analyst GEOINT API/UI, or agentic reasoning yet.

Delivered (PR 26A implementation summary):

- **Domain contract** (`domain/geoint.py`): bounded `LocationType`/
  `LocationPrecision` (`country`/`administrative_area`/`city`) and
  `GeoResolutionStatus` (`pending`/`processing`/`resolved`/`unresolvable`/
  `failed`) enums; frozen `Location`, `EntityLocation`,
  `EntityLocationObservation`, and `GeoResolution` models with
  `extra="forbid"`, timezone-aware-UTC validation, bounded nonblank
  strings, deterministic two-letter country-code normalization (no
  reference data), type-specific parent/admin shape rules, and the
  approved identity tuple `(type, country_code, admin1_code, admin2_code,
  canonical_name)`; `EntityType` unchanged (Location is not an Entity); no
  geometry/PostGIS fields anywhere.
- **PostgreSQL schema (migration 0025, SQL API v0021):**
  `ati.location` (canonical identity enforced by a unique COALESCE
  expression index, type-shape/country-code/bound checks, self-parent
  guard), `ati.entity_location_observation` (immutable, exact
  Entity/Location/Evidence FKs, no `investigation_id`, no
  `domain_object_history` duplication), `ati.entity_location` (one row per
  Entity, `latest_observation_id` FK to the observation table,
  `first_observed_at <= last_observed_at`), and `ati.geo_resolution`
  (unique `(entity_id, evidence_id)` pair, status/attempt/error-code
  checks, no second queue table), plus four database-owned version
  sequences.
- **Versioned stored functions:** `ati.upsert_location` (race-safe
  create-once/reuse, incompatible-state rejection), `ati.append_entity_location_observation`
  (database-side provenance validation with typed SQLSTATEs `U26A1`-`U26A6`,
  immutable append, and atomic EntityLocation reconciliation under
  `(COALESCE(observed_at, retrieved_at), observation_id)` currentness with
  UUID tie-break and no current-state rewind), and
  `ati.create_geo_resolution` (initial PENDING create with race-safe
  idempotent pair reuse and `U26A8` duplicate-state rejection). No
  claim/lease/retry/completion functions exist.
- **Repositories/UoW:** narrow `LocationRepository`,
  `EntityLocationRepository` (read-only, no mutation path),
  `EntityLocationObservationRepository`, and `GeoResolutionRepository`
  ABCs plus thin `Postgres*` implementations wired into the existing
  `UnitOfWork`/`PostgresUnitOfWork`; dedicated SQLSTATE-to-typed-error
  mapping (`U26A1`-`U26A9`); repositories never commit, never allocate
  versions, and never reconcile EntityLocation in Python.
- **Tests:** G26A-D01..D14 domain unit matrix and G26A-P01..P34
  real-PostgreSQL matrix (round-trip, identity reuse/version churn,
  concurrent upsert/create, provenance, rewind/non-rewind reconciliation,
  tie-breaks, rollback atomicity, no observation history duplication, no
  claim/queue/PostGIS leakage, authoritative versions), plus migration
  upgrade/downgrade coverage proving existing Entity/Evidence (including
  PR 25 GEOLOCATION Evidence) data survives and no PostGIS extension is
  required.
- **Documentation:** `DATABASE.md` (delivered GEOINT persistence tables,
  canonical identity, reconciliation, initial GeoResolution, SQL API
  v0021 / migration 0025, PR 26B PostGIS qualification),
  `ARCHITECTURE.md` (26A delivered vs 26B-G planned), `TESTING.md`
  (G26A-D/G26A-P matrices and the canonical PostgreSQL path). Fake runtime
  and PR 25 Map behavior are unchanged.

### PR 26A-2 — EntityLocation version-allocation consistency [DONE]

Corrective child of PR 26A. PR 26A created the SQL API v0021 persistence
foundation and `ati.entity_location_version_seq`, and used the sequence for
initial `EntityLocation` creation, but the v0021 reconciliation path advanced
changed current rows with `version = target.version + 1`. PR 26A-2 closes
that inconsistency through the next immutable SQL API:

- **Versioned SQL API v0022 (migration 0026):** redefines only
  `ati.append_entity_location_observation`, preserving the public signature,
  return shape, provenance validation (`U26A1`-`U26A6`), deterministic
  currentness ordering, mutation predicate, and the atomic append +
  reconciliation transaction. Both initial creation and every actual
  current-state `DO UPDATE` now allocate the persisted version from
  `nextval('ati.entity_location_version_seq')`. No schema, sequence,
  constraint, or index changes; existing EntityLocation versions are
  database-owned historical tokens and are not rewritten. SQL API v0021 is
  immutable and unedited; its downgrade reinstalls the v0021 function
  definitions.
- **Version semantics:** `EntityLocation.version` is a database-issued
  materialized-state change token, monotonic for successive committed
  mutations of one row but **not contiguous**; sequence gaps caused by
  rollback, contention, or PostgreSQL evaluation are valid. A historical
  observation that does not mutate current state leaves the persisted
  version unchanged; an earlier-time-only observation extending
  `first_observed_at` is a real mutation and receives a new token.
- **Tests:** real-PostgreSQL G26A2-P01..P05 (initial version is the exact
  next sequence value; forced-gap later-current mutation proving the version
  is not `before + 1` — the primary regression, which failed on pre-fix main
  for that reason; earliest-time-only mutation receiving a new token;
  true no-op leaving the persisted version unchanged; rollback preserving
  the prior persisted version), corrected G26A-P34 (monotonic `> before`
  rather than contiguous `+ 1`), and a narrow source-contract unit guard
  (`tests/unit/test_geoint_version_contract.py`) pinning the active SQL API
  to sequence allocation. The original G26A-D/G26A-P matrices, migration
  upgrade/downgrade coverage, and the full repository gates remain green.
- **Documentation:** `DATABASE.md` (version-token semantics, SQL API
  v0022/migration 0026), `TESTING.md` (G26A2 corrective matrix). Domain,
  repository, UoW, API, fake-data, PostGIS, and PR 25 behavior are
  unchanged.

### PR 26B — Canonical geography and PostGIS foundation [DONE]

Delivered the deterministic geographic substrate:

- **Runtime:** project-owned PostgreSQL 18 image (`docker/postgres/Dockerfile`, based on `docker.io/pgvector/pgvector:0.8.1-pg18` + `postgresql-18-postgis-3` from PGDG) ships both pgvector and PostGIS; `compose.yaml` builds it; migration 0027 runs `CREATE EXTENSION IF NOT EXISTS postgis` so existing ATI databases with PostGIS-installed servers also upgrade. The migration adds `ati.location.geometry geometry(Geometry, 4326)` and `centroid geometry(Point, 4326)` (SRID-4326 `geometry`, never `geography`), the GiST index on non-null geometry, and the b-tree `(location_type, country_code, canonical_name)` narrowing index; existing PR 26A rows keep NULL spatial fields. Downgrade drops the spatial objects in dependency-safe order and removes PostGIS only when PR 26B introduced it, never with `CASCADE`.
- **Reference/spatial write path (SQL API v0023, migration 0027):** `ati.upsert_reference_location` implements the deterministic outcome algebra CREATED/UNCHANGED/ENRICHED/CONFLICT (U26B*) with database-owned `ST_PointOnSurface` representative-point derivation (documented as on-surface, never `ST_Centroid`), city canonical-point consistency, and fail-closed spatial validation (SRID 4326, emptiness, polygon validity, type rules, WGS84 bounds). PR 26A `upsert_location` (v0021) remains unchanged.
- **Reference identity:** deterministic UUIDv5 (`ATI_LOCATION_NAMESPACE` over the canonical identity tuple), independent of external source record IDs; repeated unchanged ingestion is a true no-op; approved spatial refresh enriches the same canonical row with a new database-issued version.
- **Ingestion:** `ReferenceIngestionService` (validated, parent-before-child, one atomic transaction), the production ATI Geography Corpus NDJSON parser (`infrastructure/sources/geography`), the `ati-geography-import` CLI, and small checked-in fixtures (US/WA/Seattle, US/TX/Dallas, CA/BC/Vancouver, duplicate-name/ambiguity cases, coordinate-less records, synthetic boundary/overlap polygons). Upstream derivation: GeoNames (CC BY 4.0) + Natural Earth (public domain), documented in `DATA_SOURCES.md`; migrations never download data.
- **Resolution primitives:** `GeographicClaim` (lat/lon pairing, WGS84 bounds, precision cannot exceed semantic claim support, coordinates never upgrade precision), the `CanonicalLocationResolution` result algebra (resolved/ambiguous/unresolvable), and `CanonicalGeographyResolver` (distinct from PR 26C's `LocationResolver`) with deterministic narrowing and boundary-inclusive `ST_Covers` containment disambiguation; no nearest-city/fuzzy geocoding and no threat inference from spatial facts.
- **Tests:** G26B-D/P/I/R matrices (unit + real PostgreSQL + PostGIS integration, EXPLAIN-based index eligibility, migration upgrade/downgrade with data preservation), plus `G26A-P08` updated for the intentional PostGIS/spatial-column introduction; all prior G26A/G26A-2, PR 25 map, RAG/pgvector, and migration suites remain green.
- **Documentation:** `ARCHITECTURE.md`, `DATABASE.md`, `DEPLOYMENT.md`, `TESTING.md`, `DATA_SOURCES.md`, `LICENSING.md` reconciled with the delivered behavior.

### PR 26B-2 — Geography import operational completion [DONE]

Corrective child of PR 26B (compliance-review completion work, recorded
separately rather than rewriting PR 26B history). PR 26B delivered the
canonical-geography and PostGIS foundation. Two operational gaps remained:
(1) ``geography_import_main()`` existed but the installed entry point was
believed unregistered — fresh `main` in fact already registers
`ati-geography-import` (PR 26B shipped it), so 26B-2 closes gap 1 with
installed-package proofs instead of a re-registration; and (2) ATI
documented the ATI Geography Corpus but provided no deterministic
derivation path from supported upstream reference data, which 26B-2
closes end to end:

- **Source adapters** (`infrastructure/geoint/geonames.py`,
  `infrastructure/geoint/natural_earth.py`): bounded `GeoNamesReferenceSource`
  and `NaturalEarthReferenceSource` parsers for the exact supported inputs
  (GeoNames `countryInfo.txt`, `admin1CodesASCII.txt`, and a supported
  cities file such as `cities1000.txt`; Natural Earth 10m country and
  admin-1 GeoJSON collections). Parsers normalize only, never write
  PostgreSQL, never download, and fail closed on unsupported record
  shapes, malformed coordinates, and invalid/non-polygonal geometry.
- **Deterministic builder** (`infrastructure/geoint/geography_corpus_builder.py`):
  `GeographyCorpusBuilder` joins GeoNames records with Natural Earth
  geometry by stable ISO country codes and country+subdivision codes,
  with the bounded fallback of exact normalized-name equality within one
  country and the version-controlled `ADMIN1_CODE_EXCEPTIONS` table
  (documented, tested; never guessy). Emits the existing PR 26B corpus
  schema with parent-before-child ordering, byte-deterministic
  serialization, WGS84/SRID-4326 geometry only, a bounded city policy
  (orphan/duplicate cities rejected and reported; optional
  `--min-population`/`--countries` filters), and reports every unmatched
  Natural Earth object without ever creating a guessed identity.
- **CLI:** installed `ati-geography-build` command
  (`geography_build_main` in `cli.py`, registered in `[project.scripts]`)
  building the corpus from explicit local-file arguments with concise
  reporting and `--validate-only`; `ati-geography-import` semantics are
  unchanged.
- **Tests:** G26B2-CLI/SRC/BLD unit matrices and the G26B2-E2E
  real-PostgreSQL + PostGIS proof (real-format fixtures -> build -> corpus
  -> import -> `ati.location`: US -> Washington -> Seattle with
  deterministic UUIDv5 identities, hierarchy, polygon/city-point
  geometry, correct SRID/type, and an idempotent second import with no
  version churn). All PR 26A/26A-2/26B, postgres/pgvector, migration, and
  PR 25 Map suites remain green.
- **Documentation:** `DATA_SOURCES.md` (executable upstream derivation
  workflow, exact supported inputs/versions, licensing, unsupported
  cases), `DEPLOYMENT.md` (obtain -> build -> import -> runtime),
  `ARCHITECTURE.md` (explicit adapters != corpus != ingestion boundary),
  `TESTING.md` (G26B2 matrices). No database migration or SQL API change;
  no canonical-identity, schema, or PR 26C lifecycle change.

### PR 26C — Asynchronous geographic resolution

Deliver:

- `LocationResolver` application abstraction and typed claim/result contracts;
- bounded `GeoResolution` lifecycle;
- versioned stored functions for atomic work claiming, leases, attempts/retries, stale-lease recovery, failure/unresolvable transitions, and completion;
- bounded `FOR UPDATE SKIP LOCKED` claim semantics internally where appropriate, committed before resolution work;
- separate Geo Resolver Python process/container;
- no DB locks/transactions held while resolution executes;
- atomic successful completion that canonicalizes/reuses Location state, appends `EntityLocationObservation`, reconciles `EntityLocation`, and transitions `GeoResolution`;
- idempotency, version validation, deterministic lock/update ordering, multi-worker concurrency, crash/recovery, retry, and bounded-batch tests;
- PostgreSQL durable state + leases as the initial work-queue mechanism; no Kafka/NATS/Redis requirement.

The resolver issues no ad-hoc mutation SQL; mutations go through versioned stored functions.

### PR 26D — GEOINT query and API layer

Deliver:

- bounded Investigation-scoped PostgreSQL/PostGIS query contracts;
- Entity -> current Location and geographic observation history;
- Location -> Investigation-scoped Entities/observations;
- exact `EntityLocationObservation` -> Evidence provenance;
- bounded geographic summaries;
- narrowly justified containment/proximity primitives for concrete analyst workflows;
- deterministic ordering, pagination/bounds, scope enforcement, DTOs/errors, and OpenAPI coverage;
- no arbitrary PostGIS expression API or cross-Investigation leakage.

Purpose-built bounded reads may execute SQL/PostGIS directly; mutations remain stored-function-owned.

### PR 26E — Analyst GEOINT workspace

Deliver:

- geographic Map/table views over PR 26 query contracts;
- Location and Entity exploration through the existing PR 24 typed pivot/workspace architecture;
- Entity -> Locations, Location -> scoped Entities, and observation -> Evidence/provenance transitions;
- explicit current-vs-historical geographic context;
- precision/provider/provenance/approximation semantics;
- individually inspectable same-location entities without implied cyber association;
- accessible non-map representations;
- bounded deterministic real-stack workflows.

Visual proximity is never an analytical conclusion.

### PR 26F — Agentic GEOINT reasoning

Deliver:

- bounded deterministic GEOINT tool contracts such as geographic summary, locations-for-entity, entities-in-location, geographic history, and narrowly approved spatial queries;
- agent integration consuming deterministic PR 26 query results rather than arbitrary SQL/PostGIS;
- structured outputs with exact geographic observation/Evidence support;
- geographic pattern/signal and temporal reasoning where supported;
- safeguards preventing proximity/common city/common coordinate from becoming relationship, maliciousness, ownership, campaign, coordination, targeting, or attribution without independent support;
- deterministic `FakeLlmClient` tests and real PostgreSQL/PostGIS integration;
- no LLM ownership of canonical Location resolution, persistence reconciliation, or spatial truth.

### PR 26G — GEOINT evaluation and series closure

Deliver:

- deterministic fixtures covering country/region/city precision, changing locations, same-location unrelated infrastructure, coordinate-less/ambiguous/unresolvable claims, retries, stale leases, and Investigation isolation;
- evaluation of tool selection/results, provenance closure, unsupported geographic inference, and structured agent outputs;
- real-stack E2E from persisted geographic Evidence through asynchronous resolution, canonical Location/observations, API, analyst exploration, exact Evidence drill-down, and agentic GEOINT analysis;
- concurrency/crash-recovery tests for claim/lease/completion;
- boundedness and justified PostGIS query-plan/index eligibility checks;
- final source/test compliance audit of PR 26A-F;
- documentation reconciliation;
- no generic PR 27 evaluator-platform scope.

PR 26G is closure/evaluation, not feature expansion.

### PR 26 overall boundaries

Across PR 26A-G:

- no Monitor/scheduler/snapshot/diff/Findings/job-administration work; it is deferred to v0.2 in `PR_PLAN_V02.md`;
- no victim/targeting geography, infrastructure-to-victim correlation, physical-person tracking, generalized movement analysis, facilities intelligence, country-risk scoring, or attribution;
- no geographic fact automatically creates an ATI `Relationship`;
- no LLM-generated canonical geographic truth;
- no direct browser/provider geocoding;
- no unbounded client-side spatial reconstruction;
- no distributed broker requirement;
- no long-running transaction around asynchronous resolution;
- no application-side mutation/reconciliation bypassing versioned stored functions;
- PR 25's existing Map remains valid while PR 26 adds the richer GEOINT model and analyst workflows.


## PR 27 — Evaluation and release hardening

Expand to curated scenarios, deterministic invariants, agent evaluations, end-to-end trajectory evaluation, adversarial content, canonical malicious-domain/IP/malware trajectory, release gates, stability, performance/cost/latency reporting, licensing/source-term checks, and release documentation.

## v0.1 dispatch boundary

v0.1 uses `LocalTaskDispatcher`. Distributed task-broker infrastructure is explicitly outside the v0.1 requirement.
