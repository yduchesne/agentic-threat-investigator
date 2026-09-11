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

## PR 22 — Threat Research RAG agent

Deliver conditional research triggering, Research Agent, RAG claim/chunk citations, persisted research results, retrieval/synthesis evaluations, and no-relevant-context behavior.

RAG supplies contextual research, not live IOC facts. Execution must respect the PR 19C dispatch boundary rather than adding infrastructure-specific coupling to LangGraph.

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
