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

## PR 20C — Evidence Analyst evaluation framework

Deliver behavioral evaluation covering verdict correctness, confidence calibration, Finding completeness, Evidence support, RelationshipObservation support, semantic grounding, contradictions, unsupported claims, invalid citations, stale/conflicting evidence, contextual-vs-maliciousness regressions, limitations, unresolved questions, and recommended next steps.

Hard provenance invariants remain zero-tolerance.

## PR 21 — Adaptive pivots and stopping

Deliver evidence-driven pivots, deterministic pivot-policy validation, budgets, duplicate suppression, stopping rules/reasons, canonical trajectory, and coordinator trajectory evaluations.

PR 21 consumes PR 19A queue/state mechanics, PR 19B provider execution, PR 19C dispatch, and PR 20A/20B validated analytical output. PR 20C provides the analyst evaluation baseline.

The dispatcher does not decide investigative policy; it dispatches only work already selected/authorized by orchestration.

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
