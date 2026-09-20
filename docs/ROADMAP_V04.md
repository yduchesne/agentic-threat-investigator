# ATI — v0.4 Roadmap

> **Planning status — FUTURE / NOT YET EFFECTIVE**
>
> `ROADMAP_V04.md` preserves work deferred beyond the active ATI v0.2 roadmap. It is not an implementation authorization. Scope and decomposition must be re-evaluated against the delivered v0.2 architecture before implementation begins.

## Purpose

ATI v0.4 is currently reserved for monitor-driven recurring investigations, change detection, findings, durable job administration, and related operational UI. This work was previously held in `PR_PLAN_V02.md`; it is now explicitly targeted at v0.3 because v0.2 is dedicated to the PR 28 global-Evidence and distributed-ingestion architecture.

## Future v0.4 work

### Monitors, diffs, findings, jobs and administration

Deliver:

- Monitor persistence;
- scheduler;
- normal Investigation execution initiated from monitors;
- snapshots and diffs;
- material Finding generation;
- findings inbox;
- PostgreSQL-backed jobs;
- administration/system UI;
- operational visibility.

Architectural boundary retained from v0.1:

> The PostgreSQL job queue schedules durable investigation-level work. PR 19C `TaskDispatcher` is the in-investigation execution-dispatch seam. These are separate responsibilities.

#### Intent

Monitor functionality turns ATI from an analyst-initiated investigation tool into a system capable of repeatedly executing defined investigative work and surfacing material changes over time.

The v0.3 implementation should preserve the existing Investigation execution architecture rather than create a separate monitor-specific investigation engine. A Monitor schedules or initiates normal durable Investigation work; the existing Investigation lifecycle, Coordinator, provider execution, Research, Assessment, Report, and provenance boundaries remain authoritative unless a later approved roadmap explicitly changes them.

#### Provisional scope

The future detailed plan should define at least:

1. Monitor domain model and persistence.
2. Monitor lifecycle and administrative operations.
3. Scheduling semantics and scheduler process.
4. Durable creation/enqueueing of normal Investigations from a Monitor.
5. Idempotency, concurrency, missed-run, retry, and failure semantics.
6. Snapshot semantics for completed monitored Investigations.
7. Deterministic diff calculation between relevant snapshots.
8. Definition of a material change.
9. Material Finding generation and persistence.
10. Findings inbox/query APIs.
11. Analyst UI for monitor state, execution history, diffs, and findings.
12. PostgreSQL-backed job administration and operational visibility.
13. Authorization and audit semantics.
14. Deterministic unit, PostgreSQL integration, and real-stack E2E coverage.
15. Evaluation criteria for change detection and Finding quality where appropriate.

#### Boundaries to preserve

The future Monitor implementation must not:

- bypass the normal Investigation execution path;
- give the scheduler investigative-policy authority;
- conflate the PostgreSQL durable job queue with PR 19C `TaskDispatcher`;
- make Monitor state an alternate source of Evidence, Research, Assessment, or Report truth;
- infer a material Finding merely because any underlying row changed;
- silently create duplicate scheduled Investigations for the same logical run;
- assume that the v0.2 Evidence distributed log is also the Investigation job queue.

#### Provisional decomposition

```text
v0.4 Monitor A
    Monitor domain model, persistence and API

v0.4 Monitor B
    Scheduler and durable Investigation initiation

v0.4 Monitor C
    Snapshot and deterministic diff model

v0.4 Monitor D
    Material Findings and findings inbox

v0.4 Monitor E
    Administration, job operations and analyst UI

v0.4 Monitor F
    Evaluation, real-stack E2E and series closure
```

These identifiers are placeholders, not assigned PR numbers.

## Deferred-work governance

Adding an item here means only that ATI currently intends to reconsider the capability during v0.4 planning. It does not mean its architecture is final, its scope is approved, its PR decomposition is fixed, dependencies are satisfied, or implementation should begin.
