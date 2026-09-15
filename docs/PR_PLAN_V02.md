# ATI --- v0.2 Future PR Plan

> **Planning status --- NOT YET EFFECTIVE**
>
> `PR_PLAN_V02.md` is a holding plan for work currently intended for ATI
> v0.2. It is **not yet an effective implementation roadmap**, does not
> supersede `PR_PLAN.md`, and must not be used to infer that any v0.2 PR
> is authorized, scheduled, or ready for implementation.
>
> Until the project explicitly promotes this document to the active
> roadmap, `PR_PLAN.md` remains authoritative for current development.
> This file exists only to consign and preserve future work that has
> been deliberately deferred to v0.2.

## Purpose

This document collects feature work deliberately deferred from the
active ATI v0.1 roadmap so that the work is not lost while keeping the
current release plan bounded.

PR numbers and decomposition in this document are provisional. They
should be revisited when v0.2 planning formally begins and after the
delivered v0.1 architecture is known.

------------------------------------------------------------------------

## Future v0.2 work

### Monitors, diffs, findings, jobs and administration

**Origin:** moved from the former
`PR 26 — Monitors, diffs, findings, jobs and administration` entry in
the active `docs/PR_PLAN.md`.

Deliver:

-   Monitor persistence;
-   scheduler;
-   normal Investigation execution initiated from monitors;
-   snapshots and diffs;
-   material Finding generation;
-   findings inbox;
-   PostgreSQL-backed jobs;
-   administration/system UI;
-   operational visibility.

Architectural boundary retained from the current plan:

> The PostgreSQL job queue schedules durable investigation-level work.
> PR 19C `TaskDispatcher` is the in-investigation execution-dispatch
> seam. These are separate responsibilities.

#### Intent

Monitor functionality turns ATI from an analyst-initiated investigation
tool into a system capable of repeatedly executing defined investigative
work and surfacing material changes over time.

The v0.2 implementation should preserve the existing Investigation
execution architecture rather than create a separate monitor-specific
investigation engine. A Monitor schedules or initiates normal durable
Investigation work; the existing Investigation lifecycle, Coordinator,
provider execution, Research, Assessment, Report, and provenance
boundaries remain authoritative.

#### Provisional scope

The future detailed plan should define at least:

1.  Monitor domain model and persistence.
2.  Monitor lifecycle and administrative operations.
3.  Scheduling semantics and scheduler process.
4.  Durable creation/enqueueing of normal Investigations from a Monitor.
5.  Idempotency, concurrency, missed-run, retry, and failure semantics.
6.  Snapshot semantics for completed monitored Investigations.
7.  Deterministic diff calculation between relevant snapshots.
8.  Definition of a material change.
9.  Material Finding generation and persistence.
10. Findings inbox/query APIs.
11. Analyst UI for monitor state, execution history, diffs, and
    findings.
12. PostgreSQL-backed job administration and operational visibility.
13. Authorization and audit semantics.
14. Deterministic unit, PostgreSQL integration, and real-stack E2E
    coverage.
15. Evaluation criteria for change detection and Finding quality where
    appropriate.

#### Boundaries to preserve

The future Monitor implementation must not:

-   bypass the normal Investigation execution path;
-   give the scheduler investigative-policy authority;
-   conflate the PostgreSQL durable job queue with PR 19C
    `TaskDispatcher`;
-   make Monitor state an alternate source of Evidence, Research,
    Assessment, or Report truth;
-   infer a material Finding merely because any underlying row changed;
-   silently create duplicate scheduled Investigations for the same
    logical run;
-   require distributed broker infrastructure unless separately
    justified by future scale requirements.

#### Provisional decomposition

The exact split is intentionally deferred. A likely future decomposition
is:

``` text
v0.2 Monitor A
    Monitor domain model, persistence and API

v0.2 Monitor B
    Scheduler and durable Investigation initiation

v0.2 Monitor C
    Snapshot and deterministic diff model

v0.2 Monitor D
    Material Findings and findings inbox

v0.2 Monitor E
    Administration, job operations and analyst UI

v0.2 Monitor F
    Evaluation, real-stack E2E and series closure
```

These identifiers are placeholders, **not assigned PR numbers**.

------------------------------------------------------------------------

## Deferred-work governance

Adding an item to this document means only:

> ATI currently intends to reconsider this capability during v0.2
> planning.

It does **not** mean:

-   its architecture is final;
-   its scope is approved;
-   its PR decomposition is fixed;
-   its dependencies have been satisfied;
-   implementation should begin;
-   it takes precedence over the active `PR_PLAN.md`.

When v0.2 planning begins, each item should be re-evaluated against the
then-current codebase and product goals before detailed execution plans
are created.
