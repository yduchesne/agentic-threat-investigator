# ATI — v0.3 Roadmap

> **Planning status — APPROVED TARGET / PR 29 SERIES**
>
> This document is authoritative for ATI v0.3 telemetry and observability work.
> The monitor/diff/findings roadmap previously held here is preserved in
> `ROADMAP_V04.md`.

## Purpose

ATI v0.3 establishes production-shaped application, distributed-system, and
LLM/agent observability without making observability part of domain correctness.
The implementation must remain fail-open relative to investigation and ingestion
execution and must preserve ATI's data-minimization rules.

The PR 29 series is deliberately split so telemetry semantics are defined before
instrumentation and infrastructure are added.

## Approved architecture

ATI uses two complementary observability planes.

### Application and infrastructure observability

```text
ATI services
    |
OpenTelemetry API / ATI telemetry helpers
    |
OpenTelemetry SDK/exporters
    |
+-------------+-------------+-------------+
| Prometheus  | Jaeger      | Loki        |
| metrics     | traces      | logs        |
+-------------+-------------+-------------+
              |
           Grafana
```

OpenTelemetry is the application-facing portability layer. Business code must
not depend directly on Prometheus, Jaeger, Loki, or Grafana APIs.

Repository-owned deployment and provisioning assets live under:

```text
infra/
  observability/
    prometheus/
    jaeger/
    loki/
    grafana/
      provisioning/
        datasources/
        dashboards/
      dashboards/
```

### LLM and agent observability

LLM/agent observability is a separate concern from general distributed tracing.
ATI provides a narrow internal LLM-observability contract with user-selectable
backends:

- LangSmith;
- Langfuse;
- NoOp / disabled.

Selection is configuration-driven. Investigation, Evidence, Assessment, Report,
retry, persistence, and evaluation correctness must never depend on either
vendor. ATI defines portable semantics and adapters translate them to the
selected backend; ATI does not reduce the abstraction to every vendor-specific
feature.

A model invocation may therefore produce an OpenTelemetry operational span and
also an LLM-observability event/trace. These records serve different purposes
and should share safe correlation identifiers where practical.

## Telemetry contract

PR 29A must establish the semantic contract used by the remainder of the series.

### Tracing

Instrument architectural boundaries, especially functions or methods fronting a
distributed system or network connection. Initial boundaries include:

- every concrete PostgreSQL repository method that performs database I/O;
- PostgreSQL UnitOfWork transaction lifetime plus commit/rollback execution;
- Kafka-compatible Evidence producer/consumer operations;
- Kafka/Redpanda consumer-flow health, including authoritative consumer-group
  lag and the metrics required to compare producer and consumer cadence;
- datasource HTTP/network acquisition;
- external intelligence-provider calls;
- LLM/model calls;
- external embedding or object-storage calls when present.

Representative ATI span names include:

- `ati.datasource.acquire`
- `ati.datasource.convert`
- `ati.evidence.publish`
- `ati.evidence.consume`
- `ati.evidence.persist`
- `ati.geo.resolve`
- `ati.investigation.execute`
- `ati.agent.invoke`
- `ati.llm.invoke`
- `ati.report.generate`

Trace context must propagate across asynchronous/distributed boundaries,
including Kafka-compatible message headers, using standard W3C trace context
where supported.

### Metrics

Metrics use stable names, explicit units, and bounded-cardinality attributes.
The contract must cover at least:

- Evidence messages sent;
- Evidence messages received;
- Evidence batches committed;
- Evidence batch commit failures;
- Evidence create outcomes;
- Evidence append outcomes;
- Evidence unchanged outcomes (the current persistence contract's
  `UNCHANGED` outcome; do not invent a parallel `ignore` domain outcome);
- Evidence processing failures;
- PostgreSQL repository-operation latency/failure metrics with bounded
  repository and operation dimensions;
- PostgreSQL UnitOfWork transaction lifetime and commit/rollback
  latency/outcome metrics;
- Kafka publish, poll, and offset-commit latency/failure metrics;
- producer-published, consumer-received, successfully-processed, and
  successfully-committed Evidence message counts;
- authoritative Kafka/Redpanda consumer-group lag per topic/partition, with
  aggregate lag and lag trend derived in Prometheus/Grafana;
- latency histograms for external/distributed operations where aggregate
  latency is operationally useful;
- bounded queue/backlog gauges only where the underlying system exposes
  authoritative state.

The exact semantics of sent/published, received, processed, committed, create,
append, and unchanged must be documented before instrumentation lands.
Consumer lag must come from authoritative Kafka/Redpanda group/partition state,
not from an application-side approximation. Backlog age should be exposed only
when the deployed Redpanda version provides a reliable authoritative source.

Attributes may describe bounded dimensions such as datasource instance,
semantic format, consumer, operation, or outcome when their cardinality is
known and controlled. Evidence IDs, Entity IDs, Investigation IDs, IP/domain
values, execution UUIDs, message IDs, and other unbounded identifiers must
never be Prometheus metric labels.

### Structured logs and correlation

Application logs remain structured stdout/stderr. OpenTelemetry trace/span IDs
are included when a current span exists so Grafana/Loki can correlate logs with
Jaeger traces. Existing safe operational identifiers such as `execution_id`
may remain log fields but must not become metric labels.

Telemetry must not capture credentials, authorization headers, unrestricted
provider payloads, prompts/model output by default, hidden reasoning, or other
content prohibited by `OBSERVABILITY.md`.

### Service identity and configuration

Each deployed ATI process must expose meaningful OpenTelemetry resource/service
identity (for example API, investigation worker, geo resolver, datasource
worker/producer, Evidence consumer as those processes exist).

Prefer standard OpenTelemetry environment variables and conventions for
OpenTelemetry SDK/exporter configuration. ATI-specific configuration should be
introduced only where ATI owns semantics not represented by standard OTel
configuration.

LLM observability has an explicit backend selector for `langsmith`,
`langfuse`, or `none`, with backend-specific configuration/secrets validated
only when that backend is selected.

## PR 29 sequence

### PR 29A — OpenTelemetry and LLM-observability foundation

Deliver:

1. OpenTelemetry API/SDK dependencies required by ATI.
2. A small ATI-owned telemetry module for initialization, canonical
   tracer/meter access, common attributes, naming, and configuration.
3. Canonical span names, metric names, units, and bounded attribute vocabulary.
4. Cardinality rules and data-minimization rules.
5. Structured-log trace/span correlation conventions.
6. Service/resource identity conventions.
7. Trace-context propagation contract for asynchronous boundaries.
8. A portable LLM-observability interface plus LangSmith, Langfuse, and NoOp
   adapter/configuration contracts.
9. Focused unit-test facilities using in-memory OpenTelemetry providers where
   useful.

10. Decorator-first instrumentation helpers for stable function/method
    execution boundaries. Prefer thin ATI-owned decorators over repeated
    OpenTelemetry span/timer lifecycle boilerplate.

Do not instrument the entire application in this PR. The purpose of 29A is to
make telemetry semantics stable before call sites multiply.

#### PR 29A-1 follow-up requirements

PR 29A-1 is a logical follow-up implemented on the same PR 29A branch/PR. It
freezes additional operational semantics required before application-wide
instrumentation:

1. **PostgreSQL repository coverage:** every public method of a concrete
   PostgreSQL repository/resolver that can execute PostgreSQL I/O is a
   telemetry boundary. Repository spans/latency use bounded static
   repository+operation dimensions; SQL text, bind parameters, IDs, and other
   high-cardinality values are prohibited.
2. **PostgreSQL UnitOfWork coverage:** transaction lifetime is measured
   independently from repository calls. Implicit commit/rollback on context
   exit and explicit `commit()`/`rollback()` execution are observable,
   including latency and failure outcomes. Repository spans intentionally nest
   inside the UoW transaction span.
3. **No initial SQLAlchemy/psycopg auto-instrumentation:** ATI instruments its
   stable repository/UoW boundaries to avoid duplicate spans, SQL-content
   leakage, and implementation-level noise.
4. **Kafka flow coverage:** publish, poll, offset commit, received message
   count, successfully processed message count, and successfully committed
   message count are distinct semantics. Partial publish failure counts only
   messages whose broker acknowledgement is known to have succeeded.
5. **Cadence/lag contract:** dashboards must be able to compare producer
   publication rate with consumer receive/process/commit rates and correlate
   them with authoritative consumer-group lag. Lag is partition-aware broker
   state; aggregate lag and lag trend are derived views, not application
   counters.
6. **Structural repository coverage:** unit tests or an explicit reviewed
   operation registry must make it difficult to add a new PostgreSQL repository
   I/O method without telemetry. Do not use brittle source-text parsing.

Instrumentation must remain observational: it may not change transaction,
delivery, acknowledgement, retry, idempotency, redelivery, or cancellation
semantics.

### Decorator-first instrumentation policy

As much as practical, ATI annotates stable function and method execution
boundaries with Python decorators owned by ATI and implemented on top of the
OpenTelemetry API. Typical uses include span creation, duration measurement,
standard success/failure status, exception recording, and static or
bounded-cardinality attributes.

Conceptually:

```python
@traced("ati.evidence.persist")
async def persist_batch(...):
    ...
```

or, when both tracing and aggregate latency are part of the contract:

```python
@telemetry.operation(
    span="ati.evidence.persist",
    latency="ati.evidence.persist.duration",
)
async def persist_batch(...):
    ...
```

Decorators must remain thin and backend-neutral; they must not couple business
code to Prometheus, Jaeger, Loki, Grafana, LangSmith, or Langfuse.

Explicit telemetry calls remain appropriate for semantic events or measurements
whose meaning depends on runtime results inside an operation, such as Evidence
create/append/ignore outcomes, committed record counts, batch size, publication
counts, or retry outcomes. Do not distort domain code merely to make such
runtime semantics expressible as decorators.

### PR 29B — Application instrumentation

Instrument the delivered architecture against the 29A contract:

1. All PostgreSQL repository I/O boundaries plus UnitOfWork transaction
   lifetime and commit/rollback operations, following the PR 29A-1 contract.
2. Kafka-compatible Evidence publication, polling, processing, and offset
   commit operations, including the distinct throughput counters required to
   compare producer and consumer cadence.
3. Datasource acquisition/network boundaries.
4. Evidence persistence and processing outcomes.
5. Geo-resolution external/persistence boundaries where operationally useful.
6. Investigation, agent, provider, LLM, RAG, and report operations where the
   existing architecture exposes stable boundaries.
7. Evidence sent/received/committed/create/append/ignore/failure counters.
8. Aggregate latency histograms where they provide operational value.
9. LLM/agent events through the selected LangSmith/Langfuse/NoOp abstraction,
   alongside OTel operational spans.

Instrumentation must not alter domain behavior, delivery semantics, transaction
ownership, retry semantics, or Evidence identity.

### PR 29C — Observability infrastructure

Add source-controlled local/deployment infrastructure under
`infra/observability/`:

- Prometheus for metrics;
- Jaeger for distributed traces;
- Loki for logs;
- Grafana for visualization/correlation;
- required OpenTelemetry export/collection wiring;
- authoritative Redpanda/Kafka operational metrics needed for consumer-group
  lag, partition/topic health, broker request health, replication, and
  storage/capacity visibility;
- PostgreSQL server-health metrics where appropriate (connections/pool
  saturation, transactions/rollbacks, locks/deadlocks, and capacity);
- Compose/deployment integration appropriate to ATI's existing runtime.

The observability stack is optional infrastructure. Its failure or absence must
not cause ATI investigation or ingestion failure.

### PR 29D — Grafana dashboards as code

Provision Grafana datasources and version-controlled dashboards from
`infra/observability/grafana/`.

Initial dashboards should answer:

- Is ATI healthy?
- Is work flowing?
- Is work accumulating?
- Where is time being spent?
- Which distributed/external boundaries are failing?
- What are Evidence throughput and create/append/unchanged outcomes?
- Are Evidence consumers keeping pace with producers?
- Is Kafka/Redpanda consumer lag growing, stable, or draining, and on which
  partitions?
- Is PostgreSQL repository/UoW latency constraining consumer throughput?
- What is the state of datasource and investigation activity?

Dashboard definitions must be reproducible from the repository rather than
requiring manual Grafana configuration.

## Testing boundary

PR 29 requires focused unit tests for ATI-owned telemetry semantics and
instrumentation. For example, a deterministic Evidence-consumer unit test may
assert exact sent/received/create/append/ignore counter behavior through an
in-memory meter provider.

There is **no dedicated telemetry integration-testing PR** and no PR 29E.
The series does not require integration tests whose purpose is to prove
Prometheus, Jaeger, Loki, Grafana, LangSmith, or Langfuse themselves work.

## Boundaries to preserve

PR 29 must not:

- make telemetry authoritative domain/product state;
- replace the Investigation timeline, audit log, or datasource operational log;
- make telemetry availability a prerequisite for ATI correctness;
- add high-cardinality identifiers as metric labels;
- capture sensitive/content-bearing data merely because a backend supports it;
- couple business code to a concrete telemetry backend;
- conflate general distributed tracing with LLM/agent observability;
- change Kafka Evidence delivery or PostgreSQL transaction semantics;
- create a second Evidence-processing path for observability;
- introduce a PR 29E telemetry integration-test phase.

## Exit criteria

The PR 29 series is complete when ATI has a stable OpenTelemetry contract,
instrumented delivered distributed boundaries and Evidence-flow metrics,
optional Prometheus/Jaeger/Loki/Grafana infrastructure, reproducible Grafana
dashboards, and a configurable LangSmith/Langfuse/NoOp LLM-observability
backend while preserving fail-open behavior and data minimization.

Future monitor/diff/findings work is tracked in `ROADMAP_V04.md`.
