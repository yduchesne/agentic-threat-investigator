# Agentic Threat Investigator — Observability

## Table of contents

- [Principle](#principle)
- [Observability layers](#observability-layers)
- [Internal abstraction](#internal-abstraction)
- [LangSmith v0.1](#langsmith-v01)
- [OpenTelemetry architecture (PR 29)](#opentelemetry-architecture-pr-29)
- [PR 29A delivered foundation](#pr-29a-delivered-foundation)
- [PR 29A-1 delivered coverage](#pr-29a-1-delivered-coverage)
- [PR 29B-1 delivered coverage](#pr-29b-1-delivered-coverage)
- [PR 29B-2 delivered coverage](#pr-29b-2-delivered-coverage)
- [LLM observability backends](#llm-observability-backends)
- [Correlation](#correlation)
- [Provider telemetry](#provider-telemetry)
- [Task dispatch](#task-dispatch)
- [LLM telemetry](#llm-telemetry)
- [RAG telemetry](#rag-telemetry)
- [Datasource operational log](#datasource-operational-log)
- [Data minimization](#data-minimization)
- [Structured logging](#structured-logging)
- [Metrics vocabulary](#metrics-vocabulary)
- [Evaluation portability](#evaluation-portability)
- [Failure behavior](#failure-behavior)

## Principle

ATI emits structured application telemetry and agent/LLM traces through internal observability abstractions.

LangSmith is the initial v0.1 agent/LLM observability backend, but it is not an architectural dependency.

ATI must remain functional when tracing is disabled or unavailable.

## Observability layers

| Layer | Purpose | v0.1 persistence/backend |
|---|---|---|
| Application logs | Runtime/service diagnostics | Structured stdout/stderr |
| Metrics | Operational counters/performance | Initial instrumentation; export backend may evolve |
| Investigation timeline | Analyst-facing workflow history | PostgreSQL |
| Audit | Security/governance history | PostgreSQL |
| Agent/LLM traces and evals | Development/debug/evaluation | LangSmith initially |

The investigation timeline and audit log are product data. LangSmith traces are not.

## Internal abstraction

Agent/application code depends on ATI observability interfaces rather than scattered direct LangSmith SDK calls.

Conceptual interfaces include:

```python
class TraceBackend(ABC):
    @abstractmethod
    def start_span(
        self,
        *,
        operation: str,
        attributes: dict[str, Any],
    ) -> TraceSpan:
        ...

    @abstractmethod
    def record_error(
        self,
        error: Exception,
        attributes: dict[str, Any],
    ) -> None:
        ...
```

The abstraction has two deliberately distinct concerns:

- general application/distributed telemetry uses OpenTelemetry through ATI's
  telemetry helpers and standard OTel APIs;
- LLM/agent observability uses ATI's portable LLM-observability contract,
  implemented by LangSmith, Langfuse, or NoOp adapters.

Business/domain code must not depend directly on Prometheus, Jaeger, Loki,
Grafana, LangSmith, or Langfuse APIs.

## LangSmith v0.1

LangSmith may be used for:

- LangGraph traces;
- LLM calls;
- tool execution visibility;
- prompt/model comparison;
- evaluation datasets;
- regression experiments.

ATI does not depend on LangSmith for:

- investigation state;
- persistence;
- retries;
- job execution;
- audit;
- timeline;
- correctness.

`ATI_OBSERVABILITY_ENABLED=false` must leave investigation behavior intact.

Tracing failures are non-fatal.

## OpenTelemetry architecture (PR 29)

PR 29 makes OpenTelemetry ATI's approved application-facing telemetry
portability layer rather than a future possibility. ATI code uses
`opentelemetry-api` and ATI-owned helpers; SDK/exporter composition belongs at
the application boundary.

The approved general-observability topology (delivered in PR 29C) places one
OpenTelemetry Collector between ATI processes and the backends, so ATI knows
a single standard OTLP destination and never knows Jaeger/Prometheus/Loki
topology:

```text
ATI services (ati-api / ati-worker / ati-geo-resolver)
    |
OpenTelemetry API / ATI telemetry helpers
    |
OpenTelemetry SDK/exporters (OTLP/HTTP)
    |
OpenTelemetry Collector            <-- required gateway
    |            |            |
    |            |            +--------> Loki (native OTLP logs)
    |            +---> Prometheus scrape endpoint -> Prometheus (metrics)
    +-----------> Jaeger (OTLP traces)
                                      \
        Redpanda /public_metrics -----> Prometheus
        postgres-exporter /metrics ---> Prometheus
                                      |
                                   Grafana
```

Prometheus is the metrics backend, Jaeger the distributed-trace backend, Loki
the log backend, and Grafana the visualization/correlation surface. Application
and domain code must not import backend-specific APIs merely to emit telemetry.

Source-controlled deployment/provisioning assets belong under:

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

Grafana dashboards and datasource provisioning are code, not manually maintained
runtime state.

### Instrumentation boundary

Trace/timing instrumentation belongs at stable architectural boundaries,
especially functions or methods fronting distributed systems or network I/O:
PostgreSQL, Kafka-compatible Evidence publication/consumption, datasource HTTP
acquisition, external intelligence providers, LLM/model calls, and future
external embedding/object-storage calls.

Representative canonical spans are:

- `ati.datasource.acquire`;
- `ati.datasource.convert`;
- `ati.evidence.publish`;
- `ati.evidence.consume`;
- `ati.evidence.persist`;
- `ati.geo.resolve`;
- `ati.investigation.execute`;
- `ati.agent.invoke`;
- `ati.llm.invoke`;
- `ati.report.generate`.

Do not instrument every internal helper merely because it is callable. Spans
should expose meaningful execution boundaries. Histograms complement spans when
aggregate latency is operationally useful; they are not required as a duplicate
of every span.

### PostgreSQL operational coverage

PostgreSQL telemetry is defined at ATI's stable persistence boundaries rather
than by automatically tracing every SQLAlchemy/psycopg call.

Every public method of a concrete PostgreSQL repository or PostgreSQL-backed
resolver that can perform database I/O is an instrumentation boundary. Use a
stable span such as `ati.postgres.repository` and bounded static dimensions
for repository, operation, and outcome. Aggregate repository-operation latency
must be available so an operator can identify which persistence operation is
constraining throughput.

The PostgreSQL `UnitOfWork` is independently observable. Its transaction
lifetime begins after transaction begin succeeds and ends after commit/rollback
completes or fails; repository spans intentionally nest inside that transaction
span. Implicit context-manager commit/rollback and explicit
`commit()`/`rollback()` operations expose latency and failure outcomes.
Session cleanup must not silently inflate transaction-duration measurements.

Initial PR 29 instrumentation does **not** enable broad SQLAlchemy/psycopg
auto-instrumentation. SQL text, bind parameters, row/domain identifiers, and
other content/high-cardinality values are not telemetry dimensions.

A structural unit-test mechanism or explicit reviewed operation registry must
make omissions visible when new PostgreSQL repository I/O methods are added.

### Kafka/Redpanda flow health

ATI application telemetry and broker telemetry are complementary.

ATI emits distinct operational measurements for:

- broker-acknowledged Evidence messages published;
- valid Evidence messages returned by consumer polls;
- successfully processed Evidence messages;
- Evidence messages covered by successful consumer offset commits;
- publish, poll, processing, and commit latency/failures;
- bounded poll/batch sizes and persistence outcomes.

A message is counted as successfully processed only after the required
PostgreSQL persistence commit and Kafka consumer commit have succeeded. If
PostgreSQL commits but the Kafka commit fails, processing is not reported as
complete; normal at-least-once/redelivery and Evidence idempotency semantics
remain authoritative.

Kafka publication is success-atomic only on successful return and is not
failure-atomic. On a partial publication failure, successful-message telemetry
counts only records whose broker acknowledgement is known to have succeeded.

Consumer backlog is authoritative Kafka/Redpanda state, not an ATI in-process
queue approximation. PR 29 infrastructure must expose consumer-group lag by
topic/partition using the deployed Redpanda/Kafka supported metrics. Aggregate
lag and lag trend are derived in Prometheus/Grafana. Backlog age is exposed only
if the deployed broker version supplies a reliable authoritative metric.

The operational view must support direct comparison of:

```text
producer publication rate
consumer receive rate
consumer successful processing rate
consumer committed-message rate
consumer-group lag
lag trend
```

This allows operators to distinguish a healthy consumer, a consumer falling
behind, a backlog being drained, a stalled consumer, a slow PostgreSQL
persistence path, and a broker/offset-commit problem.

Partition is acceptable where required for broker lag/topology diagnosis.
Application message counters normally aggregate across partitions. Kafka
offsets, Evidence/message IDs, and arbitrary consumer identities are not metric
labels.

Redpanda infrastructure monitoring should also expose the bounded operational
categories needed to diagnose broker/topic availability, produce/fetch request
health, replication health, and storage/capacity. PostgreSQL infrastructure
monitoring should expose server/pool health such as connection saturation,
transaction/rollback activity, locks/deadlocks, and capacity where supported.

### Decorator-first instrumentation

As much as practical, stable function and method execution boundaries are
annotated with thin ATI-owned Python decorators built on the OpenTelemetry API.
Decorators are the preferred mechanism for span lifecycle, operation duration,
standard success/failure status, exception recording, and static or
bounded-cardinality attributes. This keeps OpenTelemetry lifecycle boilerplate
out of application code while preserving backend independence.

Conceptually:

```python
@traced("ati.evidence.persist")
async def persist_batch(...):
    ...
```

A combined operation decorator may also declare both a span and an aggregate
latency metric when both are semantically useful.

Decorator-based instrumentation is not mandatory for telemetry whose value is
known only from runtime/domain outcomes inside an operation. Evidence
create/append/ignore outcomes, committed record counts, batch sizes, publication
counts, retry outcomes, and similar semantic events should use explicit
telemetry calls at the point where their meaning is known.

ATI telemetry decorators must not import or expose Prometheus-, Jaeger-, Loki-,
Grafana-, LangSmith-, or Langfuse-specific APIs.

Standard W3C trace context is propagated across distributed/asynchronous
boundaries where supported, including Kafka-compatible message headers.
Structured logs include the current trace/span IDs so operators can correlate
Loki records with Jaeger traces through Grafana.

Each ATI process has meaningful OTel service/resource identity. Prefer standard
OpenTelemetry environment variables for SDK/exporter configuration; add
ATI-specific settings only for ATI-owned semantics.

### Metric cardinality and Evidence-flow semantics

Metric names and units are stable ATI contracts. Metric attributes must have
bounded, controlled cardinality. Bounded dimensions such as operation,
outcome, consumer, semantic format, or datasource instance may be used when
their value sets are controlled.

Never use Evidence IDs, Entity IDs, Investigation IDs, IP/domain values,
execution UUIDs, message IDs, or other unbounded identifiers as Prometheus
labels. Such identifiers belong in traces or structured logs when allowed by
the data-minimization policy.

PR 29 defines counters for at least:

- Evidence messages sent;
- Evidence messages received;
- Evidence batches committed;
- Evidence batch commit failures;
- Evidence create outcomes;
- Evidence append outcomes;
- Evidence unchanged outcomes (matching the current `UNCHANGED` persistence
  outcome rather than inventing a second `ignore` domain outcome);
- Evidence processing failures;
- PostgreSQL repository-operation and UnitOfWork transaction latency/failures;
- Kafka publish/poll/offset-commit latency and failures;
- distinct published, received, successfully processed, and successfully
  committed Evidence message counts;
- authoritative Kafka/Redpanda consumer-group lag for producer/consumer cadence
  analysis.

The exact meanings of `sent/published`, `received`, `processed`,
`committed`, `create`, `append`, and `unchanged` are fixed in the PR
29A/29A-1 telemetry contract before application-wide instrumentation is added.
Queue/backlog/consumer-lag gauges are used only when sourced from reliable
authoritative state; Kafka/Redpanda consumer-group lag is broker/group state,
not inferred from ATI's local poll loop.

Telemetry remains fail-open and is never authoritative product state.

## PR 29A delivered foundation

PR 29A ships the telemetry contracts and reusable helpers below; it does not
instrument application call sites broadly (that is PR 29B).

### Telemetry package

```text
src/agentic_threat_investigator/telemetry/
    __init__.py      # public re-exports
    attributes.py    # bounded/common attribute keys + allowlist validation
    decorators.py    # @traced / @timed / @telemetry_operation
    logging.py       # current_correlation() + TraceCorrelationFilter
    metrics.py       # canonical meters/counters, units, get_counter/get_meter
    propagation.py   # inject/extract W3C trace context for message headers
    setup.py         # configure_telemetry / shutdown_telemetry / service names
    tracing.py       # canonical tracer + span-name vocabulary
```

### Decorators

- `traced(span_name=..., attributes=...)` opens one current child span around a
  sync or async callable; the return value, ordinary exceptions, and
  `asyncio.CancelledError` are preserved unchanged. Ordinary exceptions are
  recorded using standard OTel exception semantics; static attributes are
  allowlist/bounded validated at decoration time.
- `timed(metric=..., attributes=...)` records one seconds-unit histogram
  (`metric` must use the canonical `<operation>.duration` suffix). Both
  successful and failing calls contribute duration, tagged with a bounded
  `ati.outcome` attribute; cancellation records nothing and propagates.
- `telemetry_operation(span_name=..., duration_metric=...)` composes the two
  primitives exactly once.

Decorators never capture function arguments or return values and never
serialize `self`, requests, Evidence, prompts, or provider payloads. They are
used only at boundaries whose exceptions are already safe and bounded.

### Canonical span names

```text
ati.datasource.acquire  ati.datasource.convert  ati.evidence.publish
ati.evidence.consume    ati.evidence.persist    ati.geo.resolve
ati.investigation.execute  ati.agent.invoke  ati.llm.invoke  ati.report.generate
```

Canonical names are lowercase stable semantic identifiers with no IDs or
provider names, and never generated from Python function names.

### Canonical metric names/units

All are monotonic counters under the `agentic_threat_investigator`
instrumentation scope; units are `{item}` or `{operation}` per the contract
section above. Latency histograms use the seconds unit `s` and the
`<operation>.duration` suffix.

```text
ati.evidence.messages.sent
ati.evidence.messages.received
ati.evidence.batches.committed
ati.evidence.batch_commit.failures
ati.evidence.outcomes.create
ati.evidence.outcomes.append
ati.evidence.outcomes.ignore
ati.evidence.processing.failures
```

Prometheus rendering of a `_total` suffix is a backend concern (PR 29C) and is
not baked into the ATI API. PR 29B adds counters at call sites using the frozen
names above; it never invents new names.

### Cardinality and data minimization

Metric/decorator attributes are allowlist-first and bounded. Safe keys are
`ati.component`, `ati.operation`, `ati.outcome`, `ati.datasource.semantic_format`,
and `ati.consumer`. High-cardinality or content-bearing identifiers are
rejected before any instrument is touched, including `evidence_id`, `entity_id`,
`investigation_id`, `execution_id`, `message_id`, `ip`, `domain`, `url`,
`prompt`, `response`, `exception`, and `exception_message` (both bare and
fully-qualified forms).

### Service identity

Canonical process identities are `ati-api`, `ati-worker`, `ati-geo-resolver`,
`ati-scheduler`, `ati-migrate`, and `ati-fake-data-bootstrap`. The explicit ATI
process identity establishes `service.name`; verified OTel SDK `Resource.create`
merge semantics give explicitly-passed attributes precedence over
`OTEL_SERVICE_NAME`/`OTEL_RESOURCE_ATTRIBUTES`, and this deterministic behavior
is unit-tested.

### Trace/log correlation

`current_correlation()` returns only the current valid `trace_id`/`span_id` as
lowercase hex (or `None` outside a valid span). `TraceCorrelationFilter` sets
`otel_trace_id`/`otel_span_id` on a `LogRecord` without overwriting existing
attributes or changing log semantics.

### W3C propagation

`inject_trace_context`/`extract_trace_context` operate on Kafka-style
`Sequence[tuple[str, bytes]]` headers using the standard OTel W3C propagator.
Unrelated headers are preserved, duplicates are normalized, no baggage/domain
IDs are added, and malformed incoming context yields a safe no-parent context.
PR 29A defines the contract only; Kafka producer/consumer call sites are wired
in PR 29B.

### Telemetry setup

`configure_telemetry(enabled=..., service_name=...)` is idempotent within one
process: a conflicting second call raises, and a repeated identical call
returns the existing runtime. Disabled mode installs no SDK provider and no
remote exporter. `shutdown_telemetry()` flushes/shuts down providers safely
without masking the original process error.

## PR 29A-1 delivered coverage

PR 29A-1 applies the PR 29A contracts to ATI's PostgreSQL and Kafka/Redpanda
operational boundaries. Instrumentation is observational only: it never
changes transaction, savepoint, delivery, acknowledgement, retry,
redelivery, or cancellation semantics, never captures SQL or parameters, and
never attaches high-cardinality identifiers to metrics.

### PostgreSQL repository operations

Every public method of every concrete PostgreSQL repository/resolver that can
execute PostgreSQL I/O is annotated with
`@postgres_repository_operation(repository=..., operation=...)`:

- one `ati.postgres.repository` span;
- one `ati.postgres.repository.duration` seconds histogram with bounded
  `ati.postgres.repository` / `ati.postgres.operation` / `ati.outcome`
  dimensions;
- one `ati.postgres.repository.failures` counter increment on ordinary
  errors.

A structural unit test (`tests/unit/infrastructure/
test_postgres_repository_coverage.py`) pins an explicit reviewed inventory of
all repository operations against the decorator registry, so a future public
I/O method without telemetry (or a typo'd decorator) fails the gate with a
useful message. Repository and operation names are static
developer-controlled strings, never derived from arguments, SQL, or domain
values.

### UnitOfWork transaction lifetime

`PostgresUnitOfWork` measures the **transaction lifetime** independently of
any repository call:

- an `ati.postgres.uow` span is opened only after `session.begin()` succeeds
  and closed only after commit/rollback completes, so repository spans nest
  deterministically beneath it;
- `ati.postgres.uow.duration` (s) with `ati.outcome =
  commit | rollback | failure | cancelled`;
- `ati.postgres.uow.commits` / `rollbacks` / `failures` counters;
- `ati.postgres.transaction_operation.duration` (s) with
  `ati.postgres.operation = commit | rollback` and `ati.outcome`, separating
  *long transaction lifetime* from *fast transaction + slow COMMIT*. Both
  the implicit exit commit/rollback and the explicit public `commit()` /
  `rollback()` methods are measured.

Session-close time is captured after the transaction end time and is never
reported as transaction duration.

### Kafka/Redpanda transport

`KafkaEvidencePublisher.publish`:

- `ati.kafka.publish` span; `ati.kafka.publish.duration` (s);
- `ati.kafka.messages.published` increments **per broker-acknowledged
  message** (publish is success-atomic, not failure-atomic: a partial
  failure counts only the acknowledgements known to have succeeded);
- `ati.kafka.publish.failures` increments once per failed publish;
- an empty publish performs no broker operation and emits no publish
  telemetry.

`KafkaEvidenceConsumer.poll`:

- `ati.kafka.poll` span; `ati.kafka.poll.duration` (s);
- `ati.kafka.messages.received` counts only decoded/admitted Evidence
  messages (raw bytes that fail decoding count zero);
- `ati.kafka.poll.failures`;
- `ati.kafka.poll.batch_size` histogram (`{message}`), recorded for non-empty
  polls.

`KafkaEvidenceConsumer.commit`:

- `ati.kafka.commit` span; `ati.kafka.commit.duration` (s);
- `ati.kafka.commits`; `ati.kafka.commit.failures`;
- `ati.kafka.messages.committed` counts the records of a successfully
  committed batch (never incremented before the broker commit succeeds).

Kafka metric dimensions are bounded to `ati.kafka.topic` and
`ati.kafka.consumer_group` (the deployment-controlled logical identity).
Partition/offset are never metric labels for ATI application counters.

### Evidence flow

- `EvidenceBatchPersistenceService.persist` emits the `ati.evidence.persist`
  span + duration;
- `EvidencePersistenceConsumer.process_next_batch` emits the
  `ati.evidence.consume` span + duration with nested `ati.kafka.poll`,
  `ati.evidence.persist`/`ati.postgres.uow`/`ati.postgres.repository`, and
  `ati.kafka.commit` spans;
- `ati.evidence.messages.processed` increments only after prepare + PostgreSQL
  commit + Kafka consumer commit all succeed (empty polls count nothing);
- `ati.evidence.processing.failures` increments per failed flow iteration;
- `ati.evidence.outcomes.created` / `appended` / `unchanged` reflect the
  authoritative persistence result as soon as it is known, so a PostgreSQL
  commit followed by a failed Kafka commit is visible as outcomes counting up
  while `processed` stays zero (the redelivery diagnostic).

### Redpanda operational metric contract (PR 29C)

ATI emits the application-side counters/spans above only. Consumer lag and
broker health are authoritative broker state that ATI does **not** synthesize
inside application code (no AdminAPI lag query in every poll). PR 29C scrapes
Redpanda's public metrics endpoint (``redpanda:9644/public_metrics``) and
exposes the categories below as verified against the compose-pinned
``redpandadata/redpanda:v24.3.8`` (see the PR 29C delivered-runtime section
for the exact verified public metric names):

- consumer-group lag per `topic × consumer group × partition` (log-end minus
  committed offset), plus the aggregated lag by group/topic; derived lag
  trend (growth/drain) is a PR 29D query concern;
- committed-offset/lag source and partition high-water/log-end state;
- broker/topic/partition availability, leader state, and
  under-replicated-partition state;
- produce/fetch request latency and error categories;
- disk/log-segment storage utilization;
- replication health and leadership changes where operationally useful.

Backlog age (oldest unconsumed record age) is **deferred**: ATI only relies
on it if the verified Redpanda 24.3.8 metric surface exposes a reliable,
authoritative value; ATI never approximates backlog age from poll timestamps.
PR 29C exposes the PostgreSQL server-health categories below through
postgres-exporter (active connections, transaction/commit/rollback activity,
lock waits, deadlocks, database size, scrape failures).

## PR 29B delivered coverage

PR 29B applies the PR 29A/29A-1 contracts to ATI's remaining stable
application and external/distributed boundaries. Instrumentation is
observational only: it never changes transactions, Kafka delivery,
provider retry/rate limiting, LLM accounting/repair counts, or cancellation.

### Canonical span additions

The PR 29A canonical span set gains two reviewed names (both covered by the
frozen vocabulary tests):

```text
ati.provider.execute   one logical provider work-item execution
ati.embedding.invoke   one network-backed semantic embedding request
```

### Bounded attribute additions

Two bounded attribute keys join the allowlist (values are
code/deployment-controlled, never IDs or content):

```text
ati.provider    stable source URN of one provider work item
ati.agent       closed agent vocabulary (evidence_analyst | research_agent)
```

### Datasource acquisition/conversion

- ``observe_semantic_acquisition`` is the shared acquisition seam used by
  both the datasource Evidence producer and the datasource-backed provider:
  every logical semantic acquisition emits one ``ati.datasource.acquire``
  span and one ``ati.datasource.acquire.duration`` seconds histogram, with a
  bounded success/error outcome (a typed stage-error result is a failure,
  an exception is a failure, cancellation records nothing and propagates);
- ``convert_semantic_source_objects`` emits one ``ati.datasource.convert``
  span and duration plus the ``ati.datasource.convert.items`` histogram;
  zero output is a success with a recorded count of zero;
- ``ati.datasource.acquire.failures`` / ``ati.datasource.convert.failures``
  count ordinary failures once. The durable datasource lifecycle log remains
  authoritative and is never replaced or created by telemetry, and no
  Kafka publish counters are duplicated by the producer path.

### Provider HTTP boundary

The shared ``ProviderHttpClient`` network execution emits aggregate
bounded telemetry that distinguishes one *logical* request from its
*actual* HTTP attempts:

```text
ati.provider.http.duration   one logical request (attempts + retries + backoff)
ati.provider.http.attempts   one per actual outbound request attempt
ati.provider.http.retries    attempts minus the first
ati.provider.http.failures   one per failed logical request
```

URLs, paths, query strings, headers, bodies, response content, and raw
exception text are never telemetry. ``BoundedLimiter`` is unchanged and no
queue-wait telemetry was added.

### Provider work

``ProviderWorkExecutor.execute`` emits one ``ati.provider.execute`` span and
``ati.provider.execute.duration`` per logical work item with the bounded
``ati.provider`` source-URN attribute; ``ati.provider.execute.failures``
counts FAILED outcomes and ordinary exceptions exactly once. Internal HTTP
retries remain child transport attempts and never multiply the logical
work-item count. The existing ``ProviderExecutionOutcome`` semantics are
unchanged (no PARTIAL status exists).

### Evidence persistence

The ``ati.evidence.persist`` span/duration on
``EvidenceBatchPersistenceService.persist`` (29A-1) nests over
``ati.postgres.uow`` and ``ati.postgres.repository``. The persistence
service itself never emits the outcome counters (created/appended/unchanged)
— those are owned by the consumer flow exactly once — so nothing is
double-counted.

### GEO resolution

``GeoResolutionWorker.run_once`` emits one ``ati.geo.resolve`` span and
duration per worker iteration. Per-item authoritative outcomes are counted
at their persist points:

```text
ati.geo.resolve.resolved      RESOLVED completions
ati.geo.resolve.unresolvable  terminal UNRESOLVABLE completions
ati.geo.resolve.failed        failure/retry records
```

An empty claim still measures the worker iteration and invents no item
outcomes. IP/location/entity/evidence/observation IDs are never labels, and
no expensive queue-depth query was added.

### Investigation execution

``LocalInvestigationRunner.run`` emits one ``ati.investigation.execute`` span
and duration per invocation, counts ``ati.investigation.execute.executed``
only when the graph actually runs (never for the idempotent terminal no-op
or a lifecycle rejection), and counts ``ati.investigation.execute.failures``
on ordinary exceptions. ``investigation_id`` is never a metric label and no
PARTIAL classification is inferred.

### Agents and Report Writer

- ``EvidenceAnalyst.analyze_with_result`` and
  ``ResearchAgent.research`` emit one ``ati.agent.invoke`` span and
  ``ati.agent.invoke.duration`` with the closed ``ati.agent`` vocabulary;
  ``ati.agent.invoke.failures`` counts ordinary failures once;
- ``ReportWriter.write`` emits one ``ati.report.generate`` span and duration;
  ``ati.report.generate.failures`` counts ordinary failures once.

### Common LLM instrumentation

Production composition builds exactly one observing ``LlmClient`` wrapper
(:class:`ObservedLlmClient`) over the selected
``build_llm_observability`` backend and passes it to every agent and the
Report Writer:

```text
Agent
 -> ObservedLlmClient
      -> ati.llm.invoke span + ati.llm.invoke.duration
      -> LlmObservability.observe(LlmObservation)   (selected backend)
      -> existing LlmClient delegate
```

One actual ``generate_structured()`` call equals one OTel LLM span plus one
selected backend observation; a structured-output repair is another actual
model call and therefore another span/observation, separately accounted by
the existing LLM accounting. Only bounded safe metadata is recorded
(operation name plus configured model/provider labels); prompts, outputs,
Evidence facts, and Investigation IDs are never captured, token counts are
never fabricated, ``tracing_context(enabled=False)`` is preserved in the
LangChain adapter, and a broken observability backend stays fail-open (it
can never fail the model call). Cancellation propagates and the delegate's
typed ``LlmError`` taxonomy is preserved.

### Network-backed embedding boundary

The network-backed ``LangChainEmbeddingClient.embed_texts`` emits one
``ati.embedding.invoke`` span and ``ati.embedding.invoke.duration`` plus
``ati.embedding.invoke.failures``. The deterministic offline
``HashingEmbeddingClient`` is not instrumented, and PostgreSQL/pgvector-only
retrieval keeps its existing database telemetry (never mislabeled as network
I/O).

### Kafka W3C trace-context propagation

The Kafka publisher injects W3C ``traceparent``/``tracestate`` into record
headers (never the Evidence payload or routing key); the Kafka consumer
extracts the first valid parent context onto the polled
:class:`EvidenceBatch`, and ``EvidencePersistenceConsumer`` makes the
durable PostgreSQL persist and broker commit child spans of that context.
Malformed headers are safe no-parents, unrelated headers are preserved,
and the Evidence payload/identity is byte-identical.

### Structured-log correlation

The CLI entrypoints install the PR 29A ``TraceCorrelationFilter`` on the
root logging handler so structured records carry ``otel_trace_id`` /
``otel_span_id`` when a valid span is current. Correlation is additive and
never rewrites existing log semantics or reintroduces raw exception text.

## PR 29B-1 delivered coverage

PR 29B-1 closes the remaining PR 29B gap: the FastAPI/ASGI **inbound HTTP
boundary**. The ATI API process is instrumented at the framework level with
the official ``opentelemetry-instrumentation-fastapi`` (a new direct runtime
dependency) — never with per-endpoint decorators, and no ATI HTTP span names
or duplicate HTTP metrics were added. Composition lives in
``telemetry/http.py`` (``instrument_fastapi_http`` over the providers from
:func:`configure_telemetry`) and is wired once in ``main.py``, so the API
process service identity is ``service.name=ati-api``.

### Operation identity: method × registered route template

One inbound request is one standard OTel HTTP server span. Operation
identity is the HTTP method plus the **registered route template**: the
framework emits ``http.route`` (``/api/v1/investigations/{investigation_id}``)
on spans and the standard server-duration metric carries the registered
template as its bounded route dimension, so ``GET`` and ``DELETE`` on the
same template remain distinguishable and a dynamic Investigation/UUID path
never becomes a metric label. Unknown unmatched paths are recorded without
any invented route label (the 404 boundary metric simply has no route
dimension). ``OPTIONS`` preflight and health probes participate normally.
Standard response status (``http.status_code``) is observable for ``2xx``/
``4xx``/``5xx``.

### Privacy and cardinality

The official instrumentation captures no headers or bodies by default and
PR 29B-1 passes no header-capture option, so Authorization, Cookie,
Set-Cookie, ``X-CSRF-Token``, and ``Idempotency-Key`` values never reach
telemetry. The framework records the concrete request target and full URL
(including the query string) as standard span attributes; ``redact_http_content_attributes``
— a supported ``server_request_hook`` — blanks exactly those
content-bearing attribute keys (``http.url``/``http.target``/
``url.full``/``url.path``/``url.query``) and leaves the bounded
``http.route`` identity intact. Metrics never receive concrete paths,
targets, or query values in either convention mode. Request/response bodies
are never read or serialized for telemetry.

**Deployment constraint:** keep the official header-capture environment
variables unset in the ATI API process
(``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST`` /
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE`` and the
sanitize-fields equivalent). If they were enabled they could override the
code defaults and capture arbitrary headers; ATI does not configure them.
``OTEL_SEMCONV_STABILITY_OPT_IN`` may switch the standard attribute/metric
names to the newer HTTP semantic conventions (for example
``http.request.method``/``http.server.request.duration``); ATI's bounded
route-template identity is preserved in both modes and the unit suite pins
the default mode for determinism.

### Trace continuity

A valid incoming W3C ``traceparent`` continues the upstream trace (the HTTP
server span becomes its child); malformed trace context is ignored safely
and never fails the request. ATI application spans opened during request
processing (LLM/agent/report/UoW/repository spans) inherit the HTTP server
span through OTel's normal current-context mechanism — no span/context
object is ever passed through route, service, or repository signatures.

Expected hierarchy:

```text
HTTP server span
  -> ATI application span
       -> ati.postgres.uow
            -> ati.postgres.repository
```

Standard framework metrics (``http.server.duration`` and companions as
emitted by the resolved official instrumentation) are used as-is and are
sufficient for PR 29D to derive per-bounded ``method × route-template``
request rate, latency distribution, and error/status distribution. PR 29C
remains responsible for the OTel Collector, Prometheus, Jaeger, Loki,
Grafana, and export/provisioning infrastructure; PR 29D owns the API
dashboard that consumes this telemetry. No live telemetry infrastructure is
needed to exercise or verify this boundary (see ``docs/TESTING.md``).

## PR 29B-2 delivered coverage

PR 29B-2 closes the two narrow corrective leftovers of PR 29B-1: the
**duplicate** direct ``opentelemetry-instrumentation-fastapi`` declaration in
``pyproject.toml`` is removed (exactly one declaration remains, with the
unchanged approved version range), and the ``ati-api`` production composition
now owns **deterministic telemetry shutdown**.

### Deterministic telemetry lifecycle

``main.py`` (the ``ati-api`` production composition seam) owns the whole
telemetry lifecycle:

```text
configure_telemetry(service_name=ati-api)
  -> create_app(settings)
  -> instrument_fastapi_http(app, runtime)
  -> FastAPI lifespan (ApiComposition startup ... serving ... teardown)
  -> ApiComposition.dispose()
  -> shutdown_telemetry()
```

``telemetry/lifecycle.py::arrange_fastapi_telemetry_shutdown`` composes the
existing application lifespan (``app.router.lifespan_context``, the single
supported Starlette lifespan-composition point) so the existing
``shutdown_telemetry()`` primitive runs **after** ``ApiComposition.dispose()``
completes — including when that disposal raises: the original application
teardown exception stays authoritative, and provider-shutdown failures remain
fail-open inside ``shutdown_telemetry()``. Disabled observability installs no
providers, no HTTP instrumentation, and the shutdown path stays a harmless
no-op. ``create_app(settings)`` itself remains generic and never configures
process-global telemetry.

This lifecycle closure is the deterministic setup/shutdown ordering that PR
29C attaches real exporters/OTLP delivery to. PR 29C (below) keeps this
ordering intact; ``shutdown_telemetry()`` now also flushes/stops the OTLP
exporters and detaches the additive OTel logging handler.

## PR 29C delivered runtime

PR 29C operationalizes the PR 29 series into a source-controlled local
observability stack. The runtime is **optional** and **fail-open**: default
``ATI_OBSERVABILITY_ENABLED=false`` needs no Collector/backend, and Collector
unavailability can never fail ATI domain/application work.

### One application export destination

ATI processes know exactly one standard destination — the OpenTelemetry
Collector — and never know backend topology:

```text
ATI process
   |
   | OTLP/HTTP (OTEL_EXPORTER_OTLP_ENDPOINT)
   v
OpenTelemetry Collector
   |----------------------> Jaeger       (traces)
   |----------------------> Loki (OTLP)  (logs)
   |
   +-- Prometheus scrape endpoint (:8889/metrics)
             |
             v
        Prometheus           (ATI metrics)

Redpanda /public_metrics -----> Prometheus
postgres-exporter /metrics ----> Prometheus
```

ATI never connects directly to Jaeger/Prometheus/Loki; the Collector owns
receiving, batching, and backend routing (``infra/observability/otel-collector/``
config, pinned ``otel/opentelemetry-collector-contrib:0.161.0``).

### Python OTLP exporter composition

``telemetry.setup`` gains the pinned ``opentelemetry-exporter-otlp-proto-http``
1.37.x exporter and composes the three OTLP/HTTP signal pipelines inside the
existing ``configure_telemetry``/``shutdown_telemetry`` seam (no second
telemetry runtime):

- traces: ``OTLPSpanExporter`` behind ``BatchSpanProcessor``;
- metrics: ``OTLPMetricExporter`` behind ``PeriodicExportingMetricReader``;
- logs: ``OTLPLogExporter`` behind ``LoggerProvider`` + ``BatchLogRecordProcessor``
  plus an **additive** root ``LoggingHandler``.

Composition is gated on the standard endpoint, never an ATI-prefixed
duplicate (see ``docs/CONFIGURATION.md#runtime-otlp-export-pr-29c``).

### Logging transport

OTLP log export is additive to ATI's existing console logging: developer
terminal output and container logs are preserved, the PR 29A
``TraceCorrelationFilter`` is untouched, and OTel-internal logger namespaces
(``opentelemetry.*``) are excluded from the OTLP handler to prevent a
feedback loop. A log emitted inside an active span carries standard OTel
trace/span correlation (the exported ``LogRecord`` picks up the current span
context); outside any span no identity is fabricated. ATI transports existing
logs and never expands them with request/response bodies, secrets, prompts,
Evidence payloads, raw SQL, or headers. Trace/span IDs remain queryable log
metadata, not high-cardinality Loki indexed labels.

### Service identities in the deployed processes

- ``ati-api`` (``main.py``): unchanged PR 29B-2 lifecycle, now with OTLP export.
- ``ati-worker`` (``cli.worker_main``): ``ServiceNames.WORKER``; telemetry
  starts before instrumented services and shuts down after the process-owned
  engine is disposed (``finally``-equivalent).
- ``ati-geo-resolver`` (``cli.geo_resolver_main``): ``ServiceNames.GEO_RESOLVER``;
  telemetry starts only when the resolver is enabled, and shuts down after the
  engine is disposed.

The one-shot utilities (fake-data-bootstrap, migrate, geography-import,
geography-build) are deliberately not wired: they run once and exit, so an
OTLP export pipeline is pointless. PR 29C does not add telemetry to
placeholder processes merely to satisfy the service-name list.

### Backends

The optional stack is defined in ``compose.observability.yaml`` (composed on
top of ``compose.yaml``) rather than via Compose ``profiles:`` because the
repository's pinned Compose provider, podman-compose 1.0.6, does not
implement the standard ``profiles:`` filter (verified against the pinned
version); an override file gives the same strict optional-add behavior with
the tooling the repository actually pins. Start it with:

```text
podman-compose -f compose.yaml -f compose.observability.yaml up -d
docker compose -f compose.yaml -f compose.observability.yaml up -d
```

Pinned images (never ``latest``): Collector contrib ``0.161.0``, Prometheus
``prom/prometheus:v3.14.0``, Jaeger ``jaegertracing/jaeger:2.21.0``, Loki
``grafana/loki:3.7.8``, Grafana ``grafana/grafana:13.2.2``, postgres-exporter
``quay.io/prometheuscommunity/postgres-exporter:v0.20.1``. Redpanda stays
pinned ``v24.3.8``.

- **Traces → Jaeger**: the Collector exports OTLP/HTTP to ``jaeger:4318``.
  Jaeger 2.x all-in-one runs the image's embedded in-memory config (no config
  file required): it accepts OTLP on 4317/4318 and serves the UI on 16686.
  In-memory storage means traces disappear on restart (documented local
  choice).
- **Metrics → Prometheus**: the Collector's Prometheus exporter exposes
  ``:8889/metrics``; Prometheus scrapes it (job ``ati-otel``). Collector
  self-metrics flow through the same pipeline. ATI metric names are never
  renamed in Python; counter ``_total`` translation is exporter behavior.
- **Logs → Loki**: the Collector exports OTLP/HTTP to Loki's native OTLP
  endpoint (``http://loki:3100/otlp``); the deprecated Loki-specific Collector
  exporter is not used. Loki runs a single binary pinned to
  ``grafana/loki:3.7.8`` with local filesystem storage (TSDB schema v13, 24h
  index period) and native OTLP structured metadata enabled; indexed labels stay
  bounded (§Loki label/cardinality policy below). Local-development logs are
  retained for 14 days.
- **Redpanda → Prometheus**: Prometheus scrapes ``redpanda:9644/public_metrics``
  (job ``redpanda``), the lower-cardinality public endpoint Prometheus prefix
  ``redpanda_``). Verified for ``v24.3.8``: it exposes
  ``redpanda_kafka_consumer_group_committed_offset``
  (``redpanda_group``/``redpanda_topic``/``redpanda_partition``),
  ``redpanda_kafka_consumer_group_consumers``, ``redpanda_kafka_consumer_group_topics``,
  and ``redpanda_kafka_max_offset`` (partition high-watermark). Consumer lag is
  derived in PromQL from these authoritative broker offsets (PR 29D); ATI
  never synthesizes lag.
- **PostgreSQL → Prometheus**: the Prometheus Community postgres-exporter
  (job ``postgres``, ``:9187/metrics``) exposes server health: connections,
  transactions/commits/rollbacks, locks/deadlocks, database size, and scrape
  failures. It reuses the existing local ATI database user as a documented
  local-development compromise; real deployments should use a least-privilege
  ``pg_monitor`` role. ATI repository/UoW telemetry stays a separate
  application-layer concern.
- **Grafana**: pins image ``13.2.2``, provisions stable Datasource UIDs
  ``ati-prometheus`` / ``ati-jaeger`` / ``ati-loki`` from
  ``infra/observability/grafana/provisioning/``. No dashboard JSON is added
  (PR 29D owns dashboards-as-code and the layer-specific hierarchy
  including API/HTTP, datasource/ingestion, Kafka/Redpanda, persistence/
  repository, PostgreSQL, Agents & LLM, GEO, and investigations/reports).
  Local admin credentials default to Grafana's documented ``admin/admin`` and
  are overridable via ``ATI_GRAFANA_ADMIN_USER`` / ``ATI_GRAFANA_ADMIN_PASSWORD``.

### Loki configuration and retention (PR 29C-1)

Loki runs the pinned ``grafana/loki:3.7.8`` image as a single binary. Its
source-controlled configuration (``infra/observability/loki/config.yaml``)
uses the local-development topology:

- ``target: all`` single binary on the Compose network, in-memory ring,
  replication factor 1;
- ``common.path_prefix: /loki`` over the ``ATI_DATA_DIR``-backed volume, with
  chunks and rules directly beneath it (no second storage root);
- TSDB schema v13 with a 24h index period and filesystem object store;
- native OTLP ingestion with ``allow_structured_metadata: true``.

Retention is a local-development policy, not a production one: logs are
retained for exactly 14 days via ``limits_config.retention_period: 336h``.
The obsolete ``limits_config.storage_retention_days`` key is not used.
Retention is enforced by the Compactor (``compactor.retention_enabled: true``)
with ``compactor.delete_request_store: filesystem``, matching the filesystem
object store. Filesystem storage and 14-day retention are deliberate
local-development choices and are not a production retention/storage
recommendation.

Validate the source-controlled configuration against the exact pinned Loki
binary (no telemetry stack required):

```text
podman run --rm \
  -v "$PWD/infra/observability/loki/config.yaml:/etc/loki/config.yaml:ro" \
  docker.io/grafana/loki:3.7.8 \
  -config.file=/etc/loki/config.yaml \
  -verify-config=true
```

(docker run with the same arguments is equivalent.) The command must exit 0
with ``msg="config is valid"``.

### Loki label/cardinality policy

Loki's default OTLP resource-attribute index-label set (bounded fields such
as ``service.name`` → ``service_name``) stays in effect. High-cardinality
identifiers (trace/span IDs, investigation/execution/request IDs, IP/domain/
URL content, exception messages) are stored as structured metadata, never
indexed labels.

### Manual developer smoke procedure

The stack is **not** covered by an automated telemetry integration-test
gate. Manual smoke (developer-only) flow:

```text
1. enable observability: ATI_OBSERVABILITY_ENABLED=true and
   OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
2. start core + observability stack (compose.yaml + compose.observability.yaml)
3. issue one API request / run one worker operation
4. confirm Collector is healthy (http://otel-collector:13131)
5. confirm Prometheus target health: http://localhost:9090/targets
6. inspect one ATI metric: http://localhost:9090/graph
7. inspect one Jaeger trace: http://localhost:16686
8. inspect one Loki log: http://localhost:3000 (Explore, ATI Loki)
9. stop the stack cleanly
```

Host UIs: Grafana ``http://localhost:3000`` (``ATI_GRAFANA_HOST_PORT``),
Prometheus ``http://localhost:9090`` (``ATI_PROMETHEUS_HOST_PORT``), Jaeger
``http://localhost:16686`` (``ATI_JAEGER_HOST_PORT``).

## LLM observability backends

General OpenTelemetry tracing and LLM/agent observability are complementary,
not competing, concerns. PR 29 introduces a portable ATI LLM-observability
contract with configuration-selectable backends:

- LangSmith;
- Langfuse;
- NoOp / disabled.

LangSmith remains the currently delivered v0.1 LLM-development backend.
Langfuse is an approved alternative target for PR 29. Backend-specific
credentials/configuration are required only when that backend is selected.

ATI defines the portable semantics it needs — agent/LLM operation identity,
model metadata, timing, token usage where available, structured-output
validation, safe correlation metadata, and evaluation metadata where
appropriate. Adapters translate those semantics to each backend. ATI does not
attempt to expose every vendor-specific feature through a lowest-common-
denominator interface.

An LLM invocation may emit both an OpenTelemetry operational span and an event
or trace to the selected LLM-observability backend. The OTel record answers
distributed-system/runtime questions; LangSmith or Langfuse supports AI-specific
debugging and evaluation. Neither backend owns Investigation state, Evidence,
Assessment, Report, retries, audit, timeline, or correctness.

### Delivered PR 29A abstraction

PR 29A delivers the portable boundary and backend adapters (it does not wire
LLM call sites to them; that is PR 29B):

- `app/llm_observability.py` defines `LlmObservation` (bounded, content-free
  metadata: `operation_name` plus optional model/profile/version/ID fields) and
  the `LlmObservability` ABC whose `observe()` returns a fail-open context
  manager. Prompt/model output content is not representable in the contract.
- `NoOpLlmObservability` is the default for `none` and for the master-disabled
  case; it performs no work, logs nothing, never raises, and never validates.
- `LangSmithLlmObservability` posts runs through the installed langsmith
  `RunTree` lifecycle with safe metadata and a bounded `ati.outcome` tag only;
  inputs/outputs are never captured.
- `LangfuseLlmObservability` uses Langfuse v4 (OpenTelemetry-native) APIs with a
  dedicated tracer provider so Langfuse exports only LLM/agent observations and
  never receives unrelated ATI general spans.
- `infrastructure/observability/composition.py::build_llm_observability` selects
  the backend from `ATI_LLM_OBSERVABILITY_BACKEND`; vendor secrets are resolved
  only for the active, master-enabled backend.

## LLM operation telemetry (PR 20B)

The Evidence Analyst routes model calls through the ``LlmClient`` boundary.
The LangChain adapter **disables automatic content-bearing LangSmith/LangChain
tracing** for Evidence Analyst invocations (via the installed langsmith
tracing context) before building or running the structured-output runnable.
A normal LangChain invocation can be automatically traced by LangSmith with
message inputs and model outputs; passing safe metadata alone does NOT
suppress that. Passing safe metadata therefore never re-enables content
capture, and the tests prove no tracer is installed for a suppressed call.

Safe operation metadata is prepared locally and can be attached to the local
runnable configuration without exporting prompts, Evidence facts, or model
output. Only the documented non-content keys are ever emitted:

```text
metadata = { "operation": "urn:ati:llm:evidence_analysis",
             "investigation_id": "<uuid>" }
```

The ``operation`` value always comes from the per-call ``operation_name``
argument, never from stale constructor state. Prompts, evidence facts, model
output, raw provider payloads, API keys, database sessions, and hidden
chain-of-thought are never captured in LLM telemetry. The adapter rejects any
other metadata key at construction, so content cannot leak through a caller
mistake. Tracing is not the investigation timeline, and tracing failures
remain non-fatal for investigation execution.

Future prompt/content tracing requires an explicit privacy decision plus a
tested redaction/opt-in mechanism; PR 20B ships none.

## Correlation

Telemetry propagates stable identifiers:

- `investigation_id`;
- `request_id`;
- `job_id`.

These identifiers correlate API, worker, graph, provider, RAG, and LLM activity.

## Provider telemetry

Record normalized metadata such as:

- provider ID;
- entity ID;
- start/end/duration;
- outcome;
- evidence count;
- retry count;
- typed error category.

Do not log credentials or authorization headers.

## Task dispatch

Local dispatch is an internal application boundary. PR 19C adds no investigation timeline event solely for local dispatch.

PR 21 extends the analyst-facing timeline with stable coordinator event types
(`PIVOT_ENQUEUED`, `PIVOT_EXECUTED`, `PIVOT_SKIPPED`,
`ASSESSMENT_REQUESTED`, `INVESTIGATION_STOPPED`), bounded fields
(`pivot_depth`, `reason_code`, `provider_calls_used`, `replans_used`,
`entity_count`), and the documented action URN vocabulary
(`urn:ati:action:provider_query`, `entity_discovered`, `pivot_enqueued`,
`pivot_executed`, `pivot_skipped`, `assessment_requested`,
`investigation_stopped`) consumed by coordinator trajectory evaluation.
Graph transitions append their matching events in the same UnitOfWork
transaction as the state change (PIVOT_ENQUEUED with authorization,
PIVOT_EXECUTED when a pivot enters execution, ENTITIES_DISCOVERED with
outcome recording, INVESTIGATION_STOPPED with the terminal transition);
ASSESSMENT_REQUESTED is appended in a short committed transaction before
analyst execution. A single deterministic converter
(`convert_timeline_actions`) maps ordered events to evaluator action records.
Events carry typed identifiers and bounded depth/reason/counter fields only —
never provider payloads, secrets, prompts, or free-form model reasoning — and
remain append-only.

Tracing may instrument dispatch, but tracing is not timeline or domain history, must not expose secrets, and must not imply broker delivery, acknowledgement, redelivery, or other distributed semantics that do not exist in v0.1.

## LLM telemetry

Record:

- investigation ID;
- graph/node/agent role;
- operation URN;
- model provider/model identifier;
- model profile;
- prompt version;
- timing;
- token counts where available;
- retry count;
- structured-output validation result;
- error category;
- budget consumption.

Do not persist hidden chain-of-thought.

## RAG telemetry

Record:

- research query metadata;
- subject entity IDs;
- retrieval count;
- retrieved chunk IDs;
- source IDs;
- ranking/similarity metadata where useful;
- latency;
- synthesis validation/citation outcome.

## Datasource operational log (PR 27B)

PR 27B adds a distinct durable operational layer: `ati.datasource_log`
records one acquisition execution's lifecycle events, each carrying the
same `execution_id` and `datasource_id` (`STARTED`/`ACQUIRED`/`DECODED`/
`CONVERTED`/`COMPLETED`/`FAILED`/`CANCELLED`; terminal outcomes exactly
`COMPLETED`/`FAILED`/`CANCELLED`). It is deliberately separate from:

- application logs/traces: the datasource log is not a replacement for
  structured logging or LangSmith tracing and never carries prompts,
  durations, or per-call diagnostics beyond its bounded fields;
- the investigation timeline and audit log: datasource events are
  operational acquisition history, not analyst-facing workflow or
  security/governance history;
- Evidence/provenance: datasource log events are not Evidence, never enter
  Evidence persistence, and carry no facts, payloads, or Evidence content.

The log persists only bounded operational metadata (stage-local non-negative
`item_count`/`byte_count`, a safe bounded `error_code` bound to `FAILED`)
plus identities and timestamps. Cancellation is recorded as `CANCELLED` and
never as a failure code; raw exception text, tracebacks, source bodies,
credentials, and unsafe URLs never enter the log.

### Stage-aware failure ownership (PR 27C)

The PR 27C acquisition-to-semantic path distinguishes where a datasource
acquisition failed through typed `DatasourceStage` values
(ACQUISITION / SERIALIZATION / SEMANTIC_VALIDATION) on the application-side
`DatasourceStageError`; the durable log persists only the corresponding
bounded safe `FAILED` code (`acquisition_failed`, `serialization_failed`,
`semantic_validation_failed`, or stable specific codes such as `timeout`,
`rate_limited`, `authentication_failed`, `provider_unavailable`). No new
event type was added; stage classification is typed at the failure boundary
and is never inferred by matching free-form error-message text.

### Conversion accounting (PR 27D)

The PR 27D conversion runner reuses the same PR 27B recorder and the
existing `CONVERTED` event; no conversion logger or second execution
identity exists:

- `CONVERTED.item_count` is the exact number of immutable `Evidence`
  observations produced by the pure conversion step (`len(evidence)`),
  logged in its own short committed transaction;
- `CONVERTED(0)` is a valid success: it proves conversion ran and that no
  validated source object carried an ATI-supported assertion (a valid
  no-result is never benign evidence);
- a converter contract/programming failure is a conversion-stage failure
  recorded only as the bounded safe `FAILED` code `conversion_failed` —
  never `CONVERTED`, never `COMPLETED`, and never raw exception text;
- cancellation remains `CANCELLED` (never a failure code) and
  `CancelledError` always propagates.

### Execution-level terminal timing (PR 27E)

In the migrated Investigation runtime the datasource execution terminal is
**deferred until required Evidence runtime processing succeeds** — the
PR 27B recorder's appends remain execution-level, never per Evidence:

- STARTED, ACQUIRED, and DECODED are appended by the acquisition path in
  short committed transactions;
- CONVERTED(item_count = total Evidence count) is appended immediately
  after the pure conversion step (exactly once per execution — never once
  per Evidence);
- COMPLETED is appended only after every returned Evidence was extracted
  and committed through the existing observation persistence boundary and
  the aggregate completion processing succeeded;
- a runtime failure (provider binding, extraction, persistence, timeline)
  appends FAILED with a bounded safe code
  (`provider_binding_failed`/`extraction_failed`/`persistence_failed`/
  `timeline_failed`); earlier committed Evidence remains durable and is
  never compensated;
- cancellation observed at any point appends CANCELLED (best effort) and
  propagates — never FAILED, never COMPLETED afterward;
- typed acquisition failures (timeout, rate limit, authentication,
  forbidden, malformed serialization, semantic invalid) appends FAILED
  with the corresponding bounded source-stage code and never CONVERTED;
- the batch SourceRecord ingestion path writes no datasource-log rows at
  all, so no per-batch lifecycle multiplication can occur.

All of these events stay inside the bounded log schema: no source body,
Evidence body, credential, or raw exception text ever enters the durable
log.

## Data minimization

Default telemetry favors identifiers and normalized execution metadata.

Do not automatically record:

- API keys;
- passwords;
- session cookies/tokens;
- authorization headers;
- unrestricted raw provider payloads;
- hidden reasoning;
- secret-bearing prompts;
- unrestricted document content.

Full prompt/content capture, if ever enabled for development/evaluation, must be explicit and redactable.

## Structured logging

Logs use structured fields.

Example:

```json
{
  "timestamp": "...",
  "level": "INFO",
  "service": "ati-worker",
  "event": "provider_call_completed",
  "investigation_id": "...",
  "job_id": "...",
  "provider": "urn:ati:source:threatfox",
  "duration_ms": 183,
  "evidence_count": 2
}
```

## Metrics vocabulary

Initial metric names should remain stable even if the exporter/backend changes.

Examples:

- `ati_investigations_started_total`
- `ati_investigations_completed_total`
- `ati_investigations_partial_total`
- `ati_investigations_failed_total`
- `ati_provider_calls_total`
- `ati_provider_errors_total`
- `ati_provider_latency_seconds`
- `ati_llm_calls_total`
- `ati_llm_errors_total`
- `ati_llm_tokens_input_total`
- `ati_llm_tokens_output_total`
- `ati_rag_retrievals_total`
- `ati_rag_retrieved_chunks_total`
- `ati_jobs_pending`
- `ati_jobs_running`

PR 29 standardizes Prometheus as ATI's metrics backend through OpenTelemetry
export while keeping metric semantics independent of the backend API.

PR 29 also extends this vocabulary with the canonical Evidence-flow counters
defined above. High-cardinality domain identifiers remain prohibited as metric
labels.

## Evaluation portability

Canonical evaluation scenarios, expected results, and evaluator logic live in the repository, for example:

```text
evals/
├── scenarios/
├── expected/
├── datasets/
└── evaluators/
```

LangSmith may execute/visualize evaluations, but it is not the sole owner of the expected truth set.

Switching observability platforms must not require redefining ATI's canonical evaluation semantics.

## Failure behavior

Observability is fail-open relative to investigation execution.

```text
trace export failure
 -> structured warning
 -> bounded/no retry storm
 -> investigation continues
```

Observability outages do not cause investigation `FAILED`.
