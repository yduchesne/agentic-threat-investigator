# Agentic Threat Investigator — Testing and Engineering Quality

## Table of contents

- [Purpose](#purpose)
- [Quality contract](#quality-contract)
- [Python project management](#python-project-management)
- [Formatting](#formatting)
- [Imports](#imports)
- [Linting](#linting)
- [Static typing](#static-typing)
- [Pytest test categories](#pytest-test-categories)
- [Unit tests](#unit-tests)
- [Provider contract tests](#provider-contract-tests)
- [Provider validation matrices](#provider-validation-matrices)
- [Synthetic HTTP provider integration tests](#synthetic-http-provider-integration-tests)
- [Typical provider issues to watch for](#typical-provider-issues-to-watch-for)
- [Database integration tests](#database-integration-tests)
- [Redpanda / Kafka integration tests (PR 28G)](#redpanda--kafka-integration-tests-pr-28g)
- [Distributed Evidence ingestion closure (PR 28H)](#distributed-evidence-ingestion-closure-pr-28h)
- [Migration tests](#migration-tests)
- [Test isolation](#test-isolation)
- [Synthetic fixtures](#synthetic-fixtures)
- [Fake implementations](#fake-implementations)
- [Structured agent output and deterministic formatter tests](#structured-agent-output-and-deterministic-formatter-tests)
- [Scenario factory](#scenario-factory)
- [Coverage](#coverage)
- [Pre-commit](#pre-commit)
- [Canonical quality command](#canonical-quality-command)
- [No quality-gate bypass](#no-quality-gate-bypass)
- [CI quality gate](#ci-quality-gate)
- [Frontend quality](#frontend-quality)
- [PR 26 GEOINT testing strategy](#pr-26-geoint-testing-strategy)
- [Definition of done](#definition-of-done)
- [Configuration tests](#configuration-tests)
- [Batch persistence and history tests](#batch-persistence-and-history-tests)

## Purpose

This document defines ATI's conventional software testing and source-quality requirements.

Behavioral evaluation of agents, LLM outputs, RAG quality, investigation trajectories, and release evaluation gates is specified separately in `EVALUATION.md`.

## Quality contract

ATI treats automated quality gates as mandatory engineering requirements.

Python tooling:

- `uv` — environment, dependency, lockfile, and command management.
- Ruff — formatting, import ordering, linting.
- Mypy — static type checking.
- Pytest — tests.
- pytest-cov — coverage.
- pre-commit — fast local checks.

The authoritative dependency files are:

- `pyproject.toml`
- `uv.lock`

`uv.lock` is committed.

## Python project management

`uv` owns:

- Python dependency management;
- virtual environment management;
- dependency locking;
- development command execution.

Typical commands:

```bash
uv sync --locked
uv run ruff format .
uv run ruff check .
uv run mypy ...
uv run pytest
```

Do not maintain parallel hand-edited `requirements.txt` dependency definitions unless an external integration explicitly requires an exported format.

## Formatting

Ruff formatter is authoritative for Python formatting.

Development:

```bash
uv run ruff format src tests
```

CI:

```bash
uv run ruff format --check src tests
```

No competing Python formatter is introduced.

## Imports

Ruff's `I` rules own import ordering; the first-party package is declared in
`[tool.ruff.lint.isort]`.

Commands:

```bash
uv run ruff check src tests --select I
uv run ruff check src tests --select I --fix
```

## Linting

Ruff is the Python linter. Enabled rule families are explicit in
`pyproject.toml` ([`tool.ruff.lint.select`]); enabled violations are binary
pass/fail — one violation fails the gate.

Project-wide exceptions belong in repository configuration when architecturally justified.

Local suppressions are exceptional and must use an explicit code:

```python
# noqa: <CODE>
```

Only narrowly scoped `# noqa` directives are allowed; bare `# noqa` and
blanket file/global suppressions are prohibited unless independently
justified and approved. Every non-obvious suppression should keep a short
justification. Ruff's `RUF100` gate reports any unused suppression.

## Static typing

Mypy runs in strict mode for ATI-owned production code and all integration-test code. The integration target is checked explicitly, including every module under `tests/integration/`:

```bash
uv run mypy src tests/integration
```

Conceptually:

```toml
[tool.mypy]
strict = true
```

Third-party typing gaps may receive narrowly scoped exceptions.

Do not globally weaken type checking because one dependency lacks complete typing.

Architectural boundaries should avoid casual propagation of `Any`.

Test infrastructure such as fake providers, scenario builders, repositories, `FakeLlmClient`, and fixture factories should also be strongly typed.

## Pytest test categories

Pytest owns automated Python testing.

Tests are organized into:

- unit tests;
- integration tests;
- provider contract tests;
- database/migration tests;
- deterministic scenario-support tests.

Suggested markers:

```python
@pytest.mark.unit
@pytest.mark.integration
@pytest.mark.provider_contract
```

Agent/LLM behavioral evaluation may use additional markers but its contracts and scoring belong in `EVALUATION.md`.

## Unit tests

Unit tests should be fast, deterministic, and isolated from network/database
dependencies unless the tested unit specifically requires them.

### Deterministic telemetry unit tests (PR 29A)

Telemetry tests are deterministic and fully offline; they never contact
Prometheus, Jaeger, Loki, Grafana, LangSmith Cloud, Langfuse Cloud, an OTel
Collector, or any self-hosted backend, and they never require Docker/Podman.
They use OpenTelemetry's in-memory exports/reads:

- span assertions use `InMemorySpanExporter` (name, parent/child, attributes,
  status, exception events);
- metric assertions use `InMemoryMetricReader` (name, unit, value, attributes);
- the decorator seam is injected by monkeypatching ATI's own
  `telemetry.decorators` helper functions, never process-global OTel providers
  (which OTel's public API only allows setting once).

PR 29A adds **no telemetry integration-test requirement**; that is deliberate
and matches the approved roadmap. There is no dedicated telemetry
integration-testing phase.

PR 29A-1 keeps that policy and adds deterministic unit coverage of the
PostgreSQL/Kafka/Evidence instrumentation:

- a structural repository-coverage test walks every concrete PostgreSQL
  repository/resolver class and asserts each public I/O method carries
  `@postgres_repository_operation` telemetry, pinned against a committed
  reviewed inventory (no brittle source-text parsing);
- UoW telemetry tests drive the real `PostgresUnitOfWork` with a fake
  SQLAlchemy-like session (composite registration neutralized) and assert
  commit/rollback/failure/cancelled outcomes, explicit commit/rollback
  timing, and nested repository spans;
- Kafka publish/poll/commit telemetry tests use the same broker boundary
  doubles as the PR 28G adapter matrix;
- Evidence-flow telemetry tests use the spy consumer/persistence doubles.

The telemetry helper seams (
`telemetry.decorators.get_tracer`/`get_histogram`/`get_counter` and the
corresponding module-level bindings in `database.py`, the Kafka adapters, and
the Evidence consumer) are injected through the shared `tests/unit/conftest.py`
fixtures; no test relies on process-global OTel providers.

PR 29B keeps the same deterministic, offline policy and adds unit coverage
for every remaining stable boundary:

- **DS1..DS7** (datasource): acquisition success span/duration, typed stage
  failure counts, cancellation propagation, conversion item counts (N and
  zero), conversion exception preserving the lifecycle, and no duplicate
  Kafka publication counters on the producer path;
- **H1..H7** (provider HTTP): first-attempt success, retry-then-success,
  exhausted retries, cancellation, and the absence of URLs/paths/bodies
  from attributes;
- **PW1..PW5** (provider work): one logical work span regardless of internal
  HTTP attempts, mixed-result outcome semantics, bounded failure counts,
  and cancellation;
- **EP1..EP4** (Evidence persistence): the `ati.evidence.persist` span,
  persist > UoW > repository nesting, rollback/exception preservation, and
  no double-counted outcome counters;
- **G1..G5** (GEO): resolved/unresolvable/failed counts, empty-claim no
  invented work, and cancellation;
- **I1..I4** (investigation): one execution span/counter, no-op terminals
  count nothing, bounded failures, and no Investigation-ID labels;
- **A1..A5** (agents): Research Agent normal/empty/one-repair model-attempt
  counts, Evidence Analyst and Report Writer using the common observed
  client;
- **A6..A13** (LLM): one span + one observation per actual attempt, typed
  `LlmError` and cancellation preservation, no prompt/output capture, no
  fabricated token metrics, backend fail-open, and NoOp export absence;
- **P1..P6** (Kafka W3C): producer traceparent injection, consumer parent
  extraction making downstream work a child, malformed-header safety,
  unrelated-header preservation, byte-identical payload/key, and no-outer-
  span publish correctness.

PR 29B-1 keeps the same deterministic, offline policy for the inbound
FastAPI/ASGI HTTP boundary and adds the API-T01..API-T18 unit matrix in
`tests/unit/api/test_telemetry.py` using in-memory OTel providers and the
previously delivered in-memory span/metric readers — no Collector,
Prometheus, Jaeger, Loki, Grafana, Docker/Podman, or live services:

- **API-T01/API-T15/API-T16**: one standard HTTP server span per registered
  route (including `/health/live` and `/health/ready`) and bounded identity
  for unknown unmatched paths (no route label is manufactured from an
  arbitrary incoming path);
- **API-T02/API-T03/API-T05/API-T06/API-T07**: method × registered
  route-template distinction (GET vs DELETE on the same template), dynamic
  UUID paths mapped to the registered template, and `2xx`/`4xx`/`5xx`
  standard response-status telemetry with unchanged response behavior;
- **API-T08/API-T09**: a valid incoming W3C `traceparent` resumes the
  upstream trace and a malformed one fails safely;
- **API-T10**: an ATI span started inside a route is a descendant of the
  HTTP server span (same trace ID and server parent) with no context
  plumbing into handler signatures;
- **API-T04/API-T11/API-T12/API-T13**: query, request-body, response-body,
  authorization, cookie, CSRF, and Idempotency-Key sentinels
  (`DO_NOT_CAPTURE_*_29B1`) are absent from every recorded span
  attribute/event and metric attribute;
- **API-T14/API-T17/API-T18**: disabled telemetry installs no HTTP pipeline
  and leaves API behavior identical, repeated instrumentation never
  duplicates spans/metrics, and the request-ID middleware contract is
  unchanged through the instrumented middleware stack.

The tests pin `OTEL_SEMCONV_STABILITY_OPT_IN` to an empty value so the
resolved official instrumentation deterministically emits its default
semantic-convention names in any developer environment.

PR 29B-2 keeps the same deterministic, offline policy for the API telemetry
lifecycle and adds the API-L01..API-L07 unit matrix in
`tests/unit/api/test_telemetry_lifecycle.py`, using the real `create_app`
lifespan over an `ApiComposition` double plus a plain seam-level harness with
in-memory OTel providers — no database, Kafka/Redpanda, Collector,
Prometheus, Jaeger, Loki, Grafana, Docker/Podman, or live services:

- **API-L01/API-L07**: on normal shutdown `ApiComposition.dispose()` runs
  before the telemetry-shutdown callback, which runs exactly once per
  application lifecycle;
- **API-L02**: when API disposal raises, telemetry shutdown is still
  attempted and the original disposal exception remains authoritative;
- **API-L04**: when application startup fails before serving, the
  `finally`-equivalent seam cleanup still runs and the original startup
  exception propagates;
- **API-L03**: disabled telemetry (no providers, no HTTP instrumentation)
  completes the same production-style sequence safely through the real
  `configure_telemetry`/`shutdown_telemetry`;
- **API-L05**: a request executes and its PR 29B-1 HTTP server span records
  before any shutdown, proving providers are never shut down prematurely;
- **API-L06**: a failing provider shutdown stays fail-open inside
  `shutdown_telemetry()` (logged, contained) and never replaces application
  semantics.

API-L08 (exactly one direct `opentelemetry-instrumentation-fastapi`
declaration) is enforced by dependency review and the repository build
(`uv lock`), consistent with the no-brittle-text-test policy.

### Deterministic OTLP composer tests and config validation (PR 29C)

PR 29C keeps the same deterministic, offline policy. The exporter
composition matrix (INF-C01..C09) lives in
`tests/unit/telemetry/test_setup.py` and drives the real
`configure_telemetry`/`shutdown_telemetry` with in-memory recording
exporters monkeypatched into the composition seams — no network, no
Collector/backends:

- **INF-C01/C02**: disabled (or enabled-without-endpoint) telemetry composes
  no exporter/logger pipeline and stays offline;
- **INF-C03**: enabled with an explicit endpoint composes all three
  OTLP/HTTP pipelines exactly once;
- **INF-C04/C05**: repeated identical setup is idempotent (no duplicate
  pipeline or logging handler); conflicting setup raises ``RuntimeError``;
- **INF-C06/C07**: shutdown shuts all configured signal providers, detaches
  the additive OTel logging handler, and is fail-open;
- **INF-C08/C09**: an exported log outside any span carries no fabricated
  identity; inside a span it carries the standard OTel trace/span ids;
- the endpoint contract is pinned (the exporter appends `/v1/traces`,
  `/v1/metrics`, `/v1/logs` to the standard `OTEL_EXPORTER_OTLP_ENDPOINT`).

The worker/GEO process wiring matrix (INF-C10..C14) lives in
`tests/unit/infrastructure/test_cli_telemetry.py` and proves, with fake
engines and no database, that disabled observability stays unchanged and
that engines are disposed before `shutdown_telemetry` on both normal and
failure paths, without replacing original error semantics.

PR 29C adds deterministic **configuration validation** (not
end-to-end telemetry integration tests):

- **INF-C19**: the pinned Collector accepts `infra/observability/otel-collector/config.yaml`
  via the image's non-network `validate --config` path;
- **INF-C20**: `promtool check config` (pinned `prom/prometheus:v3.14.0`)
  succeeds on `infra/observability/prometheus/prometheus.yml`;
- **INF-C21**: the Grafana datasource YAML parses and Datasource UIDs are
  unique/stable (`ati-prometheus`, `ati-jaeger`, `ati-loki`);
- **LOKI-C1..C7** (PR 29C-1): PyYAML-level static invariants on
  `infra/observability/loki/config.yaml` — global retention exactly `336h`,
  structured metadata enabled, the obsolete `storage_retention_days` key
  absent, Compactor retention enabled, filesystem delete-request store, and
  the retention-compatible TSDB/v13/24h/filesystem topology;
- **INF-C16/C17/C18**: `compose.yaml` alone and with
  `compose.observability.yaml` both validate.

The no-live-integration-test policy is unchanged: there is **no** PR 29E
and PR 29C does not add a test that boots the stack and waits for spans/logs
inside a Collector/Jaeger/Loki. The developer smoke procedure documented in
`docs/OBSERVABILITY.md` is a manual developer flow, not CI correctness.

The PR 29C-1 testing boundary for Loki configurations is three distinct
levels; unit tests deliberately cover only the first:

```text
PyYAML unit tests (LOKI-C1..C7)
  -> ATI-owned static retention/topology invariants

pinned Loki -verify-config=true (grafana/loki:3.7.8)
  -> Loki configuration/schema compatibility

full telemetry/backend integration
  -> intentionally not part of PR 29
```

PyYAML parsing never proves Loki accepts a configuration; the pinned
`-verify-config=true` command is the documented developer/reviewer check
(`docs/OBSERVABILITY.md`) and ordinary unit CI must not require a container
runtime.

### Deterministic Grafana dashboard tests (PR 29D / PR 29D-1)

PR 29D added `tests/unit/observability/test_grafana_dashboards.py`, a static
(offline, deterministic) validation of the dashboards-as-code contract. PR 29D-1
corrected the tests to validate Grafana 13.2.2's *actual* runtime fields: the
Prometheus helpers parse the executable `expr` targets (never the ATI-invented
`query` surrogate) and the navigation helpers parse Grafana's dashboard
`links` model (never `externalLink` pseudo-panels). The file parses
`infra/observability/grafana/provisioning/dashboards/dashboards.yaml`, the
provisioned datasources, `compose.observability.yaml` (mount contract), and
every dashboard JSON under `infra/observability/grafana/dashboards/`, and
asserts the frozen matrices:

- **GRAF-C01**: the file provider parses and points at the mounted canonical
  directory (`/etc/grafana/dashboards`), and Compose mounts the provisioning
  tree and the canonical dashboard directory read-only;
- **GRAF-C02..C05**: exactly nine dashboard files, all valid JSON, with the
  exact nine UIDs (unique) and the agreed titles;
- **GRAF-C06..C08**: Prometheus panels use `ati-prometheus`, Loki panels use
  `ati-loki` with classic LogQL brace expressions, and trace usage stays
  within the stable `ati-jaeger` contract (datasource provisioned; the Jaeger
  UI is reached through a supported dashboard `link`, not a pseudo-panel);
- **GRAF-C09..C11**: overview links to all eight details, every detail links
  back to the overview, and the agreed drill-down hierarchy exists
  (Investigations -> Agents & LLM, Datasource & Ingestion -> Kafka / Redpanda
  and -> Persistence / Repository, Persistence / Repository -> PostgreSQL);
- **GRAF-C12/C13**: no IDs/IP/domain/URL/request/execution identifiers or IP
  literals anywhere in the dashboard surface, and API identity is method x
  registered route template only (no concrete-path filter values);
- **GRAF-C14..C18**: panels reference only the stable datasource UIDs, tags
  include `ati`/`observability`, sane last-1h/10s defaults, plain-JSON-only
  canonical tree (no dashboard-generation framework), and no embedded
  credentials;
- **query ownership** (executable target expressions are parsed, not
  descriptions searched): API uses route-template HTTP telemetry; Kafka lag
  joins derive from `redpanda_kafka_max_offset` minus
  `redpanda_kafka_consumer_group_committed_offset` and never from `ati_kafka`
  counters; PostgreSQL uses postgres-exporter series; Persistence uses ATI
  repository/UoW series; Datasource & Ingestion contains the Evidence-flow
  series; GEO contains GEO outcome series; Agents & LLM contains
  agent/LLM/provider series; Investigations & Reports contains
  investigation/report series; counters are consumed with
  `rate()`/`increase()`/grouped `sum`; `histogram_quantile` uses `_bucket`
  series with `by (le, ...)` grouping; application and infrastructure
  dashboards remain separated;
- **GRAF-F01..F18** (PR 29D-1 runtime-contract matrix):
  - **GRAF-F01/F02**: every intended Prometheus target has non-empty,
    executable `expr` and no target uses the custom `query` surrogate field;
  - **GRAF-F03**: the frozen PR 29D PromQL multiset is preserved exactly
    (the expressions were moved into `expr` without text changes);
  - **GRAF-F04/F05**: navigation is parsed from Grafana's verified dashboard
    `links` contract (`type: "link"`, `url`, `keepTime`, `targetBlank`, ...)
    and no `type == "externalLink"` pseudo-panel remains;
  - **GRAF-F06..F10**: overview links to all eight details; every detail
    links back; the drill-down hierarchy exists; destinations use stable
    `/d/<uid>` relative URLs (only the allowlisted local Jaeger UI is an
    absolute link); `keepTime` preserves the time range on dashboard links;
  - **GRAF-F11**: the three stable datasource UIDs are unchanged; panels use
    only `ati-prometheus`/`ati-loki` and the `ati-jaeger` datasource stays
    provisioned for trace exploration;
  - **GRAF-F12**: per-dashboard query-ownership markers (API
    route-template HTTP, Redpanda-authoritative lag, postgres-exporter,
    ATI repository/UoW, Evidence flow, GEO, agent/LLM/provider/embedding,
    investigation/report);
  - **GRAF-F13**: privacy/cardinality rules preserved in every executable
    expression;
  - **GRAF-F14**: Loki targets use the verified contract (`expr` LogQL with
    a bounded `service_name` label set, `queryType: "range"`, `ati-loki`);
  - **GRAF-F15**: Jaeger uses a supported dashboard link for the developer
    UI entry point plus the provisioned `ati-jaeger` datasource — no
    proxy/plugin/backend;
  - **GRAF-F16**: exactly nine dashboards with the exact UID/title mapping;
  - **GRAF-F17**: provisioning YAML and the read-only canonical mount are
    unchanged;
  - **GRAF-F18**: no new ATI application telemetry series is referenced
    (scope guard: every `ati_*` series used belongs to the frozen PR 29D
    instrument set).

These tests never require a live stack. PromQL/Loki/panel runtime health is
verified by the manual developer smoke procedure in
`docs/OBSERVABILITY.md` (`Grafana dashboards (PR 29D)` section; PR 29D-1
re-validates it against pinned Grafana 13.2.2) — the
no-telemetry-integration-test rule is unchanged.

Priority unit-test areas include:

- entity canonicalization;
- pivot-policy helpers;
- budget accounting;
- coordinator policy (PR 21): deterministic candidate ordering from
  traversal, same-or-better-depth suppression, root work at entity-budget
  capacity, exact depth/entity/provider/replan boundaries, stop-reason
  precedence, and replan-only-with-new-work semantics;
- coordinator scenario loading (PR 21, updated by PR 21D): a strict
  13-scenario corpus under `evals/scenarios/coordinator/` that fails closed
  on malformed JSON, duplicate IDs, unsupported versions, blank fixture
  names, unknown fields, duplicate labels, and — since PR 21D — a missing
  `allowed_pivots` oracle, duplicate allowed pivot identities, blank or
  negative pivot entries, required pivots not represented in `allowed_pivots`,
  and forbidden pivots appearing in `allowed_pivots`;
- coordinator trajectory evaluation (PR 21, updated by PR 21D): every
  failure code, bounded `[0.0, 1.0]` metrics, depth-aware provider-work
  matching, transition bounds, deterministic failure ordering, and the
  independent per-scenario pivot oracle — pivot authorization
  (`PIVOT_ENQUEUED`) and `PIVOT_EXECUTED` are each validated against
  `allowed_pivots` (entity + exact depth), execution additionally requires a
  preceding matching enqueue, an illegal enqueue fails even when never
  executed, and policy-invalid rates count unique pivot identities;
- PR 21B/21D admission and corpus semantics: the entity budget is evaluated
  only above exact capacity (`entity_count > max_entities`); an
  exact-capacity pivot onto an already-admitted entity remains legal. Every
  repository-owned scenario executes through the real Coordinator graph from
  its deterministic checkpoint and evaluates cleanly (zero
  invented/policy-invalid pivots, zero budget violations, full termination)
  in `tests/unit/app/orchestration/test_coordinator_trajectories.py`, and
  the canonical PostgreSQL trajectory evaluates through the loaded oracle in
  `tests/integration/test_coordinator_trajectory.py`;
- relationship extraction;
- deterministic source extraction (PR 18B) including per-source
  malformed-fact rejection and deterministic deduplication;
- source normalization;
- content hashing;
- authorization decisions;
- soft-delete semantics;
- DTO/domain validation;
- retry classification;
- report/assessment structural validation;
- structured agent-result validation and serialization;
- deterministic report/presentation formatting;
- deterministic orchestration mechanics (PR 19A, updated by PR 19C): typed
  work-item validation, FIFO queue selection, duplicate suppression, outcome
  bookkeeping, provider-call counter accounting, and JSON state round-trip.
  Queue-exhaustion termination is legacy PR 19A mechanics exercised only
  through the explicitly named `build_legacy_investigation_graph` test
  helper; it does not describe the production graph, which is
  Coordinator-driven (coordinator -> execute provider work -> authorize
  pivot -> request analysis -> stop). Queue exhaustion no longer terminates
  production investigation execution directly: it returns control to the
  Coordinator, which selects the next bounded decision or a specific
  stop reason. Graph mechanics are tested against `TaskDispatcher`;
- local dispatch (PR 19C): `LocalTaskDispatcher` delegates the exact selected
  item exactly once, preserves the exact outcome, propagates exceptions and
  cancellation unchanged, and performs no state, persistence, or timeline
  mutation;
- deterministic provider execution (PR 19B): target/provider resolution,
  applicability validation, empty-success and error-only outcomes,
  cancellation propagation, extraction-before-persistence sequencing,
  per-Evidence PR 18C invocation, outcome ID bookkeeping (evidence,
  relationship, discovered entity merges; one provider-call increment per
  work item), and timeline event ordering/failure semantics, via fakes in
  `tests/unit/app/orchestration/test_provider_executor.py` (shared
  deterministic fakes/builders in `tests/support/provider_executor_fixtures.py`);
- provider-output provenance and partial-failure regressions (PR 19B
  fixes): binding validation of the returned provider, owning
  investigation, and persisted target (type, exact canonical value,
  subject identifier; malformed/noncanonical subjects provably reach zero
  extraction and zero persistence; a two-Evidence tuple with one invalid
  item proves full preflight), retention of all committed
  Evidence/Entity/Relationship IDs when a later Evidence fails extraction
  or persistence (including through state bookkeeping and when the failure
  timeline event itself cannot append), canonical first-seen aggregate ID
  lists across outcomes and completion events, and bounded secret-free
  logging of caught provider/persistence/timeline exceptions (adversarial
  injected exception text never appears in any log message or record and
  every record has `exc_info is None`), via
  `tests/unit/app/orchestration/test_provider_executor_regressions.py`;
- timeline event-shape and error-code contract (PR 19B): table-driven
  domain tests for every valid event type and each invalid field
  combination, including blank, padded, uppercase, punctuation, and
  65-character error codes, via
  `tests/unit/domain/test_investigation_timeline.py`, plus a database
  integration assertion that an invalid code is rejected even when model
  validation is bypassed;
- migration lifecycle and schema contract (PR 19B): migration 0013
  downgrades to 0012 and re-upgrades to head, proving the timeline table
  and owned sequence absence at 0012 and clean reinstall with checks,
  index, and sequence ownership; the schema contract asserts the
  error-code CHECK and that no ATI routine mutates timeline events, via
  `tests/integration/test_migration.py`;
- UnitOfWork lifecycle (PR 19B): a closed UoW exposes no stale timeline
  repository and re-enters with a fresh repository, including the
  rollback path, via `tests/integration/test_investigation_timeline_repository.py`;
- production composition (PR 19B, updated by PR 19C):
  `build_provider_investigation_graph` assembles `ProviderWorkExecutor`, wraps
  it in `LocalTaskDispatcher`, and injects that dispatcher into the compiled
  graph without global state. The compiled graph is invoked asynchronously in
  the vertical slice, via `tests/unit/app/orchestration/test_composition.py`
  and the pipeline test;
- application-level runner (PR 21C): `LocalInvestigationRunner` loads the
  authoritative persisted Investigation through a short UnitOfWork, closes it
  before graph execution, treats terminal investigations as idempotent
  no-ops, creates a fresh bound analysis executor and graph per invocation
  (cross-investigation isolation, conflicting bindings fail before provider
  or graph work), passes the exact persisted state into the graph, fails
  closed on non-terminal graph output and on graph/durable mismatches,
  returns the authoritative durable reload, propagates cancellation
  unchanged, and rejects non-positive recursion limits — via
  `tests/unit/app/orchestration/test_runner.py` with fakes only, plus the
  canonical PostgreSQL trajectory, terminal-idempotency, isolation,
  missing-ID, and graph-owned analysis-failure cases in
  `tests/integration/test_coordinator_trajectory.py`;
- graph context binding (PR 19B): a provider-backed compiled graph is bound
  to one investigation ID; invoking it with a state for another
  investigation raises `InvestigationGraphContextMismatchError` during
  `initialize` before queue selection, target lookup, timeline emission,
  provider I/O, extraction, or persistence. The binding path is
  `graph -> LocalTaskDispatcher -> bound ProviderWorkExecutor`: automatic
  investigation binding is preserved through the dispatcher, direct public
  composition cannot bypass isolation, an explicit conflicting ID fails at
  construction with `InvestigationGraphBindingConflictError`, and a wrong
  invocation state fails before dispatch or I/O. Generic graphs without an
  expected ID and ordinary unbound dispatchers remain supported. Unit coverage
  (all five binding
  cases, the direct-builder bypass, and the construction conflict) lives in
  `tests/unit/app/orchestration/test_graph.py`, `test_composition.py`, and
  `test_provider_executor.py`; two PostgreSQL regressions in
  `tests/integration/test_provider_execution_pipeline.py` (factory path and
  direct generic-builder path) prove durable absence (no Evidence, timeline
  event, Relationship, RelationshipObservation, or state mutation for either
  investigation) using exploding transports.

### Datasource vocabulary and definition contracts (PR 27A)

`tests/unit/domain/test_datasource.py` and
`tests/unit/config/test_datasource_settings.py` pin the typed datasource
vocabulary deterministically and offline (stable matrix IDs D27A-01..D27A-13):

- exact durable semantic-format URNs
  (`urn:ati:datasource:semanticformat:stix21` and
  `urn:ati:datasource:semanticformat:threatfox`);
- every existing durable `SourceId` serialized value remains exact;
- one immutable `DatasourceDefinition` requires all five dimensions with
  exact independent values for the ThreatFox (HTTPS + JSON + ThreatFox
  semantics) and MITRE ATT&CK (FILE + JSON + STIX 2.1 semantics)
  representative definitions;
- datasource-instance ID validation rejects blank, whitespace-only, padded,
  malformed, and over-bound values;
- unknown protocol, serialization, and semantic-format values fail closed;
- duplicate datasource IDs are rejected in any `Settings`/profile collection
  while two datasource instances sharing one `SourceId` remain legal;
- no-inference tests prove provider, protocol, and serialization never select
  semantics (JSON definitions carry distinct semantic formats; unusual
  provider/protocol combinations construct unchanged).

These tests never touch the network or the database.

### Datasource execution logging (PR 27B)

`tests/unit/domain/test_datasource_log.py`, `tests/unit/app/test_datasource_execution_recorder.py`
and `tests/integration/test_datasource_log.py` pin the PR 27B acquisition
lifecycle deterministically and offline/against real PostgreSQL (stable
matrix IDs D27B-U01..U13, D27B-P01..P15, D27B-V01/V02, D27B-C01, D27B-S01):

- fresh per-execution UUIDs; identity stability across every event of one
  execution (same `execution_id`, same `datasource_id`);
- immutable `DatasourceLogEvent` model: aware timestamps normalize to UTC,
  naive timestamps fail closed, zero/positive stage-local counts accepted and
  negative counts rejected, bounded canonical error codes (blank/
  whitespace/over-bound/malformed rejected) bound to `FAILED` only, and
  `extra="forbid"` rejecting any payload/exception/credential/metadata field;
- recorder lifecycles: success (STARTED + selected stages + COMPLETED),
  failure (STARTED + FAILED with a safe code), deterministic sleep-free
  cancellation (`CancelledError` propagates after a best-effort CANCELLED
  append; the durable log holds STARTED + CANCELLED and no
  FAILED/COMPLETED), terminal exclusivity, stage-after-terminal and
  duplicate-STARTED local rejection, and legal omitted stages
  (STARTED -> COMPLETED);
- real-PostgreSQL lifecycle/concurrency matrices: append/persist correlation,
  STARTED-first and STARTED-unique enforcement, datasource identity
  stability, terminal exclusivity, post-terminal rejection, concurrent
  terminal and initial-STARTED races yielding exactly one durable row,
  independent concurrent executions, database-owned count/error-code
  constraint backstops (direct SQL bypassing the Python model), and
  append-only repository shape (no update/delete method);
- migration round trip (D27B-P15): upgrade creates exactly the PR 27B
  objects and no `datasource_execution` table; downgrade removes only PR 27B
  objects while pre-existing authoritative rows (source records,
  investigations) survive unchanged;
- PR 28F-2 extension (F2-L12..L15 and V28F2-06): `PUBLISHED` is a
  non-terminal stage (accepted-message `item_count`, no `error_code`),
  rejected before STARTED and after a terminal outcome both locally and by
  the real stored function; SQL API v0028 (migration 0033) opens exactly
  the one additional non-terminal stage with a round-trip-tested
  downgrade restoring the seven-value v0025 vocabulary;
- the canonical vertical slice (D27B-V01/V02): the real
  `DatasourceExecutionRecorder` -> append port -> PostgreSQL repository ->
  stored function path over real PostgreSQL with simulated local work
  between short committed transactions, asserting exact ordering, counts
  only where supplied, no payload columns, no credentials/raw exception
  text, and no execution table;
- schema-level proof (D27B-S01) that the durable log columns are exactly
  the bounded operational set, so source bodies, Evidence bodies,
  credentials, and tracebacks cannot be persisted by the event schema.

### Datasource acquisition-to-semantic boundary (PR 27C)

PR 27C tests are deterministic, offline, and use real production parsing/
HTTP paths; only the external Internet endpoint is faked via in-process
`httpx.MockTransport`:

- cross-cutting contracts (`tests/unit/app/test_datasource_semantics.py`,
  D27C-U01..U08): exact context identity derived from one
  `DatasourceDefinition`, timezone-aware UTC retrieval timestamps (naive
  rejected), credential-free and bounded source references (credential-
  bearing, blank, non-HTTP, hostless, and over-bound references rejected),
  success/empty-semantics vs failure result invariants, bounded
  error-code grammar, and nonnegative retry delays;
- ThreatFox semantics (`tests/unit/infrastructure/datasources/test_threatfox_semantics.py`,
  D27C-T01..T20): no-result/empty-data empty successes, typed records in
  source order, identical-duplicate retention and conflicting-duplicate
  whole-response failure, unrelated-IOC rejection, malformed
  timestamp/URL/domain failures, body-encoded `ratelimited` as an
  operational acquisition failure, canonical `ip:port`/bracketed IPv6:port
  matching, ambiguous unbracketed IPv6+port rejection, UTC timestamps,
  parse determinism, and proof that the semantic module has no
  Evidence/provider import dependency;
- ThreatFox acquisition path (`tests/unit/infrastructure/datasources/test_threatfox_datasource.py`,
  D27C-X01..X09): full success (STARTED -> ACQUIRED -> DECODED ->
  COMPLETED), HTTP/serialization/semantic failures with typed stage-aware
  bounded codes and no intermediate stages, no-result DECODED item_count=0,
  deterministic cancellation (CANCELLED recorded, `CancelledError`
  propagates, never FAILED), distinct per-execution IDs, no UoW held across
  HTTP or semantic parsing (short committed transactions per append), no
  CONVERTED event, fail-closed dimension validation before I/O, and
  header-only Auth-Key with zero context/log leakage;
- STIX semantics (`tests/unit/infrastructure/datasources/test_stix21_semantics.py`,
  D27C-S01..S12): typed bundle/object parsing in source order, fail-closed
  envelope and object-identity validation, preserved `x_mitre_*` extension
  fields and unknown valid types, deep snapshot isolation from caller
  mutation, and the serialization boundary (raw bytes must be decoded
  before the semantic parser);
- the canonical real-stack vertical slice
  (`tests/integration/test_datasource_semantic_acquisition.py`): a
  deterministic local HTTP fixture -> real `ProviderHttpClient` -> real
  `ThreatFoxDatasource` -> real semantic parser -> real
  `DatasourceExecutionRecorder` -> real `PostgresUnitOfWork` -> real
  `ati.append_datasource_log_event` stored function -> real
  `ati.datasource_log`, asserting one execution ID, the exact
  STARTED/ACQUIRED/DECODED/COMPLETED and failure/cancellation lifecycles,
  exact bounded byte/item counts, no Evidence/SourceRecord/Investigation
  rows, and no raw body or credential in the durable log.

MITRE regressions unchanged: STIX-parser reuse in the batch source keeps
`SourceRecord` identities, canonical payloads, content hashes, and
checkpoints identical across the unit source tests, the ATT&CK ingestion
suite, and the real-format vertical slice.

### Semantic-format-driven Evidence conversion (PR 27D)

PR 27D tests are deterministic and offline; only the external Internet
endpoint is faked via in-process `httpx.MockTransport`:

- generic conversion contracts (`tests/unit/app/test_evidence_conversion.py`,
  D27D-C01..C10): immutable `EvidenceConversionContext` with exact
  Investigation/subject/semantic-context preservation, legal zero/one/
  multiple Evidence cardinality, deterministic flattening of multiple
  source objects (source-object order then converter-return order),
  structural repeatability of identical conversions, and deterministic
  local `ConversionError` failure;
- converter registry (`tests/unit/app/test_evidence_conversion.py`,
  D27D-R01..R10): lookup keyed only by `SemanticFormatId`; duplicate
  registration fails construction; unknown formats raise the typed
  `UnknownSemanticFormatError`; changed SourceId/protocol/serialization/
  datasource ID never select; misleading object shapes never fall back;
  and a wrong object for the selected converter fails closed;
- ThreatFox converter (`tests/unit/infrastructure/datasources/test_threatfox_evidence.py`,
  D27D-T01..T20): one validated `ThreatFoxRecord` -> one immutable
  `THREAT_INTELLIGENCE` Evidence with exact Investigation/subject/source
  URN/retrieved_at/observed_at/credential-free reference provenance,
  shared legacy-format match facts (identical to the legacy provider),
  source-confidence-as-source-fact, preserved tags/reference/nulls,
  `raw_payload=None`, `source_record_id` = exact upstream record ID,
  immutability, no credentials, no analytical inference, structural
  repeatability, and fail-closed wrong-format/wrong-object handling;
- legacy compatibility (D27D-L01..L08): the existing ThreatFox provider
  suites (`tests/unit/infrastructure/providers/test_threatfox*.py` and the
  extraction regression suite) remain green and assert the unchanged
  grouped-evidence shape, no-result/malformed/rate-limit/unsupported
  behaviors, and unchanged downstream extraction;
- conversion lifecycle (`tests/unit/infrastructure/datasources/test_threatfox_evidence.py`,
  D27D-E01..E06): typed `DatasourceStage.CONVERSION`, runner lifecycles
  over an in-memory UnitOfWork — success with `CONVERTED(item_count=N)`,
  valid no-result `CONVERTED(0)` then COMPLETED, converter violation
  `FAILED(conversion_failed)` with no CONVERTED/COMPLETED and no exception
  text, bounded durable error code, one execution ID, short committed
  transactions with no UoW held across HTTP/parsing/conversion, and
  cancellation (CANCELLED recorded, `CancelledError` propagates);
- the canonical real-PostgreSQL conversion-lifecycle slice
  (`tests/integration/test_datasource_evidence_conversion.py`, D27D-I01..I06):
  deterministic local ThreatFox HTTP fixture -> real `ProviderHttpClient`
  -> real `ThreatFoxDatasource` -> real semantic parser -> real
  `SemanticSourceContext` -> real `ToEvidenceConverterRegistry` -> real
  `ThreatFoxToEvidenceConverter` -> in-memory Evidence -> real
  `DatasourceExecutionRecorder` -> real `PostgresUnitOfWork` -> real
  stored function -> real `ati.datasource_log` (only the external Internet
  endpoint is faked): one-record success (exact provenance,
  STARTED/ACQUIRED/DECODED/CONVERTED(1)/COMPLETED, one execution ID, no
  Evidence persisted), valid no-result (`CONVERTED(0)`), two records ->
  two Evidence in source order, conversion failure (bounded
  `conversion_failed`, no CONVERTED/COMPLETED, no exception text),
  cancellation (CANCELLED, propagates), and minimization (Auth-Key, raw
  body, credential-bearing URL, and exception text absent from durable
  logs and Evidence).

### Runtime datasource migration (PR 27E)

PR 27E tests are deterministic and offline; only the external ThreatFox
endpoint is faked via in-process `httpx.MockTransport`:

- datasource-backed provider matrix (`tests/unit/app/test_datasource_provider.py`,
  D27E-A01..A10, E01..E10, T01..T10, L01..L06, U01..U07): the real
  `ThreatFoxDatasource`/`ProviderHttpClient`/converter/recorder over an
  in-memory UnitOfWork fake and the real `ProviderWorkExecutor` with fake
  reader/persistence/timeline seams — provider identity, legacy-identical
  `supports()`, no-I/O for unsupported/malformed inputs, exact
  Investigation/subject binding and signalled `DatasourceDefinition`,
  semantic-format-only converter selection (a registry owning an
  unrelated format fails closed), empty-result success, typed error
  mapping (timeout/429/auth/forbidden/malformed JSON/semantic invalid),
  bounded `conversion_failed`, message-independent classification,
  secret-bearing exceptions never persisted, cancellation stays CANCELLED
  and propagates, per-record Evidence provenance (exact
  `source_record_id`, per-record `observed_at`/facts, `raw_payload=None`,
  no synthesized inference), full/3-Evidence/no-result/conversion-failure/
  persistence-failure/cancellation lifecycles, and deterministic UoW
  probes (no UoW across target read/HTTP/conversion/extraction; one
  distinct persistence call per Evidence in provider order; lifecycle
  events never multiplied per Evidence; binding failure fails the
  lifecycle with `provider_binding_failed` and writes nothing);
- real-PostgreSQL vertical slices (`tests/integration/test_datasource_provider_runtime.py`,
  D27E-P01..P09): persisted Investigation + Entity -> real
  `ProviderWorkExecutor` -> migrated datasource-backed ThreatFox provider
  -> real extractor -> real `ProviderObservationPersistenceService` ->
  real `PostgresUnitOfWork`/stored functions — one-record (exact
  provenance, graph/audit rows, one STARTED + one terminal lifecycle),
  two records (per-record Evidence IDs and RelationshipObservation rows,
  one CONVERTED(count=2), one COMPLETED), no-result (CONVERTED(0),
  COMPLETED, nothing persisted), cross-Investigation and subject binding
  fail-closed (no observation written, FAILED with
  `provider_binding_failed`), later-item persistence failure (E1 committed,
  E2 rolled back, FAILED with `persistence_failed`, outcome retains E1),
  extraction failure (nothing persisted for the failed item), acquisition
  cancellation (CANCELLED, propagates, no Evidence), and lifecycle DB
  invariants (one STARTED, one terminal, stable execution/datasource
  identity, append-after-terminal rejected by the stored function);
- batch transaction regression (`tests/integration/test_batch_source_transaction_regression.py`,
  D27E-B01..B10): one batch commits records + checkpoint atomically; two
  batches commit one UoW per batch; batch-2 failure leaves batch-1 durable
  and batch-2 fully rolled back; restart resumes from the last committed
  checkpoint; a completed artifact short-circuits; a conflicting batch
  rolls back data + checkpoint; and ingestion writes zero
  `ati.datasource_log` rows. MITRE identity/hash/normalization/checkpoint
  stability is pinned by the existing MITRE suites (D27E-B09/B10).

### Evidence message wire contract (PR 28C)

PR 28C tests are deterministic, offline, and involve no database, network,
broker, or UnitOfWork. `tests/unit/app/test_evidence_message.py` pins the
E28C matrix:

- identity (E28C-I01..I10): deterministic UUIDv5 `message_id` over
  execution + flattened sequence + Evidence identity, deterministic
  `observation_candidate_id` derived from the message identity,
  tuple-reactive identity changes, retrieval-time independence, no broker
  metadata dependence, Evidence identity free of schema representation,
  and negative-sequence rejection;
- builder/binding (E28C-B01..B16): exact V1 mapping from
  `ConvertedEvidence` + `SemanticSourceContext` + execution ID + sequence,
  fail-closed Evidence/candidate/source cross-binding, empty record
  identity and empty source URL rejection, naive timestamp rejection,
  nullable `observed_at`/`raw_payload`, empty facts, deterministic
  flattened 0..N-1 sequences, and boolean `schema_version` rejection;
- round trips (E28C-R01..R06): message -> bytes -> message and
  `ConvertedEvidence` -> message -> `ConvertedEvidence` equality, exact
  nested JSON, UTF-8 Unicode, microsecond precision, and non-UTC aware
  timestamp canonicalization;
- canonical encoding (E28C-S01..S09): byte-identical repeated encoding,
  facts/raw-payload insertion-order independence, canonical lowercase
  UUID strings, stable enum URNs, pinned JSON nulls, and NaN/Infinity/
  arbitrary-object rejection;
- PR 28F-1 canonical oracle: golden V1 bytes pin the stdlib `json` codec
  (F1-E01..E10) — the encoder probe proved `orjson` cannot reproduce the
  canonical float scientific notation (`1.2e-07` vs `1.2e-7`) or parse
  beyond-64-bit integers exactly, so the EvidenceMessage codec is
  deliberately retained on Python's standard library in both directions;
- strict decode (E28C-D01..D18): malformed JSON/UTF-8 -> decode error,
  missing/non-integer/zero/bool/string/float/version-2 schema handling
  (unsupported-version vs validation error), extra-field rejection,
  malformed UUID/timestamp rejection, identity-mismatch rejection,
  facts-array/raw-payload-scalar rejection, missing-provenance rejection,
  non-standard JSON constants rejected as malformed, non-string
  `datasource_id` rejection, and bounded error text that never echoes the
  raw payload;
- contract boundary (E28C-P01..P08): no Investigation/subject/graph/
  broker/generic-metadata state, reconstructed candidate carries no
  Observation version/diff, and material-state equality under retrieval-
  time-only change;
- ThreatFox vertical slices (E28C-V01..V03): production
  `ThreatFoxToEvidenceConverter` -> builder -> canonical encode -> strict
  decode -> reconstruction with the canonical synthetic AsyncRAT fixture
  (stable Evidence identity, exact source record, bounded provenance,
  no DB/network); deterministic slot replay; and a later unchanged
  acquisition keeping Evidence identity with distinct message/candidate
  identities and equal `EvidenceMaterialState` (no DB behavior is tested
  here — that stays PR 28E).

### Distributed-log contracts and in-memory log (PR 28D)

PR 28D tests are deterministic, offline, and involve no database, network,
broker, sleep, random failure, or UnitOfWork. `tests/unit/app/
test_evidence_log.py` drives the real PR 28C `EvidenceMessage` builder and
pins the E28D matrix plus the D28D vertical slices:

- contract/value (E28D-C01..08): negative positions rejected, immutable
  comparable positions, blank and oversized consumer identities rejected,
  records carrying exact PR 28C messages, immutable batch tuples, in-memory
  handles conforming to the `EvidencePublisher`/`EvidenceConsumer` ABCs,
  and no Kafka/topic/partition/offset/group fields anywhere;
- publication (E28D-P01..P09): first position 0, contiguous ordered
  multi-message runs, position continuation, empty publish as a documented
  no-op, fail-next-publish as a typed error with no append or gap, retry
  from the original next position, the same message published twice
  creating two records (the log never deduplicates), concurrent publishes
  keeping unique contiguous positions with per-call order, and
  non-`EvidenceMessage` element rejection;
- poll/redelivery (E28D-R01..R13): empty poll, bounded prefixes, larger
  bounds, poll never advancing the cursor, repeat-before-commit returning
  the identical batch, zero/negative bounds rejected without mutation,
  exact commit advance, poll-after-commit, final commit, append after
  catch-up, handle recreation after commit resuming the cursor, and
  handle recreation after an uncommitted poll redelivering the batch;
- commit validation (E28D-K01..K11): empty-batch no-op, foreign-consumer
  rejection, skipped positions rejected, strict stale/repeat policy
  (an exact already-committed batch is rejected with the documented
  error), non-contiguous and reversed batches rejected, a forged record at
  a valid position rejected, a contiguous position beyond the log
  rejected, cursor unchanged after every failed validation, and the
  prefix-commit policy (committing a strict prefix of a larger poll is a
  valid whole-batch commit that advances exactly past the batch's final
  record; the remaining record stays redeliverable with no partial-ack
  state);
- consumer independence (E28D-G01..G05): shared initial prefix, A's
  commit never moving B's cursor and vice versa, two handles with the
  same identity sharing one cursor, and different identities keeping
  independent cursors;
- failure injection (E28D-F01..F09): one-shot `fail_next_publish` raising
  `EvidencePublishError` with no append/no gap and a clean retry,
  `fail_next_poll` raising `EvidencePollError` with the cursor unchanged,
  `fail_next_commit` raising `EvidenceCommitError` with the cursor
  unchanged so the next poll redelivers the identical batch, retry after
  each fault, consumer-targeted faults leaving other consumers unaffected,
  and cancellation propagating unchanged with the log state still valid;
- vertical slices (D28D-V01..V05): deterministic ordered
  publish/poll/commit with exact message values and positions; the
  crash/redelivery model (an uncommitted poll redelivers to a recreated
  handle); commit-failure redelivery (the seam PR 28E depends on);
  independent consumers; and PR 28C message/evidence/candidate identity
  surviving transport with the log position never appearing inside the
  message or its canonical wire.

No PostgreSQL integration test is required for PR 28D: the slice is pure
application state with no database boundary, and consumer-side PostgreSQL
processing is owned by PR 28E.

### Bounded Evidence persistence consumer (PR 28E)

PR 28E tests span three layers and pin the E28E-C/X/P, I28E, and V28E
matrices:

- deterministic unit tests (`tests/unit/app/test_evidence_consumer.py`,
  `tests/unit/app/test_evidence_batch_persistence_service.py`,
  `tests/unit/app/extraction/test_message_context.py`,
  `tests/unit/infrastructure/test_evidence_batch_repositories.py`) cover
  consumer sequencing (empty poll, bounded poll bound, one batch = one
  persistence call, DB-before-log-commit ordering, DB failure without
  consumer commit, commit failure after DB success, cancellation without
  false acknowledgement), the persistence service size/transaction
  contract, message-context reconstruction (exact ConvertedEvidence, IP/
  domain invocation contexts, malformed/unsupported fail-closed, reused
  ThreatFox extractor, no subject/log-position wire fields), and the
  adapter's deterministic JSONB serialization;
- real-PostgreSQL injection tests (`tests/integration/
  test_evidence_batch_consumer.py`) cover the I28E matrix: first batch
  with exact derived state, receipt-based exact replay, CREATED candidate
  identity, UNCHANGED candidate unused (a later same-state NEW message), a
  material update appending the authoritative observation (Option A),
  atomic batch rollback (metadata conflict), deterministic same-Evidence
  ordering in one batch, duplicate messages in one batch, soft-deleted
  Entity/Relationship conflicts, no generic Evidence history, no
  Investigation admission, exact RelationshipObservation provenance, the
  SQL-side size bound, and the required distinct-message recurrence test
  (`[M1:A, M2:B, M3:A]` — the second A is APPENDED, never resolved as a
  receipt replay);
- the required same-Evidence multi-state replay test
  (`tests/integration/test_evidence_batch_replay.py`) proves the canonical
  at-least-once boundary with the real log and real PostgreSQL: persist
  `[A,B,C]`, PostgreSQL commit succeeds, consumer commit fails, the
  identical batch is redelivered, and exactly three observations remain
  with no duplicate derived graph state (receipts are keyed by message
  identity and return the previously established authoritative results
  without invoking the Evidence transition);
- the V28E vertical slices drive the real `InMemoryEvidenceLog` through
  the real consumer/service/repository against the migrated database:
  success, DB failure before log commit (cursor unchanged, redelivery),
  material change across runs, and bounded multi-record processing in
  bounded prefixes.

### Datasource Evidence producer (PR 28F-2)

PR 28F-2 tests close the producer side of the v0.2 Global Evidence
pipeline with deterministic, offline producer vertical slices — no live
Internet, broker, or consumer is involved:

```text
real ThreatFox-format HTTP fixture (httpx.MockTransport)
 -> production ProviderHttpClient / orjson decode
 -> production ThreatFox semantic parser
 -> production ThreatFoxToEvidenceConverter
 -> production EvidenceMessage builder (evidence_message_from_converted)
 -> EvidencePublisher (InMemoryEvidenceLog.publisher())
```

- the unit matrix (`tests/unit/app/test_datasource_evidence_producer.py`)
  pins F2-M01..M10 (message construction over flattened output: one/
  multi-object order, multi-item converter return order, mixed 0/1/N
  contiguous flat sequence, zero output, PR 28C deterministic identity,
  exact recorder execution ID, exact semantic provenance, builder
  failure with no publish, and identical injected execution ID + fixture
  yielding identical messages), F2-L01..L11 (producer lifecycle through
  the real ThreatFox HTTP stack: normal, zero, typed acquisition failure,
  decode/semantic failure, conversion failure, message-construction
  failure, publisher failure, acquisition and publication cancellation,
  publish-success/PUBLISHED-append failure without republish, and
  PUBLISHED-success/COMPLETED-append failure without republish),
  F2-P01..P07 (exactly one ordered publish call, ordered input, empty
  no-op publish, no retry, no direct-persistence fallback, PUBLISHED
  count equals message count, `EvidencePublisher` ABC-only dependency),
  and F2-S01..S06 (reference corpus excluded, no observation-persistence
  dependency, no Investigation/broker fields in messages, no
  consumer/PostgreSQL wait, and the PR 28F-1 stdlib JSON codec
  unchanged). F2-L12..L15 (`PUBLISHED` non-terminal, post-terminal
  rejection, pre-STARTED rejection, no `error_code`) live at the
  recorder/domain level (`tests/unit/app/test_datasource_execution_recorder.py`,
  `tests/unit/domain/test_datasource_log.py`);
- the real-PostgreSQL vertical slices
  (`tests/integration/test_datasource_evidence_producer.py`) run the
  full production stack over the migrated database and pin V28F2-01..07:
  ThreatFox success with the exact `STARTED, ACQUIRED, DECODED,
  CONVERTED, PUBLISHED, COMPLETED` lifecycle under one execution ID,
  multi-record order (semantic order == converted order == message
  sequence == log position order), valid zero result recording
  `PUBLISHED(0)`, publisher failure via
  `InMemoryEvidenceLog.fail_next_publish()` (`FAILED(publication_failed)`,
  no direct fallback), deterministic cancellation at the publisher
  boundary (`CANCELLED` + propagation), real-PostgreSQL `PUBLISHED`
  lifecycle acceptance plus atomic post-terminal rejection (SQL API
  v0028, migration 0033), and producer/consumer separation (the producer
  reaches `COMPLETED` without any `EvidencePersistenceConsumer` running,
  no receipt/Evidence rows created).

### Deterministic vertical-slice provider execution (PR 19B)

`tests/integration/test_provider_execution_pipeline.py` proves the real
pipeline against the isolated migrated PostgreSQL database and the
in-process synthetic HTTP boundary (real `httpx.AsyncClient` over
`ASGITransport` into an ATI-authored FastAPI stub upstream guarded by a
host allowlist; no public internet):

```text
persisted DOMAIN root
  -> queued GOOGLE_PUBLIC_DNS work
  -> LangGraph
  -> LocalTaskDispatcher
  -> ProviderWorkExecutor
  -> real GooglePublicDnsProvider over the synthetic upstream
  -> normalized DNS Evidence
  -> PR 18B deterministic extraction
  -> PR 18C atomic persistence
  -> ProviderExecutionOutcome + persisted timeline events
```

The slice runs through the public `build_provider_investigation_graph`
factory along the `ProviderWorkExecutor -> LocalTaskDispatcher -> compiled
graph` composition path and invokes the graph asynchronously; it asserts the
persisted Evidence row, the discovered IP entity, the stable relationship
and its immutable observation, the outcome/state ID bookkeeping
(`provider_calls_used == 1`), the durable Investigation's
`root_entity_ids == [root.id]` (the fixture persists the actual root Entity
UUID), the started/evidence-persisted/completed timeline sequence, and that
discovered entities are never automatically enqueued. The provider's
internal HTTP parsing is not mocked. Timeline repository integration tests
cover append, chronological read, exact foreign-key SQLSTATE 23503 with
rollback and closed-UoW assertions, rollback, append-only semantics, and
the database error-code rejection.

## Provider contract tests

Every provider implementation should cover at least:

- positive response;
- valid empty/negative response;
- malformed response, including malformed nested provider structures;
- timeout;
- rate limit;
- authentication failure;
- unsupported indicator;
- normalization behavior;
- cancellation paths that propagate ``asyncio.CancelledError`` unchanged and
  release limiter permits and client resources.

Ordinary CI uses ATI-authored synthetic provider-shaped fixtures.

Optional live-provider contract tests validate external assumptions but do not gate normal deterministic CI.

## Provider validation matrices

Every live or local provider must maintain a traceable validation matrix in
its authoritative source documentation and tests. Green aggregate coverage is
not a substitute for this matrix. For each supported request/object/record
type, document and test:

| Dimension | Required coverage |
|---|---|
| Applicability | every `EntityType`, including unsupported and invalid values with proof of no I/O |
| Schema | required/optional fields, missing fields, wrong container types, strict scalar types, and unknown-field policy |
| Ordinary semantics | at least one positive normalization case with canonical facts and provenance |
| Valid miss | protocol-defined empty/negative behavior, distinct from benign assessment and provider failure |
| Canonicalization | case, whitespace, IDNA, address/range normalization, terminal delimiters, and idempotent canonical output |
| Special protocol forms | every standards-valid sentinel, root/null value, optional representation, escape form, or boundary ATI claims to support |
| Malformed nearest neighbors | values immediately outside each valid bound, incomplete escapes/tokens, wrong family/type, and contradictory identities |
| Cross-field invariants | range ordering/containment, class/identity matching, dependent fields, and timestamp requirements |
| Collection invariants | duplicates, ambiguity, entry ordering, owner/target attribution, chains/cycles, and mixed sentinel/ordinary entries |
| Error totality | malformed provider data returns a safe typed error and never an incidental parser/index/decoder/arithmetic exception |
| Eligibility | normalized values explicitly classified as discoverable entities, non-discoverable facts, or sentinels |
| Side effects | no persistence, assessment, relationship inference, pivoting, link traversal, or secret disclosure |

Tests should pair each standards-valid special case with malformed nearest
neighbors. For example, null MX requires positive `0 .` coverage plus nonzero
root preference, mixed null/ordinary MX, and duplicate-null rejection. A valid
boundary test should assert the boundary itself, not merely an interior value.

When transport documentation does not define field semantics, tests must use
the applicable protocol standard rather than extrapolating from one provider
fixture. If ATI has no approved representation for a standards-valid form,
stop and update the authoritative source contract before implementation.

Validation-order tests must prove original input is checked before lossy
canonicalization. Construction-boundary tests must instantiate reusable
policies/caches directly as well as through application settings. Injected
clocks, random/jitter functions, sleeps, and factories require valid-boundary,
invalid-return, and raised-exception tests; programming errors and cancellation
must propagate unchanged.

## Synthetic HTTP provider integration tests

Live provider integration tests (`tests/integration/test_live_provider_http_integration.py`) exercise production provider adapters through a real in-process HTTP boundary without public internet access:

- Every request traverses a real `httpx.AsyncClient` over `httpx.ASGITransport` into an ATI-authored FastAPI stub application. Virtual upstreams (Google DNS, IANA bootstrap, authoritative RDAP services, ThreatFox, URLhaus) are dispatched by request host and path inside genuine ASGI routes; tests assert on request state recorded by the routes, proving requests reached the ASGI application rather than a direct mock callback.
- A narrow `HostAllowlistASGITransport` wrapper enforces an explicit allowlist of permitted hosts and fails closed with a `RuntimeError` before the ASGI application handles any unapproved request. The wrapper never synthesizes provider responses.
- Stateful upstream behavior (a 503 followed by success, and persistent 429 responses) is implemented inside the ASGI routes so retry behavior traverses the application boundary; exact attempt counts are asserted from route-recorded requests.
- Routes assert exact method, `User-Agent`, and `Accept` headers, the DNS route asserts the absence of EDNS client-subnet parameters, the ThreatFox route asserts the exact POST search body, `Auth-Key` header, and JSON content type, and the URLhaus routes assert the exact `application/x-www-form-urlencoded` form body (`url=` / `host=` field), `Auth-Key` header, and JSON content type — all while proving the credential never appears in the URL or body. All payloads are synthetic, local, and credential-free.
- Fast, deterministic execution is guaranteed by injecting non-blocking sleep callables, fixed clocks, and deterministic zero-offset jitter.
- Multi-host discovery flows (IANA bootstrap to authoritative RDAP services) are tested with distinct virtual upstream hosts, including longest-prefix and narrowest-range authority selection and proof that wrong-authority hosts are never contacted.
- Non-persistence isolation guarantees are verified directly against PostgreSQL: provider invocation alone must leave `ati.evidence` row counts unchanged.

## Typical provider issues to watch for

The following checklist captures recurring failure modes in live-provider implementations and tests. It is intentionally non-exhaustive: implementers and reviewers must still apply provider specifications, ATI contracts, security requirements, and change-specific reasoning. Relevant items should be considered while designing and implementing code changes, the implementation should account for them, and corresponding tests should exercise them. Apply an item only when supported by the change's actual behavior, contract, or risk; do not invent speculative requirements or imaginative edge cases without a concrete basis.

- **Untrusted response validation:** Strict field types are necessary but not sufficient. Test missing, coerced, malformed, contradictory, and semantically inconsistent values, including nested structures, relationships between fields, and collection/RR-set invariants. Every malformed-provider path must be total: it returns a safe typed error rather than leaking an incidental parser, index, decoder, arithmetic, or model exception.
- **URL safety and canonical identity:** Validate URLs on the actual request path, not only in an unused helper. Require the approved scheme, reject userinfo, queries or fragments where prohibited, malformed hosts and ports, and unsafe path replacement. Canonicalize equivalent host spellings, IDNA forms, terminal dots, IPv6 literals, and default ports before authority comparison.
- **Selection and path construction:** Exercise multiple candidate services, invalid candidates followed by valid ones, ambiguity, longest-prefix/range boundaries, source-order rules, and exact percent-encoded resource paths. Never allow an entity value to replace the selected authority.
- **HTTP response handling:** Bound both declared and streamed response sizes before JSON decoding. Test missing or incorrect content types, malformed JSON, malformed content encodings, redirects, timeout and transport failures, permanent HTTP errors, rate limiting, and exhausted transient retries.
- **Provider JSON format (PR 28F-1):** accepted JSON bodies are parsed with `orjson` directly on bounded bytes. The F1-J01..J15 matrix pins valid-object/nested/array/Unicode/finite-numeric shape preservation; malformed syntax, invalid UTF-8, empty bodies, and the non-standard `NaN`/`Infinity`/`-Infinity` constants all fail closed as a non-retryable `INVALID_RESPONSE` + `SERIALIZATION` + fixed `"malformed JSON"` outcome with no decoder/payload leakage; oversize bodies, wrong content types, malformed content encodings, and retryable statuses keep their existing outcomes; V28F1-01/02 run real-format ThreatFox bytes through the production client into semantic records and prove non-standard provider JSON never reaches `DECODED`. `orjson` parses integers beyond the signed-64/unsigned-64 range as `float` (stdlib returned exact `int`); no supported provider contract emits such integers, and tests verify realistic int64-range values keep exact `int` Python shapes.
- **Safe typed errors:** Provider failures should map to stable typed codes with generic messages. Error values and logs must not expose response bodies, credentials, headers, exception URLs, query values, or other untrusted provider content.
- **Retry and limiter behavior:** Verify exact attempt counts, backoff numbering, jitter bounds, 429 `Retry-After` ordering and caps, first-request behavior, concurrency limits, and rate spacing. Test cancellation while waiting for a semaphore, rate slot, transport, retry delay, and streamed body; cancellation must propagate without leaking permits, resources, or stale future reservations.
- **Validation at construction boundaries:** Enforce invariants in directly constructible infrastructure policies and caches as well as in application `Settings`. Tests and future composition code may bypass the normal settings bootstrap.
- **Canonical evidence and provenance:** Normalize names, addresses, ranges, statuses, timestamps, handles, and fallback identifiers into stable forms. Distinguish protocol-valid values from entity-eligible values; root/null/sentinel facts must never become entities or pivots unless explicitly authorized. Assert source URNs, subjects, investigation IDs, exact credential-free source URLs, UTC timestamps, observation-time policy, immutable facts, and raw-payload policy.
- **Optional external fields:** Do not require fields that the external specification makes optional. When optional values are present, validate them strictly and define whether malformed individual entries invalidate the response or are omitted. Include absent, valid-present, wrong-type, malformed-entry, and mixed-valid/malformed tests. Keep that policy consistent in code, tests, and documentation.
- **Protocol presentation and special forms:** Transport schemas do not replace protocol semantics. Exercise standards-valid sentinels, roots/nulls, escaped presentation syntax, empty represented values, and malformed nearest neighbors. Define normalization and entity-discovery eligibility before implementation.
- **Resource ownership and cleanup:** Distinguish owned from caller-supplied clients. Test normal close, partial-construction rollback, one-close failure, and cancellation during cleanup. A component must close only resources it owns.
- **Deterministic, realistic tests:** Use fixed clocks and UUIDs, injected sleep/jitter, ATI-authored payloads, exact request and attempt assertions, and fail-closed host allowlists. Provider integration tests should cross the intended HTTP boundary rather than repeat a unit-test parser or transport callback.
- **Negative side effects and scope:** Assert that retrieval-only providers do not persist data, infer relationships, assess maliciousness, follow arbitrary links, or perform unplanned recursive lookups.
- **Quality-gate limitations:** Green typing, lint, coverage, and test commands do not prove behavioral completeness. Add adversarial contract cases for branches and invariants that aggregate coverage can miss; do not weaken gates or use broad suppressions to hide defects.
- **Documentation and completion state:** Keep accepted media types, normalization shapes, retry behavior, optional-field policy, and test topology synchronized with implemented behavior. Mark work complete only after the final code and documentation pass all required gates.

## API contract and OpenAPI tests (PR 23C)

The `/api/v1` HTTP adaptation layer is tested at three levels:

- **unit/route contract tests** (`tests/unit/api/**`) exercise pure HTTP
  contracts with injected application fakes (no database, no LLM, no
  providers): DTO validation (`extra="forbid"`), pure allowlist mappers,
  stable error envelopes (including FastAPI validation overridden to the
  ATI envelope and request-ID echo/replacement), auth route behavior,
  canonical idempotency fingerprints, filter/cursor mapping per collection,
  durable-pointer routes, deterministic Markdown, and cross-Investigation
  404s;
- **OpenAPI snapshot** (`tests/unit/api/test_openapi.py`) pins the
  normalized schema to `tests/fixtures/openapi_v1.json`, verifies explicit
  operation IDs, public DTOs only, error responses, and the accurate
  cookie-session security scheme (regeneration command is documented in the
  test module);
- **real-PostgreSQL API integration tests** (`tests/integration/test_api_*`)
  exercise the production FastAPI application and the PR 23A/23B services
  end to end: login/session round trip with only the token digest persisted;
  the atomic create-Investigation transaction (Investigation + durable job +
  audit + idempotency record); idempotent replay/race/mismatch; collection
  routes with cursors surviving HTTP; raw Evidence payload exclusion;
  durable Assessment/Report pointer correctness (never `MAX(version)`);
  history redaction/allowlist; deterministic Markdown; and the canonical
  async vertical slice proving `POST -> durable job -> worker claim ->
  InvestigationRunner -> terminal Investigation -> HTTP GET` through
  production persistence/orchestration seams with synthetic providers and
  `FakeLlmClient`.

These tests require no live Internet or API keys.

## Database integration tests

Integration tests use real PostgreSQL + pgvector from the supported database family.

They validate:

- Alembic migration from an empty database;
- versioned PostgreSQL stored functions;
- repository behavior;
- UnitOfWork transaction semantics;
- batch upserts;
- inserted/updated/unchanged classification;
- soft deletion;
- immutable observation behavior;
- relationship-history semantics;
- authentication/session persistence;
- audit persistence;
- RAG document/chunk/vector persistence;
- investigation resource and immutable evidence persistence (versions,
  history, lifecycle, soft deletion, and transaction atomicity);
- PR 18A concurrency invariants: locked-row lifecycle revalidation with a
  controlled two-session transition race, typed duplicate-identity errors
  under concurrent inserts, and evidence insertion blocked across a
  concurrent parent soft deletion;
- PR 18C atomic graph persistence: the canonical DNS/ThreatFox scenarios
  (domain RESOLVES_TO IP, IP ASSOCIATED_WITH malware) with exact Entity,
  Evidence, Relationship, RelationshipObservation, and history counts;
  repeated observations under new Evidence IDs reusing stable identities;
  same-Evidence-ID replay conflicting with unchanged counts; empty
  extraction persisting Evidence only; fact-only/URLhaus evidence creating
  no invented edges; typed preflight errors leaving zero rows; injected
  mid-transaction failures leaving no partial state; two concurrent writers
  converging on one canonical Entity/Relationship with both observations;
  fail-closed soft-deleted Entity/Relationship rediscovery; graph
  reconstruction from durable rows without re-extraction; and no spurious
  version bumps for unchanged re-observation;
- PR 18C graph-integrity hardening: a controlled two-transaction Entity
  soft-deletion race proving the locked write rejects the deleted identity
  with full observation rollback and one remaining canonical row; the
  canonical-create recovery path rejecting a raced row that was soft-deleted
  before recovery; database-enforced (not only preflight) soft-deleted
  Entity writes; Relationship soft deletion allocating a sequence version
  and exactly one immutable DELETE history row with diff and actor
  preservation, plus stale/missing/repeat rejections with zero extra
  mutation or history; the named non-cascading
  `relationship_observation_evidence_fk` rejecting dangling Evidence
  references with no residual observation or history rows; and migration
  0012 contract checks covering the FK, the `ati.soft_delete_relationship`
  signature, and an isolated downgrade/re-upgrade cycle.
- PR 20A versioned Assessment persistence: direct and graph support
  round-trips (Evidence with zero relationships; one evidence feeding
  several observations; repeated observations of one edge; ordered
  Findings/supports/string collections), cross-Investigation and
  provenance-mismatch rejections (including uncited analyzed Evidence,
  wrong-Investigation observations, and substitute observations of the
  same Relationship), database-enforced Finding/support structural
  rejection (no support, unknown/gapped/duplicate ordinals, invalid
  discriminator), deleted Relationship/endpoint-Entity ineligibility,
  empty-evidence INCONCLUSIVE round-trip and no-evidence
  SUSPICIOUS/BENIGN/MALICIOUS rejection, version 1 then version 2 with
  version 1 unchanged and distinct later versions, the Investigation
  assessment pointer only changing after durable success, stale
  expected-version conflict with no partial Assessment, failed-append
  rollback of parent/history/audit/pointer, locked-row concurrency races
  (Assessment creation serialized against Relationship and Entity soft
  deletion), the approved deletion policy (current-Assessment deletion
  rejected, superseded deletion with DELETE history and transactional
  ASSESSMENT_DELETE audit, stale-version delete rollback), and migration
  0014 checks covering the normalized schema, the empty-table guard
  (nonempty legacy rows block the upgrade and survive), and an isolated
  downgrade/re-upgrade cycle. Two additional deterministic concurrency
  tests observe PostgreSQL lock state (`pg_stat_activity`/`pg_locks` with
  bounded timeouts, never fixed sleeps) to prove that concurrent pointer
  assignment and Assessment deletion serialize on the owning Investigation
  row lock in both orders: pointer-wins (deletion rejected with the
  current-reference conflict, no DELETE history/audit) and deletion-wins
  (pointer assignment to the deleted A rejected, exactly one DELETE
  history and audit row). Input bounds are tested at three layers: unit
  tests proving each bounded candidate collection is rejected before any
  UnitOfWork entry plus exactly-at-limit acceptance, repository unit tests
  with a recording session proving oversized inputs never execute SQL, and
  a PostgreSQL test bypassing Python bounds to prove the database
  defensive hard ceiling (10,000) rejects plus-one inputs before any
  staging or mutation.

Do not replace critical PostgreSQL integration coverage with SQLite.

## Redpanda / Kafka integration tests (PR 28G)

The PR 28G real-broker tests (`tests/integration/kafka/`) prove the
Kafka-compatible Evidence adapters against a real Redpanda broker using
real `aiokafka` clients. They cover canonical EvidenceMessage round trip,
same-Evidence partition affinity, multi-Evidence/multi-partition behavior,
manual offset commit and group restart, no-commit redelivery, independent
consumer groups, corrupt/key-mismatched payloads failing closed, producer
metadata, empty publication, clean shutdown, and PR 28E application
compatibility through a deterministic persistence double.

Prerequisites and running:

- `podman`/`podman-compose` (the same toolchain as the PostgreSQL
  integration suite).
- `./integration-test.sh` provisions an isolated Redpanda broker (via
  `compose.yaml`) alongside the isolated PostgreSQL database, waits for the
  Kafka API to become ready, and exposes it to the test process as
  `ATI_EVIDENCE_KAFKA_BOOTSTRAP`. The Evidence topic is created explicitly
  with **3 partitions** so the multi-stream (partition) abstraction is
  actually exercised; each test uses an isolated topic/group identity so no
  state bleeds across runs or prior runs.
- The broker tests require no Internet and no Schema Registry; Redpanda is
  Kafka-compatible test/development infrastructure only, never a Python
  runtime dependency.
- Unit matrix (`tests/unit/infrastructure/kafka/`) covers the adapter
  boundaries with deterministic `aiokafka` doubles (E28G-P publisher,
  E28G-R consumer poll, E28G-K commit) and runs offline without any broker.

Responsibility split: unit tests pin the adapter contracts and failure
mapping; real-broker tests pin partition/offset/group/redelivery/restart
semantics. Note that `tests/integration/kafka/conftest.py` provisions a
fresh empty 3-partition Evidence topic per test (never shared between
tests), with per-test consumer groups; the suite's assertions on exact
batch sizes depend on that isolation.

## Distributed Evidence ingestion closure (PR 28H)

The PR 28H module `tests/integration/kafka/test_distributed_evidence_ingestion.py`
(H28H-01..21) proves the complete production-shaped vertical slice against
real Redpanda and real PostgreSQL, faking only the external Internet
endpoint (`httpx.MockTransport` serving deterministic ThreatFox-format
fixture bytes):

- temporal semantics: fresh A, later A-equivalent (`UNCHANGED`, never
exact replay), A->B, A->B->C, A->B->A recurrence (a distinct message
appends v3), and one atomic multi-Evidence batch;
- replay/idempotency: exact-message replay is a receipt no-op; same
semantic state with a new datasource execution is a new receipt with
unchanged EO history;
- failure/recovery: failure before PostgreSQL commit (no partial state,
no Kafka commit, same-group redelivery, one retry), PostgreSQL-commit-
then-Kafka-commit-absent recovery, poll-then-stop redelivery, atomic
multi-record rollback, committed-restart with no redelivery;
- producer lifecycle: `COMPLETED` without a consumer, `publication_failed`
failure, post-terminal lifecycle append rejection;
- provenance: exact `EvidenceObservationEntity` and
`RelationshipObservation` references per committed observation;
- Investigation reproducibility: explicit observation-exact admission
(two Investigations sharing one EO, one Investigation admitting v1+v2,
and a later global EO never silently mutating prior admissions).

Failure seams are narrow test wrappers only (a commit-failing consumer and
a fail-before-commit persistence boundary); there are no production chaos
APIs, no Kafka transactions, no retry topics/DLQ, no Schema Registry, no
live Internet, and no ThreatFox clone/download. The real PostgreSQL
integration lane, fresh per-test topics and groups, and the no-internet
rule keep the module deterministic and isolated.

## Migration tests

At minimum, CI verifies:

```text
empty database
 -> alembic upgrade head
 -> expected schema/functions/extensions
```

As the repository matures, migration regression tests should also exercise supported upgrade paths from representative prior schema versions.

Versioned SQL stored-function files must be tested against the real database.

## Test isolation

Tests must never use normal developer persistent data.

Use:

- unique test database names;
- unique Compose project name;
- isolated host/container storage;
- explicit environment guards.

Example:

```text
COMPOSE_PROJECT_NAME=ati-test-<unique>
```

Host ports for isolated containers are selected above the default Linux
ephemeral-port range (`net.ipv4.ip_local_port_range`, 32768-60999 on
GitHub-hosted runners): under rootless Podman every mapped host port is bound
by a user-space forwarder, so a port inside the ephemeral range can be
silently occupied by an outbound connection. `integration-test.sh` and
`scripts/e2e.sh` pick available ports from disjoint high ranges, probe them
by binding all interfaces exactly like the forwarder (no `SO_REUSEADDR`), and
retry container starts with a fresh port when the forwarder reports a bind
conflict.

Test startup should fail safely if configuration appears to reference a normal development database/data directory.

## Synthetic fixtures

CI fixtures are ATI-authored and deterministic.

Do not depend on live public DNS, provider APIs, changing ATT&CK web content, live model responses, or wall-clock-dependent external data for ordinary PR correctness tests.

Provider-shaped fixture data should avoid copying third-party payloads wholesale when redistribution terms are uncertain.

## Fake implementations

The test suite should provide deterministic implementations such as:

- `FakeEvidenceProvider`;
- `FakeTaskDispatcher` (PR 19C): a deterministic dispatcher used by graph
  tests so orchestration mechanics do not depend on executor behavior;
- `FakeWorkExecutor` (PR 19A, in `tests/support/orchestration_fixtures.py`):
  a deterministic in-memory `WorkExecutor` driven by an explicit
  `ProviderWorkItem -> ProviderExecutionOutcome` mapping with no network,
  database, or LLM I/O, retained for dispatcher and executor tests;
- `FakeLlmClient`;
- fake embedding model;
- fixed retriever;
- deterministic clock where needed;
- scenario factory/builders.

Fakes should implement the same ABC contracts as production components.

## Fake operating mode versus test mode (PR 23D)

Fake **operating mode** is a runtime concept, not a test mode:

- `ATI_OPERATING_MODE=fake` changes only which intelligence-source implementations are composed at bootstrap;
- automated tests are deterministic regardless of operating mode and inject `FakeLlmClient` at the model boundary;
- CI never requires live network access or a live LLM;
- runtime `fake` mode at a real deployment still uses the configured real `LlmClient` when an LLM-bearing path executes.

PR 23D adds the following deterministic, offline coverage:

- **configuration tests** (`tests/unit/config/test_operating_mode.py`): safe production default, exact `fake`/`production` values, fail-closed validation, profile orthogonality;
- **catalog/fixture tests** (`tests/unit/infrastructure/test_fake_runtime.py`): strict schema validation (duplicate scenario IDs, duplicate root indicators, unknown providers, malformed timestamps, path escapes), deterministic shared-world lookups, fake provider contract behavior, no-network invariants, and composition branches (fake only fakes, production only real);
- **runtime metadata tests** (`tests/unit/api/test_runtime.py`): `GET /api/v1/runtime` reports the mode only, requires authentication, and never exposes configuration or secrets;
- **fake batch bootstrap tests** (`tests/integration/test_fake_batch_bootstrap.py`): first ingestion through the production `MitreAttackBatchSource`, idempotent re-run, malformed-fixture fail-closed, production-mode refusal;
- **canonical fake-mode vertical slice** (`tests/integration/test_fake_canonical_vertical_slice.py`): HTTP `POST /investigations` → durable job → `InvestigationJobWorker` → `LocalInvestigationRunner` → fake intelligence providers → `FakeLlmClient` → real PostgreSQL → HTTP reads (Investigation, Evidence, Relationships, RelationshipObservations, Research, Assessment, Timeline, runtime mode);
- **relationship evolution** (`tests/integration/test_fake_relationship_evolution.py`): repeated observations of a stable relationship at distinct source-semantic times and a later new counterparty, with `observed_at` preserved separately from `retrieved_at`;
- **research-required** (`tests/integration/test_fake_research_required.py`): the coordinator research lifecycle persists a contextual `ResearchResult` that remains distinct from Evidence.

The fake world and scenario fixtures are repository-owned under `src/agentic_threat_investigator/infrastructure/fake_runtime/data/v1/` and are versioned and strictly validated; runtime randomness is forbidden and fixture-internal relevance classifications are never exposed to the analytical pipeline as privileged truth.

## Structured agent output and deterministic formatter tests

All programmatic agent outputs are validated Pydantic models. Conventional
tests and behavioral evaluations together enforce this boundary.

`TESTING.md` owns deterministic schema, serialization, formatter, and
application-boundary tests. `EVALUATION.md` owns model/agent behavioral
quality and trajectory scoring.

### Structured-output contract tests

For every agent output model, deterministic tests must cover:

- valid representative output;
- missing required fields;
- unexpected fields where `extra="forbid"` applies;
- wrong scalar/container types;
- invalid enum/URN values;
- invalid referenced-ID shapes;
- empty versus absent semantics;
- field-level bounds;
- cross-field invariants implemented outside Pydantic;
- stable JSON-compatible serialization.

An invalid LLM result must never partially update investigation state or
persistence.

### Reference validation tests

Where an agent result references ATI resources, tests must prove that
deterministic application validation rejects:

- nonexistent entity IDs;
- nonexistent Evidence IDs;
- nonexistent retrieved-chunk IDs;
- references outside the current investigation where prohibited;
- duplicate or contradictory references where prohibited;
- Coordinator pivots that are not root/evidence-discovered entities;
- references that violate pivot policy or budgets.

### FakeLlmClient

`FakeLlmClient` returns typed Pydantic results corresponding to the requested
response model.

Tests must not rely on parsing free-form fake model prose to simulate a
structured-output operation.

The fake should also support deterministic invalid-output/failure cases needed
to test bounded repair and `INVALID_STRUCTURED_OUTPUT` handling.

Deterministic PR 20B coverage requirements:

- one successful call increments the Investigation LLM budget by exactly one;
- an invalid first attempt plus a successful repair increments by two and the
  second User Prompt carries the bounded schema-repair instruction;
- prompt construction occurs BEFORE reservation: an initial-prompt
  construction failure consumes zero budget, makes zero model calls, and
  touches no persistence/audit state; a repair-prompt construction failure
  keeps the prior real attempt counted (one reservation, one call) without
  reserving the nonexistent repair call;
- a non-retryable ``INVALID_STRUCTURED_OUTPUT`` error is NOT retried (one
  call, one reservation, no Assessment, strict propagation);
- attempt counts are hard-limited to ``1..2`` even on direct constructor
  use;
- an input-loading failure and the no-evidence short circuit never consume
  budget (no model call happens at all);
- a cancellation during the model boundary propagates unchanged AND the
  actually-attempted invocation stays durably reserved;
- an attempted call that then times out/provides garbage persists no
  Assessment and moves no Investigation pointer;
- an exhausted attempt budget (or LLM budget) fails with no partial
  persistence;
- invalid support references (unknown/cross-Investigation Evidence or
  RelationshipObservation, substitute observation, soft-deleted graph
  resource) are rejected by the PR 20A validator with no pointer update and
  the durable LLM count reflects every actual invocation.

The loader bounds are fail-closed: direct construction enforces the same
hard ceilings as ``Settings`` (evidence 1..500, observations 1..1000, input
bytes 1000..1000000, normalized-facts bytes 1000..1000000); the aggregate
normalized-facts size is independently byte-bounded (UTF-8, never counting
Python characters and never inspecting raw payloads); and a 1001st
observation at a 1000 bound raises ``EvidenceAnalystInputBoundsError``
before any model call via the sentinel probe, never a silent clamp.

### Evidence Analyst vertical slice (PR 20B)

Integration tests run the complete application path against isolated
real PostgreSQL with `FakeLlmClient` standing in for the model:

```text
persist Investigation + Evidence (+ Relationship/Observation)
 -> EvidenceAnalystInputLoader (raw_payload excluded from model prompts)
 -> EvidenceAnalyst + LlmAccountingService
 -> FakeLlmClient (asserts the shared real-UnitOfWork transaction counter
    is zero while the model boundary runs; records prompts)
 -> Assessment validation/persistence
 -> durable Assessment + Investigation pointer + budget counters
```

The transaction coverage instruments the actual ``PostgresUnitOfWork``
instances composed into the analyst stack (loader, LLM accounting,
Assessment persistence) with a shared enter/exit tracker; the fake LLM
asserts the active count is exactly zero and the event order proves the read
loader exited before accounting started, the reservation UnitOfWork exited
before the model call, and Assessment persistence begins only after a typed
decision exists.

Coverage includes evidence-only, graph-backed, mixed-support, explicitly
contradicting, and no-evidence INCONCLUSIVE styles; invalid/cross-Investigation
citations; substitute-observation and deleted-graph rejection; structured-
output and persistence failures leaving no pointer; appended later analysis
versions with the earlier Assessment unchanged; and durable LLM accounting.
The observation listing read added for analyst input is covered separately
against real PostgreSQL (scope, determinism, exclusion, paging).

### Canonical real-format Threat Research/RAG path (PR 22A)

The canonical PR 22A vertical slice (`tests/integration/test_mitre_real_format_vertical.py`)
exercises the complete production corpus pipeline against isolated real
PostgreSQL:

```text
deterministic local STIX 2.1 fixture
 -> production FileSystemObjectStore + MitreAttackBatchSource (real parser)
 -> SourceRecord persistence (checkpoint/idempotency)
 -> MitreAttackDocumentBuilder (real builder)
 -> DocumentIndexingService (real chunking/indexing)
 -> PostgreSQL Document/DocumentChunk persistence (citation identities)
 -> PgVectorResearchRetriever (real cosine retrieval)
```

The embedding representation is the only external/non-deterministic boundary
and is replaced with deterministic offline embeddings; nothing else is faked.
The fixture rule for PR 22A and later research work:

> Automated tests may replace network acquisition and external embedding
> service calls, but must exercise the production source parser, document
> builder, persistence/indexing, and pgvector retrieval path being tested.

The fixture (`tests/fixtures/mitre_attack/enterprise_attack_small.json`) is
ATI-authored synthetic STIX 2.1 content that conforms exactly to the
production `MitreAttackBatchSource` input contract; it is a deterministic
real-format fixture, not a separate fake data source, and is never presented
as real threat intelligence. The slice proves ingestion, document
construction provenance, chunk persistence with stable `citation_id` values,
deterministic retrieval provenance, same-model idempotency, and embedding
identity migration (chunks replaced, citations stable, identity-filtered
retrieval). Durable research provenance is proven separately in
`tests/integration/test_research_result_repository.py` (immutable
ResearchResult round trip, reference rejection, rollback, no-Evidence
creation, and snapshot survival across active chunk replacement).

### Structured Research Agent (PR 22B)

Unit strategy (`tests/unit/domain/test_research_agent.py`,
`tests/unit/app/research_agent/`):

- immutable request/output contract boundaries (blank query, bounded
  `max_results` 1..100, filter deduplication, blank filters, claim
  citation presence/uniqueness, extra-field rejection);
- deterministic prompt construction and prompt-injection tests: hostile
  chunk instructions stay inside the untrusted-data section, the system
  prompt still forbids acting on them, no tool surface exists, and
  `chunk_id` is never rendered as the model citation token;
- deterministic prompt tests for PR 22B-2 provenance/score semantics:
  exact and empty `source_url` field rendering (null URL never renders Python
  `None`), URL provenance/no-browsing/no-unsupplied-inference guardrails,
  `similarity_score` defined as retrieval relevance/ranking only (not
  credibility, factual correctness, evidentiary strength, maliciousness, or
  claim/Assessment confidence), and the prohibition on using similarity to
  choose a winner between contradictory sources;
- application execution tests drive the real `ResearchResultPersistenceService`
  and real `LlmAccountingService` against in-memory seams with a scripted
  `FakeLlmClient` and a scripted retrieval fake: relevant-context
  persistence, unsupported-citation fail-closed behavior, no-context and
  irrelevant-context empty results, contradictory separately-cited claims,
  reuse/ordering of citation snapshots, retry/repair accounting (at most one
  repair, retry only retryable `INVALID_STRUCTURED_OUTPUT`, no retry on
  timeout/config/provider failure), cancellation propagation, constructor
  attempt bounds, prompt-build and retrieval failures consuming no budget,
  and append-only repeat executions.

Canonical PostgreSQL vertical slice (`tests/integration/test_research_agent.py`):

```text
deterministic local STIX 2.1 fixture
 -> production MitreAttackBatchSource / MitreAttackDocumentBuilder
 -> DocumentIndexingService + deterministic embeddings
 -> real PostgreSQL persistence + PgVectorResearchRetriever
 -> ResearchAgent (production composition incl. LlmAccountingService)
 -> FakeLlmClient          (model boundary only)
 -> ResearchResultPersistenceService + real ResearchResultRepository
```

The slice covers relevant context persistence with real pgvector retrieval and
copied citation provenance, unsupported-citation rejection with no partial
state, no-retrieval and irrelevant-context empty results, contradictory
context represented as separately cited claims (via a second real-format
STIX fixture), persistence reference validation/rollback, and structured-
output repair with exactly two accounted LLM calls. `FakeLlmClient` is the
only fake external model boundary; tests never require live Internet or a
live LLM.

### Coordinator research execution trajectories (PR 22C)

The canonical PR 22C slice (`tests/integration/test_research_trajectory.py`)
runs the full production research lifecycle against isolated real PostgreSQL:

```text
domain -> DNS (real provider over synthetic HTTP) -> discovered IP
 -> ThreatFox (scripted provider) -> RESEARCHABLE malware
 -> real CoordinatorPolicy + production LangGraph + LocalInvestigationRunner
 -> MARK_RESEARCH_REQUIRED -> RESEARCH_REQUESTED
 -> real Research Agent (real pgvector retriever, real result persistence)
 -> FakeLlmClient (model boundary only)
 -> COMPLETED / EXHAUSTED -> normal Coordinator stop
```

The canonical slice never fakes the research architecture: the real
production Coordinator, graph, runner, real-format MITRE ATT&CK STIX
fixture, parser/document builder, `DocumentIndexingService`, real
PostgreSQL/pgvector, real `PgVectorResearchRetriever`, real Research Agent,
and real ResearchResult persistence all participate, with `FakeLlmClient`
used only at the external LLM boundary. Provider execution uses the existing
deterministic production-compatible seam to create the RESEARCHABLE entity.

Covered trajectories:

- I01 — complete trajectory: marker consumed, `RESEARCH_REQUESTED` fired,
  one authoritative result with valid citation provenance, result linked
  once, execution COMPLETED, no Evidence/Assessment created by research, no
  direct research->pivot transition;
- I02 — no-context result is completed research (zero claims/citations, zero
  LLM calls, result linked once);
- I03 — unchanged-context rerun is idempotent (zero additional calls,
  results, or `RESEARCH_REQUESTED` events);
- I04 — crash-window reconciliation: a persisted matching result with
  REQUESTED state is adopted with zero LLM calls and no duplicate rows;
- I05 — LLM-accounting/version interaction: research reservations advance
  the Investigation version and completion reloads the authoritative
  version without overwriting accounting;
- I06 — bounded recoverable retry: exactly two `RESEARCH_REQUESTED` events,
  attempts == 2, one result, no third attempt;
- I07 — exhaustion after two recoverable failures: EXHAUSTED, no result
  link, no retry on subsequent invocation;
- I08 — research cannot authorize a pivot: completion returns to
  Coordinator and the SUFFICIENT disposition stops without any post-research
  pivot.

The transition allowlist slice (`tests/integration/test_research_execution_transition.py`)
proves `REQUEST_RESEARCH`/`RECORD_RESEARCH_OUTCOME` accept only approved
field changes, reject provider/pivot/evidence/assessment mutations and
duplicate contexts, reject stale expected versions, require authoritative
result linkage (investigation/subject/query), never link an exhausted
context, and preserve LLM-accounting version increments. `FakeLlmClient` is
the only fake external model boundary; tests never require live Internet or
a live LLM.

### PR 30A common evaluation foundation tests

PR 30A adds one backend-neutral evaluation contract under
`src/agentic_threat_investigator/evaluation/common/` and freezes it with
fully offline, deterministic tests in `tests/unit/evaluation/common/` plus
dataset tests in `tests/unit/evaluation/test_datasets.py`:

```text
common models (EVAL-A01..A12):
  COMPLETED+PASS and COMPLETED+FAIL valid; ERROR+no-verdict valid;
  ERROR+PASS/FAIL and COMPLETED+null rejected; no numeric score field;
  nonblank explanations; stable evaluator IDs; PASS/FAIL/ERROR
  aggregation rules identical to the frozen contract; timestamps absent;
  JSON-safe diagnostics that never alter aggregation

scenario-quality validation (EVAL-S01..S15):
  fully described case loads; missing/blank title, description, purpose,
  operational_relevance, and regression_risk rejected; empty, blank, or
  duplicate-normalized expected-behavior statements rejected; duplicate
  case IDs rejected; invalid dataset versions and unknown targets
  rejected; target/version mismatches rejected; invalid/duplicate
  architecture refs rejected; unknown fields fail closed; target-specific
  fixture/expectation validation still executes; strict duplicate-key JSON
  loading; deterministic target inference

runner (EVAL-R01..R10):
  all-PASS -> dataset PASS; evaluator FAIL -> FAIL; evaluator exception
  -> ERROR never FAIL; target exception -> case ERROR; cancellation
  propagates; independent cases continue after an ERROR; deterministic
  case and evaluator ordering; no backend/network dependency; diagnostics
  cannot affect aggregation; malformed datasets refuse to start

reporting (EVAL-P01..P06):
  correct PASS/FAIL/ERROR summaries; failing case/evaluator/explanation
  identified; ERROR visually distinct from FAIL; machine output
  round-trips with sorted keys; no aggregate numeric score; human report
  never exposes diagnostics or secrets

datasets:
  every registered target loads with deterministic counts/ordering;
  research-agent concatenates retrieval then synthesis; unregistered and
  version-mismatched datasets refuse; mixed-version and mixed-target
  directories reject; `ati-eval validate` CLI exit codes offline
```

PR 30A requires no LangSmith, no real LLM, and no network access anywhere
in the unit suite; future judge scenarios (PR 30B/30C) stay offline behind
deterministic fakes. The optional credentialed evaluation workflow (real
model runs uploading to LangSmith) begins in PR 30B only.

### PR 30B LangSmith adapter tests

PR 30B adds the LangSmith evaluation adapter under
`src/agentic_threat_investigator/evaluation/backends/langsmith/` with a
fully deterministic, network-free, credential-free unit matrix in
`tests/unit/evaluation/langsmith/` (fake-boundary tests only) and static
workflow tests. All ordinary tests inject the in-memory
`FakeLangSmithClient` (or the duck-typed `FakeSdkClient` for the real SDK
wrapper); no test acquires `LANGSMITH_API_KEY` or reaches the network, and
no test merely skips without a key and calls that coverage.

```text
mapping (LS-M01..M10):
  deterministic dataset names; stable case identity inputs;
  required/forbidden behavior projection; sorted tag/architecture
  metadata; identical canonical projection for identical inputs; digest
  changes on any semantic change; ordering-only changes keep the digest;
  no secret/raw runtime fields projected; projection schema version
  emitted; malformed metadata rejected before any remote call

sync (LS-S01..S16):
  absent dataset -> create + examples; existing empty dataset -> create;
  exact mirror -> no writes; only missing examples created; same
  identity/digest -> unchanged; digest mismatch -> fail without overwrite;
  remote extra ATI identity -> fail without delete; duplicate remote
  identity -> fail; dataset identity mismatch -> fail; unsupported
  projection schema -> fail; malformed local -> no remote mutation;
  create/list/create-examples API errors surfaced; repeated identical sync
  performs zero writes; cancellation propagates

verify (LS-V01..V08):
  exact mirror success; missing dataset/example/extra example/digest
  mismatch/duplicate identity/malformed metadata all fail closed;
  verification performs no writes

result mapping (LS-R01..R10):
  PASS/FAIL/ERROR map to categorical pass/fail/error (never numeric);
  bounded explanations preserved; ERROR explanations sanitized;
  diagnostics never published by default; case/run aggregates categorical
  only; stable evaluator feedback keys/order; no score/weight/percentage

client boundary (LS-C01..C06):
  SDK dataset/example objects convert to bounded DTOs; foreign metadata
  filtered to the ati.* namespace; SDK exceptions become bounded backend
  errors; credential-like/control-character text bounded out of messages;
  cancellation propagates; no SDK object escapes the adapter boundary

CLI (LS-CLI01..CLI09):
  valid sync/verify succeed through the fake; invalid datasets fail
  before any client call; missing credentials bounded nonzero failure
  with no environment dump; drift exits nonzero; pre-existing validate
  unchanged; run command deferred to PR 30C; no secret in output

workflow static tests (LS-W01..W13):
  evaluation.yml exists; workflow_dispatch only (no push/PR/schedule);
  contents: read; LANGSMITH_API_KEY only (PR 30B has no model-provider
  secret); Python 3.14; uv sync --locked; local validation before the
  remote operation; invokes ati-eval langsmith; ci.yml stays
  uncredentialed (GITHUB_TOKEN only)
```

PR 30B changes no production agent/persistence behavior, requires no
living LangSmith service for mandatory CI, and adds no dependency beyond
the already-locked `langsmith>=0.3.45,<0.12` bound inspected against the
installed 0.11.x SDK. A real LangSmith smoke is manual only, through the
optional `workflow_dispatch` workflow or operator execution.

### PR 30C real Evidence Analyst target tests

PR 30C adds the first real target execution layer
(`tests/unit/evaluation/analyst/`, `tests/unit/evaluation/langsmith/`,
`tests/integration/`) with the same deterministic discipline: mandatory
CI stays offline/uncredentialed (FakeLlmClient at the model boundary,
FakeLangSmithClient at the remote boundary, real PostgreSQL only in the
`integration`-marked vertical slice).

```text
target executor (EA-T01..T12):
  exact identity lookup; unknown case/version mismatch/duplicate identity
  fail closed; target mismatch refuses before any model call;
  materialization then exactly one analyst call; persisted Assessment +
  resolution returned; LLM/persistence failures are runner ERROR;
  cancellation propagates; two cases never cross-contaminate;
  deterministic same-case rerun; target has no LangSmith dependency

evaluator adapter (EA-E01..E10):
  existing evaluator PASS/FAIL map to COMPLETED/PASS and COMPLETED/FAIL;
  deterministic nonblank explanation; JSON-safe descriptive diagnostics;
  partial coverage never decides a verdict; no numeric correctness;
  identity mismatch is runner ERROR; cancellation propagates; forbidden
  support and missing required contradiction FAIL

run service (EA-R01..R14):
  all cases projected to the runner; non-analyst dataset rejected;
  pass/fail/error aggregation preserved; no LangSmith dependency;
  cancellation propagates; exactly one materializer + analyst call per
  case; one case rerun stays deterministic

LangSmith experiment (EA-LS01..LS15):
  exact mirror allows the experiment; one case -> one remote case
  association; PASS/FAIL/ERROR map to pass/fail/error; missing remote
  dataset/digest drift refuse before any model work (verify-first);
  feedback acceptance confirms; feedback/confirmation failures fail
  closed; no score/threshold; diagnostics not uploaded; metadata bounded
  and secret-free; cancellation propagates; no duplicate model execution
  (evaluate()/aevaluate() never invoked)

CLI run (EA-R06..R12):
  local run constructs no LangSmith client; PASS exits 0; FAIL exits 1;
  ERROR exits 2; missing model credential bounded exit 2; deterministic
  driver rejected; publication failure is exit 2; FAIL stays exit 1 after
  successful publication; non-analyst dataset rejected

workflow static tests (EA-W01..W18):
  workflow_dispatch only; contents read; operations verify/sync/run;
  Python 3.14; uv sync --locked; validate before run; LangSmith verify
  before the model run; PostgreSQL and migrations configured for run;
  LANGSMITH_API_KEY used; the model-provider secret is wired only for run;
  verify/sync need no model execution; ordinary CI uncredentialed; no
  push/PR/schedule; no write permission; secrets never echoed/literalized

PostgreSQL vertical slice (integration):
  real scenarios -> real materializer -> real loader -> real
  EvidenceAnalyst -> FakeLlmClient -> real AssessmentPersistenceService
  -> persisted Assessment -> real evaluator through the PR 30 adapter ->
  common EvaluationRunner; direct-evidence PASS, contradiction PASS,
  nonconforming output FAIL (still persists), LLM failure ERROR (nothing
  persists, one bounded attempt); rerun reuses the fixture and evaluates
  the current invocation
```

PR 30C changes no existing V1 scenario semantics, no production
Evidence Analyst behavior, and no common evaluation contract; adds no DB
migration; and keeps every mandatory test free of live LLM/LangSmith
dependencies.

### Threat Research evaluation baseline (PR 22D)

PR 22D adds a separate **behavioral evaluation layer** over the unchanged
PR 22A-C runtime: the runtime tests above prove *what the production path
does*; the PR 22D evaluators prove *whether the persisted artifacts satisfy
repository-owned scenario expectations*. The two layers are deliberately
distinct and both remain fully offline.

Evaluator unit matrix (`tests/unit/evaluation/research/`,
`tests/unit/evaluation/test_coordinator_research_evaluator.py`):

```text
retrieval metrics: Recall@k, Precision@k, MRR, expected-source rank,
  duplicate identities, empty denominators, explicit gap, filter leaks,
  forbidden records, deterministic failure ordering (22D-U01..U12)
strict retrieval/synthesis loaders: malformed JSON, duplicate JSON keys,
  duplicate (id, version) identities, duplicate expectation labels,
  invalid scenario ids, extra-field rejection (22D-U13..U15)
synthesis envelope: citation closure, supplied-set membership,
  required/forbidden citations, empty-result semantics, claim matching,
  contradiction pairs, deterministic failure ordering, denominator-safe
  metrics (22D-U16..U29)
epistemic snapshots: unchanged Evidence/RelationshipObservation/Assessment
  passes; any promotion is a stable failure; a ResearchResult alone is not
  promotion (22D-U30..U34)
coordinator research lifecycle: required/forbidden requests, bounded
  budgets, legitimate retry vs. post-completion duplicate, exhaustion,
  termination, backward compatibility of pre-research scenarios
  (22D-U35..U42)
```

Real-format retrieval evaluation slice
(`tests/integration/test_research_retrieval_evaluation.py`, 22D-I01):

```text
local MITRE ATT&CK STIX 2.1 fixture
 -> production MitreAttackBatchSource / MitreAttackDocumentBuilder
 -> DocumentIndexingService + deterministic embeddings
 -> real PostgreSQL / pgvector
 -> PgVectorResearchRetriever
 -> ordered RetrievedChunk values
 -> ResearchRetrievalEvaluator
```

Repository-owned scenarios under `evals/scenarios/research/retrieval/`
declare stable ATT&CK identities expected/forbidden at bounded ranks, filter
contexts, and an explicit retrieval-gap case. A deliberately failing
scenario (`real-mitre-forbidden-technique`) proves a structurally successful
retrieval can fail the baseline.

Synthesis evaluation slice
(`tests/integration/test_research_evaluation.py`, 22D-I02..I06):

```text
real-format fixture
 -> production parser/builder/indexing/retrieval
 -> ResearchAgent + FakeLlmClient (model boundary only)
 -> real ResearchResult persistence
 -> repository-read-back result -> ResearchSynthesisEvaluator
 -> epistemic snapshots before/after the isolated research interval
```

The slice covers RAG-S01 relevant context, S02 no-retrieval empty result,
S03 retrieved-but-irrelevant empty result, S04 contradictory separately
cited claims, S05 unsupported-citation safe failure (execution envelope, no
fabricated result), and S06 hostile corpus text. A runtime-valid but
scenario-wrong persisted result (supplied-but-wrong citation) is proven to
fail the behavioral evaluation (22D-I03). The canonical synthesis/trajectory
career observes the exact supplied citation set with a recording wrapper
around the production retriever; nothing is re-ranked or substituted.

Bounded research retrieval is total and deterministic: production pgvector
retrieval orders by vector distance first and the stable unique chunk
identity second, so chunks with equal distance have a well-defined order and
top-N membership cannot vary across otherwise identical executions. A test
that claims a citation was supplied to a model execution must derive it from
the exact retrieval of that execution (a `FakeLlmClient` response factory
over the chunks recorded by the `RecordingResearchRetriever`), never from an
independent probe retrieval; only the genuinely unsupplied-citation failure
path (rag-S05) intentionally probes a wider set. Intentional equal-distance
regression coverage (`tests/integration/test_research_retrieval_determinism.py`,
RDET-01..05) pins distinct-distance ranking, equal-distance stable ordering,
ties crossing the `LIMIT` boundary, repeated-retrieval identity, and
filtered-set determinism through the production path.

Coordinator trajectory evaluation slices
(`tests/integration/test_research_trajectory_evaluation.py`, 22D-I07/I08)
run the full production research lifecycle (real CoordinatorPolicy, real
LangGraph, real runner, real corpus/research agent) and evaluate the durable
timeline/state with the extended `CoordinatorTrajectoryEvaluator` against
the repository scenarios C-R01 (research requested), C-R02 (completed
unchanged context not re-requested on rerun), C-R03 (bounded exhaustion, no
further request), and C-R04 (no direct research->pivot authority).

### Evidence Analyst evaluation vertical slices (PR 20C)

`tests/integration/test_evidence_analyst_evaluation.py` runs the repository-
owned analyst scenarios end to end against isolated real PostgreSQL with
`FakeLlmClient`:

```text
AnalystScenario JSON -> AnalystScenarioMaterializer (UnitOfWork seam)
 -> existing EvidenceAnalystInputLoader
 -> existing EvidenceAnalyst + LlmAccountingService
 -> FakeLlmClient (canonical decision built from the scenario expectations)
 -> existing PR 20A validation/persistence
 -> persisted Assessment read back through the repository
 -> EvidenceAnalystEvaluator
```

Documented properties of the PR 20C slice:

- **Evaluator consumes persisted Assessments only.** Inputs are scenario,
  resolution, and the repository-read-back Assessment; no raw LLM response,
  pre-persistence decision, prompt, or provider response object is ever
  evaluated (see `EVALUATION.md`).
- **Deterministic fixtures win over a second model.** Scenario truth -
  allowed verdict/confidence envelopes, required/forbidden support,
  contradiction pairs, canonical limitation/question/next-step phrases -
  drives both the scripted fake decision and the evaluator, so they can
  never drift.
- **Semantic labels resolve to exact UUIDs.** Expectation labels point into
  the fixture; materialization returns `AnalystScenarioResolution`. The
  evaluator fails closed on unknown labels. Corpus identity is the exact
  `(id, version)` pair: distinct versions of one stable id may coexist.
- **Fail-closed authoring validation.** Duplicate entries inside any
  expectation label/phrase collection and duplicate JSON object keys at any
  nesting depth are rejected before set conversion; every fixture label and
  support reference must be a stable bounded lowercase semantic label
  (`^[a-z0-9][a-z0-9._-]*$`, ≤ 64 characters); invalid UTF-8 scenario
  bytes surface as `AnalystScenarioLoadError`, never a raw decoding error.
- **Repository-confirmed persisted IDs only.** `AnalystScenarioMaterializer`
  fails closed when a repository returns `id=None` instead of substituting
  a planned UUID, and records the repository-returned identity (including
  canonical redirects) everywhere dependent rows reference it.
- **Truthful support metrics.** `required_support_satisfied` reflects the
  best single shape-matching, clean candidate's required-label coverage;
  support split across Findings never counts twice, missing-label messages
  name labels absent from that one candidate, and disallowed Finding
  confidence does not erase otherwise present support. Tie-breaking controls
  support metrics and diagnostics only; any fully supported candidate may
  satisfy the confidence requirement.
- **Behavioral failure is not persistence failure.** Negative slices prove a
  structurally valid (PR 20A-accepted) Assessment that is behaviorally wrong
  still persists exactly one durable row while the evaluator rejects it with
  the stable bounded codes (for example MALICIOUS-on-geolocation-only,
  missing required limitation, one-sided contradiction).
- **No live LLM in CI.** Normal PR tests require no external model key, no
  internet, no provider credential, and no LangSmith service.

Unit coverage (`tests/unit/evaluation/analyst/`) exercises every bounded
failure code with passing and failing cases, deterministic failure ordering,
metrics derived from the same comparisons (including partial-support
coverage and confidence-not-erasing-support), scenario/DTO validation
exhaustively (duplicate labels, duplicate JSON keys, invalid semantic
labels, unknown fixture references, blank/naive fields, empty envelopes,
extra-field rejection), scenario loader fail-closed behavior (malformed
JSON, invalid UTF-8, duplicate top-level and nested object keys,
duplicate `(id, version)` identities, deterministic discovery order),
committed-corpus integrity, and deterministic materializer identity
derivation against an in-memory `UnitOfWork` (including fail-closed
`id=None` repositories and repository-confirmed redirects).

### Serialization tests

For persisted/API-visible structured agent results, test:

```text
Pydantic model
 -> JSON-compatible serialization
 -> persistence/API mapping
```

as applicable.

Tests must verify preservation of:

- stable IDs;
- enum/URN values;
- verdict/confidence;
- typed Finding provenance (Evidence and RelationshipObservation references);
- research/chunk citations;
- list ordering where semantically relevant;
- optional/empty semantics.

Do not use human-readable rendered text as the source for reconstructing
the structured result.

### Deterministic formatter tests

Every human-readable formatter must be tested without an LLM.

Given a fixed structured result and fixed formatter configuration,
repeated calls must produce identical output bytes unless the formatter
contract explicitly defines a non-semantic presentation variation.

Formatter tests must prove that rendering:

- preserves verdict/confidence;
- preserves findings;
- preserves Evidence references;
- preserves research citations;
- preserves limitations;
- preserves recommended next steps;
- introduces no unsupported claim;
- does not omit material structured content required by the target
  format;
- does not mutate the source Pydantic object;
- performs no provider/retriever/LLM call.

Use golden/snapshot fixtures only when repository policy permits them
and when the fixture is reviewed as a deterministic presentation
artifact. Semantic assertions must still cover critical fields so that
an indiscriminate snapshot update cannot hide a semantic regression.

### Report Writer versus formatter tests

Keep these responsibilities separate:

**Report Writer structural tests (PR 23B)**

- strict domain contracts: blank titles/statements rejected, unsupported
  narrative statements rejected, duplicate source references rejected,
  forbidden model-authored verdict/confidence/persistence metadata rejected
  via `extra="forbid"`;
- input materialization: no current Assessment fails typed before any LLM
  call, missing provenance fails closed, input collections and serialized
  bytes are independently bounded, raw Evidence payloads never enter the
  context, ordering and prompt bytes are deterministic;
- deterministic provenance validation: unknown finding/research references,
  cross-Investigation references, snapshot drift, caveat changes, and
  source-set drift all fail before persistence;
- LLM execution: one reservation per actual invocation, at most one
  schema-repair invocation, cancellation propagates, no free-form fallback;
- report persistence: DB-assigned versions, one CREATE history row, atomic
  append + pointer update, stale-Assessment rejection, superseded-only soft
  deletion, current-report delete rejection;
- report query: `version DESC, id ASC` keyset pagination, current report via
  the durable `report_id` pointer, index eligibility via EXPLAIN.

**Report Writer behavioral evaluation**

- grounded synthesis;
- correct Evidence/research references;
- no unsupported material claims;
- Assessment verdict/confidence preserved;
- useful structured report content.

Behavioral evaluation is repository-owned and deterministic (scenario JSON
under `evals/scenarios/report_writer/`, stable failure codes, no
LLM-as-judge); it never claims that deterministic reference validation
proves semantic entailment.

**Formatter deterministic tests**

- exact rendering behavior;
- escaping;
- ordering;
- headings/labels;
- citation presentation;
- format-specific syntax;
- semantic preservation.

A formatter failure is a deterministic software defect, not an LLM
evaluation failure.

**Canonical offline vertical slice**

The primary “PR 23B actually works” proof is a real-PostgreSQL slice that
runs the production input loader, prompt builder, Report Writer service,
provenance validation, report persistence, and Markdown formatter with
`FakeLlmClient` ONLY at the model boundary, asserting the exact persisted
report is returned, verdict/confidence equal the Assessment, provenance
references resolve, and Markdown is deterministic. No live Internet or live
LLM participates.

### No free-form fallback

Tests must prove that ATI does not silently accept free-form text when a
structured response model is required.

If structured parsing/validation fails after the bounded repair policy,
the operation returns the typed LLM failure. ATI must not:

- persist the raw text as the authoritative result;
- regex/heuristically extract a verdict or action;
- execute a pivot inferred from prose;
- generate a final report directly from the unvalidated text.

### Deterministic report equivalence

For a fixed `InvestigationReport` version, formatter tests should verify
that all supported renderers represent the same material semantics even
though their syntax differs.

For example:

```text
InvestigationReport JSON
       |             |
       v             v
   Markdown         HTML
       \             /
        same verdict
        same findings
        same citations
        same limitations
        same next steps
```

## Scenario factory

A reusable `ThreatScenarioFactory` should construct deterministic integration/evaluation fixtures.

Representative scenarios include:

1. benign;
2. clearly malicious;
3. inconclusive;
4. conflicting evidence;
5. domain-to-malicious-IP pivot;
6. two IOCs sharing infrastructure;
7. malware with RAG context;
8. monitor with no material change;
9. monitor with meaningful change;
10. historical evolution.

Canonical fixture:

`malicious_domain_with_ip_and_malware_pivot`

Behavioral expectations and scoring for these scenarios live in `EVALUATION.md`.

## Coverage

Use pytest-cov to report test coverage in CI.

Do not invent a repository-wide percentage before meaningful implementation exists.

Critical deterministic logic should receive especially strong coverage:

- canonicalization;
- pivot-policy enforcement;
- budget accounting;
- relationship extraction;
- deterministic source extraction;
- source normalization;
- persistence invariants;
- assessment validation;
- authorization;
- soft deletion;
- job claiming;
- monitoring diff logic.

Coverage is a diagnostic and quality gate, not a substitute for meaningful tests.

## Pre-commit

Pre-commit provides fast developer feedback for inexpensive deterministic checks such as:

- trailing whitespace;
- end-of-file normalization;
- Ruff check (with safe fixes) and Ruff format;
- selected fast checks.

Do not require slow database integration or real-model evaluation for every local commit.

CI remains authoritative.

## Canonical quality command

The repository exposes one documented command, for example:

```bash
make quality
```

It should run the required source-quality/test checks in a stable order, conceptually:

```text
Ruff format --check
Ruff check
Mypy
Pytest deterministic suites
```

A separate command may run full integration tests when containerized dependencies are required.

As implementation matures, `make quality` may orchestrate both fast and required integration stages in CI.

## No quality-gate bypass

A coding agent or developer must not make a failing gate pass by:

- weakening global configuration;
- lowering a coverage requirement without justification;
- adding broad `type: ignore`;
- adding broad Ruff/`noqa` suppression;
- skipping failing tests;
- deleting assertions;
- disabling migration checks;
- replacing real PostgreSQL integration tests with weaker substitutes;

unless the change is independently justified and reviewed.

## CI quality gate

Every PR should eventually run approximately:

```text
uv sync --locked
      |
Ruff format --check
Ruff check
Mypy
      |
unit tests
provider fixture contract tests
      |
PostgreSQL/pgvector integration environment
Alembic migration from empty database
database/integration tests
      |
deterministic agent evaluation hard gates
      |
license/SPDX checks
```

See `EVALUATION.md` for the behavioral-evaluation portion.

## Frontend quality

The React/TypeScript frontend must have equivalent automated engineering discipline:

- formatting;
- linting;
- strict TypeScript;
- unit/component tests;
- relevant integration tests.

The v0.1 frontend toolchain (PR 24A):

- **Vitest + jsdom** for unit/component tests, with global setup in
  `frontend/src/test/setup.ts`;
- **Testing Library + user-event** for interaction, and jest-dom matchers;
- **MSW** centralizes deterministic HTTP behavior: `src/test/server.ts`
  owns the server lifecycle and `src/test/handlers.ts` owns the
  `/auth/me`, `/auth/login`, `/auth/logout`, `/runtime` and PR 24B
  Investigation handlers (list, create, detail, current Assessment,
  current Report, Report Markdown) with deterministic lifecycle
  transitions (`pending -> running -> completed`, `pending -> failed`,
  `running -> partial`) modeled on the public HTTP contract only — never
  on worker internals. Every test builds an isolated QueryClient (no
  shared Query cache); unhandled requests fail loudly;
- **OpenAPI-derived types**: `npm run api:generate` regenerates
  `frontend/src/api/schema.generated.ts` from the committed snapshot
  `tests/fixtures/openapi_v1.json`; `npm run api:check` fails when the
  committed types are stale. CI never fetches a live development server's
  OpenAPI document;
- **Playwright** runs the real-browser production-path slice against real
  FastAPI/PostgreSQL — see *Browser E2E* below.

What is mocked versus real:

| Layer | Unit/component tests | Playwright E2E |
|---|---|---|
| HTTP | MSW handlers | real FastAPI via Nginx `/api` proxy |
| Auth/session | jsdom cookie jar + real CSRF contract code | real HttpOnly session + CSRF cookies |
| Database | none | real throwaway PostgreSQL 18 |
| LLM | none (unit tests inject `FakeLlmClient`/the deterministic client directly) | `ATI_LLM_DRIVER=deterministic` offline scripted boundary; never a live LLM |

TanStack Query itself is never mocked and the API client is never replaced
with per-component fakes.

### Browser E2E (PR 24A)

`scripts/e2e.sh` builds the full production-path topology in isolation:
throwaway PostgreSQL → migrations → fake-data bootstrap → FastAPI (fake
mode, generated bootstrap admin) → static frontend + Nginx `/api` proxy →
Playwright Chromium. Isolation follows `integration-test.sh` principles:
unique Compose project, unmistakable test database/user, random host
ports, a throwaway named volume, and generated test-only credentials.
Cleanup only touches resources the harness created; no live LLM is used
and no normal developer data is touched.

### Investigation workflow tests (PR 24B)

Component tests (`frontend/src/investigations/`) cover the full matrix:

- list: default bounded page, exact status filter enum, opaque cursor
  Previous/Next via a browser-local cursor stack, no count/page-number
  fiction, empty/error/retry states, and no fabricated subject labels;
- create: localized requiredness and the exact backend bounds exposed in
  OpenAPI (objective ≤ 4000, indicator value ≤ 2048, at least one typed
  indicator), exact `EntityType` submission, cryptographic in-memory
  `Idempotency-Key` generation, commit-uncertain retry reusing the same
  key for transport failures and transient HTTP 5xx outcomes (API 500/
  502/503 envelopes and malformed 5xx bodies, PR 24F F-B02..F-B05),
  new key for changed semantic content after an uncertain attempt
  (including after a 503, F-B11), definitive 4xx validation/conflict/
  auth-permission settling the attempt (F-B06/F-B07/F-B08), pre-transport
  CSRF never treated as uncertain (F-B09), explicit
  `409 idempotency_conflict`, `202` immediate workspace navigation, list
  invalidation, and CSRF preservation;
- polling: pending/running refetch on the bounded 2s interval,
  completed/partial/failed stop refetching, no interval-in-background,
  AbortSignal propagation and cancellation on unmount, transient poll
  failure retaining the last successful state;
- current-resource queries are pointer-gated (`/assessments/current`,
  `/reports/current` only) — never version-list `MAX(version)` — with one
  bounded detail reconciliation for pointer/read-race 404s;
- Overview: Report-based presentation when present, Assessment fallback
  otherwise, partial/failed terminal states, no invented progress, escaped
  analytical text (no raw HTML), Research visibly distinct from Evidence,
  and visible support references;
- full Report route with persisted metadata and the optional deterministic
  Markdown view as plain text;
- workspace placeholders (Evidence/Relationships/Research/Timeline) issue
  no collection queries; detail 404 renders a scoped not-found surface.

### Browser E2E (PR 24B)

`scripts/e2e.sh` now includes the real durable Investigation worker in the
isolated topology (isolated PostgreSQL → migrations → fake-data bootstrap →
FastAPI → worker → static frontend + Nginx → Playwright Chromium). The
worker runs the production Coordinator/runner/persistence with the
deterministic offline LLM boundary (`ATI_LLM_DRIVER=deterministic`),
including the worker-owned PENDING -> RUNNING lifecycle transition and the
post-run Report writing, so the browser slice exercises the complete
workflow with no live LLM or live network: login → create the documented F02 fake-world Investigation → 202 →
immediate workspace → bounded detail polling → terminal lifecycle → current
Assessment → current Report → Overview, verifying `Idempotency-Key`,
`FAKE DATA`, verdict/confidence, executive summary, findings and support
references, and that the list shows exactly one logical Investigation.

Covered paths (frontend/e2e):

- E01 login → authenticated shell → runtime `FAKE DATA` indicator;
- E02 reload restores the server-side session;
- E03 real CSRF-protected logout revokes the session;
- E04 direct SPA navigation through Nginx resolves via React Router;
- E10 create → 202 → workspace → poll → terminal Assessment/Report
  Overview (real stack, fake world, deterministic LLM boundary);
- E11 the created Investigation appears exactly once in the real list.

### Analyst resource tables and drill-down (PR 24C)

Component tests (`frontend/src/analyst-table/`, `frontend/src/{evidence,
relationships,research,timeline,history}/`) cover the full PR 24C matrix
over central MSW handlers for every list/detail route:

- shared table mechanics: semantic header rows, loading/empty/error/retry
  states, keyboard-operable row `View` actions, no sort affordances,
  Next enabled only with a `next_cursor`, opaque cursor bytes passed
  unchanged, Previous over the browser-local back stack, filter-change
  cursor/back-stack reset, URL-cursor deep links, invalid-cursor first-page
  recovery, stale-data retention on transient failure, and the running-
  Investigation freshness notice with Refresh;
- filter codecs: unknown/invalid enum/UUID values normalize to absence
  (never sent), empty values are omitted, local datetime inputs convert to
  UTC ISO with half-open semantics preserved, and `selected` never alters
  list query identity;
- CSV: RFC 4180 quoting of commas/quotes/CR/LF, spreadsheet
  formula-injection neutralization, objective-free filenames, and export
  scoped to the loaded page only (no recursive cursor fetching);
- Evidence: subject/type/source and distinct observed/retrieved rendering,
  exact type/source/entity/time filters, authoritative scoped detail,
  safe HTTP(S)-only source links, escaped markup, and empty-does-not-mean-
  benign;
- Relationships/Observations: source/type/target with analyst labels,
  exact filters, Investigation-scoped detail, bounded relationship-scoped
  observation previews (never generic History), first-class observations
  route, observed/retrieved range independence, and no ended/removed
  inference;
- Research: metadata/counts, exact filters, inspectable claim-to-citation
  closure, visible separation from Evidence, escaped external text, no
  browser source fetching, and retrieval scores never labeled as
  credibility/confidence;
- Timeline: canonical order preserved, exact event/date filters, label
  mapping with safe unknown fallback, and no Relationship Evolution
  wording;
- History: allowlisted object types only (the exact backend public
  allowlist), exact operation/date filters, escaped state/diff rendering,
  exact-version detail (including scoped 404), bounded object-version
  browsing, and RelationshipObservation never fetched through generic
  History; the generic History list skips non-allowlisted audit rows (such
  as the immutable ``evidence`` rows appended by the stored functions)
  instead of failing with a 500, while explicit requests for
  non-allowlisted types fail closed with ``400 invalid_request``
  (api/routes/history.py + tests/unit/api/test_history_routes.py).

### Browser E2E (PR 24C)

`scripts/e2e.sh` exercises the built frontend + real FastAPI + real
PostgreSQL + the durable worker over the PR 23D fake world with the
deterministic offline LLM boundary. PR 24C coverage (frontend/e2e):

- E20 completed-Investigation browsing: bounded Evidence table with a real
  exact filter (evidence type DNS) surviving URL round-trip reload, the
  authoritative scoped detail drawer with distinct Observed at / Retrieved
  at, Relationship analyst-label rows with detail and a bounded
  relationship-scoped observation preview, first-class
  `/relationships/observations`, Research context (visible separation),
  Timeline with an exact event filter, secondary History with
  exact-version state/diff detail, a browser-proven current-page CSV
  download with the safe filename shape;
- E21 plain browsing after completion opens no pivot modal: pivot triggers
  exist on typed values but the modal appears only after an explicit
  pivot action;
- the PR 24C browser suite runs after the PR 24A/24B specs
  (`frontend/e2e/zz-analyst-tables.spec.ts`) and performs a single login
  (the E2E harness sets the test-only `ATI_CONFIG_PROFILE=local` on the
  API so the throwaway stack's in-process login rate limit (100/60s
  instead of the production 5/60s) never makes the authenticated
  multi-spec suite timing-dependent; production deployments keep the
  default limit), then captures a Playwright storageState
  (`test-results/analyst-session.json`) that the PR 24D suite reuses
  without an additional login.

### Cross-resource pivots and provenance navigation (PR 24D)

Separate generated-schema-projected pivot steps from router-backed page
components so the pivot modal and the normal routes reuse the exact PR 24C
resource query/filter/table/detail machinery (`frontend/src/pivots/`,
`frontend/src/analyst-table/resource-page.ts`):

- serializer/parser (`pivot-url.test.ts`): versioned base64url JSON
  envelope in the reserved `pivot` search parameter; query-identity
  stability, unicode labels, headers-only URL length stays within the
  4096-byte bound, malformed/truncated/foreign-version/base64url-off-json
  payloads fail closed, unknown resources filter to presence, max depth 5;
- capability registry (`pivot-capabilities.test.ts`): at least one legal
  action per typed value (Evidence subject/type/source, Relationship
  source/target, observation relationship + exact Evidence) and the
  RelationshipObservation support reference opening the exact scoped
  observation selection;
- navigation/URL projection (`pivot-port.test.ts` regressions inside
  `PivotWorkspace.test.tsx`): step filters arrive pre-applied at the
  table, pillars (evidence type/source) stay anchored to the Investigation;
- modal behavior (`PivotWorkspace.test.tsx`): one Material UI Dialog
  hosting the extracted route-independent workspaces, breadcrumbs with
  clickable truncation, depth cap at five with a visible notice, browser
  history push (Back/Forward restore prior pivot states and the base URL
  search parameters), malformed-cycle deep links degrade to the first
  legal step, 404/network failure shows the in-modal error/retry state,
  network retry, drawing exact Evidence inside the modal, and Close
  preserving base filters;
- provenance (`provenance.test.tsx`): the Report/Overview support list
  pivots exact Evidence by persisted id, Research context/claim
  references pivot exact Research, and RelationshipObservation support
  pivots the exact Investigation-scoped observation (F-P03/F-P04 via the
  scoped GET — the list page deliberately serves a different row, so the
  exact id must drive the request; F-P08 free Report text never enters
  the URL; F-P09 bounded breadcrumb label). A scoped observation 404
  keeps the pivot workspace open with an honest not-found and no
  fallback/substitute (F-P05/F-P06); observation detail pivots to exact
  Evidence by `evidence_id` (F-P07); Close restores the base Overview
  (F-P10). Report/Research free text never enters the URL;
- real-stack E22 (`frontend/e2e/zz-pivots.spec.ts`): overall completing
  F02 Investigation, Evidence support → exact Evidence workspace →
  subject pivot Relationships where source → open Relationship →
  RelationshipObservations → observation Evidence → Evidence; breadcrumb
  path mirrors the sequence; browser Back/Forward traverse pivot states;
  breadcrumb truncation restores the Relationships step; reload restores
  the active modal; Close restores the underlying Overview route; `FAKE
  DATA` and a clean browser console throughout. Interactions inside the
  pivot overlay use the raw pointer path (`page.mouse`) because the
  Playwright/Chromium composite locator hit-test can hang the browser
  main thread while a full-viewport fixed layer is open (DIAG-verified:
  raw events dispatch and the page stays responsive; identical events
  dispatched through the composite path do not). The same raw events can
  intermittently wedge the Chromium pointer dispatch on this stack
  (environment-specific; the identical interaction passes on retry and
  passed whole-suite runs), so CI retries E22 once before failing;
- real-stack E22-B (`frontend/e2e/zz-pivots.spec.ts`, PR 24F): benign/
  dead-end pivot path against the deterministic F01 fake-world
  Investigation — a legal typed pivot (Evidence subject -> Research for
  this entity) opens the target modal with the exact server filter
  visible, shows the honest filtered-empty research state (no invented
  relationship, no automatic fallback, no entity equivalence),
  preserves the breadcrumb context, closes safely to the base Evidence
  route with `FAKE DATA` visible and a clean browser console;
- exact observation query/API coverage (PR 24F): backend contract tests
  F-O01..F-O06 (same-Investigation item, missing/cross-Investigation
  `None`, joined relationship semantics, distinct observed/retrieved),
  real-PostgreSQL identity + Investigation-scope matrix
  (`tests/integration/test_query_relationship_observations.py`),
  API tests F-A01..F-A06 (200 projection, unknown/cross-Investigation
  scoped 404 without existence leaks, malformed UUID stable 422
  envelope, unauthenticated 401, same public fields as the list DTO),
  the regenerated OpenAPI snapshot, and frontend exact-detail coverage
  (F-P04 plus the observations-workspace selection test);
- the PR 24 series is closed: PR 24F performs the final source-and-test
  compliance sweep of PR 24A–24E and reconciles the authoritative
  documentation; no PR 24A–24E requirement remains unrecorded as
  compliant and no material architectural debt blocks PR 25.

### Investigation geolocation read projection and API (PR 25A)

PR 25A delivers the backend/query/API foundation for the v0.1 Investigation
Map: a bounded, Investigation-scoped, read-only projection over already-
persisted immutable `GEOLOCATION` Evidence joined to its canonical IP
entity. Coverage (G-Q01..G-Q10, G-M01..G-M12, G-P01..G-P16, G-A01..G-A10,
plus the vertical slices):

- **read-model invariants** (`tests/unit/app/query/test_geolocation_query.py`):
  fully mappable item; coordinate-less context accepted; partial
  coordinate pair rejected; latitude [-90,90]/longitude [-180,180] bounds;
  precision restricted to the existing persisted vocabulary; provider
  required and non-blank; canonical IP value carried; timezone-aware
  timestamps; frozen/extra-forbid behavior;
- **pure persisted-facts mapping** (`tests/unit/app/query/test_geolocation_query.py`):
  all approved facts map; unknown extra facts ignored (never leaked);
  missing optional city/region/country accepted; missing required
  provider/precision rejected; non-numeric, boolean, NaN/infinity, and
  partial-pair coordinates rejected; out-of-vocabulary precision and
  country-code representations rejected; only the approved fields can ever
  appear on the item;
- **real-PostgreSQL query matrix** (`tests/integration/test_query_geolocation.py`,
  G-P01..G-P16): core projection/bounded-read cases G-P01..G-P13 — empty
  Investigation; one IP; multiple IPs with deterministic ordering;
  latest-per-entity; deterministic id tie-breaker; generic Evidence types
  (REPUTATION/NETWORK/DNS) excluded; non-IP GEOLOCATION defensively
  excluded; cross-Investigation isolation with a shared Entity; coordinate-
  less context retained; truncation at `max_items + 1` with deterministic
  prefix; exactly-at-bound not truncated; historical volume stays one
  item per entity; and the G-P13 bounded-single-read verification — and
  defensive cases G-P14..G-P16: malformed persisted facts and partial
  coordinate pairs fail closed with `GeolocationFactsError`
  (G-P14/G-P15), and an unknown Investigation yields the established empty
  collection (G-P16). G-P13 verifies the single-read criterion
  structurally: the service issues exactly one SELECT over the
  latest-per-entity ranked subquery with a `max_items + 1` LIMIT, never
  per-item Evidence gets or Python-side grouping of historical rows. PR
  25D explicitly inspected the repository for reusable SQL
  statement-counting infrastructure (SQLAlchemy event listeners, query
  counters, statement recorders); the only SQLAlchemy event listeners
  present register batch composite types (the E2E geolocation seeder) or
  track UnitOfWork lifecycle phases (the analyst pipeline transaction
  tracker) — neither counts SQL statements. No generic instrumentation
  framework was created; structural verification is retained and
  documented at the test and in the PR 25D closure note below;
- **index eligibility** (`tests/integration/test_query_indexes.py`,
  test_p13): the latest-per-entity projection drives through the existing
  investigation-prefixed evidence listing indexes; no new index/migration
  is required at v0.1 (plan 28)
- **API contract** (`tests/unit/api/test_geolocation.py`): unauthenticated
  401; ANALYST and ADMIN 200; exact allowlisted response DTO; no
  facts/raw payload/source record id/artifact path leakage; empty
  collection 200; truncation transport; malformed persisted projection
  maps to a safe 500 internal error without leaking values; OpenAPI
  declares path, GET, operation id `list_investigation_geolocations`,
  cookie-session security, and the dedicated response schemas (a lower-
  privilege authenticated role does not exist in the v0.1 UserRole
  vocabulary, so the 403 branch remains covered at the shared
  `require_analyst` dependency);
- **real PostgreSQL + FastAPI vertical slices**
  (`tests/integration/test_api_geolocation.py`): persisted Entity +
  `GEOLOCATION` Evidence -> PostgreSQL query service -> QueryServiceBundle
  -> FastAPI route -> public JSON DTO (raw-payload-bearing non-geolocation
  Evidence never enters the projection), and the same path proving strict
  cross-Investigation HTTP isolation;
- regenerated OpenAPI fixture (`tests/fixtures/openapi_v1.json`) and
  frontend generated API types (`frontend/src/api/schema.generated.ts`,
  verified with `npm run api:check`).

### Investigation Map / Leaflet visualization (PR 25B)

PR 25B is the frontend Map feature over the PR 25A bounded projection
(`frontend/src/geolocation/`). The rendering boundary mock
(`frontend/src/test/react-leaflet-mock.tsx`) replaces the react-leaflet
surface with inert labeled elements so component tests assert Leaflet
semantics (one marker per mappable item, popup content, tile attribution,
and the deterministic viewport commands) without a layout engine or live
tile requests; TanStack Query and the centralized API client are never
mocked. Coverage:

- **pure map view model** (`geolocation-map-model.test.ts`, B-M01..B-M10):
  empty collection; valid paired coordinates; null/null context retained;
  mixed partition; server order preserved inside groups; truncation
  propagated exactly; partial pairs, NaN/infinity and out-of-range
  coordinates never plotted (inclusive boundary values are); input
  transport objects never mutated;
- **location labels** (`geolocation-labels.test.ts`, B-L01..B-L05):
  city/region/country join; region+country without punctuation artifacts;
  country only; no-label yields the explicit unavailable signal; external
  strings remain escaped text;
- **viewport policy** (`geolocation-viewport.test.ts`, B-V01..B-V07): zero
  points -> no fit command; one point -> exact center at the conservative
  fixed zoom 8; two/many points -> bounds over every mappable returned
  coordinate; multi-point max zoom cap; coordinate-less and malformed
  defensive items ignored for bounds;
- **API/key/query seam** (`geolocation-queries.test.tsx`, B-Q01..B-Q08):
  exact PR 25A path with no query string/cursor/limit; centralized
  `apiGet`; caller AbortSignal cancellation reaches the fetch; query key
  contains the Investigation ID (distinct per Investigation); one bounded
  fetch with no polling; errors remain typed `ApiError`;
- **route page states** (`InvestigationMapPage.test.tsx`, B-U01..B-U17):
  Map is a primary route-owned tab (Overview | Evidence | Relationships |
  Map | Research | Timeline) selected on the route; translated loading
  state; API failure + Retry with no fallback; honest empty state with no
  invented marker; one/multiple mappable items reach the map and the
  non-map list; unlocated-only state; mixed state with explicit counts;
  truncated warning (server bound never bypassed); persistent visible
  approximation disclaimer; exact precision enum -> translated neutral
  labels; known provider friendly label and unknown provider escaped
  text; observed/retrieved timestamps stay distinct; the exact Evidence
  drawer opens from the row action; the page is built from the
  geolocation endpoint and never from Evidence pagination; hostile
  external values cannot inject markup; the global `FAKE DATA` marker
  remains visible;
- **Leaflet wrapper** (`InvestigationMap.test.tsx`, B-F01..B-F08): one
  Marker per mappable item and none for unlocated items; popup carries
  the exact item and Evidence action; TileLayer carries the centralized
  OSM attribution/URL (no secret-bearing URL); no fabricated precision
  circle; no clustering plugin/component; unmount leaves no
  application-owned timers/listeners; single-point `setView` and
  multi-point `fitBounds` wiring matches the pure viewport policy;
- **provenance** (`InvestigationMapPage.test.tsx`, B-P01..B-P06): marker
  popup and non-map row both drive the exact PR 25A `evidence_id` (no
  lookup by IP, no Evidence list scan, Investigation-scoped request, and
  Close returning to the intact Map view) through the shared
  DetailDrawer/EvidenceDetail PR 24C surface;
- **accessibility** (`InvestigationMapPage.test.tsx`, B-A11Y01..B-A11Y08):
  translated heading; visible disclaimer; labeled keyboard-reachable
  non-map table; native Evidence buttons; no hover-only information;
  unlocated items inspectable without the map; labeled map region; tile
  attribution present.

Real-stack browser coverage **E24** (`frontend/e2e/zz-geolocation.spec.ts`)
runs the principal Map workflow over the full production-path stack (built
frontend + Nginx + real FastAPI + real PostgreSQL + the durable worker
over the fake world, real PR 25A endpoint, no geolocation interception,
no correctness dependency on live tile delivery). The E24 data
prerequisite is closed by the PR 25C deterministic real-stack seeding
seam: after the browser completes the exact Investigation, the spec
invokes `scripts/e2e-seed-geolocation.sh <investigation-id>
single_mappable` (the harness-only seeder persists a normal canonical IP
Entity + `GEOLOCATION` Evidence row through the normal repositories into
the throwaway E2E database), then asserts the disclaimer, the exact
seeded IP in the non-map representation, a real Leaflet marker, and the
exact persisted geolocation Evidence provenance in the drawer (subject
IP + `Geolocation` type + `urn:ati:source:dbip_city_lite` source),
followed by a safe return, `FAKE DATA`, and a clean browser console.
Seed failure is test failure; there is no data-path skip.

### Map analyst workflow and E2E seeding (PR 25C)

Deterministic E2E seeding and the Map-origin typed pivot workflow:

- **seeder unit contracts** (`tests/unit/infrastructure/test_e2e_geolocation_seed.py`,
  C-S01..C-S13): unknown scenarios rejected; malformed/nil Investigation
  IDs rejected; missing/soft-deleted Investigation refused; the explicit
  E2E guard (`ATI_OPERATING_MODE=fake` **and** `ATI_E2E_SEEDING_ENABLED`)
  required with the CLI exiting nonzero without it; valid single mappable
  construction; distinct multi-IOC identities; same-coordinate identities
  remain distinct; null/null coordinate fixture valid; deterministic
  timestamps/values on repeat derivation; repeated invocation bounded and
  idempotent against an in-memory seam; no raw payload/secret-bearing
  values; and a structural review that the seeder owns no raw SQL (only
  `investigations.get_by_id` / `entities.upsert` / `evidence.insert` on
  the real `PostgresUnitOfWork` seam);
- **seeder real-PostgreSQL proof** (`tests/integration/test_e2e_geolocation_seed.py`,
  SG01..SG07): a normal Investigation is created and seeded, then read
  through `PostgresInvestigationGeolocationQueryService` with exact
  seeded Entity/Evidence identity, mappable/unlocated/same-coordinate
  records, deterministic ordering, idempotent repeat, and strict
  cross-Investigation isolation; an authenticated FastAPI check proves
  the real `/geolocations` endpoint returns the seeded projection without
  leaking facts/raw payloads;
- **map-origin entity action contracts**
  (`frontend/src/geolocation/GeolocationEntityActions.test.tsx`, C-P01..C-P12):
  the single `map_entity` source kind; exact Evidence subject filter;
  exact Relationship source and target filters (never merged); exact
  Research subject filter; IP display label (never coordinates); View
  Evidence remains the exact `evidence_id`; marker popup and non-map row
  expose equivalent Explore actions; coordinate-less items stay
  actionable; same-coordinate items keep distinct Entity IDs; no client
  Relationship OR merge; no unsupported resource/scoped selection; a
  rendering test proves Explore opens the typed PivotWorkspace with the
  `map_entity` step and an IP-identity breadcrumb;
- **pivot model/URL validation** (`pivot-url.test.ts`, `pivot-capabilities.test.ts`,
  C-V01..C-V08): `map_entity` accepted and URL round-trips; unknown
  source kinds (`map_marker`, `map_row`) rejected; max pivot depth (5),
  label bound (128), UUID filter validation, no-op suppression, and
  close/back behavior unchanged;
- **real-stack browser matrix** (`frontend/e2e/zz-geolocation-workflow.spec.ts`,
  E25..E28): E25 seeds `multi_ioc` and explores each IP independently
  through typed pivots (Evidence with breadcrumb IP identity and
  server-filtered target; a legal Relationships-source target resolving
  to an honest empty/dead-end state; exact Evidence drill-down and
  disclaimer after return); E26 seeds two identical-coordinate IPs and
  proves both remain distinct inspectable rows with their own View
  Evidence/Explore actions and no co-location/cluster claim; E27 seeds a
  coordinate-less item and proves the row is fully actionable (exact
  Evidence, legal Explore action, honest empty Research target, safe
  close/back) with no marker; E28 uses an unseeded fake-world
  Investigation to prove the honest empty Map and strict isolation from
  every other Investigation's seeded rows.

Related real-stack instability is separately recorded: E22/E22-B
(`zz-pivots.spec.ts`) and occasional E23 (`zz-relationship-evolution.spec.ts`)
interactions hit the documented Chromium/MUI main-thread wedge under the
existing retry-1 configuration (reproduced on the pre-PR base commit;
E22/E22-B consistently, E23 intermittently) and are outside PR 25C scope
per the PR 24F stability notes and `docs/INVESTIGATION_STABILITY.md`.
The PR 25C E24-E28 geolocation suite passes deterministically.

### PR 25D — PR 25-series compliance closure [DONE]

PR 25D is the final closure PR for the PR 25 geolocation-map series; it
added no geolocation, Map, API, persistence, pivot, provider, spatial, or
GEOINT functionality. Delivered:

- **Fresh source-level audit of PR 25A-C** against actual source/tests
  (not implementation summaries) with a COMPLIANT/PARTIAL/MISSING/
  OUT-OF-SCOPE classification of every material requirement; no material
  PR 25 production defect was found;
- **G-P matrix normalization:** the three duplicate `gp12` identifiers
  became the distinct G-P14 (malformed persisted facts fail closed), G-P15
  (partial coordinate pair fails closed), and G-P16 (nonexistent
  Investigation empty); G-P12 remains the historical-volume test and
  G-P13 the bounded-single-read test; the test module and this document
  reflect G-P01..G-P16 with G-P01..G-P13 as the core projection/
  bounded-read cases and G-P14..G-P16 as the defensive cases;
- **G-M matrix normalization:** the duplicate `gm10` identifiers became
  the distinct G-M11 (invalid precision vocabulary) and G-M12 (invalid
  country code); the test module and this document reflect G-M01..G-M12;
- **Seeder unit matrix normalization:** the duplicate `cs04` identifier
  became the distinct C-S13 (CLI exits nonzero when the guard is not
  satisfied); the test module and this document reflect C-S01..C-S13;
- **G-P13 disposition:** existing test support for SQL statement counting
  was explicitly inspected (see above); no reusable lightweight mechanism
  exists, so structural verification is retained and documented at the
  test, and no generic instrumentation framework was added;
- **B/C/SG/E traceability audit:** B-M/B-L/B-V/B-Q/B-U/B-F/B-P/B-A11Y,
  C-P/C-V, SG01..SG07, and E24-E28 carry no duplicate or misleading
  identifiers (the E22/E22-B Chromium/MUI wedge remains separately
  classified per `docs/INVESTIGATION_STABILITY.md`);
- **E24-E28 rerun** on the canonical full stack with all four real-stack
  browser specs passing through the real PR 25A read path;
- **No production/API/schema/persistence change:** the PR 25A endpoint,
  operation ID, DTO, paired coordinates, provider/precision/timestamps,
  `{items,truncated}` shape and authentication, PR 25B Map route/Leaflet
  behavior, 30s stale time, viewport policy and disclaimer, PR 25C typed
  pivot behavior, and the deterministic seeder implementation are
  unchanged.

PR 25A-D are closed; no known PR 25 functional residual remains, and PR 26
remains the next v0.1 feature phase.

### Relationship Evolution and graph (PR 24E)

Backend test coverage for the entity-centric observation query:

- **query contracts** (`tests/unit/app/query/test_query_contracts.py`):
  `direction`/`counterparty_entity_id` without `entity_id` fail closed;
  a bare `entity_id` has the documented `either` behavior; fingerprints
  include entity/direction/type/counterparty (entity-only and
  explicit-`either` share one cursor context; different entities,
  directions, types and counterparts never share one);
- **route contracts** (`tests/unit/api/test_relationship_evolution_routes.py`):
  valid entity UUIDs, direction/counterparty/type filters map exactly to
  the query DTO; malformed UUIDs, unknown direction values and unknown
  relationship types fail with the stable 422 envelope; `direction` and
  `counterparty_entity_id` without `entity_id` fail with 400
  `invalid_request`; the public observation DTO exposes the joined
  relationship fields without leaking operational columns; the one-hop
  Relationships `entity_id` filter maps to the DTO;
- **real PostgreSQL integration**
  (`tests/integration/test_query_relationship_evolution.py`): the PR 24E
  E-B01..E-B16 matrix over a synthetic world (focal A, counterparties
  B/C, reverse edge, unrelated D->E, multiple providers, distinct
  observed/retrieved times, a null-observed row, another Investigation
  re-observing the same edge): entity/direction/counterparty/type/provider/
  observed-range intersection, wrong-Investigation isolation, no
  self-relationship duplication, canonical `retrieved_at DESC, id ASC`
  ordering, bounded one-row cursor pagination, and cursor/filter mismatch
  (across focal entity, direction, type, and collection kind) failing
  closed;
- **plan eligibility** (`tests/integration/test_query_indexes.py` P12):
  the entity-joined observation query shape uses the existing
  `relationship_observation_investigation_retrieved_idx` — no structural
  migration was required, so none was added;
- the OpenAPI snapshot fixture is regenerated after the contract change
  (governed by `tests/unit/api/test_openapi.py`).

Frontend coverage (`frontend/src/relationship-evolution/`,
`frontend/src/relationship-graph/`):

- pure derived model (`relationship-evolution-model.test.ts`, E-D01..E-D09):
  outbound/inbound/self lanes, null-observed rows in the explicit
  unavailable group, stable ID tie-breaks, retrieved-time independence,
  repeated observations as distinct points, type-separated lanes, and
  page-scoped annotations that never claim global first-observed;
- Evolution workspace (`relationship-evolution.test.tsx`, E-U01..E-U18 via
  central MSW handlers): no request without an entity, bounded
  entity/direction page, direction/type/counterparty/provider/observed-range
  filters reaching exact server params with cursor reset, points rendered
  from `observed_at` with `retrieved_at` as distinct tooltip metadata,
  explicit null-observed state, bounded-page notice + Next/Previous,
  activation opening the observation detail with Evidence provenance,
  honest no-results wording, running-Investigation notice, error Retry
  preserving context, keyboard-accessible points, and the tabular
  alternative;
- graph (`relationship-graph-model.test.ts` + `relationship-graph.test.tsx`,
  E-G01..E-G11): focal node identity, deduplicated counterparties,
  self-edge purity, distinct multi-type edges, compact labels without
  entity N+1, deterministic radial layout, honest bounded-neighborhood
  notice, empty state, and the always-available edge-list navigation
  (relationship + evolution routes carrying exact IDs); the jsdom test
  environment stubs `ResizeObserver` for `@xyflow/react` (documented in
  `src/test/setup.ts`); no pixel/layout snapshots are asserted;
- real-stack E23 (`frontend/e2e/zz-relationship-evolution.spec.ts`):
  completed F03 fake-world Investigation (`logistics-corp.test`),
  Relationships -> source entity -> Relationship Evolution, temporal
  points driven by `observed_at` with distinct `retrieved_at` tooltips,
  `Earliest shown on this page`, observation activation -> exact
  observation detail, observation -> Evidence exact navigation through
  the PR 24D pivot workspace, switch to Graph -> accessible relationship
  list -> exact Relationship table context, route refresh preserving
  Evolution filters/entity, browser Back/Forward preserving focal entity
  identity, `FAKE DATA` visible, clean console;
- PR 24E adds no speculative second graph/visualization dependency and
  no new fake-world fixture: the F03 world's repeated observed-at stamps
  drive the browser slice.

## PR 26 GEOINT testing strategy

PR 26 testing must preserve the production-path principle: deterministic tests fake true external/non-deterministic boundaries, not ATI's persistence, canonicalization, PostGIS, resolver state machine, or query contracts.

### PR 26A delivered testing (G26A-D and G26A-P matrices)

PR 26A's non-spatial foundation is covered by:

- **G26A-D01..D14** (`tests/unit/domain/test_geoint.py`): exact
  `LocationType`/`LocationPrecision`/`GeoResolutionStatus` vocabularies;
  country/administrative-area/city type-shape constraints; deterministic
  two-letter country-code normalization without reference data; blank/
  oversized names and codes fail closed; EntityLocation inverted-time
  rejection; naive/offset observation timestamp normalization; mandatory
  exact Entity/Location/Evidence observation IDs; initial pending
  GeoResolution validity; malformed status/error/claim metadata fail
  closed; bounded PostGIS-compatible EWKT text on Location (added by PR 26B);
  `EntityType` unchanged (Location is
  not an Entity); deterministic identity tuple excluding parent.
- **G26A-P01..P34** (`tests/integration/test_geoint_persistence.py`): the
  canonical real-PostgreSQL matrix — Location round-trip, parent/admin
  shape enforcement, canonical-identity reuse without version churn,
  concurrent same-identity upsert yielding one row, incompatible duplicate
  state failing atomically, database-side shape rejection; first observation creating EntityLocation
  atomically, exact provenance storage, GEOLOCATION Evidence requirement,
  Evidence subject mismatch rejection, missing Entity/Location/Evidence
  rejection, duplicate observation rejection without current-state
  mutation, later-observation advancement, older-observation non-rewind,
  equal-timestamp UUID tie-break, earliest first-observed preservation,
  deterministic latest association, zero `domain_object_history` rows for
  observations, rollback atomicity, no public EntityLocation mutation
  path; initial pending GeoResolution creation with exact state, duplicate
  pair idempotency, concurrent duplicate creation yielding one row,
  non-GEOLOCATION and subject-mismatch rejection, missing/invisible
  Entity/Evidence rejection, no second queue table; normal UnitOfWork
  participation, exception rollback, no independent repository commits,
  and authoritative database-assigned versions. (PR 26C supersedes the
  historical "no claim/lease/completion API" assertion: the lifecycle API
  now lives on this same repository and is asserted complete in
  G26A-P29/P42/P43.)

#### PR 26A-2 corrective matrix (G26A2-P01..P05 + corrected G26A-P34)

PR 26A-2 (`tests/integration/test_geoint_persistence.py`, plus the narrow
source-contract guard in `tests/unit/test_geoint_version_contract.py`)
proves `EntityLocation.version` is consistently database-sequence allocated
from `ati.entity_location_version_seq` — never arithmetic `target.version + 1`
— with gaps valid:

- **G26A2-P01** initial version is the exact next value the sequence issues
  (no assumption that the sequence starts at 1);
- **G26A2-P02** the forced-gap provenance regression: deliberately advances
  the sequence with a direct test-only `nextval`, appends a later
  observation, and asserts the persisted version is strictly beyond the
  forced gap — so it cannot be `before + 1`. This is the primary regression
  test and failed on pre-fix main for exactly that reason;
- **G26A2-P03** earliest-time-only mutation (older observation extending
  `first_observed_at`) moves earliest time earlier while leaving
  Location/precision/latest observation/`last_observed_at` untouched and
  receives a new sequence-issued token;
- **G26A2-P04** a true historical no-op (observation inside the current
  window) persists as history while current fields and the persisted version
  stay exactly unchanged — without asserting the sequence itself was not
  consumed;
- **G26A2-P05** a current-state-changing append that is rolled back leaves
  the pre-transaction EntityLocation state/version intact in a new UoW;
- **G26A-P34 (corrected)** no longer asserts `current.version == before + 1`;
  it asserts `current.version > before` (monotonic, non-contiguous). The
  unit guard pins the newest shipped GEOINT SQL API to sequence allocation
  and forbids an arithmetic `target.version + 1` reassignment in the active
  function.
- **Migration tests** (`tests/integration/test_migration.py`) traverse SQL
  API v0022/migration 0026 in both directions: existing EntityLocation
  versions are database-owned historical tokens and are never rewritten.
- **Migration tests** (`tests/integration/test_migration.py`): the 0025
  upgrade installs the four tables, four version sequences, and three
  stored functions; the downgrade removes only the PR 26A objects in
  dependency-safe order while existing Entity/Evidence (including PR 25
  GEOLOCATION Evidence) rows survive untouched. PR 26B supersedes the
  26A-era ``no PostGIS`` assertion: PostGIS is now installed by migration
  0027 and is asserted present at head (and removed on downgrade).

#### PR 26B delivered testing (G26B-D/P/I/R matrices)

PR 26B's deterministic geographic substrate is covered by real PostgreSQL
**+ PostGIS** tests (PostGIS is never mocked):

- **G26B-D01..D14** (`tests/unit/domain/test_geo_reference.py`,
  `tests/unit/app/geoint/test_geo_canonicalization.py`,
  `tests/unit/app/geoint/test_resolution.py`): reference record
  country/admin/city contracts; deterministic UUIDv5 canonical identity
  independent of external source record IDs; identity unchanged by
  geometry changes; claim lat/lon pairing, finite/range validation,
  precision cannot exceed semantic claim support, coordinates never
  upgrade precision; resolution result discriminators/invariants
  (resolved exactly one, ambiguous requires candidates, unresolvable
  carries a reason); deterministic name normalization (NFC/whitespace/
  case-preserving); EWKT canonicalization (SRID 4326 prefix, type rules,
  WGS84 bounds, malformed coordinate rejection); fail-closed hierarchy
  rules.
- **G26B-I01..I12** (`tests/integration/test_geoint_reference_spatial.py`
  plus unit-level ingestion tests in `tests/unit/app/geoint/`):
  parent-before-child country -> admin -> city import; repeated identical
  import is a true no-op; deterministic UUIDv5 ids identical across clean
  databases; a pre-existing PR 26A Location is enriched (same row id, new
  sequence version) rather than duplicated; geometry refresh allocates a
  new version; a repeated refresh is a no-op; incompatible hierarchy and
  malformed source geometry fail closed with no partial state;
  transaction rollback never leaves a partial child hierarchy; aliases
  collapse onto one canonical row; input order never changes canonical
  state; concurrent identical reference upserts converge on one row.
- **G26B-P01..P18** (`tests/integration/test_geoint_reference_spatial.py`
  + migration tests): PostGIS extension availability; pgvector + PostGIS
  coexistence; `ati.location.geometry`/`centroid` are SRID-4326
  `geometry` (never `geography`); country polygon/admin polygon/city
  point persistence round-trips; derived on-surface representative point
  (`ST_PointOnSurface`, documented — never `ST_Centroid`); invalid SRID,
  empty geometry, invalid polygon, city polygon, country/admin point,
  and out-of-WGS84-bounds inputs rejected fail-closed; NULL spatial state
  remains valid; the justified GiST index exists and the concrete
  containment query is proven spatial-index eligible with EXPLAIN;
  pre-26B Location rows migrate with NULL spatial fields; migration
  downgrade restores the pre-26B schema without data loss and without
  CASCADE collateral; pgvector/RAG schema survives upgrade + downgrade.
- **G26B-R01..R18** (`tests/integration/test_geoint_reference_spatial.py`):
  country code resolves the country; country + admin code/name resolves
  the administrative area; country + admin + city resolves the city;
  coordinates never upgrade precision (country-only stays country,
  admin-only stays admin even inside a city); coordinates only
  validate/disambiguate duplicate city names (containment
  disambiguation); unknown country/admin/city are unresolvable outcomes;
  duplicate city names without a discriminator are ambiguous; a semantic
  admin discriminator resolves deterministically; containment is
  boundary-inclusive (`ST_Covers`) and competing boundary coverage is
  ambiguous; coordinate-less semantic claims resolve normally; no
  nearest-city inference; candidate ordering is deterministic; hierarchy
  and spatial containment can disagree without rewriting either;
  resolution performs no mutation and never touches `GeoResolution` (the
  resolver boundary holds in PR 26C: mutations belong to the lifecycle SQL
  API, never the canonical resolver).

### PR 26B-2 delivered testing (G26B2-CLI/SRC/BLD/E2E matrices)

PR 26B-2 (corrective completion) proves the upstream reference-data supply
path: source adapters -> deterministic corpus builder -> installed CLI ->
existing importer -> PostgreSQL/PostGIS.

- **G26B2-CLI01..05** (`tests/unit/infrastructure/test_cli_entrypoints.py`):
  `ati-geography-import` and `ati-geography-build` exist in the installed
  package metadata and resolve to `geography_import_main`/
  `geography_build_main`; both `--help` exits succeed offline with no
  database or network access; the builder refuses mutually exclusive
  output modes fail-closed.
- **G26B2-SRC01..07** (`tests/unit/infrastructure/test_geonames_source.py`):
  the supported GeoNames files parse deterministically (countryInfo.txt,
  admin1CodesASCII.txt, cities-file schema); malformed/non-finite/
out-of-bounds coordinates fail closed; malformed admin/country references
  fail closed; Unicode/diacritics parse and stay NFC-normalizable;
  unsupported record shapes (wrong column counts) can never silently
  become a Location.
- **G26B2-SRC08..12** (`tests/unit/infrastructure/test_natural_earth_source.py`):
  country Polygon and MultiPolygon and admin Polygon parse to canonical
  SRID-4326 EWKT; invalid/non-polygonal/empty/unclosed geometry is
  rejected; country identifiers normalize deterministically (`iso_a2` with
  `iso_a2_eh`/`iso_a2_wb` fallbacks; unusable codes stay `None`).
- **G26B2-BLD01..14** (`tests/unit/infrastructure/test_geography_corpus_builder.py`):
  countries join by stable ISO code; admins join deterministically within
  country; the reviewed `ADMIN1_CODE_EXCEPTIONS` mapping resolves a known
  fixture mismatch; ambiguous admin matches are reported, never guessed;
  unmatched Natural Earth objects cannot create canonical records; a
  GeoNames record without a polygon emits null geometry; parent-before-
  child output ordering; byte-identical output for identical inputs;
  input ordering never changes output; no timestamps/random values;
  output conforms exactly to the PR 26B corpus schema (production parser
  round-trip); city coordinates never become polygons; orphan cities are
  rejected and reported; geometry stays WGS84/SRID-4326; explicit
  `--min-population`/`--countries` filters; invalid options and duplicate
  source codes fail closed.
- **G26B2-E2E** (`tests/integration/test_geography_build_import.py`): real
  PostgreSQL + PostGIS end-to-end proof: real-format fixtures ->
  `ati-geography-build` -> corpus NDJSON -> production corpus parser ->
  `ReferenceIngestionService` -> `ati.location`; United States -> Washington
  -> Seattle is created with deterministic canonical UUIDv5 identities,
  correct parent hierarchy, country MultiPolygon / admin Polygon / city
  point, correct PostGIS SRID (4326) and geometry types, and a second
  import is a true no-op with no version churn. The actual installed
  `ati-geography-import` console script is executed in a subprocess against
  the isolated database (first import creates the corpus atomically, second
  import has no version churn), and a malformed artifact exits non-zero
  committing nothing.

### Domain and persistence

Cover:

- Location type/hierarchy invariants;
- precision preservation/no invented precision;
- immutable EntityLocationObservation;
- explicit historical `entity_id` + `location_id` + Evidence provenance;
- current EntityLocation reconciliation;
- GeoResolution lifecycle/version invariants;
- rollback atomicity and idempotency.

### PostgreSQL/PostGIS

Real-PostgreSQL + PostGIS integration tests cover (PR 26B delivered):

- PostGIS availability through the normal migration path (project-owned
  PostgreSQL 18 image ships both pgvector and PostGIS);
- pgvector + PostGIS coexistence (HNSW/RAG suites stay green);
- spatial Location schema (SRID 4326, type/validity/emptiness/bounds
  rejection, round-trips, NULL spatial state);
- canonical reference ingestion (idempotency, enrichment/version
  semantics, concurrency, rollback atomicity);
- canonical Location claim resolution (exact/code/name matching,
  boundary-inclusive containment disambiguation, explicit
  resolved/ambiguous/unresolvable outcomes);
- hierarchy versus spatial containment;
- justified spatial-index eligibility via EXPLAIN;
- migration upgrade/downgrade with data preservation;
- Investigation isolation remains covered by PR 26D analyst query tests.

### Analyst read/API layer (PR 26D)

- **G26D-Q01..Q10** (`tests/unit/app/query/test_geoint_query.py`): typed
  frozen query contracts carry the mandatory Investigation scope, page
  limits reuse the PR 23A `QueryLimits` bound, the containment flag stays a
  required bounded boolean, Location references expose coordinates only
  (no raw geometry/EWKT/WKB field exists), observation read models retain
  the exact `observation_id`/`evidence_id`, Entity current is explicitly
  Investigation-relative (no global `EntityLocation` state fields), the
  summary is bounded with consistent counts, and malformed persisted rows
  fail the pure persisted-row mappers closed with `GeointReadError`.
  Cursor codec tests pin the PR 26A currentness ordering
  (`COALESCE(observed_at, retrieved_at)` + observation UUID, greater pair
  wins) and the deterministic Location-Entity ordering, and cursor
  fingerprints bind investigation/Entity/Location/containment scope.
- **G26D-A01..A16** (`tests/unit/api/test_geoint.py`): 401
  unauthenticated; shared `require_analyst` 403 gate; typed 200s
  (summary, Entity detail, entity history `PageResponse`, Location-Entity
  and Location-observation typed pages with the `containment_applied`
  flag mapped exactly); 404 `geoint_entity_not_found` /
  `geoint_observation_not_found` for cross-scope detail without resource
  disclosure; stable `invalid_cursor` 400; bounded cursor length 422;
  oversized limits forwarded to the shared bound; PR 25 `/geolocations`
  unchanged; malformed persisted reads surface a safe `internal_error` 500
  with no internals. Six explicit stable operation ids are pinned in the
  OpenAPI snapshot.
- **G26D-P01..P32** (`tests/integration/test_geoint_query.py`): real
  PostgreSQL 18 + PostGIS matrices seeded with two Investigations sharing
  Entities/Locations backed by different Evidence. Scope: observations
  visible only under their Evidence's Investigation, shared Entities see
  only own history, a newer I2 observation never advances I1 current,
  Locations unused in scope are empty collections, cross-scope
  observation detail is not found. Current/history: the exact PR 26A
  ordering and UUID tie-break, `observed_at=NULL` -> `retrieved_at`
  semantics, global-vs-scoped latest divergence. Location/pagination:
  distinct scoped Entities once, every qualifying observation, static-set
  paging with no gaps/duplicates, exact second-page continuation, terminal
  cursor NULL. Containment (US/WA/Seattle, TX/Dallas, CA/BC/Vancouver):
  WA exact vs contained, US contained scope, US excludes Canada,
  boundary-point inclusion via `ST_Covers`, NULL selected geometry
  degrades to exact with `containment_applied=false`, city Point never
  expands, and reads never mutate hierarchy/Relationship rows. Summary:
  zero/empty, exact observation/distinct-Entity counts, precision
  vocabulary counts, deterministic top-group tie-breaks, bounded
  truncation. Plus EXPLAIN-based index-eligibility proof (entity history
  uses the PR 26A entity index; scope joins, Location reverse lookups,
  latest-per-Entity, and containment use the PR 26D read indexes and the
  GiST index, never scanning `entity_location_observation`) and the
  canonical vertical slice: production PR 26C resolution -> real
  `PostgresGeointQueryService` -> real FastAPI -> exact Evidence drill-down
  via the existing Evidence endpoint, cross-scope 404, deterministic
  pagination, and reads mutate nothing.
- **G26D-P33/P34** (`tests/integration/test_migration.py`): migration
  0029 round-trip installs exactly the two read indexes without touching
  rows and downgrade drops only them.

Every GEOINT integration case runs in the standard isolated PostgreSQL
fixture (`reset_application_data` truncates the GEOINT tables between
tests); the API slices reuse `tests/integration/api_helpers.py` with a
real seeded local analyst user.

### Analyst GEOINT workspace (PR 26E)

- **G26E-Q01..Q08** (`frontend/src/geoint/geoint-queries.test.tsx`): the
  six PR 26D operations use the exact paths; the Entity query is keyed by
  Investigation + Entity; the opaque history cursor is forwarded
  unchanged; exact Location sends no `include_contained` while contained
  sends `true`; the observation detail uses the exact scoped path;
  AbortSignal flows through the centralized client; and no polling exists
  (single fetch, typed `ApiError` on failure).
- **G26E-M01..M08** (`frontend/src/geoint/geoint-model.test.ts`): a valid
  centroid is plottable; null and malformed/out-of-range coordinates are
  never plotted but remain table-visible; no clamping or (0,0) recovery;
  Location-type and precision labels cover the exact PR 26D vocabulary;
  current is Investigation-relative; history never encodes ended/
  continuous inference; and same-coordinate items retain distinct stable
  identities.
- **G26E-U01..U28** (`frontend/src/geoint/GeointPage.test.tsx`,
  `EntityGeointView.test.tsx`, `LocationViews.test.tsx`): empty state
  renders no map; truncated summary is visible; top-Location typed Explore
  works; the GEOINT tab is first-class and active; safe API error with
  Retry; deterministic one-point/multi-point viewports; mixed
  mappable/non-mappable sets; neutral markers; popup precision/provenance;
  same-coordinate items individually actionable; no risk styling;
  attribution present; current section says "Current in this
  Investigation"; history follows server order; three timestamps stay
  distinct; Evidence uses the exact returned id; opaque next-cursor;
  no movement path; exact Location default; containment toggle triggers a
  semantic filter change (resets cursor); `containment_applied` and
  exact-only explanations are visible; the same-location disclaimer is
  visible; coordinate-less rows stay actionable; observation detail shows
  exact semantics; scoped 404 is safe; unknown resolution methods render
  the raw bounded string (provider never fabricated).
- **G26E-PV01..PV18** (`frontend/src/pivots/pivot-capabilities.test.ts`,
  `pivot-url.test.ts`, `geoint-pivots.test.tsx`): Entity -> GEOINT,
  GEOINT -> Location, Location -> Entities/observations, observation ->
  exact Evidence, existing Entity exploration reuse, no generic `geoint`
  target, one modal with active-step-only mounting, no API prefetch while
  a menu is open, bounded breadcrumbs, old PR 24 URLs still decode, and
  no geometry/response/viewport payload in the pivot envelope (containment
  round-trips as the exact boolean only).
- **G26E-S01..S06** (`tests/unit/infrastructure/test_e2e_geoint_seed.py`):
  the harness-only seed scenarios are allowlisted and bounded, identity
  derivation is deterministic, fixture facts use the exact PR 26C claim
  vocabulary, cross-Investigation scoping and the other-Investigation
  guard fail closed, and the E2E environment guard requires both fake
  mode and `ATI_E2E_SEEDING_ENABLED`.
- **G26E-P01..P06** (`tests/integration/test_e2e_geoint_seed.py`): the
  real-stack seeding path (reference-geography build/import -> normal
  GEOLOCATION Evidence -> GeoResolution -> production worker with the
  real PostGIS resolver -> canonical Location / EntityLocationObservation)
  proves Entity history current/order, same-Location distinctness,
  exact-vs-contained expansion, non-mappable NULL coordinates, and
  cross-Investigation isolation (I2 observation never visible to I1),
  and a second seeding run is idempotent. No table is ever inserted
  directly.
- **G26E-E1..E6** (`frontend/e2e/zz-geoint.spec.ts`): deterministic
  real-stack Chromium workflows (`geoint_entity_history`,
  `geoint_same_location`, `geoint_containment`, `geoint_cross_investigation`,
  `geoint_non_mappable`, and the GEOINT row -> Location -> Entity ->
  Evidence -> Back -> Close stability regression) driven entirely through
  the real PR 26 pipeline seeded by `scripts/e2e-seed-geoint.sh` against
  reference geography imported by `scripts/e2e-geography-import.sh`; the
  browser only observes clean console output.

### Bounded agentic GEOINT reasoning (PR 26F)

PR 26F keeps `FakeLlmClient` strictly at the model boundary: the canonical
integration slice drives the real Evidence Analyst over production
PostgreSQL 18 + PostGIS, the real PR 26D `PostgresGeointQueryService`, the
real GeoResolution path, and the existing Assessment persistence.

- **G26F-T01..T10** (`tests/unit/app/geoint/test_analysis_tools.py`): the
  `GeointAnalysisTools` facade delegates the exact Investigation-scoped
  summary/Entity/history/Location/observation queries; history returns one
  bounded page only and `has_more` without a second query or cursor
  exposure; containment flags report exact vs applied honestly; requested
  page sizes over the bound are clamped before execution; cancellation
  propagates; and the facade has no SQL/PostGIS import or mutation
  surface.
- **G26F-C01..C10** (`tests/unit/app/geoint/test_analysis_context.py`):
  the deterministic context policy returns an empty context with no
  GEOINT data, enriches eligible Entities from the authoritative analyst
  input only (never fanning out to unrelated Investigation Entities),
  keeps stable input ordering (roots, then Evidence subjects, then
  RelationshipObservation endpoints), fails closed on entity/observation/
  byte bounds with typed `GeointAnalysisInputBoundsError`, never drains
  pages, preserves `summary_truncated` and `has_more_history` explicitly,
  and fails closed when an observation's Evidence is outside the supplied
  analyst input.
- **G26F-S01..S08** (`tests/unit/domain/test_analyst_geoint_contract.py`):
  the frozen model-visible context DTOs validate, reject extra fields/
  malformed UUIDs, serialize to stable JSON without representative
  coordinates, and the geographic output contract rejects unsupported
  (inferential) kinds, empty/duplicate support, and collections over the
  hard ceiling.
- **G26F-V01..V12 / G26F-G01..G08**
  (`tests/unit/app/test_geoint_finding_validator.py`): deterministic
  validation accepts only exact supplied observation/Evidence pairs and
  rejects unknown observations, substituted Evidence, wrong Entity/
  Location sets, cross-Entity history, same-Location "change", equal-
  effective-time "change", and containment claims without an established
  containment selection. The closed kind vocabulary makes
  coordination/common-ownership/campaign/movement claims structurally
  impossible; the independent-support gate rejects geography-only
  positive verdicts; independent evidence plus descriptive GEOINT
  persists; and a missing `observed_at` never invents an observed time.
- **Evidence Analyst execution tests**
  (`tests/unit/app/test_evidence_analyst_geoint.py`, plus the extended
  PR 20B world in `tests/unit/app/test_evidence_analyst.py`): GEOINT
  context flows into one normal accounted model call; valid geographic
  findings are validated then persist as `GEOLOCATION` Findings with
  exact Evidence support; invalid/substituted/cross-scope references and
  context-bound failures reserve zero or leave no pointer, exactly like
  the existing fail-closed conventions; the one-repair ceiling,
  cancellation accounting, and persistence-failure isolation are
  unchanged.
- **Canonical real-PostgreSQL vertical slice**
  (`tests/integration/test_evidence_analyst_geoint.py`, G26F-I01..I07):
  descriptive current geography persists with exact Evidence support;
  same-Entity location history allows descriptive
  `location_change_observed`; same-city unrelated Entities cannot drive a
  positive verdict (no Relationship, no Assessment row); cross-
  Investigation observation IDs stay invisible and are rejected; bounded
  history never lets the model cite omitted observations
  (`has_more_history: true` is explicit); independently supported
  MALICIOUS may carry descriptive GEOINT context; and the no-GEOINT case
  keeps baseline behavior with exactly one LLM call.

### Asynchronous resolution

Multi-worker integration tests cover:

- bounded atomic claims;
- `SKIP LOCKED` workers claiming disjoint eligible work;
- claim transaction committed before resolution;
- no long-running DB transaction during resolution;
- leases and expiry;
- stale-claim recovery;
- attempt/retry semantics;
- crash between claim and completion;
- duplicate/idempotent completion;
- stale version/ownership rejection;
- deterministic update ordering for contended completion;
- bounded batch behavior.

### Canonical GEOINT fixtures

Fixtures should include at minimum:

- country-only claim;
- administrative-area claim;
- city claim;
- coordinates with supported precision;
- coordinate-less valid context;
- ambiguous/unresolvable claim;
- one Entity observed at different Locations over time;
- multiple unrelated Entities at the same Location;
- same/similar coordinates without cyber relationship;
- cross-Investigation identity/isolation cases.

### Fake runtime

The fake runtime must not seed derived geographic truth directly.

The desired test/demo flow is:

```text
deterministic fake geographic input
 -> normal persisted Evidence/claim
 -> GeoResolution
 -> real resolver state machine
 -> real PostgreSQL/PostGIS canonicalization
 -> EntityLocationObservation
 -> EntityLocation
```

This is distinct from the PR 25C E2E seeder, which is a guarded harness-only mechanism for exact browser-created Investigation IDs. PR 26 may extend/create test harness support where necessary, but the canonical PR 26 vertical slice must exercise the production geographic pipeline.

### API/frontend

Real-stack coverage should prove:

- bounded Investigation-scoped geographic queries;
- current/history distinction;
- exact observation -> Evidence provenance;
- Location -> scoped Entities and Entity -> Locations navigation;
- map/table accessibility;
- same-location entities independently inspectable;
- no unbounded browser reconstruction;
- exact typed pivot identity and breadcrumbs;
- approximation/precision semantics retained.

### Agentic GEOINT

`FakeLlmClient` remains the deterministic model boundary. GEOINT tools beneath it execute against real PostgreSQL/PostGIS in canonical integration/evaluation slices.

Tests must prove that agent output cannot silently promote:

- proximity;
- same city/country;
- same coordinates;
- spatial containment

into maliciousness, cyber relationship, common ownership, campaign, coordination, targeting, or attribution without independent support.

### PR 26G delivered testing (G26G evaluation baseline)

PR 26G (`src/agentic_threat_investigator/evaluation/geoint/`,
`evals/scenarios/geoint/`, `tests/unit/evaluation/geoint/`,
`tests/integration/test_geoint_evaluation.py`) closes the PR 26 series
with a deterministic evaluation/closure baseline over the delivered
PR 26A--F runtime. No GEOINT runtime capability is added and no
production migration/stored-function change is required.

- **G26G-CC01..CC07** (`tests/unit/evaluation/geoint/test_geoint_evaluator.py`):
  the pure evaluator's canonical passing path and exact metrics
  (claim/support counts, provenance closure, tool calls, context
  entity/observation counts).
- **G26G-S01..S16** (`evals/scenarios/geoint/`): the committed canonical
  corpus — country-only, administrative-only, and city precision
  retention (no invented precision, no representative coordinates in
  model context); changing Location with correct current/history and no
  movement; same-Location and same-coordinate unrelated Entities with no
  Relationship/ownership/coordination; coordinate-less valid geography;
  ambiguous and unresolvable claims with no invented truth; retry,
  stale-lease, and crash recovery with exactly one final truth;
  cross-Investigation isolation; valid descriptive pattern with exact
  support; model overstatement of co-location rejected; independent
  non-geographic support plus descriptive GEOINT.
- **G26G-E01..E16** (evaluation matrix): wrong/missing canonical
  Location, precision inflation, duplicate truth after retry, broken
  provenance, cross-Investigation visibility, unsupported agent
  inference, bound exceeded, unexpected validation outcome, and
  geography-only verdicts are all hard failures; a Location without an
  observation is never support.
- **G26G-P01..P06** (provenance matrix): exact observation/Evidence
  closure, wrong Evidence, wrong Investigation, reference-Location-only
  support, omitted-context citations, and persisted Assessment support
  closing over exact Evidence — all evaluated at the structured boundary
  without claiming the Assessment schema stores observation identities.
- **G26G-T01..T10** (tool/bounds): evaluated via an evaluation-only
  recording wrapper (`evaluation/geoint/tracing.py`) around the real
  query service plus the unit fake: eligible Entity bounded queries only,
  no unrelated Entity fan-out, one history page with `has_more` surfacing,
  no cursor draining, entity/observation/byte bounds respected, no
  Location fan-out, no automatic containment expansion, no proximity,
  and arbitrary spatial queries impossible.
- **G26G-A01..A14** (structured agent-output matrix): valid current
  geography, valid history, supported location change, omitted/substituted
  observations and Evidence, cross-Investigation support, same-city
  coordination attempts, same-coordinate ownership attempts, containment
  targeting attempts, geography-only MALICIOUS attempts, two-Location
  travel attempts, independent support plus descriptive GEOINT, country
  described as city, and the no-GEOINT baseline.
- **G26G-R01..R05** (recovery closure): concurrent disjoint claims,
  stale-lease takeover with stale-worker rejection, crash-after-claim
  reclaim, retry-then-success, and duplicate/stale completion — the
  existing PR 26C lifecycle/vertical-slice coverage plus the combined
  exactly-one-final-truth assertions over the worker-completed state in
  `test_geoint_evaluation.py::test_recovery_scenarios_produce_exactly_one_final_truth`.
- **G26G-QP01..QP06** (query plans): the existing PR 26D EXPLAIN
  infra now also covers the bounded summary (`test_explain_summary_stays_bounded_and_index_eligible`);
  representative statements assert intended index eligibility and the
  absence of accidental Cartesian joins — never exact costs/timings.
- **G26G-X01** (`tests/integration/test_geoint_evaluation.py`): the
  canonical real-stack closure — reference geography via the normal
  reference API, Investigation + GEOLOCATION Evidence + PENDING work,
  production `GeoResolutionWorker` + `PostgresCanonicalGeographyResolver`
  completion, real `PostgresGeointQueryService` through the recording
  wrapper, `GeointAnalysisTools`/`GeointAnalysisContextPolicy`, real
  `EvidenceAnalystInputLoader`, `FakeLlmClient` at the model boundary
  only, deterministic geographic validation, real
  `AssessmentPersistenceService`, persisted Assessment read back, and
  `GeointDeterministicEvaluator` — with the browser and analyst segments
  sharing the same deterministic persisted scenario (browser coverage
  remains `frontend/e2e/zz-geoint.spec.ts` G1..G6).

No canonical closure fixture directly inserts derived geographic truth
(`EntityLocationObservation`/`EntityLocation` are created only by the
production worker completion), `FakeLlmClient` is the only model fake, no
live network/geocoder/LLM is required, and no PR 27 generic
evaluator/release framework is introduced.

## Definition of done

A change is not complete until:

1. required quality commands pass;
2. relevant tests exist and pass;
3. database migrations/integration tests pass where applicable;
4. strict typing is preserved;
5. behavioral evaluation expectations are updated when agent semantics intentionally change;
6. authoritative documentation is updated for deliberate contract changes;
7. new/changed agent operations have typed structured-output tests;
8. new/changed human-readable analytical output has deterministic formatter
   tests and does not depend on an LLM for presentation.

## Configuration tests

Configuration tests must cover default/profile selection, shallow override semantics, invalid and missing profiles, malformed modules, non-mutation of input dictionaries, deterministic logging, and recursive sensitive-value redaction. Tests inject an environment mapping rather than mutating global process environment where practical. See `CONFIGURATION.md`.

## Batch persistence and history tests

Integration tests against pinned PostgreSQL 18 must exercise composite-array input, `unnest` staging with ordinality, temporary-table reconciliation, INSERT/UPDATE/UNCHANGED/CONFLICT outcomes, optimistic version conflict detection, set-based version allocation/history insertion, and large batches up to the configured application boundary. Tests must prove UNCHANGED rows receive no new version/history. JSONB diff tests cover scalar changes, additions/removals, missing versus JSON null, nested objects as atomic top-level values, excluded metadata fields, and empty diffs. No SQLite substitute is acceptable for these behaviors.

#### PR 26C delivered testing (G26C-D/W/B/P + vertical slices)

PR 26C (`tests/unit/app/geoint/test_geo_claim_extraction.py`,
`tests/unit/domain/test_geoint_observation_identity.py`,
`tests/unit/app/geoint/test_geo_retry_policy.py`,
`tests/unit/app/geoint/test_geo_resolution_worker.py`,
`tests/integration/test_geo_resolution_lifecycle.py`) delivers the
asynchronous geographic-resolution lifecycle on the PR 26A/26B foundation:

- **G26C-D01..D06** (`tests/unit/app/geoint/test_geo_claim_extraction.py`,
  `tests/unit/domain/test_geoint_observation_identity.py`): exact
  GEOLOCATION Evidence -> `GeographicClaim` conversion preserves source
  semantic precision; coordinates never upgrade precision; non-GEOLOCATION
  and malformed payloads fail closed with typed errors; the deterministic
  resolution-produced observation identity is UUIDv5 of the `GeoResolution`
  id under the fixed ATI observation namespace (stable per work, unique
  across work).
- **G26C-B01..B05** (`tests/unit/app/geoint/test_geo_retry_policy.py`):
  deterministic bounded exponential backoff (`base * 2^(attempt-1)` capped at
  the max, no jitter), attempt-1 base, attempt-2 doubling, high-attempt cap,
  invalid config/input rejection.
- **G26C-W01..W11** (`tests/unit/app/geoint/test_geo_resolution_worker.py`):
  worker orchestration with a fake `LocationResolver` only — resolved /
  unresolvable / ambiguity (never guessed) completions; malformed/missing/
  wrong-type Evidence as terminal failures; bounded retryable failure;
  cancellation propagation with no persisted transition; empty batch no-op;
  resolver executes with NO claim UnitOfWork open; every completion opens a
  NEW short UnitOfWork; a rejected failure persistence never terminates the
  iteration (lease expiry recovers).
- **G26C-P01..P12** (`tests/integration/test_geo_resolution_lifecycle.py`):
  eligible PENDING claimed exactly once with claimant/lease/attempt/version;
  future-scheduled PENDING and unexpired PROCESSING never claimed; expired
  PROCESSING reclaimed (attempt N+1); terminal rows never claimed; bounded
  claim limit; deterministic (eligibility, created, id) ordering; two
  concurrent workers claim disjoint batches; each claim increments attempt
  exactly once and allocates a fresh DB version; expired-at-budget work
  becomes FAILED instead of being reclaimed; claim rollback preserves the
  prior durable state.
- **G26C-P13..P18** (stale-claim matrix): correct owner/version/live lease
  accepted; wrong owner, stale version, and expired lease all typed
  conflicts with zero mutation; A expires -> B reclaims -> A's completion
  rejected and B completes (the required stale-worker race on real
  PostgreSQL).
- **G26C-P19..P30** (resolved-completion matrix): one atomic success appends
  the exact observation and reconciles current state; missing/soft-deleted
  Entity, missing Evidence, wrong Evidence type, subject mismatch, and
  missing Location are full rollbacks; the exact replay (deterministic
  observation identity) is a no-op with no duplicate; a conflicting terminal
  replay is typed; existing current-state/first-observed/latest semantics are
  preserved; an injected post-append rollback commits nothing; unknown work
  is not-found; PENDING completion is an invalid transition; a deterministic
  observation identity bound to a different tuple is a duplicate-identity
  conflict.
- **G26C-P31..P38** (failure/unresolvable matrix): unresolvable and
  ambiguity are terminal with no observation/current-state mutation; retry
  schedules PENDING with the bounded backoff and clears the lease; terminal
  errors FAIL with no next attempt; stale failure requests are rejected; a
  rolled-back failure transition keeps PROCESSING.
- **G26C-P39..P43** (migration/index matrix): the claim predicates are proven
  index-eligible by EXPLAIN using the two partial claim indexes (no seq
  scan); pgvector + PostGIS coexist with the v0024 API installed; the
  v0021/v0022/v0023 APIs remain installed and callable; migration
  `tests/integration/test_migration.py::test_geoint_lifecycle_migration_upgrade_and_downgrade`
  proves the 0028 upgrade preserves existing PENDING LOCATION/OBSERVATION/
  resolution rows and allows claiming/completing the pre-existing work, and
  the downgrade removes only the PR 26C functions/indexes/constraints while
  preserving every authoritative row (terminal work included).
- **Vertical slices** (production `GeoResolutionWorker` against real
  PostgreSQL + PostGIS): multi-worker disjoint claims with exactly one
  observation per work item and terminal RESOLVED; crash/recovery (A claims
  and dies, lease expires, B reclaims at attempt N+1 under a new version, A
  is rejected, B completes with exactly one final observation); retry/
  exhaustion with a fake `LocationResolver` only (no early claims, exact
  attempt boundaries, no observations on failures, exactly one observation
  on the eventual success, and terminal FAILED at exhaustion). Timestamp
  control is deterministic SQL, never sleep-based.
