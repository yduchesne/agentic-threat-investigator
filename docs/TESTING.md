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

Unit tests should be fast, deterministic, and isolated from network/database dependencies unless the tested unit specifically requires them.

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

The exact frontend toolchain is selected during frontend bootstrap and integrated into the repository-level quality command.

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
