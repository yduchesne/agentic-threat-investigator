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
- Black — formatting.
- isort — import ordering.
- Pylint — linting.
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
uv run black .
uv run pylint ...
uv run mypy ...
uv run pytest
```

Do not maintain parallel hand-edited `requirements.txt` dependency definitions unless an external integration explicitly requires an exported format.

## Formatting

Black is authoritative for Python formatting.

Development:

```bash
uv run black .
```

CI:

```bash
uv run black --check .
```

No competing Python formatter is introduced.

## Imports

isort owns import ordering and is configured to remain compatible with Black.

```toml
[tool.isort]
profile = "black"
```

Commands:

```bash
uv run isort .
uv run isort --check-only .
```

## Linting

Pylint is the Python linter.

CI uses rule-based pass/fail behavior rather than a cosmetic minimum score.

Project-wide exceptions belong in repository configuration when architecturally justified.

Local suppressions are exceptional and should include an explanatory comment when the reason is not obvious.

Avoid accumulating blanket `# pylint: disable=...` directives.

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
- deterministic report/presentation formatting.

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
- Evidence references;
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

**Report Writer behavioral evaluation**

- grounded synthesis;
- correct Evidence/research references;
- no unsupported material claims;
- Assessment verdict/confidence preserved;
- useful structured report content.

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
- Black;
- isort;
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
Black --check
isort --check-only
Pylint
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
- adding broad Pylint suppression;
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
Black --check
isort --check-only
Pylint
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
