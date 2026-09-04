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
- [Database integration tests](#database-integration-tests)
- [Migration tests](#migration-tests)
- [Test isolation](#test-isolation)
- [Synthetic fixtures](#synthetic-fixtures)
- [Fake implementations](#fake-implementations)
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
- source normalization;
- content hashing;
- authorization decisions;
- soft-delete semantics;
- DTO/domain validation;
- retry classification;
- report/assessment structural validation.

## Provider contract tests

Every provider implementation should cover at least:

- positive response;
- valid empty/negative response;
- malformed response;
- timeout;
- rate limit;
- authentication failure;
- unsupported indicator;
- normalization behavior.

Ordinary CI uses ATI-authored synthetic provider-shaped fixtures.

Optional live-provider contract tests validate external assumptions but do not gate normal deterministic CI.

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
- RAG document/chunk/vector persistence.

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
6. authoritative documentation is updated for deliberate contract changes.

## Configuration tests

Configuration tests must cover default/profile selection, shallow override semantics, invalid and missing profiles, malformed modules, non-mutation of input dictionaries, deterministic logging, and recursive sensitive-value redaction. Tests inject an environment mapping rather than mutating global process environment where practical. See `CONFIGURATION.md`.

## Batch persistence and history tests

Integration tests against pinned PostgreSQL 18 must exercise composite-array input, `unnest` staging with ordinality, temporary-table reconciliation, INSERT/UPDATE/UNCHANGED/CONFLICT outcomes, optimistic version conflict detection, set-based version allocation/history insertion, and large batches up to the configured application boundary. Tests must prove UNCHANGED rows receive no new version/history. JSONB diff tests cover scalar changes, additions/removals, missing versus JSON null, nested objects as atomic top-level values, excluded metadata fields, and empty diffs. No SQLite substitute is acceptable for these behaviors.
