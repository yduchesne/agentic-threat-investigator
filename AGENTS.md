# Agentic Threat Investigator — Coding Agent Instructions

## Table of contents

- [Source of truth](#source-of-truth)
- [Non-negotiable rules](#non-negotiable-rules)
- [Python engineering](#python-engineering)
- [Tests](#tests)
- [Documentation](#documentation)
- [Configuration and batch-persistence invariants](#configuration-and-batch-persistence-invariants)
- [Storage, acquisition, and secrets invariants](#storage-acquisition-and-secrets-invariants)
- [Configuration, artifact-storage, and secrets implementation rules](#configuration-artifact-storage-and-secrets-implementation-rules)

## Source of truth

Before implementing a change, read the relevant authoritative documents under `docs/` and the root project documentation.

Major product/architecture decisions are already defined. Do not replace them with alternate designs without an explicit approved documentation change.

## Non-negotiable rules

- ATI is an open-source threat-investigation product.
- Use `abc.ABC` for architectural provider/repository/client abstractions.
- Domain models remain independent of FastAPI, SQLAlchemy, LangChain, LangGraph, HTTP clients, and persistence implementations.
- Providers retrieve and normalize; they do not persist, assess maliciousness, infer basic relationships, or decide pivots.
- Application services own persistence and invariants through repositories/UnitOfWork.
- LLMs do not directly mutate persistence or receive unrestricted HTTP/SQL/shell/Python tools.
- All autonomous pivots must target existing root/evidence-discovered entities and pass deterministic policy/budget checks.
- Evidence is immutable.
- Relationship observations are historical and append-oriented.
- Persistent application/domain deletion is soft deletion only.
- AuditEvent is immutable.
- Material assessment/research claims require valid evidence/chunk provenance.
- Do not expose or persist hidden chain-of-thought.
- RAG provides threat context, not live IOC facts.
- Geolocation is approximate context, not maliciousness evidence.
- PostgreSQL + pgvector is the v0.1 persistence/vector platform.
- Local deployment uses Podman Compose with durable host bind mounts.
- LangSmith is optional observability, not a functional dependency.
- API contracts do not leak LangGraph/provider/ORM/LLM implementation internals.

## Python engineering

Use `uv`.

Before considering work complete, run the repository canonical quality command, expected to cover:

- Black;
- isort;
- Pylint;
- strict Mypy;
- Pytest;
- applicable integration tests.

Additionally:

- Do not make a quality gate pass by weakening configuration, adding broad suppressions, skipping tests, or deleting
  assertions without independent justification.
- Source code must use type hints.
- We are leveraging async IO for application code. Unit tests, integration tests should use async io as well.

## Tests

CI must remain deterministic and must not require live internet/API keys for ordinary PR validation.

Use fake providers/FakeLlmClient and synthetic scenario fixtures.

Integration tests use isolated PostgreSQL + pgvector storage and must never use normal developer persistent data.

## Documentation

When implementation intentionally changes a confirmed contract, update the relevant authoritative document in the same PR.

Do not add speculative functionality to documentation or implementation.

Additionally: 

- Classes, interfaces, modules should have docstrings.
- Public functions and methods should have docstrings.
- For methods that are inherited from an interface: do not repeat the docstrings of the interface. 
  Create specific docstrings that describe the override logic that the level of implementations.
- After completing the implementation of functionality corresponding to a PR item in
  [PR_PLAN.md](docs/PR_PLAN.md), add the `[DONE]` marker at the end of the PR item. Do so prior to
  the changes being committed and pushed, and after all quality checks an integration tests have
  completed successfully.

## Configuration and batch-persistence invariants

- Follow `CONFIGURATION.md`: `default` is the base profile; `ATI_CONFIG_PROFILE` selects an optional override profile; configuration is loaded once at bootstrap.
- Never log sensitive configuration values. Preserve recursive key-name redaction.
- Batch persistence always uses bounded arrays of resource-specific PostgreSQL composite input types, expanded into temporary tables with set-oriented stored-function logic.
- Assume batches may be large. Do not add a separate small-batch JSONB/CTE persistence path.
- Python repositories must not implement reconciliation, version allocation, JSONB diff generation, or history creation.
- Do not introduce row-level triggers for domain versioning/history.
- Successful CREATE/UPDATE/soft DELETE creates a DB-assigned version and immutable history entry in the same transaction; UNCHANGED creates neither.
- PostgreSQL 18 is the v0.1 database baseline.

## Storage, acquisition, and secrets invariants

- BatchSource consumes pre-existing artifacts; it does not download them.
- Batch artifact locations use URIs (`file://`, future `s3://`, etc.).
- BatchSource must remain storage-agnostic; storage-specific behavior belongs behind ObjectStore.
- v0.1 uses FileSystemObjectStore and `${ATI_DATA_DIR}/datasets/<source>/` for local datasets.
- Do not embed credentials in artifact URIs.
- Downloader is a future, separate acquisition abstraction; do not merge acquisition into BatchSource.
- A future event-log layer carries artifact references/metadata, not bulk dataset payloads.
- Secrets are obtained through SecretsResolver; v0.1 uses EnvVarSecretsResolver.
- Resolve secrets during bootstrap/composition and pass resolved credentials to providers; providers should not depend directly on SecretsResolver.
- Never log resolved secret values.

## Configuration, artifact-storage, and secrets implementation rules

- Configuration profiles live under `ati.config` as `config_<profile>.py` modules exposing `CONFIG`.
- `ATI_CONFIG_PROFILE` selects the profile; absent/blank means `default`.
- Always load `default` first; a non-default profile shallowly overrides it.
- Reject invalid or nonexistent profile names; never silently fall back after an explicitly requested profile fails.
- Load configuration once during bootstrap and inject it; application/domain components must not independently read environment variables.
- Log the selected profile and effective configuration only after recursive sensitive-value redaction.
- BatchSource consumes pre-existing artifacts and must not implement downloading.
- Artifact locations are URIs. Use canonical forms such as `file:///...` and future `s3://bucket/key`.
- Keep URI resolution/storage-specific behavior behind `ObjectStore`; BatchSource must remain storage-agnostic.
- v0.1 uses `FileSystemObjectStore` with datasets beneath `${ATI_DATA_DIR}/datasets/<source>/`.
- A future `Downloader` is separate from BatchSource and writes acquired artifacts to ObjectStore.
- A future producer/consumer/event-log layer carries artifact references and metadata, not bulk dataset contents.
- Use `SecretsResolver` for secret acquisition; v0.1 uses only `EnvVarSecretsResolver`.
- Configuration stores secret reference names, not resolved values.
- Resolve secrets in bootstrap/composition and pass credentials to constructed providers/infrastructure components.
- Do not make providers depend directly on `SecretsResolver` unless an explicit architecture change is documented.
- Never embed credentials in artifact URIs or log/persist resolved secret values.


  