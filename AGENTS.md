# Agentic Threat Investigator — Coding Agent Instructions

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
- Local deployment uses Docker Compose with durable host bind mounts.
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

- Do not make a quality gate pass by weakening configuration, adding broad suppressions, skipping tests, or deleting       '
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