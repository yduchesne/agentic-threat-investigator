# Agentic Threat Investigator — Implementation / PR Plan

## Delivery principle

Implement ATI in small, reviewable increments. Every PR must preserve repository quality gates and add tests appropriate to the new behavior.

Do not allow coding agents to invent major architecture contrary to the authoritative documentation.

## PR 1 — Repository bootstrap and development environment

Deliver:

- repository layout;
- `uv` project configuration;
- `pyproject.toml`;
- committed `uv.lock`;
- Black/isort/Pylint/Mypy/Pytest/pytest-cov/pre-commit;
- canonical `make quality` or equivalent;
- Docker Compose baseline;
- backend/frontend skeletons;
- environment configuration;
- CI baseline;
- SPDX/license files.

## PR 2 — Frontend themes and user preference

Deliver:

- a theme foundation based on semantic design tokens;
- three predefined looks:
  - `darknite` — black-background default theme;
  - `brightlight` — white-background theme;
  - `wargames` — 1980s terminal-inspired green foreground and lines on a black background;
- `darknite` as the default for users without a stored preference;
- a user-accessible theme switcher;
- persistence of the selected theme in a `user_preference` table;
- typed application boundaries for reading and updating theme preference;
- accessible contrast, focus indicators, and reduced-motion behavior across themes;
- deterministic tests for default selection, switching, and preference persistence.

Theme styling must preserve the explicit visual separation between evidence,
research context, and ATI assessment. The `wargames` look may draw on generic
1980s terminal aesthetics but must not copy protected movie assets.

## PR 3 — Core domain model

Implement typed domain models/enums for:

- entities;
- evidence;
- relationships;
- assessment;
- geolocation;
- investigation state/budgets/pivots/stopping;
- common identifiers/canonicalization contracts.

No infrastructure coupling.

## PR 4 — Database migrations and repository contracts

Deliver:

- PostgreSQL/pgvector schema;
- Alembic;
- repository ABCs;
- UnitOfWork ABC;
- initial PostgreSQL implementations;
- soft-delete conventions;
- integration-test database.

## PR 5 — Local identity/authentication

Deliver:

- users/credentials/sessions;
- Argon2id;
- bootstrap administrator;
- ADMIN/ANALYST enforcement;
- CSRF/session protections;
- admin invariant.

## PR 6 — Audit and history

Deliver:

- AuditEvent;
- stable audit action vocabulary;
- transactional audit behavior;
- actor/system semantics.

## PR 7 — PostgreSQL batch persistence

Deliver:

- `upsert_batch` repository contracts;
- versioned stored functions;
- JSONB/set-based merge;
- content-hash behavior;
- inserted/updated/unchanged result;
- integration tests.

## PR 8 — Batch source/ingestion framework

Deliver:

- BatchSource ABC;
- SourceRecord;
- checkpoints/capabilities;
- IngestionService;
- normalization versioning;
- source cache behavior.

## PR 9 — MITRE ATT&CK ingestion

Deliver:

- STIX ingestion;
- normalized ATT&CK entities/relationships;
- idempotent update behavior;
- provenance.

## PR 10 — Documents/chunks/embeddings

Deliver:

- Document/DocumentChunk persistence;
- source-aware chunking;
- embedding abstraction/config metadata;
- pgvector indexing.

## PR 11 — RAG retrieval

Deliver:

- ResearchQuery/RetrievedChunk;
- ResearchRetriever ABC;
- PgVectorResearchRetriever;
- metadata filtering;
- retrieval evaluation fixtures.

## PR 12 — Live provider framework + RDAP + Google DNS

Deliver:

- EvidenceProvider ABC;
- ProviderResult/errors;
- retry/rate-limit infrastructure;
- RDAP provider;
- Google DNS provider;
- deterministic provider tests.

This PR establishes the first domain-to-IP discovery path.

## PR 13 — Remaining v0.1 live sources

Deliver:

- IPinfo Lite;
- DB-IP City Lite local MMDB;
- AbuseIPDB;
- ThreatFox;
- URLhaus;
- source-specific normalization/tests.

## PR 14 — Investigation persistence and relationship construction

Deliver:

- Investigation persistence;
- Evidence persistence;
- deterministic relationship extractors;
- RelationshipObservation;
- discovered-entity processing;
- atomic provider-result persistence.

## PR 15 — LangGraph skeleton

Deliver:

- graph state integration;
- Coordinator skeleton;
- collector nodes;
- job execution through worker;
- typed transitions;
- deterministic FakeLlmClient path.

## PR 16 — Evidence Analyst

Deliver:

- structured analysis contract;
- verdict/confidence semantics;
- supporting/contradicting evidence;
- limitations/unresolved questions;
- evidence-reference validation;
- analytical regression tests.

## PR 17 — Adaptive pivots and stopping

Deliver:

- deterministic pivot policy;
- depth/entity/provider/replan/LLM budgets;
- cycle prevention;
- Coordinator proposal validation;
- stop reasons;
- canonical trajectory tests.

## PR 18 — Threat Research RAG Agent

Deliver:

- conditional research triggers;
- ResearchResult;
- claim/chunk citation validation;
- grounded synthesis;
- RAG evaluation suite.

## PR 19 — Report Writer and API

Deliver:

- versioned InvestigationReport;
- `/api/v1` DTOs/routes;
- asynchronous investigation creation;
- evidence/relationship/research/assessment/report/timeline/geolocation resources;
- pagination/errors/idempotency/concurrency behavior.

## PR 20 — Frontend analyst workbench

Deliver:

- Investigations;
- investigation creation;
- Overview;
- Evidence;
- Relationships with React Flow;
- Map with Leaflet;
- Research;
- Timeline;
- Report.

Maintain explicit visual separation between evidence, research context, and assessment.

## PR 21 — Monitors, diffs, findings

Deliver:

- Monitor domain/persistence;
- scheduler integration;
- scheduled investigations;
- deterministic comparison;
- materiality analysis;
- Finding;
- findings inbox/workflow.

## PR 22 — System/jobs/admin UI

Deliver:

- minimal provider/job/system status;
- user administration;
- monitor administration;
- relevant health/config visibility.

## PR 23 — Evaluation and release hardening

Deliver:

- canonical scenario suite;
- real-model regression workflow;
- optional live-provider contracts;
- observability/evaluation integration;
- security review;
- dependency/license review;
- documentation verification;
- backup/restore verification;
- clean install/migration verification.

## Every PR

Before completion:

1. run canonical quality command;
2. run applicable deterministic tests;
3. add/update tests for changed behavior;
4. maintain strict typing;
5. preserve architectural boundaries;
6. update authoritative documentation when a contract intentionally changes;
7. do not weaken quality gates to make a PR pass.
