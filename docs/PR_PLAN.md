# Agentic Threat Investigator — Implementation / PR Plan

## Table of contents

- [Delivery principle](#delivery-principle)
- [PR 1 — Repository bootstrap and development environment \[DONE\]](#pr-1-repository-bootstrap-and-development-environment-done)
- [PR 2 — Core domain model \[DONE\]](#pr-2-core-domain-model-done)
- [PR 3 — Database migrations and repository contracts \[DONE\]](#pr-3-database-migrations-and-repository-contracts-done)
- [PR 4 — Local identity/authentication \[DONE\]](#pr-4-local-identityauthentication-done)
- [PR 5 — Audit and history \[DONE\]](#pr-5-audit-and-history-done)
- [PR 6 — PostgreSQL batch persistence \[DONE\]](#pr-6-postgresql-batch-persistence-done)
- [PR 7 — SecretsResolver implementation and integration \[DONE\]](#pr-7-secretsresolver-implementation-and-integration)
- [PR 8 — Batch source/ingestion framework \[DONE\]](#pr-8-batch-sourceingestion-framework)
- [PR 9 — MITRE ATT&CK ingestion \[DONE\]](#pr-9-mitre-attck-ingestion-done)
- [PR 10 — Documents/chunks/embeddings \[DONE\]](#pr-10-documentschunksembeddings-done)
- [PR 11 — RAG retrieval](#pr-11-rag-retrieval)
- [PR 12 — Live provider framework + RDAP + Google DNS](#pr-12-live-provider-framework-rdap-google-dns)
- [PR 13 — Remaining v0.1 live sources](#pr-13-remaining-v01-live-sources)
- [PR 14 — Investigation persistence and relationship construction](#pr-14-investigation-persistence-and-relationship-construction)
- [PR 15 — LangGraph skeleton](#pr-15-langgraph-skeleton)
- [PR 16 — Evidence Analyst](#pr-16-evidence-analyst)
- [PR 17 — Adaptive pivots and stopping](#pr-17-adaptive-pivots-and-stopping)
- [PR 18 — Threat Research RAG Agent](#pr-18-threat-research-rag-agent)
- [PR 19 — Report Writer and API](#pr-19-report-writer-and-api)
- [PR 20 — Frontend analyst workbench](#pr-20-frontend-analyst-workbench)
- [PR 21 — Monitors, diffs, findings](#pr-21-monitors-diffs-findings)
- [PR 22 — System/jobs/admin UI](#pr-22-systemjobsadmin-ui)
- [PR 23 — Evaluation and release hardening](#pr-23-evaluation-and-release-hardening)
- [Every PR](#every-pr)
- [Latest persistence/configuration requirements](#latest-persistenceconfiguration-requirements)

## Delivery principle

Implement ATI in small, reviewable increments. Every PR must preserve repository quality gates and add tests appropriate to the new behavior.

Do not allow coding agents to invent major architecture contrary to the authoritative documentation.

## PR 1 — Repository bootstrap and development environment [DONE]

Deliver:

- repository layout;
- `uv` project configuration;
- `pyproject.toml`;
- committed `uv.lock`;
- Black/isort/Pylint/Mypy/Pytest/pytest-cov/pre-commit;
- canonical `make quality` or equivalent;
- Podman Compose baseline;
- backend/frontend skeletons;
- environment configuration;
- CI baseline;
- SPDX/license files.

## PR 2 — Core domain model [DONE]

Implement typed domain models/enums for:

- entities;
- evidence;
- relationships;
- assessment;
- geolocation;
- investigation state/budgets/pivots/stopping;
- common identifiers/canonicalization contracts.

No infrastructure coupling.

## PR 3 — Database migrations and repository contracts [DONE]

Deliver:

- PostgreSQL/pgvector schema;
- Alembic;
- repository ABCs;
- UnitOfWork ABC;
- initial PostgreSQL implementations;
- soft-delete conventions;
- integration-test database.

## PR 4 — Local identity/authentication [DONE]

Deliver:

- users/credentials/sessions;
- Argon2id;
- bootstrap administrator;
- ADMIN/ANALYST enforcement;
- CSRF/session protections;
- admin invariant.

## PR 5 — Audit and history [DONE]

Deliver:

- AuditEvent;
- stable audit action vocabulary;
- transactional audit behavior;
- actor/system semantics.

## PR 6 — PostgreSQL batch persistence [DONE]

Deliver:

- `upsert_batch` repository contracts;
- versioned stored functions;
- JSONB/set-based merge;
- content-hash behavior;
- inserted/updated/unchanged result;
- integration tests.

## PR 7 — SecretsResolver implementation and integration [DONE]

Deliver:

- `SecretsResolver` ABC with `get`/`require` semantics and `SecretNotFoundError`;
- `EnvVarSecretsResolver` with an injectable environment mapping for deterministic tests;
- bootstrap/composition-time resolution with clear failure on missing required secrets;
- configuration carrying secret reference names only (for example `ATI_ABUSEIPDB_API_KEY`), never secret values;
- resolved credentials passed into provider/infrastructure construction; providers must not depend directly on `SecretsResolver`;
- confirmation that resolved secret values are never logged, persisted, or embedded in artifact URIs;
- `.env.example` documentation of required secret variables without real credentials;
- deterministic unit tests without live keys.

This PR prepares credential wiring for subsequent provider and batch PRs.

## PR 8 — Batch source/ingestion framework [DONE]

Deliver:

- BatchSource ABC;
- SourceRecord;
- checkpoints/capabilities;
- IngestionService;
- normalization versioning;
- URI-oriented ObjectStore artifact behavior.

## PR 9 — MITRE ATT&CK ingestion [DONE]

Deliver:

- STIX ingestion;
- normalized ATT&CK entities/relationships;
- idempotent update behavior;
- provenance.

## PR 10 — Documents/chunks/embeddings [DONE]

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

## Latest persistence/configuration requirements

PR 1 delivers the initial environment configuration as a single typed settings module, `src/agentic_threat_investigator/config.py`, based on pydantic-settings: `Settings`, a cached `get_settings()` accessor, and `ensure_test_database_safe`, which fails closed when an integration-test database URL lacks the isolated test marker. The profile-based configuration system described in `CONFIGURATION.md` (`ati.config` profile modules, `ATI_CONFIG_PROFILE` selection, `config_utils`, sensitive-value redaction, and its tests) is not yet implemented and must be delivered by a subsequent PR.

PR 3 establishes PostgreSQL 18 as the database baseline, domain-resource version columns/sequences, immutable domain-object history schema, and versioned SQL-function conventions.

PR 6 implements the canonical batch path: application-bounded arrays of resource-specific PostgreSQL composite types, `unnest ... WITH ORDINALITY`, temporary staging/work tables for every batch, set-oriented INSERT/UPDATE/UNCHANGED/CONFLICT reconciliation, optimistic version checks, version allocation, shallow `ati_jsonb_diff`, final target mutations, and immutable history insertion. It must not introduce row-level history/version triggers, Python-side reconciliation, or an alternate small-batch path.
