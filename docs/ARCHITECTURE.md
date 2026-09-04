# Agentic Threat Investigator — Architecture

## Table of contents

- [Architectural objective](#architectural-objective)
- [High-level architecture](#high-level-architecture)
- [Layering](#layering)
  - [Domain](#domain)
  - [Application](#application)
  - [Infrastructure](#infrastructure)
  - [Agents](#agents)
  - [API](#api)
  - [Frontend](#frontend)
- [Core architectural rule](#core-architectural-rule)
- [Asynchronous investigation execution](#asynchronous-investigation-execution)
- [LangGraph topology](#langgraph-topology)
- [Agent boundaries](#agent-boundaries)
- [Provider architecture](#provider-architecture)
- [Relationship construction](#relationship-construction)
- [RAG](#rag)
- [Persistence](#persistence)
- [Transactions](#transactions)
- [Batch ingestion](#batch-ingestion)
- [Geospatial](#geospatial)
- [Observability](#observability)
- [Technology baseline](#technology-baseline)
- [Configuration architecture](#configuration-architecture)
- [Batch persistence responsibility boundary](#batch-persistence-responsibility-boundary)
- [Batch artifact storage boundary](#batch-artifact-storage-boundary)
- [Secrets boundary](#secrets-boundary)
- [Batch artifact acquisition and storage evolution](#batch-artifact-acquisition-and-storage-evolution)

## Architectural objective

ATI separates domain semantics, application orchestration, infrastructure adapters, persistence, agent behavior, and presentation so that external providers, LLMs, tracing systems, and deployment details can change without altering the core investigation model.

## High-level architecture

```text
React / TypeScript UI
        |
     REST API
        |
  Application Services
        |
  PostgreSQL Job Queue
        |
      Worker
        |
     LangGraph
        |
+-----------------------------+
| Coordinator                 |
| Infrastructure Collector    |
| Threat Intel Collector      |
| Threat Research Agent       |
| Evidence Analyst            |
| Report Writer               |
+-----------------------------+
        |
+-----------------------------+
| Evidence Providers          |
| RAG Retriever               |
| LLM Client                  |
| Repositories / UnitOfWork   |
| Observability Adapter       |
+-----------------------------+
        |
 PostgreSQL + pgvector
```

## Layering

### Domain

Pure Pydantic domain models and enums. The domain must not depend on SQLAlchemy, HTTP clients, FastAPI, LangChain, LangGraph, pgvector, or a specific LLM provider.

### Application

Coordinates use cases, persistence, transactions, policies, jobs, and state transitions. Application services enforce invariants.

### Infrastructure

Contains PostgreSQL repositories, HTTP clients, source/provider implementations, pgvector retrieval, LLM adapters, tracing adapters, and other external integrations.

### Agents

Agents interpret evidence and make typed recommendations within explicit contracts. They do not directly mutate the database or invoke unrestricted infrastructure.

### API

FastAPI request/response DTOs and REST routes. API DTOs are separate from domain and ORM models.

### Frontend

React/TypeScript analyst workbench consuming the stable `/api/v1` contract.

## Core architectural rule

> Providers retrieve. Collectors coordinate retrieval. Repositories persist. Application workflows decide persistence. Agents decide investigative actions within policy.

## Asynchronous investigation execution

Investigation creation is asynchronous.

```text
POST /api/v1/investigations
        |
persist investigation + job
        |
return 202
        |
worker claims job
        |
execute LangGraph
        |
persist state/results
```

Long-running investigation work must not execute as an in-process FastAPI background task.

v0.1 uses a PostgreSQL-backed job queue rather than introducing Redis/Kafka solely for background work.

## LangGraph topology

Conceptually:

```text
START
  |
Initialize
  |
Coordinator
  |
Collectors
  |
Persist Evidence
  |
Extract Relationships
  |
Update Discoveries
  |
Coordinator
  +----> Pivot / Collect More
  |
  +----> Threat Research
  |
Evidence Analyst
  +----> Coordinator if more evidence is justified
  |
Assessment
  |
Report Writer
  |
END
```

The persisted domain objects are authoritative. `InvestigationState` carries identifiers, queues, budgets, status, and outcomes rather than copies of all domain objects.

## Agent boundaries

ATI has six logical agent roles:

1. Investigation Coordinator.
2. Infrastructure Collector.
3. Threat Intelligence Collector.
4. Threat Research / Context RAG Agent.
5. Evidence Analyst.
6. Report Writer.

There is not one agent per external API.

## Provider architecture

All live evidence providers implement an `abc.ABC` contract.

Providers:

- determine deterministic applicability via `supports()`;
- retrieve external information;
- normalize it into ATI Evidence;
- return typed errors.

Providers do not:

- persist;
- create relationships;
- assess maliciousness;
- decide pivots.

## Relationship construction

Relationships are derived deterministically from normalized evidence/source records through relationship extractors.

No LLM is required to infer basic relationships such as DNS resolution or network ownership.

Relationship extraction can discover entities. The Coordinator may then evaluate those entities as possible pivots.

## RAG

PostgreSQL + pgvector is the v0.1 vector store.

RAG is conditional and concept-driven. It is invoked for entities such as malware, ATT&CK techniques, vulnerabilities, or explicit analyst contextual questions.

Live IOC facts remain evidence-provider responsibility.

## Persistence

PostgreSQL is the authoritative datastore.

Categories:

- append-oriented immutable observations: Evidence, RelationshipObservation, AuditEvent;
- stable identities: Entity, Relationship;
- versioned outputs: Assessment, InvestigationReport;
- mutable operational state: Investigation, Monitor, jobs, users/sessions;
- replaceable derived indexing artifacts: document chunks/embeddings.

All persistent application/domain deletion is soft deletion. Immutable historical observations normally expose no delete operation.

## Transactions

External provider and LLM calls occur outside database transactions.

A normalized provider result is persisted atomically as the relevant evidence, entities, relationships, observations, and audit changes.

Repositories never self-commit. Application services use an explicit Unit of Work.

## Batch ingestion

Structured batch sources follow:

```text
download
 -> normalize SourceRecord
 -> batch repository
 -> PostgreSQL stored function / set-based merge
 -> inserted/updated/unchanged result
 -> downstream processing only for changed records
```

The canonical path is the bounded resource-specific PostgreSQL composite-array transport described in DATABASE.md; PostgreSQL expands it into temporary staging tables and performs the set-based merge. There is no alternate small-batch path.

## Geospatial

v0.1 uses DB-IP City Lite through a local MMDB database. Latitude/longitude are used for map visualization.

PostGIS is not required until ATI needs actual spatial queries.

## Observability

Product history and operational observability are separate:

- AuditEvent: governance/security history.
- Investigation timeline: analyst-facing workflow history.
- Structured logs: runtime diagnostics.
- LangSmith or future trace backend: agent/LLM development observability.

No observability backend is required for correct execution.

## Technology baseline

- Python managed by `uv`.
- FastAPI.
- Pydantic.
- PostgreSQL + pgvector.
- SQLAlchemy/repository implementations.
- Alembic migrations.
- LangChain/LangGraph.
- LangSmith initially.
- React + TypeScript.
- React Flow.
- Leaflet.
- Podman Compose for local deployment.

## Configuration architecture

Runtime configuration follows `CONFIGURATION.md`. `ATI_CONFIG_PROFILE` selects a source-controlled profile under `ati.config`; `default` is always the base and a selected non-default profile shallowly overrides it. Configuration is loaded once during process bootstrap and injected into application components. Components do not independently read process environment variables. Effective configuration is logged with conservative sensitive-value redaction.

## Batch persistence responsibility boundary

Batch persistence always uses resource-specific PostgreSQL composite arrays as the bounded application-to-database transport and temporary tables inside set-oriented stored functions. ATI assumes batches may be large; there is no small-batch alternate path. The application enforces a configurable maximum batch size. PostgreSQL owns reconciliation, concurrency checks, version allocation, JSONB diff generation, target mutation, immutable history creation, and outcome classification. Python repositories must not duplicate this logic. Row-level history/version triggers are prohibited.

## Batch artifact storage boundary

Batch ingestion separates acquisition, storage, and interpretation. BatchSource consumes an artifact through an abstract ObjectStore using a URI and is unaware of how the artifact was acquired. v0.1 provides filesystem-backed object storage; cloud object-store implementations are future extensions.

A future Downloader is a producer-side acquisition abstraction. A later producer/consumer topology may use a distributed event log to announce artifact availability while retaining the artifact itself in filesystem/object storage.

## Secrets boundary

Secret acquisition is abstracted through `SecretsResolver`. v0.1 uses `EnvVarSecretsResolver`. Secret resolution occurs in the application composition/bootstrap layer; constructed providers receive resolved credentials rather than depending on the resolver itself.


## Batch artifact acquisition and storage evolution

The architectural dependency direction is:

```text
v0.1

manual acquisition
      ↓
FileSystemObjectStore
      ↓
artifact URI
      ↓
BatchSource
      ↓
SourceRecord
      ↓
batch repository
```

A `BatchSource` consumes an already-present artifact. It does not perform HTTP downloads, authenticate to the upstream publisher, or decide where artifacts are stored.

Artifact locations are represented by URIs. Canonical examples are:

```text
file:///var/lib/ati/datasets/mitre-attack/enterprise-attack.json
s3://ati-datasets/mitre-attack/enterprise-attack.json
```

The URI identifies the resource; it never carries credentials. URI-scheme resolution selects the appropriate `ObjectStore` implementation outside the `BatchSource`. The source must not contain `if scheme == "file"` / `if scheme == "s3"` storage branching.

For v0.1 the only required storage implementation is `FileSystemObjectStore`, rooted operationally beneath:

```text
${ATI_DATA_DIR}/datasets/<source>/
```

A future `Downloader` is a producer-side abstraction:

```text
external publisher
      ↓
Downloader
      ↓
ObjectStore
      ↓
artifact URI
```

A still-later distributed topology may introduce a producer/consumer layer and distributed event log such as Kafka:

```text
Downloader
      ↓
ObjectStore
      ↓
ArtifactAvailable event
      ↓
distributed event log
      ↓
consumer
      ↓
BatchSource
```

The event log carries artifact metadata/reference information such as source ID, artifact URI, content hash, and retrieval timestamp. Bulk datasets remain in filesystem/object storage and are not transported as event payloads.

Secret acquisition remains orthogonal to all of the above. `SecretsResolver` resolves credentials during bootstrap/composition; storage implementations, downloaders, and providers receive only the credentials they require.
