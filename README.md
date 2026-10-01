# Agentic Threat Investigator

ATI is an open-source, analyst-oriented threat investigation system that uses
bounded agentic workflows to turn security data into evidence-backed
investigations and reports. An analyst starts with one or more indicators such
as a domain, IP address, or URL. ATI gathers applicable infrastructure and
threat-intelligence data, preserves what the sources actually returned as
provenance-bearing Evidence, discovers related entities and relationships, and
uses those observations to decide what is worth investigating next.

The investigation is agentic rather than a fixed sequence of lookups. A
Coordinator plans and replans bounded work as evidence arrives. Specialized
collection components obtain infrastructure and threat-intelligence data;
threat research retrieves relevant context from curated research sources; an
Evidence Analyst assesses the accumulated evidence; and a Report Writer turns
the structured result into an analyst-facing report. Autonomous pivots are
constrained by deterministic policy, explicit budgets, and the entities
actually discovered during the investigation.

ATI can ingest and normalize data such as DNS observations, domain
registration data, IP and network information, ASNs and organizations,
reputation and threat-intelligence observations, malware associations, and
approximate geospatial context. These source observations become typed
Evidence and relationships rather than an undifferentiated collection of API
responses. Curated threat-research material is handled separately through RAG:
it provides context for what ATI observed, but does not establish live IOC
facts by itself.

The result is an investigation that an analyst can inspect from the original
indicator through the evidence, discovered infrastructure, relationships,
research context, assessment, and final report. Material analytical claims are
designed to remain traceable to their supporting evidence or cited research.
ATI is therefore not just an IOC lookup aggregator: its defining behavior is
evidence-driven investigation, bounded autonomous pivoting, and
provenance-backed analysis.

See [`docs/PRODUCT.md`](docs/PRODUCT.md) for the product specification and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the authoritative
architecture description.

## How ATI works

A typical investigation follows this flow:

```text
Indicators
    |
    v
Infrastructure + threat-intelligence sources
    |
    v
Typed Evidence + Entities + Relationships
    |
    v
Coordinator
  plans / pivots / replans within policy and budget
    |
    +----------------------+
    |                      |
    v                      v
Additional collection   Threat research (RAG)
    |                      |
    +----------+-----------+
               |
               v
        Evidence Analyst
               |
               v
          Assessment
               |
               v
          Report Writer
               |
               v
     Provenance-backed report
```

The analyst workbench exposes the investigation from several perspectives,
including evidence, relationships and graph exploration, research, timeline,
geospatial context, assessment, and reporting. Historical observations are
preserved so the system can distinguish durable entities and relationships
from the individual observations that support them.

## Architecture at a glance

```text
React / TypeScript analyst workbench
                |
             REST API
                |
       Application services
                |
       PostgreSQL job queue
                |
              Worker
                |
            LangGraph
                |
+----------------------------------+
| Agentic investigation workflow   |
|                                  |
| Coordinator                      |
| Infrastructure Collector         |
| Threat Intel Collector           |
| Threat Research Agent            |
| Evidence Analyst                 |
| Report Writer                    |
+----------------------------------+
                |
          TaskDispatcher
                |
+----------------------------------+
| Execution components             |
|                                  |
| Evidence Providers               |
| RAG Retriever                    |
| LLM Client                       |
| Repositories / Unit of Work      |
| Observability                    |
+----------------------------------+
                |
       PostgreSQL + pgvector
```

The architecture deliberately separates deterministic application policy from
LLM judgment. Agents operate through typed contracts; they do not receive
unrestricted HTTP, SQL, shell, or Python access. Evidence is distinct from
interpretation, and every autonomous pivot must remain traceable to user input
or observed evidence. See [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md),
[`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md), and
[`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) for the detailed contracts.

## Requirements

ATI's development and local integration environment uses:

- Python and `uv` for the backend environment and dependency management;
- Node.js/npm for the React/TypeScript frontend;
- PostgreSQL with ATI's required extensions for persistence, vector search,
  and geospatial data;
- Podman and a Compose provider for local containerized infrastructure.

The bootstrap script installs the supported development prerequisites on a
supported Linux distribution.

## Installation

Run:

```bash
./install.sh
```

This installs missing development prerequisites, `uv`, Python dependencies,
frontend dependencies, and the pre-commit hook.

The local runtime is Podman Compose-based. Configure `ATI_DATA_DIR` and the
other values in `.env.example` in a local `.env` before using Compose.

## Validation

Run the deterministic quality suite (Ruff formatting/lint, strict Mypy, unit
tests, and frontend lint) with:

```bash
./build.sh --qa
```

To format Python sources and apply safe lint fixes with Ruff:

```bash
./build.sh --fmt
```

Unit tests are kept under `tests/unit/` and integration tests under
`tests/integration/`. The integration tests provision an isolated PostgreSQL
container via Podman and therefore require `podman` and `podman-compose`
(installed by `./install.sh`); after the integration tests succeed, the
frontend production bundle is built (`tsc` type-check plus `vite build`).

Other build operations include:

| Command | Purpose |
| --- | --- |
| `./build.sh --chk` | Quality checks and unit tests without the formatting check |
| `./build.sh --unit` | Unit tests only |
| `./build.sh --intg` | Integration tests plus frontend tests |
| `./integration-test.sh` | PostgreSQL integration suite and frontend build |

## Project status

ATI is early-stage software; domain, persistence, provider, and agent features
are delivered incrementally according to the versioned roadmap documents under
[`docs/`](docs/).

The README is intentionally an entry point rather than the authoritative
specification. Detailed behavior, invariants, implementation status, and
version-specific scope live in the project documentation and roadmaps.

## Authoritative documentation

- [`docs/PRODUCT.md`](docs/PRODUCT.md) — product purpose, use cases, scope,
  and principles.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system architecture and
  component boundaries.
- [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md) — entities, Evidence,
  relationships, investigations, assessments, and reports.
- [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) — live providers, batch
  sources, and threat-research inputs.
- [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md) — Coordinator, agents,
  provider execution, LLM, and RAG contracts.
- [`docs/PERSISTENCE.md`](docs/PERSISTENCE.md) — PostgreSQL persistence
  model and invariants.
- [`docs/TESTING.md`](docs/TESTING.md) — deterministic testing, integration
  testing, fake-world scenarios, and browser validation.
- [`docs/API.md`](docs/API.md) — REST API.
- [`docs/FRONTEND.md`](docs/FRONTEND.md) — analyst workbench architecture.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security model and controls.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — deployment guidance.
- [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) — telemetry and
  observability.
- [`docs/PR_PLAN.md`](docs/PR_PLAN.md) and versioned `ROADMAP_*.md` files —
  implementation sequencing and delivered/planned scope.

## License

ATI is open-source software licensed under
[AGPL-3.0-only](LICENSE). If you run a modified ATI service for users over a
network, AGPLv3 requires offering those users the corresponding source; see the
full license for details.
