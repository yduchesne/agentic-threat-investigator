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

## Getting Started

The quickest way to try ATI locally is to run the complete stack with the
repository's startup script. The default local configuration uses ATI's
**fake world** for intelligence sources, so you can create investigations,
follow pivots, inspect evidence and relationships, explore the graph and
timeline, and generate reports without obtaining API keys for DNS,
registration, reputation, or threat-intelligence providers. The LLM is
separate from the fake-world data sources: normal local use still calls the
real LLM that you configure.

### 1. Install the prerequisites

After cloning the repository, run:

```bash
./install.sh
```

ATI's local stack uses Podman Compose. The installer sets up the supported
development prerequisites and project dependencies.

### 2. Create your local configuration

Copy the supplied example rather than creating the configuration from
scratch:

```bash
cp .env.example .env
```

Edit `.env` and, at minimum, choose a writable absolute data directory,
set a local PostgreSQL password, and provide the administrator account that
you want ATI to create on the first run:

```dotenv
ATI_DATA_DIR=/absolute/path/to/ati-data/dev
POSTGRES_PASSWORD=choose-a-local-database-password

ATI_BOOTSTRAP_ADMIN_USERNAME=admin
ATI_BOOTSTRAP_ADMIN_PASSWORD=choose-an-admin-password
```

The bootstrap administrator is created only when the user database is empty.
Changing these two values later does not reset an existing account. If you
want to discard the local database and bootstrap it again, use the teardown
command described below.

Keep `ATI_OPERATING_MODE=fake` for this quick-start experience. In fake
mode ATI uses repository-owned, deterministic intelligence-source data and
does not contact the live intelligence providers. The startup process also
bootstraps the packaged synthetic data and research corpus. This gives you a
safe, repeatable world to investigate while the rest of the application —
FastAPI, PostgreSQL, the durable worker, Coordinator, agent workflow,
persistence, and UI — runs normally.

### 3. Configure a real LLM

The local worker uses ATI's `openai` driver, which can call OpenAI directly
or an OpenAI-compatible endpoint such as OpenRouter. The LLM configuration
is independent of `ATI_OPERATING_MODE=fake`: the fake world replaces
external intelligence sources, **not** the model.

For OpenAI, the simplest configuration is:

```dotenv
ATI_LLM_DRIVER=openai
ATI_LLM_MODEL=gpt-4o-mini
ATI_LLM_BASE_URL=
ATI_LLM_API_KEY_SECRET=ATI_OPENAI_API_KEY
ATI_OPENAI_API_KEY=your-openai-api-key
```

For OpenRouter, point the same driver at OpenRouter and name the environment
variable that contains your OpenRouter key:

```dotenv
ATI_LLM_DRIVER=openai
ATI_LLM_BASE_URL=https://openrouter.ai/api/v1
ATI_LLM_MODEL=your-openrouter-model-id
ATI_LLM_API_KEY_SECRET=ATI_OPENROUTER_API_KEY
ATI_OPENROUTER_API_KEY=your-openrouter-api-key
```

OpenRouter can be used with supported Anthropic models by selecting the
corresponding OpenRouter model ID. ATI's current local stack does **not**
provide a native Anthropic driver or accept an Anthropic API key directly;
use OpenRouter when you want to run an Anthropic model.

Do not commit `.env` or real credentials. `ATI_LLM_API_KEY_SECRET` is the
**name** of the environment variable containing the key, not the key itself.

### 4. Optional LangSmith observability

ATI includes a LangSmith LLM/agent observability backend. Its application
configuration selects LangSmith with:

```dotenv
ATI_OBSERVABILITY_ENABLED=true
ATI_LLM_OBSERVABILITY_BACKEND=langsmith
LANGSMITH_API_KEY=your-langsmith-api-key
```

LangSmith is optional; ATI does not depend on it for investigation state,
persistence, retries, or job execution.

At present, the repository's local Compose worker does not forward
`ATI_LLM_OBSERVABILITY_BACKEND` and `LANGSMITH_API_KEY` into the worker
container, so adding these values to `.env` alone does not enable LangSmith
for a `./start.sh` stack. The local stack still includes the OpenTelemetry
observability services (Collector, Prometheus, Jaeger, Loki, and Grafana).
See `docs/OBSERVABILITY.md` for the observability architecture and current
runtime configuration. This limitation should be removed before documenting
LangSmith as a one-step local-stack option.

### 5. Start ATI

Start the complete local stack:

```bash
./start.sh
```

The first run can take several minutes because container images may need to
be built or pulled and the database initialized. `start.sh` waits for the
services, runs migrations and the fake-data bootstrap, checks health, and
prints the reachable endpoints when it finishes. The application is normally
available at:

```text
http://localhost:8080/
```

Sign in with the bootstrap administrator username and password from your
`.env`, create an Investigation, and explore the generated evidence,
relationships, graph, timeline, research, assessment, and report.

If you change backend, migration, or frontend source code and need to force
the project images and containers to be rebuilt, use either form:

```bash
./start.sh -r
# or
./start.sh --rebuild
```

Ordinary `./start.sh` is idempotent: when the stack is already healthy it
leaves the running services in place.

### 6. Stop or remove the local environment

To stop ATI while keeping its containers and stored data for the next run:

```bash
./stop.sh
```

To completely tear down the local environment after you are finished:

```bash
./stop.sh -t
# or
./stop.sh --teardown
```

`-t` and `--teardown` is destructive: it removes the ATI
stack containers and deletes the service-managed PostgreSQL, Prometheus,
Loki, and Grafana data below `ATI_DATA_DIR`. Repository/operator-provided
dataset artifacts are not deleted. The next `./start.sh` therefore starts
with fresh service-managed state and bootstraps the fake world again.

For more detailed configuration and deployment options, see
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

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
