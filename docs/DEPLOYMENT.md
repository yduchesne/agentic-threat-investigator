# Agentic Threat Investigator — Local Deployment and Development Environment

## v0.1 deployment target

ATI v0.1 deploys locally with Docker Compose.

Containers are disposable. Durable data is not.

## Eventual production web deployment

The frontend is a browser-based React application. "Desktop-first" describes
the initial screen-size and interaction design; it does not require native
desktop packaging. The frontend can eventually be served as a web application,
with a reverse proxy serving its static assets and routing `/api/v1` requests
to FastAPI.

Public or multi-user production hosting is outside the confirmed v0.1 local
deployment target. A future production deployment must define and validate, at
minimum:

- TLS termination and trusted-proxy behavior;
- secure sessions, CSRF protection, authentication, and authorization;
- trusted-host and CORS policies;
- secrets management and credential rotation;
- request rate, body-size, and timeout limits;
- private database networking with no public PostgreSQL exposure;
- durable backup, restore, monitoring, and operational logging procedures;
- scaling and availability behavior for API, worker, and scheduler services;
- an appropriate way for network users to obtain corresponding source as
  required by AGPL-3.0-only.

These requirements must be specified before treating the Docker Compose
baseline as a production deployment architecture.

## Runtime topology

```text
Host
 |
 +-- Docker Compose
 |    +-- ati-frontend
 |    +-- ati-api
 |    +-- ati-worker
 |    +-- ati-scheduler
 |    +-- ati-migrate (one-shot)
 |    +-- ati-postgres (PostgreSQL + pgvector)
 |
 +-- ATI_DATA_DIR
      +-- postgres/data
      +-- geo/dbip
      +-- source-cache
      +-- backups
      +-- runtime
```

Redis, Kafka, Kubernetes, and a separate vector database are not required for v0.1.

## Persistent host root

A single environment-specific root controls durable host data:

```text
ATI_DATA_DIR=/absolute/unique/path/ati-data
```

Example:

```text
${ATI_DATA_DIR}/
├── postgres/
│   └── data/
├── geo/
│   └── dbip/
├── source-cache/
│   ├── attack/
│   ├── cisa/
│   └── other/
├── backups/
└── runtime/
```

PostgreSQL uses an explicit bind mount:

```yaml
volumes:
  - ${ATI_DATA_DIR}/postgres/data:/var/lib/postgresql/data
```

DB-IP and source cache are likewise explicitly mounted where required.

## Environment isolation

Each concurrently usable environment must have both:

- a unique `COMPOSE_PROJECT_NAME`;
- a unique `ATI_DATA_DIR`.

Example:

```text
COMPOSE_PROJECT_NAME=ati-dev
ATI_DATA_DIR=/.../ati-data/dev
```

and:

```text
COMPOSE_PROJECT_NAME=ati-demo
ATI_DATA_DIR=/.../ati-data/demo
```

This avoids container/network naming conflicts and accidental data sharing across clones/worktrees/environments.

## Data safety

`docker compose down` must be safe for durable ATI data.

Persistent application data must not depend on Docker-managed anonymous/named-volume lifecycle.

A deliberately destructive command such as:

```bash
make reset-dev-data
```

may erase/reinitialize development data but must require explicit intent.

## PostgreSQL

Use a pinned PostgreSQL image with a compatible pinned pgvector release.

Never use floating `latest` tags.

The exact supported image/version is frozen during implementation after compatibility verification.

PostgreSQL has a health check.

Development may expose PostgreSQL on a configurable non-default host port, for example:

```text
ATI_POSTGRES_HOST_PORT=54320
```

to avoid collisions with host PostgreSQL.

## Database migrations

Schema creation is not hidden inside API startup.

Startup ordering:

```text
PostgreSQL healthy
 -> one-shot Alembic migration
 -> application services
```

`ati-migrate` runs the repository migrations/stored-function versions and exits.

Application services assume the expected schema exists.

## Backend image

One backend image is reused with different commands for:

- API;
- worker;
- scheduler;
- migrations.

This avoids environment drift between Python services.

## API and worker

The API persists asynchronous work.

The worker claims jobs from PostgreSQL and executes LangGraph investigations.

Investigation execution must survive API container restart because it is not tied to the HTTP-serving process.

## Scheduler

The scheduler determines when monitors or batch-source jobs are due and creates jobs.

It does not perform the substantive investigation/ingestion work itself.

## Frontend development

Base `compose.yaml` represents the canonical local runtime.

A development override such as `compose.dev.yaml` may provide:

- source bind mounts;
- FastAPI reload;
- frontend dev server;
- developer ports.

Frontend developers may optionally run the frontend dev server on the host while Docker provides backend/database services.

## Configuration

Environment-based configuration is loaded into a typed settings object.

Categories include:

- database;
- auth/session;
- provider credentials;
- LLM/model profiles;
- LangSmith/observability;
- investigation budgets;
- RAG;
- DB-IP/source-cache paths;
- logging;
- scheduler.

Commit `.env.example`.

Do not commit `.env` or credentials.

## Networking

Use a private Compose network.

Services address one another by Docker DNS names, not `localhost`.

Host exposure:

- frontend: yes;
- API: yes;
- PostgreSQL: optional/configurable for development;
- worker: no;
- scheduler: no.

## Health

API exposes:

- `/health/live`
- `/health/ready`

Liveness means the process is alive.

Readiness means required local dependencies are usable.

Readiness must not fail merely because an optional external CTI provider is temporarily unavailable.

## Logging

Application containers emit structured logs to stdout/stderr.

Persistent product history belongs in PostgreSQL AuditEvent/investigation timeline, not container log files.

## DB-IP

DB-IP City Lite MMDB lives under:

`${ATI_DATA_DIR}/geo/dbip`

and is mounted read-only into lookup processes where practical.

Dataset/version metadata is retained for provenance.

Refreshing the MMDB does not require rebuilding ATI application images.

## Source cache

Downloaded ATT&CK/CISA/etc. artifacts live under:

`${ATI_DATA_DIR}/source-cache`

The cache aids reproducibility/debugging but is not the authoritative normalized datastore.

## Backup/restore

Use PostgreSQL-native backup tools.

Repository scripts should expose operations such as:

- `scripts/backup-db.sh`
- `scripts/restore-db.sh`

Do not back up a running database by blindly copying the live PostgreSQL data directory.

## Runtime versions

Policy:

- pinned supported Python version;
- pinned supported Node version;
- pinned PostgreSQL/pgvector image;
- Docker Compose v2;
- committed Python lockfile;
- committed frontend lockfile.

No floating runtime versions.

## Test environment isolation

Integration tests use isolated PostgreSQL/pgvector storage and a test-specific Compose project.

Tests must never point at the normal development `ATI_DATA_DIR`.

Use explicit safeguards such as a test database name and unique Compose project.

## Developer commands

The repository exposes simple documented script commands, for example:

```text
./install.sh
./build.sh

docker compose up -d
docker compose down
docker compose run --rm migrate
```

The exact runtime commands may grow as features are implemented, but developers
and coding agents should have a single documented script command surface for
installation and quality validation.
