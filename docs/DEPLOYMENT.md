# Agentic Threat Investigator — Local Deployment and Development Environment

## Table of contents

- [v0.1 deployment target](#v01-deployment-target)
- [Runtime topology](#runtime-topology)
- [Persistent host root](#persistent-host-root)
- [Environment isolation](#environment-isolation)
- [Data safety](#data-safety)
- [PostgreSQL](#postgresql)
- [Database migrations](#database-migrations)
- [Backend image](#backend-image)
- [API and worker](#api-and-worker)
- [Scheduler](#scheduler)
- [Frontend development](#frontend-development)
- [Configuration](#configuration)
- [Networking](#networking)
- [Health](#health)
- [Logging](#logging)
- [DB-IP](#db-ip)
- [Artifact datasets](#artifact-datasets)
- [Backup/restore](#backuprestore)
- [Runtime versions](#runtime-versions)
- [Test environment isolation](#test-environment-isolation)
- [Developer commands](#developer-commands)
- [Configuration profiles](#configuration-profiles)
- [Database baseline update](#database-baseline-update)

## v0.1 deployment target

ATI v0.1 deploys locally with Podman Compose.

Containers are disposable. Durable data is not.

## Runtime topology

```text
Host
 |
 +-- Podman Compose
 |    +-- ati-frontend
 |    +-- ati-api
 |    +-- ati-worker
 |    +-- ati-scheduler
 |    +-- ati-migrate (one-shot)
 |    +-- ati-postgres (PostgreSQL + pgvector)
 |
 +-- ATI_DATA_DIR
      +-- postgres/data
      +-- datasets
           +-- dbip-city-lite
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
├── datasets/
│   ├── dbip-city-lite/
│   ├── mitre-attack/
│   ├── cisa-kev/
│   └── other/
├── backups/
└── runtime/
```

PostgreSQL uses an explicit bind mount:

```yaml
volumes:
  - ${ATI_DATA_DIR}/postgres/data:/var/lib/postgresql/data
```

DB-IP and artifact datasets are likewise explicitly mounted where required, read-only for ingestion consumers where practical.

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

`podman compose down` must be safe for durable ATI data.

Persistent application data must not depend on Podman-managed anonymous/named-volume lifecycle.

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

Frontend developers may optionally run the frontend dev server on the host while Podman provides backend/database services.

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
- DB-IP/artifact dataset paths;
- logging;
- scheduler.

Commit `.env.example`.

Do not commit `.env` or credentials.

### Provider credential provisioning

Provider composition (`ProviderComposition`) is not yet started by any
current Compose service; no v0.1 service constructs live evidence
providers at this time. When provider composition is activated for a
service in a future PR, that PR must provision each provider credential
(`ATI_IPINFO_LITE_TOKEN`, `ATI_ABUSEIPDB_API_KEY`) to that service only,
preferably through the Compose secret mechanism, and must not place the
resolved values into `Settings`.

Until then, executing the provider composition directly on the host
requires exporting `ATI_IPINFO_LITE_TOKEN` and `ATI_ABUSEIPDB_API_KEY`
into the process environment:

```bash
export ATI_IPINFO_LITE_TOKEN="..."
export ATI_ABUSEIPDB_API_KEY="..."
```

Placing a token or API key in an unexported `.env` file does not make it
available to `EnvVarSecretsResolver`, which reads the process environment.
Pydantic loading of `.env` into `Settings` does not export values to the
process environment, and Compose does not inject every `.env` value into
a container automatically. This applies to both provider tokens and API
keys (`ATI_IPINFO_LITE_TOKEN`, `ATI_ABUSEIPDB_API_KEY`).

## Networking

Use a private Compose network.

Services address one another by Podman network DNS names, not `localhost`.

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

The DB-IP IP to City Lite MMDB artifact lives under the datasets store:

`file://${ATI_DATA_DIR}/datasets/dbip-city-lite/city-lite.mmdb`

The DB-IP City Lite provider is composed only when the artifact URI setting
`ATI_DBIP_CITY_LITE_ARTIFACT_URI` is configured; blank (the default) disables
the provider. The configured artifact must already exist and be readable at
composition time — there is no downloader in ATI and no DB-IP API access.

Operator procedure:

1. Obtain the DB-IP IP to City Lite MMDB from the authoritative DB-IP source
   (<https://db-ip.com/db/lite.php>);
2. comply with the DB-IP attribution/license terms (CC BY 4.0; see
   `docs/LICENSING.md`);
3. place the artifact at the configured dataset location, for example
   `${ATI_DATA_DIR}/datasets/dbip-city-lite/city-lite.mmdb`;
4. configure the credential-free artifact URI
   `ATI_DBIP_CITY_LITE_ARTIFACT_URI=file://...`;
5. grant the API/worker container read access to the artifact path
   (read-only mounts where practical);
6. restart/reload the consuming processes: the MMDB reader is opened once at
   composition time, so refreshing the artifact requires a restart/reload to
   take effect.

Dataset/version metadata may be retained alongside the artifact for
provenance. Refreshing the MMDB does not require rebuilding ATI application
images. Do not hard-code a release-month filename into configuration.

## Artifact datasets

Already-acquired ATT&CK/CISA/etc. artifacts live under:

`${ATI_DATA_DIR}/datasets/<source>/`

Consumers receive this directory as a read-only mount where practical and address artifacts with canonical `file://` URIs. Batch ingestion does not download artifacts, and credentials must never appear in artifact URIs. PostgreSQL remains the authoritative normalized datastore.

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
- Podman with a Compose provider (`podman compose` via `podman-compose`, or an
  external Compose implementation wired to the Podman socket);
- committed Python lockfile;
- committed frontend lockfile.

No floating runtime versions.

## Test environment isolation

Integration tests use isolated PostgreSQL/pgvector storage and a test-specific Compose project.

Tests must never point at the normal development `ATI_DATA_DIR`.

Use explicit safeguards such as a test database name and unique Compose project.

## Developer commands

The repository should expose simple documented commands, for example:

```text
make up
make down
make migrate
make test
make integration-test
make quality
make backup
make restore
```

The exact implementation may be Make/scripts, but developers and coding agents should have a single documented command surface.

## Configuration profiles

All ATI processes use the profile mechanism defined in `CONFIGURATION.md`. `ATI_CONFIG_PROFILE` selects the profile and defaults to `default`. Compose manifests should make the selected profile explicit where appropriate. Source-controlled profile modules contain no production secrets; secrets are supplied through deliberate runtime mechanisms.

## Database baseline update

ATI v0.1 targets a pinned PostgreSQL 18 image plus a verified compatible pgvector release. Batch size is an operational configuration value (for example `db_batch_size`) enforced by the application before composite-array submission to PostgreSQL; the exact default is benchmark-driven.
