# Agentic Threat Investigator — Authoritative Documentation

## Table of contents

- [Documents](#documents)

## Documents

- `PRODUCT.md` — product goals, scope, use cases, and boundaries.
- `ARCHITECTURE.md` — system architecture and component boundaries.
- `DOMAIN_MODEL.md` — entities, evidence, relationships, assessment, state, pivots, and stopping.
- `DATA_SOURCES.md` — evidence and research sources plus ingestion rules.
- `DATASOURCE_ARCHITECTURE.md` — datasource architecture: acquisition, protocol/serialization/semantic-format separation, execution correlation, and semantic conversion to Evidence.
- `AGENT_DESIGN.md` — agent roles, provider/LLM/RAG contracts, and decision boundaries.
- `DATABASE.md` — persistence, transactions, migrations, batch upserts, and soft deletion.
- `TESTING.md` — conventional software testing, Python tooling, and source-quality gates.
- `EVALUATION.md` — agent/LLM/RAG evaluation architecture, scenarios, metrics, and release gates.
- `API.md` — `/api/v1` REST contract.
- `FRONTEND.md` — frontend scope and contracts.
- `SECURITY.md` — authentication, authorization, audit, secrets, and agent/tool security.
- `DEPLOYMENT.md` — Podman Compose local deployment and development environment.
- `OBSERVABILITY.md` — LangSmith-first, provider-neutral observability architecture.
- `LICENSING.md` — AGPL and third-party attribution/licensing policy.
- `ROADMAP_V01.md` — completed v0.1 implementation roadmap and historical PR sequence.
- `ROADMAP_V02.md` — active v0.2 roadmap: PR 28 global Evidence and distributed Evidence ingestion.
- `ROADMAP_V03.md` — future v0.3 roadmap: monitors, diffs, findings, jobs, and administration.
- `DETAILED_PR_PLAN_AUTHORING_GUIDE.md` — requirements for coding-agent-ready detailed PR plans.
- `AGENTS.md` — concise coding-agent non-negotiables.

These documents describe the open-source ATI product only.
