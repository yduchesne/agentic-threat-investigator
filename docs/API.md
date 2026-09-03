# Agentic Threat Investigator — REST API Contract

## Principles

ATI exposes stable domain resources and asynchronous investigation workflows.

The API does not expose provider-specific schemas, ORM/database details, LangGraph internals, or LLM-vendor contracts.

Base path:

`/api/v1`

Format:

JSON over HTTP.

FastAPI-generated OpenAPI is a supported API artifact.

## DTO boundary

API request/response DTOs are separate from internal domain and persistence models even when fields overlap.

Examples:

- `CreateInvestigationRequest`
- `InvestigationResponse`

Internal refactoring must not silently change the public contract.

## Authentication

Primary endpoints:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

Authentication uses server-side sessions and secure cookies.

## Investigations

- `POST /api/v1/investigations`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}`

Creation is asynchronous and returns `202 Accepted`.

Example request:

```json
{
  "indicators": [
    {
      "type": "domain",
      "value": "example.com"
    }
  ],
  "objective": "Determine whether this domain is suspicious and identify associated infrastructure."
}
```

Example response:

```json
{
  "id": "uuid",
  "status": "pending",
  "created_at": "2026-09-02T17:00:00Z"
}
```

## Investigation subresources

- `/api/v1/investigations/{id}/evidence`
- `/api/v1/investigations/{id}/relationships`
- `/api/v1/investigations/{id}/research`
- `/api/v1/investigations/{id}/assessments`
- `/api/v1/investigations/{id}/assessments/current`
- `/api/v1/investigations/{id}/reports`
- `/api/v1/investigations/{id}/timeline`
- `/api/v1/investigations/{id}/geolocations`

## Evidence

Evidence is read-only through normal application endpoints.

Responses expose normalized facts and provenance.

Raw provider payloads are not exposed by default.

## Relationships

Relationships expose stable ATI relationship URNs.

Example:

```json
{
  "id": "uuid",
  "type": "urn:ati:relationship:dns:resolves_to",
  "source_entity_id": "uuid",
  "target_entity_id": "uuid"
}
```

## Assessment

Assessment endpoints preserve version history and evidence references.

The current assessment endpoint returns the current/final analytical version.

## Research

Research responses expose structured claims and citations to retrieved document chunks.

The frontend must not need to parse free-form LLM prose to determine provenance.

## Timeline

The timeline is an analyst-facing sequence of observable workflow events such as:

- investigation started;
- provider query completed;
- entity discovered;
- pivot executed;
- threat research requested;
- assessment produced;
- report completed.

It does not expose hidden reasoning, raw prompts, or LangGraph implementation details.

## Map/geolocation

The geolocation endpoint returns investigation-relevant approximate geographic data and provenance suitable for the map.

## Monitors

- `POST /api/v1/monitors`
- `GET /api/v1/monitors`
- `GET /api/v1/monitors/{id}`
- update/enable/disable operations
- `DELETE /api/v1/monitors/{id}` with soft-delete semantics

## Findings

- `GET /api/v1/findings`
- `GET /api/v1/findings/{id}`
- workflow operations such as acknowledge/dismiss

## Administration

Administrative endpoints live under:

`/api/v1/admin`

including user and minimal system administration.

## Resource identifiers

Public resource IDs are opaque UUIDs.

Semantic identifiers such as relationship, evidence, source, LLM operation, and audit action types use stable ATI URNs.

## Pagination

Collections use cursor pagination.

Example:

`GET /api/v1/investigations?limit=50&cursor=...`

Response:

```json
{
  "items": [],
  "next_cursor": "..."
}
```

Server configuration controls default and maximum limits.

## Filtering

v0.1 supports bounded explicit filters rather than a general query language.

Examples:

- investigations by status;
- evidence by source/entity;
- findings by workflow status;
- monitors by enabled state.

## Errors

Consistent envelope:

```json
{
  "error": {
    "code": "investigation_not_found",
    "message": "Investigation was not found.",
    "request_id": "..."
  }
}
```

Stable error codes are contract. Human-readable messages may evolve.

Representative mappings:

- 400 invalid request;
- 401 authentication required;
- 403 forbidden;
- 404 resource not found;
- 409 conflict;
- 422 validation error;
- 429 rate limited;
- 500 internal error;
- 503 dependency unavailable.

Never expose Python stack traces, SQL errors, secrets, provider raw responses, or LLM internals.

## Idempotency

Mutation endpoints where retry duplication matters support an idempotency key.

Most importantly:

`POST /api/v1/investigations`

A repeated request from the same authenticated actor with the same key and equivalent request returns the same created investigation.

## Optimistic concurrency

Mutable resources such as monitors/users expose a version and require expected-version semantics for updates.

Conflicting updates return HTTP 409 rather than silently losing changes.

## Soft deletion

API DELETE means soft deletion for persistent domain/application resources.

Immutable Evidence, RelationshipObservation, and AuditEvent have no normal DELETE endpoint.

## Authorization

- unauthenticated: 401;
- authenticated but unauthorized: 403;
- analyst operations: ADMIN or ANALYST;
- administrative operations: ADMIN.

Authorization is enforced server-side.

## Progress updates

v0.1 uses polling of investigation/timeline resources.

WebSockets are not required. SSE may be introduced later if justified.

## Versioning

Within `/api/v1`:

- compatible fields may be added;
- existing semantics are not silently changed;
- published URN values remain stable;
- breaking changes require a new API version.

## No implementation leakage

Public responses do not expose internal identifiers such as LangGraph checkpoint IDs, reducer names, raw tool-call internals, ORM metadata, or model-provider implementation state unless a future explicit debug interface is designed.

## Resource versions and history

Persisted domain resources expose their database-assigned `version` where relevant. Mutable-resource writes use expected-version semantics and return HTTP 409 on detected concurrent modification. Semantic DELETE is soft deletion and produces a new version/history record. Resource-history endpoints may expose immutable post-operation snapshots and diffs without exposing secrets or internal persistence mechanics.
