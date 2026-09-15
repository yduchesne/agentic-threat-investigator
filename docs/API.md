# Agentic Threat Investigator — REST API Contract

## Table of contents

- [Principles](#principles)
- [DTO boundary](#dto-boundary)
- [Structured analytical resources](#structured-analytical-resources)
- [Authentication](#authentication)
- [Investigations](#investigations)
- [Investigation subresources](#investigation-subresources)
- [Evidence](#evidence)
- [Relationships](#relationships)
- [Assessment](#assessment)
- [Research](#research)
- [Timeline](#timeline)
- [Map/geolocation](#mapgeolocation)
- [Monitors](#monitors)
- [Findings](#findings)
- [Administration](#administration)
- [Resource identifiers](#resource-identifiers)
- [Pagination](#pagination)
- [Filtering](#filtering)
- [Errors](#errors)
- [Idempotency](#idempotency)
- [Optimistic concurrency](#optimistic-concurrency)
- [Soft deletion](#soft-deletion)
- [Authorization](#authorization)
- [Progress updates](#progress-updates)
- [Versioning](#versioning)
- [No implementation leakage](#no-implementation-leakage)
- [Internal task dispatch](#internal-task-dispatch)
- [Resource versions and history](#resource-versions-and-history)

## Principles

ATI exposes stable domain resources and asynchronous investigation workflows.

The API does not expose provider-specific schemas, ORM/database details, LangGraph internals, or LLM-vendor contracts.

Base path:

`/api/v1`

Format:

JSON over HTTP.

## Delivered contract (PR 23C)

The Investigation REST API described in this document is **delivered** and
served by FastAPI (`src/agentic_threat_investigator/api/`). The delivered
surface covers authentication, investigation creation (asynchronous,
idempotent), investigation list/detail, and the Evidence, Relationships,
RelationshipObservations, Research, Assessment, Report (including the
deterministic Markdown representation), Timeline, geolocation projection,
and scoped generic history
subresources. Every endpoint is documented in the generated OpenAPI document
(pinned by `tests/fixtures/openapi_v1.json`), declares the cookie-session
security scheme, and returns the stable error envelope.

Endpoints still in future sections of this document (Monitors, Findings,
Administration) are **not** part of the v0.1 delivered
surface and must not be consumed.

FastAPI-generated OpenAPI is a supported API artifact.

## DTO boundary

API request/response DTOs are separate from internal domain and persistence models even when fields overlap.

Examples:

- `CreateInvestigationRequest`
- `InvestigationResponse`

Internal refactoring must not silently change the public contract.

## Structured analytical resources

ATI's API exposes structured analytical resources. The frontend and API
clients must never need to parse free-form LLM prose to recover programmatic
meaning.

Internally, agent outputs are first validated as concrete ATI Pydantic models.
API DTOs remain a separate boundary, but they map deterministically from those
validated structured models.

The authoritative representation of an analytical result is therefore:

```text
validated ATI Pydantic model
        |
        v
JSON-compatible structured representation
        |
        v
API response DTO
```

Human-readable Markdown/HTML is a derived presentation and is not the
authoritative API representation.

### Structured fields

Where applicable, API resources expose explicit fields for:

- verdict;
- confidence;
- supporting and contradicting Evidence references;
- findings;
- limitations;
- unresolved questions;
- recommended next steps;
- research claims;
- retrieved-chunk citations;
- report sections and references.

Clients must not be required to extract any of these values from
generated prose.

### Reports

Report endpoints return the structured `InvestigationReport`
representation (or a stable API DTO mapped from it).

PR 23B delivers the domain/application/persistence side of the report
contract; PR 23C exposes it over HTTP. The report resource semantics are:

- a report is an immutable versioned presentation of the current Assessment;
  repeated explicit generation appends a new report version;
- the current report resolves the Investigation's durable `report_id`
  pointer, never `MAX(version)`;
- report version listings are keyset-paginated with canonical order
  `version DESC, id ASC`; soft-deleted reports are hidden;
- verdict and confidence equal the current Assessment exactly;
- findings, research context, limitations, unresolved questions, and
  recommended next steps are authoritative structured snapshots;
- GET never regenerates a report and never invokes an LLM.

If ATI exposes a human-readable report representation, that
representation is generated deterministically from the same validated
structured report. It must not invoke an LLM during request rendering
and must not alter report semantics.

If content negotiation or a dedicated export endpoint is later
introduced, for example Markdown or HTML, the structured JSON report
remains the authoritative resource.

### Deterministic rendering invariant

For a given report version and explicit formatter configuration,
repeated rendering must preserve the same semantic content, verdict,
confidence, findings, citations, limitations, and recommendations.

Rendered content may differ only in presentation aspects explicitly
controlled by formatter inputs, such as target format or locale.

### No model-output leakage

The API does not expose unvalidated raw model responses, model-provider
tool call envelopes, hidden reasoning, or chain-of-thought as analytical
resources.

Operational/debug metadata may be exposed only through a separately
designed diagnostic interface and must not become the authoritative
analytical result.

## Authentication

Primary endpoints:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

Authentication uses server-side sessions and secure cookies.

Delivered behavior:

- `POST /api/v1/auth/login` — body `{"username": "...", "password": "..."}`;
  a successful login returns `200` with the public user DTO
  `{"id": "...", "alias": "...", "role": "..."}` and sets two cookies:
  `ati_session` (HttpOnly, `SameSite=Lax`, `Path=/`, `Secure` outside
  local/dev profiles) and `ati_csrf` (double-submit CSRF token).
  Wrong-password and unknown-user failures are indistinguishable and both
  return `401 invalid_credentials`. Excessive attempts return
  `429 rate_limited`.
- `POST /api/v1/auth/logout` — CSRF-protected; revokes the server-side
  session, expires both cookies, and returns `204`. Already-invalid logout
  is idempotent.
- `GET /api/v1/auth/me` — returns the public user DTO for the current
  session or `401 authentication_required`.

Session tokens are opaque, generated with a CSPRNG (>= 256 bits), and only
their SHA-256 digest is persisted or logged. The raw token is never returned
in JSON. State-changing requests must also present the CSRF cookie token in
the `X-CSRF-Token` header with a matching Origin/Referer.

## Investigations

- `POST /api/v1/investigations`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}`

Creation is asynchronous: a successful `POST` atomically persists the
PENDING Investigation, its durable PostgreSQL investigation job, the
mutation audit event, and the actor-scoped idempotency record in one
transaction, then returns `202 Accepted` with a `Location:
/api/v1/investigations/{id}` header. The request never executes the
Investigation and never uses in-process background tasks; a worker claims
the durable job and invokes `InvestigationRunner` later.

`POST /api/v1/investigations` **requires** an `Idempotency-Key` header
(1..128 visible ASCII characters). Equivalent replays return the same
Investigation; reusing a key for a semantically different request returns
`409 idempotency_conflict`.

Request DTO (`extra="forbid"`, unknown fields rejected):
- `indicators`: 1..N objects `{"type": "<entity type>", "value": "<raw value>"}`;
- `objective`: nonblank, bounded.

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

Delivered routes (PR 23C):

- `GET /api/v1/investigations/{id}/evidence`
- `GET /api/v1/investigations/{id}/evidence/{evidence_id}`
- `GET /api/v1/investigations/{id}/relationships`
- `GET /api/v1/investigations/{id}/relationships/{relationship_id}`
- `GET /api/v1/investigations/{id}/relationship-observations`
- `GET /api/v1/investigations/{id}/relationship-observations/{observation_id}` (PR 24F)
- `GET /api/v1/investigations/{id}/research`
- `GET /api/v1/investigations/{id}/research/{research_result_id}`
- `GET /api/v1/investigations/{id}/assessments`
- `GET /api/v1/investigations/{id}/assessments/current`
- `GET /api/v1/investigations/{id}/assessments/{assessment_id}`
- `GET /api/v1/investigations/{id}/reports`
- `GET /api/v1/investigations/{id}/reports/current`
- `GET /api/v1/investigations/{id}/reports/{report_id}`
- `GET /api/v1/investigations/{id}/reports/{report_id}/markdown`
- `GET /api/v1/investigations/{id}/timeline`
- `GET /api/v1/investigations/{id}/geolocations` (PR 25A)
- `GET /api/v1/investigations/{id}/history`
- `GET /api/v1/investigations/{id}/history/{object_type}/{object_id}`
- `GET /api/v1/investigations/{id}/history/{object_type}/{object_id}/{version}`

Future (not delivered):

- `GET /api/v1/maps` (PR 25B presentation, not a backend resource)

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

### Relationship listing filters

`GET /api/v1/investigations/{id}/relationships` supports bounded explicit
filters (all intersect):

- `source_entity_id` — the exact source entity UUID;
- `target_entity_id` — the exact target entity UUID;
- `entity_id` (PR 24E) — the bounded one-hop neighborhood of one focal
  entity, with **source-or-target OR semantics applied on the server**
  (never merged client-side across two bounded pages);
- `relationship_type` — the exact relationship type URN.

Soft-deleted edges stay excluded. Pagination remains the opaque keyset
cursor bound to the exact filter set (`cursor` reuse across different
entities/filters fails closed).

### RelationshipObservation listing filters

`GET /api/v1/investigations/{id}/relationship-observations` lists the
immutable historical record directly, ordered `retrieved_at DESC, id ASC`
with opaque cursors. Existing filters (all intersect):

- `relationship_id`;
- `source` (exact provider/source);
- `retrieved_from` / `retrieved_to` and `observed_from` / `observed_to`
  (UTC half-open ranges; `observed_at` and `retrieved_at` stay
  independent);
- `limit`, `cursor`.

PR 24E adds entity-centric filters, all evaluated **in SQL through the
joined stable Relationship** (an inner join on `relationship.id =
relationship_observation.relationship_id`; Investigation isolation is
enforced by the observation's own `investigation_id` predicate):

- `entity_id` — focal entity UUID; the query returns observations whose
  edge has this entity as source or target;
- `direction` — `source`, `target`, or `either` relative to `entity_id`
  (required only if a direction is supplied; a bare `entity_id` behaves as
  `either`);
- `counterparty_entity_id` — pins the other endpoint (`source` means
  source=focal AND target=counterparty; `target` means target=focal AND
  source=counterparty; `either` means either orientation);
- `relationship_type` — filters the joined edge's type URN (never copied
  into observation persistence).

Validation rules:

- `direction` without `entity_id` fails with the stable public 400
  `invalid_request` envelope;
- `counterparty_entity_id` without `entity_id` fails the same way;
- a bare `entity_id` is legal and deterministic: `either`.

Self-relationships (source = target = focal) match either OR branch but
are returned once (rows are unique by id). Cursor identity includes the
new filters: a cursor produced for one focal entity/direction/type cannot
be reused for another and fails with the existing
`cursor_filter_mismatch` contract.

Each response row additionally carries the joined stable Relationship
semantics as public projection fields (never persisted duplicates):

```json
{
  "id": "uuid",
  "relationship_id": "uuid",
  "evidence_id": "uuid",
  "investigation_id": "uuid",
  "source": "urn:ati:source:google_public_dns",
  "observed_at": "2026-01-10T09:00:00Z",
  "retrieved_at": "2026-07-01T10:00:00Z",
  "relationship_source_entity_id": "uuid",
  "relationship_target_entity_id": "uuid",
  "relationship_type": "urn:ati:relationship:dns:resolves_to"
}
```

The frontend never issues one Relationship GET per observation, never
downloads unrelated observations to join/filter client-side, and never
reconstructs unbounded relationship history.

### Exact RelationshipObservation read (PR 24F)

`GET /api/v1/investigations/{id}/relationship-observations/{observation_id}`
returns one immutable RelationshipObservation by exact persisted identity,
Investigation-scoped by the path Investigation. The response uses the exact
public list projection shown above (joined stable Relationship semantics
included); observations remain immutable first-class history and are never
routable through generic History.

Semantics:

- the observation exists and belongs to the path Investigation -> `200`
  with `RelationshipObservationResponse`;
- the observation is missing, or belongs to another Investigation -> the
  same stable scoped `404 relationship_not_found` (cross-Investigation
  existence is never revealed);
- a malformed `observation_id` UUID -> the stable `422 validation_error`
  envelope.

The endpoint is authenticated and requires the analyst role. There is no
generic object-by-id resolver and no global observation search.

## Assessment

Assessment endpoints preserve version history and evidence references.

The current assessment endpoint returns the current/final analytical version.

Assessment JSON is mapped from the validated typed `Assessment` model. Verdict,
confidence, evidence references, limitations, unresolved questions, and
recommended next steps are explicit fields and are never recovered by parsing
LLM prose.

## Research

Research responses expose structured claims and citations to retrieved document chunks.

The frontend must not need to parse free-form LLM prose to determine provenance.

The structured research resource is mapped from a validated Pydantic result.
Any human-readable research narrative is a deterministic presentation of that
structured result and must preserve its claim/citation associations.

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

## Reports (delivered)

Report endpoints return the structured `InvestigationReport` DTO mapped from
the validated persisted report resource:

- version listing uses `version DESC, id ASC` keyset pagination;
- `GET .../reports/current` resolves the Investigation's durable
  `report_id` pointer (never `MAX(version)`);
- detail endpoints verify the report belongs to the path Investigation;
  cross-Investigation lookups return `404 report_not_found`;
- `GET .../reports/{report_id}/markdown` returns
  `text/markdown; charset=utf-8` rendered deterministically by the pure
  PR 23B formatter; GET never regenerates a report and never invokes an
  LLM.

## Runtime mode (PR 23D)

`GET /api/v1/runtime` is an authenticated, read-only endpoint returning the
selected intelligence-source composition mode:

```json
{"operating_mode": "fake"}
```

`operating_mode` is exactly `fake` or `production`. It describes which
intelligence-source implementations are composed — it never claims anything
about the LLM implementation (runtime fake mode still uses the configured
real LLM). The response exposes mode only: never provider credentials,
secret reference names, LLM providers, database URLs, filesystem paths, or
the effective configuration. No endpoint can switch the operating mode and
no request can select fake versus production.

## Generic history redaction (delivered)

Generic history identity is `object_type + object_id` (no `natural_key`).
Raw `state`/`diff` JSONB snapshots are never exposed wholesale: each record
is projected through a per-object-type public allowlist. Public object
types:

- `investigation`
- `entity`
- `relationship`
- `assessment`
- `investigation_report`

Credential/session/password/secret/job/internal orchestration types are not
browsable through history and fail closed. RelationshipObservation remains
outside generic history (it is queryable directly as the historical
resource).

## Map/geolocation

### Geolocation projection (PR 25A, delivered)

`GET /api/v1/investigations/{id}/geolocations` (operation id
`list_investigation_geolocations`) returns one bounded server-owned
current geolocation context projection for the Investigation, derived
exclusively from already-persisted immutable `GEOLOCATION` Evidence joined
to its canonical IP entity. The API performs no DB-IP/MMDB lookup, opens
no artifact, invokes no provider, and consults no other source.

The projection contains at most one item per IP entity: the latest
persisted `GEOLOCATION` Evidence by `(retrieved_at DESC, id ASC)`. Each
item retains the exact persisted Evidence ID (`evidence_id`) and Entity ID
(`entity_id`) as provenance; the canonical IP value is `ip_address`.

Response shape:

```json
{
  "items": [
    {
      "evidence_id": "...",
      "entity_id": "...",
      "ip_address": "203.0.113.10",
      "country_code": "US",
      "region": "Washington",
      "city": "Seattle",
      "latitude": 47.6062,
      "longitude": -122.3321,
      "precision": "city",
      "provider": "urn:ati:source:dbip_city_lite",
      "observed_at": null,
      "retrieved_at": "2026-01-01T00:00:00Z"
    }
  ],
  "truncated": false
}
```

- `items` is ordered `ip_address ASC, entity_id ASC`; `truncated` is true
exactly when the projection exceeded the configured server-owned maximum
(`ATI_API_MAX_MAP_GEOLOCATION_ITEMS`). There is no cursor and no
caller-controlled limit: the Map backend never paginates through generic
Evidence.
- `country_code`, `region`, `city` are typed optional location fields;
`latitude`/`longitude` are paired (both present or both absent). Valid
geolocation context without plot coordinates is retained with `null`
coordinates.
- `precision` uses the existing persisted vocabulary (`country`, `region`,
`city`, `unknown`); `provider` is the persisting source identity.
- The response exposes only typed allowlisted fields: arbitrary normalized
`facts`, raw provider payloads, source record ids, and DB-IP
artifact/filesystem locations are never returned.
- Geolocation is approximate network-address context; it never identifies
an attacker's or device's physical location and implies no maliciousness,
attribution, or Assessment confidence.
- Missing or not-visible Investigations return the established collection
semantics: an empty `200` with `items: []` (same as other collection
subresources).

Presentation (Leaflet map, markers, fit-bounds) is PR 25B and remains
outside this document's delivered surface.

Map-origin analyst exploration (PR 25C) introduces **no new production
endpoint**: every Map item's Explore surface reuses the existing typed
Evidence/Relationships/Research list and detail endpoints through the PR
24 PivotWorkspace with a single frontend-only `map_entity` navigation
provenance kind. Exact Evidence provenance continues through the existing
`GET /api/v1/investigations/{id}/evidence/{evidence_id}` detail route. The
deterministic E2E geolocation seeding seam is a harness-only CLI
(`scripts/e2e-seed-geolocation.sh` over `tests/e2e_support/`) that writes
ordinary rows through the normal application repositories into the
throwaway E2E database; it is **not** an HTTP endpoint, carries no
credentials to browsers, and is inert in normal fake mode without the
explicit `ATI_E2E_SEEDING_ENABLED` flag.

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

### Collection query semantics (PR 23A)

The query/read foundation underlying these collections is implemented and
documented in `docs/DATABASE.md`, and the HTTP endpoints map HTTP parameters
directly onto those contracts. The semantics:

- each listed collection has exactly **one canonical v0.1 ordering** (no
  arbitrary client sort selection);
- cursors are **opaque** values that encode only the ordering identity
  needed to continue a query;
- cursors are **bound to their query and filter context**: reusing a cursor
  produced for another collection or another filter set fails closed;
- pagination is **keyset/seek** based; there is no OFFSET-based public
  pagination and no total-count query per page;
- every page is bounded by `limit + 1` continuation reads;
- date ranges are **UTC half-open intervals** (`from` inclusive, `to`
  exclusive);
- RelationshipObservation is a first-class historical resource and is
  queryable independently by relationship/investigation and date;
- generic resource history uses **`object_type + object_id`** as its stable
  object identity; there is no `natural_key`.

## Filtering

v0.1 supports bounded explicit filters rather than a general query language.

Examples:

- investigations by status;
- evidence by source/entity;
- findings by workflow status;
- monitors by enabled state.

PR 23A already implements the typed filter contracts for investigations
(status, created range), evidence (source, subject entity, type, retrieved
range), relationships (source/target entity, type), relationship
observations (source, retrieved/observed ranges), research results (subject
entity, created range), assessments, timeline events (event type, occurred
range), and generic history (object type/object ID, investigation,
operation, occurred range).

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

Mutation endpoints where retry duplication matters require an idempotency
key. Most importantly:

`POST /api/v1/investigations`

Delivered semantics:

- the `Idempotency-Key` header is **required** and bounded (1..128 visible
  ASCII characters);
- identity is scoped by `authenticated actor ID + operation ("create
  investigation") + key digest`; different actors may reuse the same raw
  key independently;
- only the SHA-256 digest of the key is persisted (never the raw value);
- the request fingerprint is a canonical SHA-256 over the semantic
  normalized request (schema marker, sorted canonical indicator identities,
  normalized objective) — raw HTTP JSON bytes are never fingerprinted, so
  property reordering and whitespace replays identically;
- a repeated request from the same authenticated actor with the same key
  and an equivalent request returns the same created investigation
  (consistent `202` semantics even after completion);
- the same key with a semantically different request returns
  `409 idempotency_conflict`;
- race safety is owned by the database unique scope; concurrent identical
  submissions create exactly one Investigation and one logical job;
- retention policy: no cleanup scheduler exists in v0.1; deployment defines
  record retention (see `docs/DATABASE.md`).

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

## Internal task dispatch

PR 19C makes no REST API change. `TaskDispatcher` is an internal application boundary and does not appear in request or response DTOs. Public contracts do not expose dispatcher implementations, worker IDs, broker subjects, delivery attempts, or acknowledgement status.

## Resource versions and history

Persisted domain resources expose their database-assigned `version` where relevant. Mutable-resource writes use expected-version semantics and return HTTP 409 on detected concurrent modification. Semantic DELETE is soft deletion and produces a new version/history record. Resource-history endpoints may expose immutable post-operation snapshots and diffs without exposing secrets or internal persistence mechanics.
