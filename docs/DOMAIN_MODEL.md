# Agentic Threat Investigator — Domain Model

## Table of contents

- [Entity](#entity)
- [Evidence](#evidence)
- [Deterministic extraction (PR 18B)](#deterministic-extraction-pr-18b)
- [Relationships](#relationships)
- [Assessment](#assessment)
- [Structured agent results](#structured-agent-results)
- [Geolocation](#geolocation)
- [Investigation state](#investigation-state)
- [Stopping](#stopping)
- [Pivot behavior](#pivot-behavior)
- [Persisted resource versions and history](#persisted-resource-versions-and-history)

## Entity

```python
class EntityType(str, Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    NETWORK_PREFIX = "network_prefix"
    ASN = "asn"
    ORGANIZATION = "organization"
    MALWARE = "malware"
    ATTACK_TECHNIQUE = "attack_technique"
    VULNERABILITY = "vulnerability"
```

```python
class Entity(BaseModel):
    id: UUID | None = None
    type: EntityType
    value: str
    display_name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
```

Entities are globally deduplicated by `(type, canonical_value)`.

Canonicalization is type-specific:

- domain: lowercase, normalized trailing dot and IDN handling;
- IP: canonical compressed representation;
- URL: strict HTTP/HTTPS-only identity contract (below);
- ASN: canonical numeric identity, rendered consistently;
- network prefix: canonical network boundary;
- CVE: uppercase;
- ATT&CK identifier: canonical ATT&CK ID;
- malware: strict nonblank lowercase machine identifier (at most 128
  characters, only lowercase ASCII letters, digits, and ``.``, ``_``, ``-``).
  This narrow machine-identity grammar is shared by the sources that publish
  machine malware identifiers (ThreatFox). Printable names, aliases, and
  human-readable labels never determine MALWARE identity, and no
  ORGANIZATION canonicalization contract exists in v0.1.

### URL identity contract (v0.1)

ATI URL canonicalization (`canonicalize_url`) is deterministic,
conservative, stable across Python runtimes, safe for persistence
identity and provider identity checks, and non-lossy with respect to
security-relevant URL components:

- Only the `http` and `https` schemes are supported; every other scheme
  is rejected.
- Rejected before I/O: userinfo (username/password), fragments, missing
  hosts, invalid ports (including port 0 and ports above 65535),
  embedded whitespace, and control characters.
- The scheme is lowercased; DNS hosts are strictly validated (strict
  DNS validation, lowercased, IDNA-encoded); IP hosts use the canonical
  IP representation; IPv6 hosts render bracketed in the canonical URL.
- Default ports (80 for `http`, 443 for `https`) are omitted; other
  ports are preserved.
- An empty path becomes `/`. The path, query, and non-default ports are
  preserved exactly: query parameters are never sorted or dropped,
  dot-segments are never resolved, trailing slashes are never removed,
  application-specific path case is never normalized, and percent
  escapes are preserved byte-for-byte after syntax validation (every
  `%` must introduce two hex digits).
- Fragments are excluded because they are not transmitted in HTTP
  requests and would create ambiguous IOC identity. An empty query is
  indistinguishable from no query and canonicalizes to no query.
- Canonicalization is idempotent; canonically equivalent spellings
  produce identical output; meaningful differences (path, query, query
  order, port, percent-encoding, scheme) remain distinct identities.

An item is an entity when it is independently identifiable, reusable across observations, and meaningful as a relationship participant. Otherwise it is an attribute or evidence fact.

## Deterministic extraction (PR 18B)

Extraction is a pure, database-free application layer
(``app/extraction``) that converts one normalized, persisted ``Evidence``
observation into canonical discovered entity identities and evidence-backed
relationship assertions. It performs no I/O, persistence, provider calls,
SQL, LangGraph, LLM calls, ``RelationshipObservation`` creation, or
database-ID allocation, and depends only on domain models, source IDs,
Pydantic, and the standard library.

### Output contract

```python
class ExtractedEntity(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: EntityType
    value: str  # canonical
    display_name: str | None = None

class EntityIdentity(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: EntityType
    value: str  # canonical

class RelationshipAssertion(BaseModel):
    model_config = ConfigDict(frozen=True)
    source: EntityIdentity
    type: RelationshipType
    target: EntityIdentity
    evidence_id: UUID

class ExtractionResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    entities: tuple[ExtractedEntity, ...] = ()
    relationships: tuple[RelationshipAssertion, ...] = ()
```

The persisted ``Relationship`` model is never an extraction output because
it requires database entity UUIDs; extraction never fabricates identifiers.
``RelationshipObservation`` creation, entity/relationship upserts, and
transactionality belong to PR 18C. The application service consumes this
output without reinterpretation: preflight rejects non-canonical identities,
assertion Evidence-ID mismatches, uncovered endpoints, and duplicates
(extraction output is already deduplicated); it then resolves canonical
identities, preserves the Evidence ID exactly, and appends one immutable
observation per assertion in the same transaction as Evidence and graph
mutations.

### Extraction rules

- Extraction consumes normalized Evidence facts only, never provider HTTP
  responses or ``raw_payload``.
- Every extracted identity passes the shared domain canonicalizer for its
  type; a fact value that canonicalizes differently than promised is a
  contract failure, not a silent repair.
- Every relationship assertion is directly justified by the documented
  source semantics in `DATA_SOURCES.md` and carries the supporting persisted
  Evidence ID. If an assertion is required and ``Evidence.id`` is ``None``,
  extraction fails explicitly.
- No relationship is inferred merely because two values co-occur.
  ``RELATED_TO`` does not exist and no existing relationship URN is
  repurposed.
- Provider confidence/scores never become ATI relationship confidence.
- Fact-only values remain fact-only (see the per-source matrix in
  `DATA_SOURCES.md`).
- Malformed normalized facts raise ``EvidenceExtractionError``; extraction
  is all-or-nothing per Evidence and never returns a partial result. The
  error carries only safe context: source, bounded reason category, and the
  Evidence ID when known.
- Entity deduplication key: ``(type, canonical value)``. Assertion
  deduplication key: ``(source type, source value, relationship type,
  target type, target value, evidence id)``. Duplicates collapse within one
  Evidence preserving first-seen order; the first non-null display name
  wins.
- The dispatcher maps ``(source, evidence type)`` to one extractor. A known
  source with an impossible evidence type is an extraction error; an
  unknown or unregistered source deliberately yields an empty result.

### Source extraction matrix

- **Google Public DNS** (`DNS`): A/AAAA assert answer owner DOMAIN
  ``RESOLVES_TO`` answer IP_ADDRESS and discover the address; CNAME asserts
  ``CNAME_OF`` and discovers the target; NS asserts ``USES_NAME_SERVER`` and
  discovers the target; ordinary MX asserts ``USES_MAIL_SERVER`` and
  discovers the exchange; the null-MX sentinel (``0 .``) produces nothing;
  PTR discovers the target DOMAIN only and asserts no relationship; TXT and
  SOA produce nothing; the DNS root is never an entity. Forward-record
  relationships use the normalized ``answers[].name`` owner, not blindly the
  Evidence subject, because CNAME chains change owners.
- **ThreatFox** (`THREAT_INTELLIGENCE`): for every ``facts.matches[]``, the
  Evidence subject IOC is asserted ``ASSOCIATED_WITH`` the canonical MALWARE
  derived from the machine identifier; ``malware_printable`` is display
  metadata only; repeated same-malware matches deduplicate; confidence,
  threat type, tags, references, and timestamps are ignored.
- **URLhaus** (`THREAT_INTELLIGENCE`): ``matches[].url`` discovers a
  canonical URL entity; direct URL records with non-null ``matches[].host``
  discover a canonical DOMAIN or IP_ADDRESS entity after strict validation;
  host-response records carry ``host=null`` and never synthesize a host from
  ``queried_host``. No URL↔host relationship is emitted (no existing
  ``RelationshipType`` is repurposed for URL composition). Payload hashes,
  filenames, file types, sizes, signatures, tags, statuses, threat labels,
  and timestamps remain fact-only; MALWARE is never inferred from URLhaus
  data.
- **RDAP** (`NETWORK` with an IP subject, conservative): when normalized
  ``cidr0_cidrs`` supplies explicit prefixes, each prefix is canonicalized,
  verified to contain the subject address, discovered as ``NETWORK_PREFIX``,
  and asserted as the subject IP ``BELONGS_TO`` the prefix. No prefix is
  synthesized from arbitrary start/end ranges. RDAP handles/display names
  never become ORGANIZATION entities or ``REGISTERED_TO``/``OPERATED_BY``/
  ``ANNOUNCED_BY`` assertions, RDAP domain nameservers produce no extraction,
  and domain/ASN RDAP (`REGISTRATION`) returns an empty result.
- **IPinfo Lite** (`NETWORK`): a present ``facts.asn`` discovers the
  canonical ASN entity; an absent ASN yields an empty result. No
  relationship is emitted and ``as_name``/``as_domain`` never become an
  ORGANIZATION; ``ANNOUNCED_BY`` is not authorized for IPinfo evidence.
- **DB-IP City Lite** (`GEOLOCATION`) and **AbuseIPDB** (`REPUTATION`):
  always empty extraction results. Geolocation and reputation remain
  contextual/source facts and never leak graph structure.

## Evidence

```python
class EvidenceType(str, Enum):
    DNS = "urn:ati:evidence:dns"
    REGISTRATION = "urn:ati:evidence:registration"
    NETWORK = "urn:ati:evidence:network"
    GEOLOCATION = "urn:ati:evidence:geolocation"
    REPUTATION = "urn:ati:evidence:reputation"
    THREAT_INTELLIGENCE = "urn:ati:evidence:threat_intelligence"
    VULNERABILITY = "urn:ati:evidence:vulnerability"
    THREAT_RESEARCH = "urn:ati:evidence:threat_research"
```

```python
class EntityRef(BaseModel):
    id: UUID | None = None
    type: EntityType
    value: str

class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID | None = None
    investigation_id: UUID
    type: EvidenceType
    subject: EntityRef
    source: str
    source_record_id: str | None = None
    source_url: str | None = None
    observed_at: datetime | None = None
    retrieved_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] | None = None
```

Evidence is an immutable observation from a source about one primary subject.
Its subject and nested JSON facts/raw payload are defensively snapshotted and
recursively immutable, not merely protected from top-level field assignment.

Provider-specific scores remain normalized facts. ATI analytical confidence belongs in Assessment.

`observed_at` is the time represented by the source when known. `retrieved_at` is when ATI retrieved the information.

## Relationships

```python
class RelationshipType(str, Enum):
    RESOLVES_TO = "urn:ati:relationship:dns:resolves_to"
    CNAME_OF = "urn:ati:relationship:dns:cname_of"
    USES_NAME_SERVER = "urn:ati:relationship:dns:uses_name_server"
    USES_MAIL_SERVER = "urn:ati:relationship:dns:uses_mail_server"
    BELONGS_TO = "urn:ati:relationship:network:belongs_to"
    ANNOUNCED_BY = "urn:ati:relationship:routing:announced_by"
    REGISTERED_TO = "urn:ati:relationship:registration:registered_to"
    OPERATED_BY = "urn:ati:relationship:organization:operated_by"
    ASSOCIATED_WITH = "urn:ati:relationship:threat:associated_with"
    USES_TECHNIQUE = "urn:ati:relationship:attack:uses_technique"
    EXPLOITS = "urn:ati:relationship:vulnerability:exploits"
```

URN values are durable external identifiers stored in the database/API. Enum member names are implementation conveniences.

```python
class Relationship(BaseModel):
    id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    type: RelationshipType
```

```python
class RelationshipObservation(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID
    relationship_id: UUID
    evidence_id: UUID
    investigation_id: UUID | None
    observed_at: datetime | None
    retrieved_at: datetime
    source: str
    confidence: float | None
```

Relationship identity is unique by source entity, relationship URN, and target entity.

A Relationship is the durable semantic edge. RelationshipObservation records when and why ATI observed or imported the assertion and is frozen after validation.

Historical relationships are not deleted merely because they are no longer current.

## Assessment

```python
class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"

class AssessmentConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class EvidenceReference(BaseModel):
    evidence_id: UUID
    rationale: str

class Assessment(BaseModel):
    id: UUID | None = None
    investigation_id: UUID
    verdict: Verdict
    confidence: AssessmentConfidence
    summary: str
    analyzed_evidence_ids: list[UUID]
    supporting_evidence: list[EvidenceReference] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
```

Assessment is ATI's interpretation of evidence. Every material conclusion must be traceable to evidence IDs.

Verdict semantics:

- BENIGN: positive evidence supports a benign interpretation.
- SUSPICIOUS: meaningful risk indicators exist, but evidence is insufficient for MALICIOUS.
- MALICIOUS: evidence materially supports malicious activity/infrastructure.
- INCONCLUSIVE: evidence is absent, insufficient, weak, or materially conflicting.

"Nothing malicious found" is not equivalent to BENIGN.

Confidence expresses confidence in the verdict, not severity.

## Structured agent results

ATI agent outputs are domain/application data, not opaque conversational
transcripts.

Every programmatic agent result is represented by a concrete Pydantic model.
The validated model is authoritative; its JSON-compatible serialization is
the canonical machine representation used for persistence, API mapping,
evaluation, and deterministic rendering.

Free-form LLM output is not a domain object and is not persisted as the
authoritative result of an agent operation.

### Common rules

Structured agent result models:

- use explicit typed fields;
- use stable enums/URNs where ATI defines them;
- reference existing resources by stable IDs;
- reject unexpected fields where appropriate;
- distinguish required, optional, and empty values explicitly;
- contain no hidden chain-of-thought;
- contain no infrastructure clients, tool objects, prompts, or model-provider
  state.

Text fields are allowed when the text is an explicit part of the domain
result, but the surrounding structure remains authoritative.

### Coordinator result

The Coordinator's executable recommendation is represented as a typed result,
conceptually:

```python
class CoordinatorDecision(BaseModel):
    action: CoordinatorAction
    pivot_entity_ids: list[UUID] = Field(default_factory=list)
    research_entity_ids: list[UUID] = Field(default_factory=list)
    stop_reason: StopReason | None = None
```

The exact implementation model may evolve, but these invariants do not:

- referenced entities already exist in the root/discovered set;
- the model cannot manufacture an arbitrary target;
- deterministic policy validates eligibility and budgets;
- prose is not parsed to determine the action.

### Evidence Analyst result

`Assessment` is the authoritative Evidence Analyst output.

Verdict and confidence are typed fields. Supporting/contradicting
evidence references, limitations, unresolved questions, and recommended
next steps remain explicit structured fields rather than being recovered
from a prose report.

### Threat Research result

Threat Research output uses a typed result containing structured claims
and retrieved-chunk references. Material research claims must remain
attributable to chunk IDs.

### InvestigationReport

The Report Writer produces a structured `InvestigationReport` Pydantic
model.

At minimum, the report model must preserve structured references to:

- the investigation;
- the authoritative Assessment;
- key findings;
- Evidence references;
- research/chunk citations where used;
- limitations;
- recommended next steps.

The exact field decomposition is finalized with the Report Writer PR,
but the following are hard invariants:

1. the report is a Pydantic model;
2. its JSON-compatible serialization is authoritative;
3. the report references, rather than redefines, the Assessment verdict
   and confidence;
4. material claims are traceable to Evidence or research citations;
5. the Report Writer cannot change the Assessment verdict/confidence;
6. the final human-readable document is a deterministic rendering of
   this structured model.

### Deterministic rendered representations

Markdown, HTML, and plain-text reports are derived representations, not
separate analytical domain objects.

A rendered representation MUST NOT contain a material semantic claim
that is absent from the structured source model.

The same structured model plus the same explicit formatter configuration
must produce semantically identical rendered output.

## Geolocation

```python
class GeoPrecision(str, Enum):
    COUNTRY = "country"
    REGION = "region"
    CITY = "city"
    UNKNOWN = "unknown"

class GeoLocation(BaseModel):
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    provider: str
    precision: GeoPrecision
```

Geolocation is approximate contextual information. It does not identify the physical location of an attacker or device.

## Investigation state

```python
class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"

class InvestigationTriggerType(str, Enum):
    MANUAL = "manual"
    MONITOR = "monitor"
    API = "api"

class PivotStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"

class PivotRequest(BaseModel):
    entity_id: UUID
    reason: str
    depth: int
    status: PivotStatus = PivotStatus.PENDING

class InvestigationBudget(BaseModel):
    max_depth: int
    max_entities: int
    max_provider_calls: int
    max_replans: int
    provider_calls_used: int = 0
    replans_used: int = 0
```

The budget is extended by implementation with separate LLM call limits/counters.

### Investigation lifecycle

The approved PR 18A status lifecycle is narrow and deterministic:

```text
PENDING  -> RUNNING | FAILED
RUNNING  -> COMPLETED | PARTIAL | FAILED
COMPLETED/PARTIAL/FAILED  (terminal)
```

An identical target status is not a transition: the persistence layer treats
it as an unchanged result without allocating a version or writing history.
Transitioning to a terminal status stamps `completed_at` when absent. The
lifecycle is validated by the domain (`can_transition_status`) before any
database mutation and revalidated against the locked PostgreSQL row inside
`ati.update_investigation_status`, so a concurrent writer cannot invalidate a
transition after the pre-lock check.

PR 18A also exposes, by explicit maintainer approval: an optional optimistic
`expected_version` argument on status updates (a stale expectation conflicts
without mutation), and Investigation soft deletion following the standard
soft-deletion conventions.

`InvestigationState` additionally carries optional database-owned persistence
metadata — `version`, `created_at`, `updated_at`, `deleted_at`, and
`deleted_by_actor_id` — following the `Entity` persistence-metadata
convention. Reads return the authoritative database values; callers must not
supply them, and the persistence layer never serializes them into `budget`
or `operational_state`.

`started_at` and `completed_at` must be timezone-aware and are normalized to
UTC; naive values are rejected. `started_at` is required and the schema
enforces `NOT NULL`.

```python
class InvestigationError(BaseModel):
    source: str | None = None
    code: str
    message: str
    recoverable: bool

class InvestigationState(BaseModel):
    investigation_id: UUID
    status: InvestigationStatus
    trigger_type: InvestigationTriggerType
    trigger_id: UUID | None = None
    root_entity_ids: list[UUID]
    objective: str
    discovered_entity_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    relationship_ids: list[UUID] = Field(default_factory=list)
    pending_pivots: list[PivotRequest] = Field(default_factory=list)
    pending_provider_work: list[ProviderWorkItem] = Field(default_factory=list)
    completed_provider_work: list[ProviderWorkItem] = Field(default_factory=list)
    current_provider_work: ProviderWorkItem | None = None
    last_provider_outcome: ProviderExecutionOutcome | None = None
    investigated_entity_ids: list[UUID] = Field(default_factory=list)
    research_required_for_entity_ids: list[UUID] = Field(default_factory=list)
    research_result_ids: list[UUID] = Field(default_factory=list)
    assessment_id: UUID | None = None
    report_id: UUID | None = None
    budget: InvestigationBudget
    stop_reason: str | None = None
    errors: list[InvestigationError] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None
```

State contains IDs and operational workflow information, not raw provider payloads, complete document chunks, prompts, database clients, repositories, HTTP clients, or hidden reasoning.

### Provider work orchestration (PR 19A)

PR 19A adds typed provider-work models to the domain (pure Pydantic, no
LangGraph dependency) and deterministic queue mechanics in
`app/orchestration`:

```python
class ProviderWorkItem(BaseModel):
    provider: SourceId
    entity_id: UUID
    depth: int = Field(ge=0)

class ProviderExecutionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"

class ProviderExecutionOutcome(BaseModel):
    work_item: ProviderWorkItem
    status: ProviderExecutionStatus
    evidence_ids: tuple[UUID, ...] = ()
    discovered_entity_ids: tuple[UUID, ...] = ()
    relationship_ids: tuple[UUID, ...] = ()
    error: InvestigationError | None = None
```

ProviderResult execution-status contract (approved): a mixed result carrying
both Evidence and provider errors is a valid partial provider result. The
executor persists valid Evidence in provider-return order and returns
`SUCCEEDED` when at least one Evidence observation committed and no
extraction, persistence, or timeline failure followed; otherwise `FAILED`
takes precedence and all previously committed IDs remain in the outcome.
Only the first provider error, in provider-return order, is retained — its
stable code and retryability, never its free-form message — and the
`PROVIDER_WORK_COMPLETED` timeline event carries that code as its
`error_code`. Errors without Evidence fail the work; an all-empty result
succeeds. No `PARTIAL` execution status exists in PR 19B.

The work identity is exactly `(provider, entity_id, depth)` and is used only
for deterministic queue duplicate suppression. Work items carry operational
identifiers only; no entity values, provider instances, reasons, or metadata
dictionaries.

The orchestration queue helpers (`enqueue_provider_work`,
`select_next_provider_work`/`select_provider_work`, `record_provider_outcome`)
are pure functions over `InvestigationState`:

-   enqueue appends in input order, skipping any work identity already
    pending or already completed;
-   selection is strictly FIFO with no semantic priority, evidence
    inspection, or pivot policy;
-   recording an outcome (success or failure) moves the work item from
    pending to completed exactly once, records
    `last_provider_outcome`, merges `evidence_ids`, `relationship_ids`,
    and `discovered_entity_ids` preserving first-seen order, appends the
    outcome's typed `InvestigationError` when present, increments
    `budget.provider_calls_used` exactly once, and
    clears `current_provider_work`;
-   a work item never exists simultaneously in pending and completed
    collections, and failure is still completed work (retry policy is not
    part of PR 19A).

Discovering an entity updates the working set only; it does not enqueue
further provider work. Adaptive pivot scheduling, budget enforcement, and
stopping policy remain PR 21. The state remains JSON-serializable via
`model_dump(mode="json")` and reconstructable through Pydantic validation,
and the persistence layer stores the new fields inside the schemaless
`operational_state` JSONB document (no migration required).

## Investigation timeline (PR 19B)

The analyst-facing workflow timeline is a dedicated append-only domain model
(`domain/investigation_timeline.py`), distinct from `AuditEvent`,
domain-object history, application logs, and distributed tracing:

```python
class InvestigationTimelineEventType(str, Enum):
    INVESTIGATION_STARTED = "investigation_started"
    PROVIDER_WORK_STARTED = "provider_work_started"
    PROVIDER_WORK_COMPLETED = "provider_work_completed"
    PROVIDER_WORK_FAILED = "provider_work_failed"
    EVIDENCE_PERSISTED = "evidence_persisted"
    ENTITIES_DISCOVERED = "entities_discovered"

class InvestigationTimelineEvent(BaseModel):
    id: UUID
    investigation_id: UUID
    type: InvestigationTimelineEventType
    occurred_at: datetime  # timezone-aware, normalized to UTC
    provider: SourceId | None = None
    target_entity_id: UUID | None = None
    evidence_ids: tuple[UUID, ...] = ()
    entity_ids: tuple[UUID, ...] = ()
    relationship_ids: tuple[UUID, ...] = ()
    error_code: str | None = None
```

Invariants:

-   events are immutable; there is no update or delete operation anywhere
    in the stack (domain, repository, or database API);
-   events carry typed identifiers and a stable event type only. There is
    deliberately no free-form `reason` field: presentation prose, when
    required, is derived deterministically from the event type and fields.
    Raw provider bodies, stack traces, prompts, secrets, and
    chain-of-thought never appear in timeline events;
-   `EVIDENCE_PERSISTED` is emitted only after PR 18C commits the
    observation; `PROVIDER_WORK_COMPLETED` is emitted only after all
    intended processing completes; a failed append never rolls back already
    committed domain data and surfaces a typed `timeline_error` instead.

Event-shape contract (enforced by a Pydantic `model_validator(mode="after")`
and mirrored by PostgreSQL CHECK constraints for the error-code grammar):

-   `INVESTIGATION_STARTED`: `provider`, `target_entity_id`, and
    `error_code` are `None`; all ID tuples are empty.
-   `PROVIDER_WORK_STARTED`: `provider` and `target_entity_id` are required;
    `error_code` is `None`; all ID tuples are empty.
-   `EVIDENCE_PERSISTED`: `provider` and `target_entity_id` are required;
    exactly one Evidence ID is required; Entity/Relationship ID tuples may
    be empty; `error_code` is `None`.
-   `PROVIDER_WORK_COMPLETED`: `provider` and `target_entity_id` are
    required; aggregate ID tuples may be empty; `error_code` may carry the
    retained first provider error for the approved mixed-result contract.
-   `PROVIDER_WORK_FAILED`: `provider`, `target_entity_id`, and `error_code`
    are required; all ID tuples are empty because committed IDs live in the
    operational outcome and prior `EVIDENCE_PERSISTED` events.
-   `ENTITIES_DISCOVERED`: at least one Entity ID is required; `error_code`
    is `None`; the executor does not emit this currently-unused event.

`error_code` is bounded to 64 ASCII characters matching
`^[a-z][a-z0-9_]{0,63}$`; leading/trailing whitespace is rejected, never
stripped or normalized. The same grammar is enforced by the database CHECK
constraint so an invalid code is rejected even if model validation is
bypassed. Append-only enforcement is an application boundary: the repository
ABC exposes append and chronological read only, and no ATI routine mutates
timeline events; direct owner/admin SQL is outside that boundary, with
runtime-role privilege separation deferred as future hardening.

## Stopping

```python
class StopReason(str, Enum):
    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    NO_ELIGIBLE_PIVOTS = "no_eligible_pivots"
    DEPTH_LIMIT_REACHED = "depth_limit_reached"
    ENTITY_BUDGET_EXHAUSTED = "entity_budget_exhausted"
    PROVIDER_BUDGET_EXHAUSTED = "provider_budget_exhausted"
    REPLAN_LIMIT_REACHED = "replan_limit_reached"
    FATAL_ERROR = "fatal_error"
```

```python
class AnalysisDisposition(str, Enum):
    SUFFICIENT = "sufficient"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    EXHAUSTED = "exhausted"
```

Initial configurable defaults:

- `max_depth = 2`
- `max_entities = 10`
- `max_provider_calls = 40`
- `max_replans = 3`

LLM calls have a separate configurable budget.

## Pivot behavior

PIVOTABLE:

- DOMAIN
- IP_ADDRESS
- URL

ENRICHABLE/CORRELATION:

- NETWORK_PREFIX
- ASN
- ORGANIZATION

RESEARCHABLE:

- MALWARE
- ATTACK_TECHNIQUE
- VULNERABILITY

A pivot is allowed only when semantically relevant, evidence-backed, not already handled, within budget, and expected to improve the investigation objective.

The LLM may propose only existing root/discovered entity IDs. Deterministic application policy authorizes execution.

Every autonomous pivot must have a provenance chain to user input or observed evidence.

## Persisted resource versions and history

Every persisted ATI domain resource exposes a database-assigned `version`. A new version is created only for a successful CREATE, semantic UPDATE, or soft DELETE. `UNCHANGED` persistence outcomes do not change version. Version numbers are monotonically increasing table-wide revisions and need not be contiguous for an individual object.

Domain-object history records the complete state after each mutation plus a shallow JSONB diff. This is distinct from `AuditEvent`: history answers how state evolved; audit answers who attempted/performed a business or security action and its outcome.
