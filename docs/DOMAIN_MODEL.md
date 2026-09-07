# Agentic Threat Investigator — Domain Model

## Table of contents

- [Entity](#entity)
- [Evidence](#evidence)
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
- ASN: canonical numeric identity, rendered consistently;
- network prefix: canonical network boundary;
- CVE: uppercase;
- ATT&CK identifier: canonical ATT&CK ID.

An item is an entity when it is independently identifiable, reusable across observations, and meaningful as a relationship participant. Otherwise it is an attribute or evidence fact.

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
