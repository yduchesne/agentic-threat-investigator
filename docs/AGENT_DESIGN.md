# Agentic Threat Investigator — Agent Design

## Table of contents

- [Objective](#objective)
- [Agent roles](#agent-roles)
  - [Investigation Coordinator](#investigation-coordinator)
  - [Infrastructure Collector](#infrastructure-collector)
  - [Threat Intelligence Collector](#threat-intelligence-collector)
  - [Threat Research / Context Agent](#threat-research-context-agent)
  - [Evidence Analyst](#evidence-analyst)
  - [Report Writer](#report-writer)
- [Provider contract](#provider-contract)
- [Provider failure behavior](#provider-failure-behavior)
- [Pivot policy](#pivot-policy)
- [LLM contract](#llm-contract)
- [Prompt-injection resistance](#prompt-injection-resistance)
- [LLM failure](#llm-failure)
- [RAG contract](#rag-contract)
- [Observable reasoning](#observable-reasoning)

## Objective

ATI uses agents for interpretation, prioritization, synthesis, and bounded investigative decision-making. Deterministic code retains control of persistence, provider applicability, policy enforcement, budgets, and invariants.

## Agent roles

### Investigation Coordinator

Responsibilities:

- evaluate investigation state;
- determine whether more evidence is needed;
- propose eligible pivots using already discovered entities;
- request threat research when contextual knowledge is needed;
- replan within budget;
- stop when sufficient evidence exists or further progress is exhausted.

The Coordinator cannot manufacture an arbitrary pivot target. A pivot target must already be a root or evidence-discovered entity.

### Infrastructure Collector

Coordinates deterministic infrastructure providers such as:

- DNS;
- RDAP;
- IPinfo Lite;
- DB-IP City Lite.

It does not assess maliciousness.

### Threat Intelligence Collector

Coordinates applicable threat-intelligence providers such as:

- AbuseIPDB;
- ThreatFox;
- URLhaus.

It does not create verdicts.

### Threat Research / Context Agent

Uses RAG to explain concepts already discovered by the investigation, including malware, ATT&CK techniques, vulnerabilities, or explicit contextual analyst questions.

It cannot establish live IOC facts or produce the final Assessment.

### Evidence Analyst

Consumes the persisted evidence snapshot and produces a typed analytical result.

Responsibilities:

- weigh supporting and contradicting evidence;
- distinguish context from maliciousness evidence;
- identify limitations/gaps;
- produce a verdict and confidence;
- state whether the evidence is sufficient or more collection is justified.

### Report Writer

Transforms structured evidence, research, relationships, and Assessment into the final analyst-facing report.

It cannot change the verdict or introduce unsupported facts.

## Provider contract

```python
class ProviderErrorCode(str, Enum):
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTHENTICATION_FAILED = "authentication_failed"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    UNSUPPORTED_INDICATOR = "unsupported_indicator"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_UNAVAILABLE = "provider_unavailable"

class ProviderError(BaseModel):
    provider: str
    code: ProviderErrorCode
    message: str
    retryable: bool
    retry_after_seconds: int | None = None

class ProviderResult(BaseModel):
    provider: str
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[ProviderError] = Field(default_factory=list)

class EvidenceProvider(ABC):
    @property
    @abstractmethod
    def id(self) -> str: ...

    @abstractmethod
    def supports(self, entity: Entity) -> bool: ...

    @abstractmethod
    async def investigate(self, entity: Entity) -> ProviderResult: ...
```

Provider applicability is deterministic.

Providers retrieve and normalize. They do not persist, infer relationships, assess maliciousness, or decide pivots.

## Provider failure behavior

Distinguish:

- positive result;
- valid empty/negative result;
- provider error.

A valid "no hit" result is not globally equivalent to benign evidence.

Infrastructure retries are bounded. Initial policy:

- configurable timeout;
- up to two retries for transient network/429/5xx failures;
- exponential backoff with jitter;
- no retry for permanent auth/unsupported errors.

Rate limits produce typed errors with retry-after information when available.

Independent providers may execute concurrently subject to provider-specific rate/concurrency limits.

## Pivot policy

A pivot is eligible only when:

1. the entity exists in the root/discovered set;
2. the entity type is pivotable;
3. the pivot is relevant to the investigation objective;
4. discovery is supported by observed evidence;
5. it is not already investigated or pending;
6. depth/entity/provider/LLM/replan budgets permit it;
7. the expected information gain justifies the action.

Depth:

- root = 0;
- direct discovery = 1;
- next discovery = 2.

Contextual enrichment does not consume investigative depth.

Network prefixes and ASNs may be enriched but are not recursively expanded into arbitrary contained infrastructure.

Malware triggers research rather than recursive IOC expansion.

## LLM contract

```python
class LlmClient(ABC):
    async def invoke_structured(
        self,
        request: LlmRequest,
        response_model: type[T],
    ) -> T: ...
```

```python
class LlmRequest(BaseModel):
    operation: str
    prompt_version: str
    system_instructions: str
    input: dict[str, Any]
    model_profile: str
    temperature: float | None = None
```

Stable operation identifiers:

- `urn:ati:llm:evidence_analysis`
- `urn:ati:llm:research_synthesis`
- `urn:ati:llm:investigation_planning`
- `urn:ati:llm:report_writing`

Structured output is mandatory for programmatic decisions.

Prompts are source-controlled and versioned.

LLMs cannot:

- mutate persistence directly;
- execute unrestricted HTTP/shell/SQL/Python;
- invent evidence IDs;
- invent RAG chunk citations;
- execute an unvalidated pivot;
- bypass budgets;
- persist hidden reasoning.

Application code validates all referenced evidence/entity/chunk IDs.

## Prompt-injection resistance

Provider and RAG text is untrusted data. System instructions explicitly prohibit following instructions embedded in evidence or retrieved documents.

Raw provider payloads are normally excluded from LLM context; normalized evidence facts are preferred.

## LLM failure

LLM failures are typed and bounded. Examples:

- TIMEOUT
- RATE_LIMITED
- AUTHENTICATION_FAILED
- MODEL_UNAVAILABLE
- CONTEXT_LIMIT_EXCEEDED
- INVALID_STRUCTURED_OUTPUT
- SAFETY_REFUSAL
- PROVIDER_ERROR

Transport retries are bounded, and one structured-output repair attempt may be allowed.

LLM failure does not necessarily fail the investigation. ATI preserves collected evidence and may complete PARTIAL.

## RAG contract

RAG supplies contextual research for already discovered concepts.

```python
class ResearchQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    investigation_id: UUID
    query: str
    entity_ids: list[UUID] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    document_types: list[str] = Field(default_factory=list)
    max_results: int = Field(default=8, ge=1, le=100)

class RetrievedChunk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    chunk_id: UUID
    document_id: UUID
    source_id: str
    text: str
    title: str | None = None
    source_url: str | None = None
    published_at: datetime | None = None
    similarity_score: float | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

class ResearchRetriever(ABC):
    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]: ...
```

The PostgreSQL retriever searches only visible chunks whose provider, model,
model version, and dimension match the query embedding. Non-empty `source_ids`
and `document_types` filters are combined with AND; `entity_ids` remain
contextual subjects and are not a document filter. Results are ordered by
pgvector cosine distance and expose `1 - distance` in `[-1, 1]`; an empty
compatible corpus returns `[]`. Retrieved text is untrusted context.

Every material factual research claim must cite retrieved chunks.

No relevant retrieval result produces an explicit limitation rather than hallucinated context.

## Observable reasoning

ATI exposes observable actions and concise evidence-backed action rationales, such as why a discovered IP was investigated.

ATI does not persist or display hidden chain-of-thought, scratchpads, or provider/model reasoning traces.
