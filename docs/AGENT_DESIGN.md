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
- [Execution boundary](#execution-boundary)
- [Provider contract](#provider-contract)
- [Provider failure behavior](#provider-failure-behavior)
- [Provider URL, path, and redirect safety](#provider-url-path-and-redirect-safety)
- [Pivot policy](#pivot-policy)
- [LLM contract](#llm-contract)
- [Structured agent output contract](#structured-agent-output-contract)
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

Runs one bounded, standalone contextual research execution on demand (PR 22B):

- one immutable `ResearchAgentRequest` (investigation, contextual subject entity, normalized query, retrieval-context filters, bounded `max_results`);
- exactly one retrieval pass through `ResearchRetriever`;
- deterministic prompt construction, then structured-only synthesis through the existing `LlmClient`;
- the model may cite only stable `DocumentChunk.citation_id` values from the exact chunks supplied to that execution;
- the application validates citation membership and provenance closure, stamps all durable IDs/timestamps, and persists one immutable `ResearchResult` through `ResearchResultPersistenceService`;
- empty retrieval deterministically persists a zero-claim/zero-citation result without spending a model call;
- retrieved documents are untrusted data;
- the agent has no tools, no web browsing, no recursive retrieval, and no model-side retrieval loop.

It uses RAG to explain concepts already discovered by the investigation, including malware, ATT&CK techniques, vulnerabilities, or explicit contextual analyst questions.

It cannot establish live IOC facts or produce the final Assessment, and it never creates Evidence, Relationships, Relationships observations, or Assessment/verdict/confidence content.

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

## Execution boundary

```text
Coordinator / agent policy
 -> authorized work
 -> TaskDispatcher
 -> executor/handler
```

The Coordinator and deterministic policy decide what work is eligible and authorized. The dispatcher only routes that already-selected work to an execution mechanism. It does not decide pivots, assess Evidence, choose goals, bypass deterministic policy, or expose broker mechanics to agents.

PR 19C introduces only the concrete provider-work contract already required by the running investigation. Task contracts should be generalized only when a real second work category requires it; speculative agent envelopes are not part of this boundary.

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
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)
    errors: tuple[ProviderError, ...] = Field(default_factory=tuple)

class EvidenceProvider(ABC):
    @property
    @abstractmethod
    def id(self) -> str: ...

    @abstractmethod
    def supports(self, entity: Entity) -> bool: ...

    @abstractmethod
    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult: ...
```

Provider applicability is deterministic.

Providers retrieve and normalize. They do not persist, infer relationships, assess maliciousness, or decide pivots.

For Google Public DNS and RDAP, Evidence objects carry `raw_payload=None`
(conservative data-minimization pending source-terms review).

## Provider failure behavior

Distinguish:

- positive result;
- valid empty/negative result;
- provider error.

A valid "no hit" result is not globally equivalent to benign evidence.

### Layered provider-response validation

External responses are untrusted and must pass all applicable validation
layers before Evidence construction:

1. **Transport/schema:** status, media type, response size, JSON shape, strict
   scalar types, required fields, and container types.
2. **Field semantics:** protocol syntax, numeric/address/name bounds,
   canonicalization, and standards-defined special values.
3. **Cross-field/object consistency:** requested object class and identity,
   range ordering/containment, address family, and mutually dependent fields.
4. **Collection/RR-set consistency:** uniqueness, ambiguity, CNAME/owner
   attribution, null/sentinel cardinality, and contradictions among entries.
5. **ATI eligibility:** whether a normalized protocol value is a reusable
   entity, a non-discoverable source fact, or an explicitly supported
   sentinel. Protocol validity does not automatically imply entity
   eligibility.
6. **Provenance:** subject, source, source record identity, credential-free
   source URL, and observation/retrieval timestamps.

Validation must inspect original external input before lossy normalization can
erase invalid syntax. Fact builders consume only validated canonical values.
Provider-originated malformed data must produce a typed provider error and
must not escape as incidental parser, index, decoding, arithmetic, or model
exceptions. Programming errors and cancellation continue to propagate.

For every optional external field or nested entry, source documentation must
state whether absence is accepted and whether malformed content invalidates
the response or is omitted. Implementations must not infer this policy from a
fixture. Standards-valid protocol forms that differ from ATI entity syntax
require an explicit normalized representation; they must not be rejected as
malformed merely because a general entity canonicalizer cannot represent them.

Infrastructure retries are bounded. Initial policy:

- configurable timeout;
- up to two retries for transient network/429/5xx failures;
- exponential backoff with jitter;
- no retry for permanent auth/unsupported errors.

Rate limits produce typed errors with retry-after information when available.

HTTP infrastructure uses `ProviderHttpClient.request_json()` for all provider
data I/O. Streaming with bounded buffer prevents oversized responses.
Transport errors produce generic messages (no URL/path leakage). Provider
modules own their provider-specific parsing and normalization; IANA RDAP
bootstrap parsing, selection, and caching live in the narrowly named
`rdap_bootstrap.py` module permitted by the implementation plan.
Responses must match accepted provider-specific media types: Google DNS accepts
`application/json` and `application/dns-json`; RDAP accepts
`application/rdap+json` and `application/json`. Other `+json` types are not
implicitly accepted. Redirects are terminal (never followed to unapproved hosts).
Retry backoff computes the exponential delay for the retry number, applies
bounded symmetric jitter to that component alone, and then takes the larger
of the jittered exponential delay and a valid HTTP 429 `Retry-After`
value, so a negative jitter never schedules a retry earlier
than an in-cap `Retry-After` minimum. `Retry-After` is parsed and reported
only for HTTP 429 rate-limit responses; timeout, network, and 5xx retries
use local exponential/jitter backoff only, and permanent statuses never
parse or report it. Backoff arithmetic is overflow-safe: huge retry
indices and oversized valid 429 `Retry-After` values saturate at
`provider_retry_max_delay_seconds` instead of raising, while the parsed
retry-after value may still be reported unchanged on the final rate-limit
error. The final result is clamped to
`provider_retry_max_delay_seconds`, which remains the hard upper bound even
when the provider requests a longer wait; the reported `retry_after_seconds`
error field is never altered by that clamping. The injectable jitter source
is sampled exactly once per retry delay and must return a finite value in
`[0.0, 1.0]`; an invalid sample is a propagated programming error rather than
a typed provider failure. The rate limiter computes wait outside the scheduling
lock so concurrent acquirers are not
blocked, and cancellation safely releases concurrency permits and reclaims
the canceled rate reservation so canceled waiters never delay later requests.

Independent providers may execute concurrently subject to provider-specific rate/concurrency limits.

## Provider URL, path, and redirect safety

Live-provider URLs are security boundaries. ATI validates the actual URL used
for each request before acquiring limiter permits or performing I/O; validating
an unused configuration value or helper result is insufficient.

### Base URLs

Production provider and authoritative-service base URLs must:

- use an explicit `https` scheme;
- contain a nonempty, syntactically valid DNS hostname or IP literal;
- contain no username, password, or other userinfo;
- contain no query string or fragment;
- contain a valid port when a port is present; and
- be reconstructable from their validated components without changing
  authority semantics.

Missing or relative schemes, scheme-relative authorities, malformed IPv6
brackets, invalid ports, empty hostname labels, invalid hostname characters,
and malformed IDNA hostnames are rejected. Canonicalization lowercases and
IDNA-normalizes DNS hosts, removes a terminal DNS root dot, canonicalizes IP
literals, preserves IPv6 brackets, and omits the default HTTPS port. A valid
non-default port is preserved.

A malformed hard-coded or configured production endpoint is a programming or
configuration error: raise `ValueError` before limiter acquisition or I/O. Do
not convert programming errors into `ProviderResult` failures.

IANA RDAP bootstrap URLs are untrusted response data. For services matching the
entity value, ATI scans services and each service's URL list in registry source
order, skips invalid candidates, and selects the first valid HTTPS base. No
matching service produces `NOT_FOUND`; one or more matching services but no
valid candidate produces non-retryable `INVALID_RESPONSE`. Equal-specificity
IP or ASN matches that select different canonical authorities are ambiguous and
produce `INVALID_RESPONSE`. Invalid candidates never trigger HTTP, and ATI
never falls back to a hard-coded RIR.

### Resource paths and query parameters

Entity values cannot choose or replace the selected authority. ATI constructs
only provider-approved resource paths from already validated canonical entity
values and percent-encodes the resource component. RDAP uses only:

- `domain/{canonical-domain}`;
- `ip/{canonical-ip}`; and
- `autnum/{decimal-asn}`.

A resource path containing a scheme, authority, query, fragment, or malformed
URL syntax is rejected with `ValueError` before I/O. Raw entity values must not
be concatenated into URLs. Google DNS uses the fixed
`https://dns.google/resolve` endpoint and passes validated `name` and `type`
values through the HTTP client's query-parameter API; it does not manually
construct a query string or send EDNS client-subnet data.

Invalid entity values return one non-retryable `UNSUPPORTED_INDICATOR` without
clock evaluation or HTTP. Validation must inspect the original value before a
lossy normalization step can erase malformed syntax. Valid case differences,
surrounding whitespace, one terminal DNS root dot, and valid IDNA forms remain
canonicalizable; malformed repeated terminal dots, empty labels, embedded
whitespace, underscores, and invalid or overlong labels are rejected.

### Redirects and response-provided links

Provider HTTP clients set `follow_redirects=False`. Every redirect is terminal
and maps to `INVALID_RESPONSE`; ATI does not follow a `Location` value even when
it names another HTTPS host. Redirect targets are never logged or persisted.
Supporting redirects in the future requires an explicit authority-validation
contract and deterministic tests.

RDAP links, entity links, notice links, and remark links are untrusted text.
ATI validates fields required by the response schema but never uses those links
as lookup targets, recursively calls them, or derives ownership,
relationships, pivots, or maliciousness from them.

### Errors, logging, and provenance

Malformed URL handling never exposes the full URL, credentials, query values,
headers, redirect target, or response body in an error or log. Provider-facing
failures use stable typed codes and generic messages. Persisted `source_url`
values are credential-free: Google DNS stores the fixed endpoint without its
query string, while RDAP stores the exact validated authoritative resource URL.
`asyncio.CancelledError` always propagates unchanged.

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

The PR 20B-implemented application boundary (`app.llm`) supersedes the
earlier illustrative ``invoke_structured`` sketch. It is a narrow, typed,
structured-output-only operation with an explicit ATI-owned Pydantic output
type and no provider-specific response objects, chat history, configuration
reads, persistence, or hidden retries:

```python
ResponseT = TypeVar("ResponseT", bound=BaseModel)

class LlmClient(ABC):
    async def generate_structured(
        self, *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT: ...
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

## Structured agent output contract

All agent/LLM operations that produce programmatic ATI results MUST return
schema-validated structured output. Free-form model prose is not an
authoritative programmatic result.

The contract is:

```text
LLM / Agent
    |
    v
structured model output
    |
    v
Pydantic validation
    |
    v
typed ATI result
    |
    +--> persistence / workflow decisions
    |
    v
deterministic formatter
    |
    v
human-readable Markdown / HTML / plain text
```

### Authoritative representation

For each agent operation, ATI defines a concrete Pydantic response
model. `LlmClient.generate_structured()` returns an instance of that
model, not an unvalidated string or arbitrary dictionary.

The validated Pydantic object, and its JSON-compatible serialized form,
are the authoritative machine-readable representation of the agent
result.

Examples include:

- Coordinator decisions;
- Evidence Analyst results / `Assessment`;
- Threat Research synthesis results;
- report content / `InvestigationReport`.

Structured result models SHOULD use strict validation and
`extra="forbid"` where appropriate so that unexpected model-generated
fields cannot silently become part of ATI semantics.

### Validation before effect

No agent result may affect investigation state, persistence, pivots,
assessment, research claims, or reporting until:

1. the LLM output has been parsed into the expected Pydantic model;
2. Pydantic/schema validation succeeds;
3. ATI deterministic validators verify semantic invariants that cannot
   be expressed by the schema alone;
4. all referenced entity, Evidence, chunk, Assessment, and other
   resource IDs are verified against authoritative ATI state;
5. policy and budget checks succeed where applicable.

Invalid structured output follows the bounded LLM failure/repair policy
and must never be treated as a partially valid result.

### No authoritative free-form output

Agents MUST NOT return free-form prose as the system-of-record
representation for a programmatic result.

Text fields inside a structured model are permitted when prose is itself
part of the domain result, for example:

- an evidence-reference rationale;
- an assessment summary;
- a research claim;
- a report finding;
- a limitation;
- a recommended next step.

Such text remains contained within, validated by, and attributable
through the surrounding typed result.

### Deterministic human-readable rendering

Human-readable output is produced from validated structured ATI models
by deterministic formatter/presenter code.

A formatter:

- performs no LLM call;
- performs no investigation;
- introduces no new facts;
- changes no verdict or confidence;
- changes no citation/reference;
- adds no new recommendation;
- does not infer missing information;
- does not mutate the structured source object.

Given the same structured object and formatter configuration, the
formatter MUST produce the same semantic output. Presentation-only
variation such as an explicit locale or date-format setting is allowed
when it is an input to the formatter.

Conceptually:

```python
class ReportFormatter(ABC):
    @abstractmethod
    def format(self, report: InvestigationReport) -> str:
        ...
```

Concrete implementations may include deterministic Markdown, HTML, or
plain-text renderers.

### Agent-role implications

**Investigation Coordinator**

The Coordinator returns a typed decision containing actions and
references to already-known ATI entity IDs. It does not communicate
executable decisions through prose. Deterministic policy code validates
every proposed action before execution.

**Evidence Analyst**

The Evidence Analyst returns a typed analytical model such as
`Assessment`. Verdict, confidence, evidence references, limitations,
unresolved questions, and next steps are explicit fields.

**Threat Research / Context Agent**

Research synthesis returns typed claims and citations to retrieved chunk
IDs. The frontend or report layer never needs to parse prose to recover
citation structure.

**Report Writer**

The Report Writer returns a typed `InvestigationReport`. It does not
return the final Markdown/HTML document directly. A deterministic
formatter renders the validated report for human consumption.

The Report Writer cannot change the current Assessment
verdict/confidence and cannot introduce unsupported facts. Deterministic
validation enforces these invariants before the report becomes
authoritative.

### Serialization

Persisted or API-visible structured agent results serialize using their
defined JSON-compatible representation. Serialization must preserve
stable identifiers, enum values, citations, ordering where semantically
relevant, and versioned domain semantics.

Serialization is not a substitute for validation: ATI validates the
Pydantic model first and serializes the validated result.

## Prompt-injection resistance

Provider and RAG text is untrusted data. System instructions explicitly prohibit following instructions embedded in evidence or retrieved documents.

Raw provider payloads are normally excluded from LLM context; normalized evidence facts are preferred.

## LLM failure

LLM failures are typed and bounded. The PR 20B v0.1 taxonomy is deliberately
small (`app.llm.LlmErrorCode`):

- TIMEOUT
- PROVIDER_FAILURE
- INVALID_STRUCTURED_OUTPUT
- CONFIGURATION_ERROR

Finer-grained provider categories (rate limiting, content refusal, model
availability) remain future work and are conservatively mapped onto these
categories at the adapter. Every ``LlmError`` carries a stable code and an
explicit retryability flag; messages are bounded and content-free (no
prompts, model output, raw exception text, or credentials), and mapped
errors never retain the raw provider/framework exception as ``__cause__``.
No setup-time or invocation-time provider/framework exception escapes the
taxonomy. The Evidence Analyst retries only a retryable
``INVALID_STRUCTURED_OUTPUT`` error, at most once (attempts hard-limited to
``1..2``), and counts every actual invocation durably against the
Investigation LLM budget. Cancellation propagates unchanged.

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

### Research Agent execution

```text
ResearchAgentRequest
 -> ResearchQuery
 -> ResearchRetriever        (one bounded pass; its transaction closes inside)
 -> deterministic prompt
 -> LlmClient                (structured-only synthesis)
 -> citation-membership validation
 -> ResearchResult           (application stamps IDs, clock, anchors)
 -> ResearchResultPersistenceService
```

One execution performs at most one retrieval pass and at most one bounded
structured-output sequence. The model-visible citation token is the stable
`DocumentChunk.citation_id`; `chunk_id` is operational provenance only and is
deliberately not the model citation contract. A schema-valid claim that cites
a stable citation ID outside the exact supplied chunk set fails closed before
any persistence, even when the citation exists elsewhere in the corpus. Empty
retrieval deterministically persists a zero-claim/zero-citation result without
spending a model call, and the LLM may return `claims=()` when supplied
context is irrelevant or insufficient. Structured-output repair is bounded to
at most one attempt (`max_structured_output_attempts` in `1..2`), repair is
limited to retryable `INVALID_STRUCTURED_OUTPUT`, every actual invocation is
durably reserved against the Investigation LLM budget, and cancellation
propagates unchanged. Retrieval and LLM work never run inside a long
PostgreSQL transaction; persistence is one short atomic insert through the
PR 22A seam. Contradictory supplied material is represented as separately
cited claims, never reconciled with a verdict or confidence.

## Observable reasoning

ATI exposes observable actions and concise evidence-backed action rationales, such as why a discovered IP was investigated.

ATI does not persist or display hidden chain-of-thought, scratchpads, or provider/model reasoning traces.
