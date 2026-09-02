# Agentic Threat Investigator — Observability

## Principle

ATI emits structured application telemetry and agent/LLM traces through internal observability abstractions.

LangSmith is the initial v0.1 agent/LLM observability backend, but it is not an architectural dependency.

ATI must remain functional when tracing is disabled or unavailable.

## Observability layers

| Layer | Purpose | v0.1 persistence/backend |
|---|---|---|
| Application logs | Runtime/service diagnostics | Structured stdout/stderr |
| Metrics | Operational counters/performance | Initial instrumentation; export backend may evolve |
| Investigation timeline | Analyst-facing workflow history | PostgreSQL |
| Audit | Security/governance history | PostgreSQL |
| Agent/LLM traces and evals | Development/debug/evaluation | LangSmith initially |

The investigation timeline and audit log are product data. LangSmith traces are not.

## Internal abstraction

Agent/application code depends on ATI observability interfaces rather than scattered direct LangSmith SDK calls.

Conceptual interfaces include:

```python
class TraceBackend(ABC):
    @abstractmethod
    def start_span(
        self,
        *,
        operation: str,
        attributes: dict[str, Any],
    ) -> TraceSpan:
        ...

    @abstractmethod
    def record_error(
        self,
        error: Exception,
        attributes: dict[str, Any],
    ) -> None:
        ...
```

Implementations may include:

- `LangSmithObservability`;
- `NoOpObservability`;
- future `OpenTelemetryObservability`.

## LangSmith v0.1

LangSmith may be used for:

- LangGraph traces;
- LLM calls;
- tool execution visibility;
- prompt/model comparison;
- evaluation datasets;
- regression experiments.

ATI does not depend on LangSmith for:

- investigation state;
- persistence;
- retries;
- job execution;
- audit;
- timeline;
- correctness.

`ATI_OBSERVABILITY_ENABLED=false` must leave investigation behavior intact.

Tracing failures are non-fatal.

## Future open-source replacement

The architecture plans for a Docker-deployed open-source observability backend.

OpenTelemetry is the preferred portability layer.

Future topology may be:

```text
ATI services
    |
ATI observability abstraction
    |
OpenTelemetry
    |
OTel Collector
    |
+----------------------+
| Langfuse             |
| or Phoenix           |
| or compatible backend|
+----------------------+
```

Langfuse and Phoenix are plausible LLM-aware replacements. Generic OTel-compatible systems such as Jaeger or Grafana Tempo may also participate where appropriate.

v0.1 should architect for OTel portability without requiring a full OTel stack before it provides value.

## Correlation

Telemetry propagates stable identifiers:

- `investigation_id`;
- `request_id`;
- `job_id`.

These identifiers correlate API, worker, graph, provider, RAG, and LLM activity.

## Provider telemetry

Record normalized metadata such as:

- provider ID;
- entity ID;
- start/end/duration;
- outcome;
- evidence count;
- retry count;
- typed error category.

Do not log credentials or authorization headers.

## LLM telemetry

Record:

- investigation ID;
- graph/node/agent role;
- operation URN;
- model provider/model identifier;
- model profile;
- prompt version;
- timing;
- token counts where available;
- retry count;
- structured-output validation result;
- error category;
- budget consumption.

Do not persist hidden chain-of-thought.

## RAG telemetry

Record:

- research query metadata;
- subject entity IDs;
- retrieval count;
- retrieved chunk IDs;
- source IDs;
- ranking/similarity metadata where useful;
- latency;
- synthesis validation/citation outcome.

## Data minimization

Default telemetry favors identifiers and normalized execution metadata.

Do not automatically record:

- API keys;
- passwords;
- session cookies/tokens;
- authorization headers;
- unrestricted raw provider payloads;
- hidden reasoning;
- secret-bearing prompts;
- unrestricted document content.

Full prompt/content capture, if ever enabled for development/evaluation, must be explicit and redactable.

## Structured logging

Logs use structured fields.

Example:

```json
{
  "timestamp": "...",
  "level": "INFO",
  "service": "ati-worker",
  "event": "provider_call_completed",
  "investigation_id": "...",
  "job_id": "...",
  "provider": "urn:ati:source:threatfox",
  "duration_ms": 183,
  "evidence_count": 2
}
```

## Metrics vocabulary

Initial metric names should remain stable even if the exporter/backend changes.

Examples:

- `ati_investigations_started_total`
- `ati_investigations_completed_total`
- `ati_investigations_partial_total`
- `ati_investigations_failed_total`
- `ati_provider_calls_total`
- `ati_provider_errors_total`
- `ati_provider_latency_seconds`
- `ati_llm_calls_total`
- `ati_llm_errors_total`
- `ati_llm_tokens_input_total`
- `ati_llm_tokens_output_total`
- `ati_rag_retrievals_total`
- `ati_rag_retrieved_chunks_total`
- `ati_jobs_pending`
- `ati_jobs_running`

A Prometheus-compatible export path may be added without changing the domain.

## Evaluation portability

Canonical evaluation scenarios, expected results, and evaluator logic live in the repository, for example:

```text
evals/
├── scenarios/
├── expected/
├── datasets/
└── evaluators/
```

LangSmith may execute/visualize evaluations, but it is not the sole owner of the expected truth set.

Switching observability platforms must not require redefining ATI's canonical evaluation semantics.

## Failure behavior

Observability is fail-open relative to investigation execution.

```text
trace export failure
 -> structured warning
 -> bounded/no retry storm
 -> investigation continues
```

Observability outages do not cause investigation `FAILED`.
