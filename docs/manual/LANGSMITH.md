# LangSmith

`LangSmith` is used for both observability and evaluation. Those integrations are deliberately separated in the codebase.

## References

We suggest reading the following in the given order, as they provide information that is foundational to this document:

- [Core Concepts](CORE_CONCEPTS.md): Presents core concepts such as `Entity`, `Evidence`, etc.
- [Investigations](INVESTIGATIONS.md): Goes over the investigation workflow, especially the notion of __pivoting__.
- [Agentic Architecture](AGENTIC.md): Goes deeper than this document in the details of the different agents and the use of `LangChain`/`LangGraph`.
- [Testing](TESTING.md): Describes the different forms of testing in ATI (including agent evals).

## Observability

ATI declares the `LlmObservability` interface, a backend-neutral application-level facade for observing one LLM operation. Its contract is intentionally very small:

```python
class LlmObservability(ABC):

    @abstractmethod
    @contextmanager
    def observe(
        self,
        observation: LlmObservation,
    ) -> Iterator[None]:
        ...
```

`LangSmith` has its implementation of the interface: `LangSmithLlmObservability`. Its usage amounts to:

```python
with observability.observe(observation):
    result = await llm_client.generate_structured(...)
```

The input (`observation`) is an `LlmObservation` instance. It describes the operation in question using bounded metadata rather than prompt/output content. The `LangSmith` adapter supports the following fields (among others):

- `operation_name`
- `model_provider`
- `model_name`
- `model_profile`
- `prompt_version`
- `investigation_id`

The important architectural property is that this is metadata about the LLM operation, not the LLM conversation itself. More specifically, the `LangSmith` implementation explicitly avoids sending:

- Prompt
- Model response
- Raw evidence
- Retrieved research chunks
- Chain-of-thought
- Secrets

### Decoupling

The `LlmObservability` interface is what agents depend on. This allows using such  implementations:

- `NoOpLlmObservability`
- `OpenTelemetryLlmObservability`
- `TestLlmObservability`
- `LangSmithLlmObservability`
- ...

### Fail-Open Behavior

The `context-manager` contract (hidden behind Python's `with` statement) is important, as it allows guaranteed error handling, in accordance with `LangSmith`'s tracing expectations:

```python
with observability.observe(obs):
    ...
    # succeeds
```

vs 

```python
with observability.observe(obs):
    ...
    raise SomeError(...)
```

The `LangSmith` implementation translates that into approximately:

```
observe()
   │
   ├── start observation/run
   │
   ├── execute caller's operation
   │
   └── finish
        ├── outcome = success
        └── outcome = error
```

The `LangSmith` adapter is __fail-open__ with respect to observability.

If `LangSmith` itself is unavailable or its API fails:

```
LLM operation succeeds
        +
LangSmith interaction fails
        ↓
LLM operation still succeeds
```

Observability is not allowed to become an availability dependency of ATI's investigation. Conversely, an exception from the operation being observed is not swallowed.

## Evaluation

On the evaluation path, `LangSmith` is primarily an external dataset/experiment backend and visualization system. 

They key boundary is: ATI decides correctness; LangSmith records and presents it.

The flow is:

```
Repository-owned scenarios
        │
        │ sync / verify
        ▼
LangSmith Dataset
        │
        │ remote mirror only
        │
        ▼
ATI executes benchmark locally
        │
        ├── real ATI agents/orchestration
        ├── real evaluators
        └── ATI determines PASS / FAIL / ERROR
        │
        ▼
EvaluationRunResult
        │
        │ publish
        ▼
LangSmith Experiment
        ├── run status
        ├── per-case results
        ├── per-evaluator results
        └── experiment metadata
```

There three main `LangSmith` responsibilities:

1. __Dataset mirroring__. Repository scenarios such as evidence-analyst/v1, research-agent/v1, and investigation/v1 are projected into LangSmith datasets. sync creates missing remote content; verify checks that the remote dataset exactly corresponds to the repository-owned dataset. Drift fails closed. The repository remains the source of truth.
2. __Experiment recording__. ATI executes each benchmark itself through its normal evaluation runner. `LangSmith` does not execute ATI's target via evaluate()/aevaluate(). Once ATI has an `EvaluationRunResult`, it creates a `LangSmith` experiment associated with that execution.
3. __Result and metadata publication__. ATI publishes categorical pass / fail / error feedback at run, case, and evaluator levels, along with bounded metadata such as commit SHA, dataset/version, prompt/model information, fixture version, evaluator version, etc. This gives `LangSmith` useful experiment history and comparison/visualization capabilities.

### Dataset Mirroring

ATI manages the `LangSmith` evaluation dataset programmatically through the `LangSmith` Python SDK/API. There is no need to manually create and populate the dataset in the LangSmith UI.

The automation path is:

```
evals/scenarios/*
       ↓
ATI scenario loaders
       ↓
canonical EvaluationCase objects
       ↓
LangSmith projection/mapping
       ↓
LangSmithEvaluationClient
       ↓
LangSmith Python SDK
       ↓
LangSmith API
       ↓
LangSmith Dataset + Examples
```

The implementation is under:

```
src/agentic_threat_investigator/evaluation/backends/langsmith/
├── client.py       # wrapper around LangSmith SDK
├── datasets.py     # sync / verify behavior
├── mapping.py      # ATI → LangSmith projection
├── models.py       # adapter DTOs
├── experiments.py
└── results.py
```

#### `ati-eval`

ATI has a command-line interface for interacting with `LangSmith`:

```bash
uv run ati-eval langsmith sync "investigation/v1"
uv run ati-eval langsmith verify "investigation/v1"
uv run ati-eval validate "investigation/v1"
```

##### Authentication

The `LANGSMITH_API_KEY` environment variable must be set for the authentication with `LangSmith` to work. In the context of GitHub workflow, for CI, that variable would be defined as a GitHub secret.

For example, in GitHub Actions, the secret would be  used as follows:

```YAML
env:
  LANGSMITH_API_KEY: ${{ secrets.LANGSMITH_API_KEY }}
```

##### `langsmith sync`

This command validates its local scenarios and converts them to canonical evaluation cases. It then projects those into `LangSmith`'s dataset/example representation.

Despite the name, the command does a one-way repository -> `LangSmith` projection (therefore, it is more of a `push`...).

Example:
```
ATI

investigation/v1
    ├── inv-s01-malicious-multi-source@1
    ├── inv-s02-benign@1
    ├── inv-s03-inconclusive-sparse@1
    └── ...
             │
             ▼
LangSmith

Dataset
    ATI investigation/v1
       ├── Example
       ├── Example
       ├── Example
       └── ...
```

ATI stores metadata on the `LangSmith` objects that preserves identities such as the ATI dataset ID, case ID/version and projection schema version.

__Idempotency___

The command is idempotent. More specifically, suppose the repository contains:

```
Dataset: investigation/v1
│
├── Case A: inv-s01-malicious-multi-source@v1
├── Case B: inv-s02-benign@v1
└── Case C: inv-s03-inconclusive-sparse@v1
```

and LangSmith contains exactly `A`/`B`/`C` with matching semantic digests, then the `sync` results in a no-op. On the other hand if `LangSmith` is missing `C`, then `C` is created in `LangSmith`.

But if `C` exists remotely with conflicting ATI metadata/content, ATI does not silently overwrite it. It fails closed. 

This protects against the `LangSmith` dataset silently diverging from the Git repository.

##### `langsmith verify`

This command performs the comparison between the Git repository and `LangSmith`, without writing anything:

```
Repository dataset
       │
       ├──── compare ──── LangSmith dataset
       │
       ▼
   identical?
       │
     yes → success
      no → fail
```

And the real CI workflow explicitly does `verify` before model execution.

That means ATI won't spend LLM calls evaluating against a `LangSmith` mirror that doesn't correspond to the checked-out repository corpus.

##### `validate`

This command operates entirely on the checked-out repository. It catches problems such as malformed scenarios, invalid fields/types, duplicate identities, invalid required/forbidden combinations, and other dataset invariants.

No authentication (i.e.: no `LangSmith` API key) is required for running this command.

#### GitHub Workflow

The GitHub worklow essentially corresponds to the following (see further above regarding the `LangSmith` authentication):

```
Developer changes:
    evals/scenarios/...

        ↓ commit

Git repository
    = authoritative dataset

        ↓ GitHub Action

ati-eval validate

        ↓

ati-eval langsmith sync

        ↓ LangSmith API

LangSmith dataset mirror
```

#### Summary

The following table summarizes the dataset management commands see above:

| Command                               | Checks                                               | Requires LangSmith? | Writes remotely? |
| ------------------------------------- | ---------------------------------------------------- | ------------------: | ---------------: |
| `ati-eval validate <dataset>`         | Local scenario/dataset correctness                   |                  No |               No |
| `ati-eval langsmith verify <dataset>` | Local ↔ LangSmith mirror consistency                 |                 Yes |               No |
| `ati-eval langsmith sync <dataset>`   | Same consistency plus creates missing remote content |                 Yes |              Yes |

### Experiment Recording

Experiment recording is the step where ATI publishes the results of an already-completed evaluation run to `LangSmith`.

The flow is:

```
ATI dataset
    ↓
ATI executes benchmark
    ↓
ATI evaluators determine PASS / FAIL / ERROR
    ↓
EvaluationRunResult
    ↓
LangSmith experiment recording
    ↓
LangSmith UI/history
```

"Benchmark", above, means the actual execution of ATI against the evaluation dataset—not the integration test itself and not an operation triggered by an integration-test result. 

At a high level, the benchmarking flow is the following:

```
Load evaluation scenarios
        ↓
For each EvaluationCase
        ↓
Materialize controlled fixture world
        ↓
Run real ATI investigation
        ↓
Obtain Assessment / Report / trajectory
        ↓
-- EvaluationRunner --
Run ATI evaluators against observed results
        ↓
Produce PASS / FAIL / ERROR
        ↓
Aggregate into EvaluationRunResult
-----------------------
```

Here's another angle, from the point of a CI point of view:

```
GitHub Actions
      │
      ▼
ati-eval run investigation/v1 --langsmith
      │
      ▼
EvaluationRunner
      │
      ├── Case 1 → real ATI execution → evaluators
      ├── Case 2 → real ATI execution → evaluators
      ├── Case 3 → real ATI execution → evaluators
      └── ...
      │
      ▼
EvaluationRunResult
      │
      ▼
publish LangSmith experiment
```

The important points are:

- ATI executes the benchmark, not `LangSmith`. ATI deliberately does not use LangSmith evaluate()/aevaluate() to rerun the target.
- One completed ATI evaluation run becomes a `LangSmith` experiment associated with the corresponding mirrored dataset.
- ATI gives the experiment a deterministic identity incorporating the dataset, commit SHA (when available), and execution ID.
- ATI publishes categorical feedback: pass, fail, or error, including run-level, case-level, and evaluator-level results.
- It can attach bounded reproducibility metadata such as commit SHA, model/provider, prompt version, fixture version, evaluator version, retriever/embedding versions, etc.
- ATI then reads back and confirms the remote experiment and feedback. Publication failures therefore fail closed rather than being silently accepted.
- `LangSmith` does not determine correctness. The authoritative `EvaluationRunResult` has already been produced by ATI before publication.

#### Evals vs Integration Tests

```
                       Evaluation infrastructure
                      /                         \
                     /                           \
            Integration tests                 ati-eval
                  │                              │
          deterministic CI                 benchmark run
          FakeLlmClient                    configured LLM
                  │                              │
                  ▼                              ▼
       verify implementation            produce eval results
                                                 │
                                                 ▼
                                      LangSmith experiment
```                                      

The integration tests and the real eval run share the production infrastructure (Postgres, etc.) and the repository-owned fake worlds/scenarios + Python code. They do not share the `Pytest` tests themselves.

Additionally, the evals dependent on a real LLM (as integration tests use the `FakeLlmClient`).

### Result and Metadata Publication

After ATI completes an evaluation run, it has an authoritative `EvaluationResult`. ATI then publishes that result to `LangSmith` as experiment feedback plus metadata. `LangSmith` records the result; it does not calculate ATI's verdict.

An `EvaluationResult` in fact consists of potentially many sub-results:

```
EvaluationRunResult
│
├── Run
│     └── pass / fail / error
│
├── Case A
│     ├── pass / fail / error
│     └── evaluator results
│           └── pass / fail / error
│
├── Case B
│     └── ...
│
└── Case C
      └── ...
```

`error` denotes a system problem (an outage, etc.). `pass` and `fail` denote that the evaluation either met of failed expectations.

> No numeric correctness score, weighting, threshold, or partial-pass calculation is performed, has this can be subjective and result in CI pipeline flakyness.

ATI also publishes metadata that identifies what configuration produced this experiment. For example:

```
commit SHA
dataset identity
projection schema version
agent implementation version
prompt version
model provider
model name
bounded model parameters
fixture-set version
normalization version
retriever version
embedding version
evaluator version
judge model / prompt version
timestamp
```

This provides reproducibility and makes LangSmith useful for comparing experiments, for example:

```
investigation/v1

Experiment 1
  commit: abc123
  model: model-A
  prompt: v3
  result: PASS

Experiment 2
  commit: def456
  model: model-A
  prompt: v4
  result: FAIL

Experiment 3
  commit: def456
  model: model-B
  prompt: v4
  result: PASS
```

Finally, ATI reads back and confirms the published experiment and categorical feedback. A publication is therefore not considered successful merely because the API call returned.

#### Security

ATI deliberately excludes sensitive/unbounded material such as secrets, raw prompts, raw model outputs, and chain-of-thought from this metadata envelope.


