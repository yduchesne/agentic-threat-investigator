# ATI — v0.4 Roadmap

> **Planning status — APPROVED TARGET / PR 30 SERIES**
>
> This document is authoritative for the ATI evaluation series. The PR 29
> telemetry/observability series is preserved in `ROADMAP_V03.md`; the
> monitor/diff/findings roadmap is preserved in `ROADMAP_UNPLANNED.md`.

## Purpose

ATI evaluation is a repository-owned **executable specification of expected
investigative behavior**, independent of any external platform. The PR 30
series builds one common evaluation foundation (semantics, scenario-quality
contract, binary verdicts, deterministic runner, local validation), then
adds LangSmith as an optional execution/visualization adapter, then delivers
per-agent behavioral suites, and finally an end-to-end investigation
benchmark.

PR 30A is deliberately backend-independent. It does **not** call LangSmith,
add `LANGSMITH_API_KEY`, upload datasets, execute experiments, add the
optional GitHub Actions evaluation workflow, invoke a real LLM judge, alter
production agent behavior, or establish numeric quality thresholds.

## Series decomposition

```text
PR 30A — Evaluation foundation
PR 30B — dataset/result LangSmith adapter + manual sync/verify workflow [DONE]
PR 30C — first real agent target experiment (Evidence Analyst evaluation
         suite and the first workflow path needing an LLM provider secret)
PR 30D — Coordinator + Research Agent evaluation suite
PR 30E — Report Writer evaluation suite
PR 30F — End-to-end investigation evaluation
```

## PR 30A scope (delivered)

- one backend-neutral result contract (`EvaluationResult`,
  `EvaluationCaseResult`, `EvaluationRunResult`);
- completed evaluator decisions strictly PASS/FAIL;
- ERROR distinct from FAIL (invalid status/verdict combinations rejected);
- deterministic evaluator -> case -> dataset aggregation;
- dataset identity/versioning (`<target>/v<N>` vocabulary incl. GEOINT);
- mandatory scenario-quality fields (`ScenarioSpecification`) composed into
  every target-specific scenario model;
- full migration of the committed scenario corpus (60 cases) with
  scenario-specific metadata — no behavioral meaning changed;
- strict loader/validation that fails closed;
- common async evaluator/target-executor seams and a deterministic runner
  (test doubles only; production target adapters arrive in PR 30C..30F);
- local offline validation via `ati-eval validate <dataset-or-path>`;
- deterministic human/machine reporting without numeric correctness scores;
- docs: `docs/EVALUATION.md`, `docs/TESTING.md`, this roadmap.

PR 30A leaves PR 30B able to add LangSmith purely as an adapter without
changing core semantics.

## PR 30B scope (delivered) [DONE]

- deterministic ATI dataset/case -> LangSmith dataset projection
  (`ati/<target>/v<version>` names, stable example identity, bounded
  `ati.*` metadata, projection schema v1);
- truthful semantic digest over the complete typed scenario object
  (canonical JSON + SHA-256; ordering-only changes keep the digest);
- idempotent, fail-closed synchronization (`ati-eval langsmith sync`:
  create missing dataset/examples, no-op on identical, fail on
  drift/extras/duplicates/mismatches; never overwrite or delete);
- read-only exact-mirror verification (`ati-eval langsmith verify`);
- categorical PASS/FAIL/ERROR result projection and adapter-only
  experiment-metadata builder (no numeric correctness, no thresholds);
- narrow injectable LangSmith SDK boundary (bounded DTOs, sanitized
  errors, no credential logging, cancellation preserved);
- optional manual GitHub Actions evaluation workflow
  (`.github/workflows/evaluation.yml`: `workflow_dispatch` only,
  `contents: read`, `LANGSMITH_API_KEY` only; no real agent target);
- deterministic fake-backed unit/static coverage (LS-M/S/V/R/C/CLI/W)
  with ordinary CI remaining offline and uncredentialed;
- docs: `docs/EVALUATION.md`, `docs/TESTING.md`, this roadmap;
  `.env.example` documents the optional key for explicit commands.

PR 30B deliberately delivers **no** real-model target execution, no
LLM-as-judge invocation, no numeric quality score or baseline promotion,
and no automatic/scheduled evaluation runs. Real agent experiments start
in PR 30C, which consumes PR 30B's adapter without redefining dataset
naming, example identity, digest, feedback keys, PASS/FAIL/ERROR mapping,
client construction, or the workflow security model.

## PR 30C scope (delivered) [DONE]

First real agent target: the **Evidence Analyst** evaluation execution.

- typed execution output (persisted `Assessment` +
  `AnalystScenarioResolution`) and a run-scoped exact scenario lookup;
- `EvidenceAnalystTargetExecutor` executing repository-owned scenarios
  through the real materializer (fresh or `materialize_or_reuse`),
  `EvidenceAnalystInputLoader`, `EvidenceAnalyst`, configured `LlmClient`,
  `AssessmentPersistenceService`, and `LlmAccountingService`;
- `EvidenceAnalystContractEvaluator` — a thin PR 30 adapter over the
  existing deterministic `EvidenceAnalystEvaluator` (COMPLETED/PASS and
  COMPLETED/FAIL with deterministic explanations and JSON-safe descriptive
  diagnostics; exceptions become ERROR through the common runner; no
  numeric correctness/threshold);
- `run_evidence_analyst_evaluation` service composing scenarios, target,
  evaluator, and the common `EvaluationRunner`;
- `materialize_or_reuse` idempotent fixture lifecycle (no destructive
  cleanup, no history mutation, fail-closed on incomplete state);
- `ati-eval run evidence-analyst/v1 [--langsmith]` with exact exit
  semantics (0 PASS, 1 FAIL, 2 ERROR/config/backend/publication);
- minimum LangSmith experiment association — one experiment run per
  execution, PR 30B categorical feedback, remote confirmation — without
  ever re-executing the target (no `evaluate()`/`aevaluate()`);
- optional manual workflow `run` operation (workflow_dispatch only,
  `contents: read`, PostgreSQL 18 + pgvector + Alembic migrations,
  `LANGSMITH_API_KEY` and `ATI_OPENAI_API_KEY` GitHub Secrets);
- deterministic unit matrices (target, evaluator adapter, run service,
  experiment, workflow, CLI) plus a PostgreSQL vertical slice with a
  FakeLlmClient boundary;
- docs: `docs/EVALUATION.md`, `docs/TESTING.md`, this roadmap.

PR 30C deliberately delivers **no** Coordinator/Research/Report Writer/
end-to-end real targets, no LLM-as-judge, no numeric quality scoring, no
prompt tuning to pass evals, no scheduled/PR/push real-model triggers, no
DB migration, and no change to production analyst behavior. PR 30D adds
Coordinator/Research Agent targets without redefining common result
semantics, LangSmith dataset identity/digest, feedback vocabulary,
experiment association, or workflow security.

## PR 30D scope (delivered) [DONE]

Second real-target execution PR: the **Coordinator** and **Research Agent**
behavioral suites execute through the common PR 30 contract.

Coordinator:

- exact run-scoped typed lookup and `CoordinatorEvaluationOutput` (durable
  terminal `InvestigationState`, runtime resolution, structured timeline
  actions, transition span);
- run-scoped execution identity in
  `CoordinatorScenarioMaterializer.materialize` (repeated runs isolated;
  semantic labels preserved);
- deterministic fixture-world composition
  (`evaluation/coordinator_fixtures.py`: semantic `ConvertedEvidence`
  DNS/AbuseIPDB/ThreatFox providers, DNS root discovery, TXT-only worlds,
  AsyncRAT association truth);
- production `LocalInvestigationRunner` + Coordinator graph/policy execute
  unchanged; structured actions come from the durable timeline, never logs;
- `CoordinatorTrajectoryContractEvaluator`
  (`coordinator-trajectory-contract`) mapping the existing evaluator's
  PASS/FAIL with JSON-safe descriptive diagnostics;
- `run_coordinator_evaluation` service and `ati-eval run coordinator/v1`.

Research Agent:

- exact typed lookup preserving retrieval/synthesis kinds and rejecting
  cross-family duplicate identities;
- family dispatch on one target (`ResearchAgentTargetExecutor`) and one
  evaluator (`ResearchAgentEvaluatorDispatcher`) without redesigning the
  common runner;
- retrieval cases run the production pgvector retriever with zero LLM calls;
- synthesis cases run the real `ResearchAgent` (existing `LlmClient`,
  structured-output policy, empty-retrieval zero-call short circuit) with
  exact supplied-citation observation (recording wrapper, no probe
  retrieval), before/after epistemic snapshots, and the persisted current
  `ResearchResult`;
- `research-retrieval-contract` / `research-synthesis-contract` evaluator
  ids; existing metrics (recall@k, precision@k, MRR, citation-validity,
  coverage) stay diagnostics only; epistemic non-promotion stays a hard
  gate;
- run-scoped anchor seeding + repository-owned ATT&CK corpus bootstrap
  through production ingestion/indexing (deterministic hashing embeddings;
  no live web);
- `run_research_agent_evaluation` service and
  `ati-eval run research-agent/v1`.

Shared:

- `ati-eval run coordinator/v1 [--langsmith]` and
  `ati-eval run research-agent/v1 [--langsmith]` with the same exit
  semantics, verify-first mirror check, and one-execution-per-case
  categorical LangSmith publication as PR 30C;
- manual workflow `run` step is dataset-agnostic (`evidence-analyst/v1`,
  `coordinator/v1`, `research-agent/v1`); PostgreSQL + migrations, plus the
  deterministic research corpus/index bootstrap for any benchmark run;
- deterministic PostgreSQL/pgvector vertical slices (Coordinator
  productive-pivot/stop/research-lifecycle PASS, nonconforming FAIL,
  materialization ERROR; Research retrieval PASS/FAIL/zero-LLM, synthesis
  relevant/contradiction/empty PASS, unsupported-citation ERROR, wrong-claim
  FAIL);
- V1 corpora reviewed: no expectations weakened and no scenario added;
  coordinator V1 scenarios whose authored oracles/budgets predate the
  current production Coordinator topology report FAIL/ERROR honestly (never
  crash), documented in `docs/TESTING.md`;
- docs: `docs/EVALUATION.md`, `docs/TESTING.md`, this roadmap.

PR 30D deliberately delivers **no** Report Writer/end-to-end real targets, no
LLM-as-judge, no numeric quality scoring, no prompt/policy tuning to pass
evals, no scheduled/PR/push real-model triggers, no DB migration, and no
change to production Coordinator/Research behavior. PR 30E should add Report
Writer without redefining PASS/FAIL/ERROR, dataset identity/versioning,
common runner, LangSmith mirror/digest, categorical feedback, experiment
publication, or workflow security.


## Explicitly out of scope for PR 30A

LangSmith dataset upload/sync, experiment execution/result fetching,
`LANGSMITH_API_KEY`, GitHub secret configuration, the optional eval
workflow, real LLM-as-judge execution, real-model benchmark runs, numeric
quality scores, pass-rate thresholds, weighted scoring, pairwise ranking,
automatic baseline promotion, online/live evaluation, prompt tuning to make
evals pass, new threat-intelligence behavior, retry/Tenacity hardening, and
telemetry redesign.

## Boundaries to preserve

- ordinary CI (`quality`, `integration`, `security`) stays uncredentialed
  and offline in the PR 30 series; the credentialed LangSmith workflow is
  PR 30B's own optional, initially manual job.
- Evaluators/baselines/rubrics/release gates remain repository-owned even
  when LangSmith visualizes them.
- No DB migration is expected for the evaluation foundations.
