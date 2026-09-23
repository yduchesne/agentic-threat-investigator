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
