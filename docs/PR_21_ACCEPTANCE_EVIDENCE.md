# PR 21 Acceptance Evidence

This matrix maps the 69 acceptance criteria in `.plans/PR_21_DETAILED_EXECUTION_PLAN.md` to implementation and verification evidence.

| # | Acceptance criterion | Evidence |
|---:|---|---|
| 1 | Queue exhaustion routes to Coordinator | `app/orchestration/graph.py`; coordinator graph and canonical trajectory tests |
| 2 | Deterministic application policy | `app/orchestration/coordinator.py`; `test_coordinator_policy.py` |
| 3 | Dispatcher policy-free | `dispatcher.py`; graph dispatch tests |
| 4 | Provider executor execution-only | `provider_executor.py`; executor tests |
| 5 | Only roots/discoveries pivot | policy checks plus coordinator SQL target-membership validation |
| 6 | Invented targets impossible | candidate-specific UNKNOWN_TARGET handling and PostgreSQL invented-pivot rejection test |
| 7 | Duplicate pivots suppressed | `_equivalent_pivot_exists`; policy and scenario tests |
| 8 | Same/worse-depth suppression | `best_investigated_depth`; policy tests |
| 9 | Cycle replay suppressed | cycle policy/scenario trajectory tests |
| 10 | Deterministic depth | typed traversal builder and outcome bookkeeping tests |
| 11 | max_depth enforced | policy, SQL authorization validation, depth scenario |
| 12 | max_entities enforced/documented | policy and entity-budget scenario; `DOMAIN_MODEL.md` |
| 13 | Provider budget never exceeded | policy, budget model, SQL checks, provider-budget scenario |
| 14 | Replan budget never exceeded | explicit `consumes_replan`, policy, SQL counter intent, scenario tests |
| 15 | LLM accounting remains PR 20B-owned | `LlmAccountingService`; SQL rejects coordinator LLM-counter changes |
| 16 | Provider counter ownership unchanged | outcome helper and SQL RECORD-only increment |
| 17 | Replan increments once per additional round | decision flag, graph authorization, SQL explicit intent |
| 18 | Candidate order deterministic | root/traversal ordering and policy tests |
| 19 | Provider order deterministic | `RegistryProviderWorkPlanner` and composition tests |
| 20 | Existing applicability semantics | planner calls enabled providers' `supports(Entity)` |
| 21 | PIVOTABLE entities handled | policy tests and canonical DOMAIN/IP trajectory |
| 22 | RESEARCHABLE marked only | research marker policy, scenario expectation, canonical test |
| 23 | No generic task framework | provider dispatcher and separate AnalysisExecutor remain narrow |
| 24 | Analyst synchronization point | graph analyze route after provider drain |
| 25 | Analysis outside DB transaction | AnalysisExecutor/service transaction-boundary tests |
| 26 | No unchanged-evidence reanalysis | policy unchanged-evidence test and layered trajectory |
| 27 | SUFFICIENT stop | policy/evaluator/canonical trajectory |
| 28 | NEEDS_MORE can authorize bounded work | replan policy and canonical two-analysis trajectory |
| 29 | EXHAUSTED terminal without work | policy tests |
| 30 | Specific blocker stop reason | depth/entity/provider/replan policy tests and scenarios |
| 31 | No candidate stop | no-eligible policy and graph trajectory |
| 32 | Fatal errors bounded | `FatalStopService`; graph fatal routes/tests |
| 33 | Terminal lifecycle valid | domain lifecycle plus FINALIZE SQL checks |
| 34 | Stable enum stop reason | StopReason serialization and finalization tests |
| 35 | PR 19C binding preserved | dispatcher/graph binding tests |
| 36 | Analysis identity isolated | bound AnalysisExecutor and dependency binding checks |
| 37 | Partial provider results preserved | provider executor regression/integration tests |
| 38 | Provider failure not automatically fatal | failed outcome bookkeeping and trajectory tests |
| 39 | Canonical DOMAIN→IP passes | `tests/integration/test_coordinator_trajectory.py` |
| 40 | Replan→new evidence→sufficient passes | canonical PostgreSQL trajectory |
| 41 | Duplicate/cycle passes | scenario corpus and layered trajectory tests |
| 42 | Depth scenario passes | scenario corpus/policy trajectory |
| 43 | Provider-budget scenario passes | scenario corpus/policy trajectory |
| 44 | Entity-budget scenario passes | scenario corpus/policy trajectory |
| 45 | Replan-limit scenario passes | scenario corpus/policy tests |
| 46 | Sufficient early stop passes | scenario corpus/policy tests |
| 47 | No eligible pivot passes | layered graph trajectory |
| 48 | Research marker causes no RAG | canonical assertion: marker present, no research results |
| 49 | Scenarios repository-owned | `evals/scenarios/coordinator/*.json` |
| 50 | Scenario loading strict | loader and loader tests |
| 51 | Evaluation uses structured actions | timeline action converter/evaluator |
| 52 | Invented pivot rate zero | evaluator hard gate and canonical evaluation |
| 53 | Policy-invalid rate zero | ordered enqueue/execution evaluator gate |
| 54 | Budget violation rate zero | evaluator budget checks and scenario runs |
| 55 | Every scenario terminates | all 13 bounded graph scenario test plus measured canonical test |
| 56 | No LLM judge | deterministic evaluator implementation |
| 57 | No live LLM in CI | FakeLlmClient in canonical integration |
| 58 | No live provider internet in CI | synthetic HTTP/fake providers |
| 59 | No PR 22 RAG | research marker only |
| 60 | No Report/API/frontend scope | PR 21 diff remains orchestration/evaluation/persistence focused |
| 61 | No PR 27 broad platform | coordinator-specific evaluator only |
| 62 | Architecture docs match graph | `ARCHITECTURE.md` |
| 63 | Domain docs define budgets/depth/replan | `DOMAIN_MODEL.md` |
| 64 | Evaluation docs distinguish PR 21/27 | `EVALUATION.md` |
| 65 | Typing/lint/format green | `./build.sh --qa` |
| 66 | Coverage preserved | QA result above 85% threshold |
| 67 | Unit tests pass | 2,770 tests in final QA run |
| 68 | PostgreSQL integration passes | 259 tests in final integration run |
| 69 | Full QA passes | `./build.sh --qa` and `./build.sh --intg` |
