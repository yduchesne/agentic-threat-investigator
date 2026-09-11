# Detailed PR Plan Example

This serves as an example of a PR plan that is meant to be provided to a low reasoning coding agent. 
It is in fact a plan that was used as part of this project.

- Use only for inferring what the structure of a detailed PR plan should be and what the nature of its content should be.
- Do not use this example to construe the current state of this project or any requirements.



## --- Example Start ---

## Purpose

PR 21 was broader than a low-reasoning coding agent could reliably implement in one pass. PR 21B is intentionally narrow.

This PR fixes **two correctness issues only** in the coordinator implementation currently merged to `main`:

1. **Entity-budget admission semantics are incorrect at the exact-capacity boundary.**
   - An entity already admitted to the bounded investigation working set must remain eligible for provider work even when the working set size is exactly `max_entities`.
   - Persisted discoveries beyond the admitted working-set capacity may remain persisted for provenance/history, but they must not be authorized for pivot expansion.
   - The coordinator must determine admission deterministically from roots first, then discovery traversal order.

2. **`investigated_entity_ids` is updated too early.**
   - Today, `authorize_pivot()` marks the entity investigated before provider execution begins.
   - After this PR, authorization must mean only "approved and queued".
   - An entity becomes investigated only when provider work for that entity is actually selected for execution.
   - `best_investigated_depth` and `investigated_entity_ids` must describe the same execution event.

This PR does **not** implement the remaining PR 21 follow-up work.

---

# Scope boundaries

## In scope

- Fix deterministic entity-budget admission logic in `CoordinatorPolicy`.
- Fix exact-capacity behavior for discovered entities.
- Preserve persisted overflow discoveries without authorizing them for expansion.
- Make `investigated_entity_ids` transition at provider-work selection rather than pivot authorization.
- Keep `best_investigated_depth` synchronized with that transition.
- Update narrowly affected coordinator evaluation entity-budget semantics so exact-capacity execution is not falsely reported as a violation.
- Add focused unit tests.
- Add focused PostgreSQL integration tests using the existing coordinator graph/persistence infrastructure.
- Run the repository quality suite and integration suite.

## Explicitly out of scope

Do **not** implement any of the following in PR 21B:

- Do not redesign the LangGraph topology.
- Do not add a worker/bootstrap/runtime entry point.
- Do not implement PR 22 RAG / Threat Research.
- Do not add generic task-union dispatch.
- Do not redesign `CoordinatorTrajectoryEvaluator`.
- Do not strengthen `POLICY_INVALID_PIVOT` beyond what is required for the entity-budget correction; that belongs to PR 21D.
- Do not add new coordinator scenario infrastructure.
- Do not rewrite the canonical PostgreSQL trajectory; broader trajectory completeness belongs to PR 21C.
- Do not add new `StopReason` values.
- Do not change provider-call accounting.
- Do not change replan accounting.
- Do not change LLM accounting.
- Do not delete persisted Entity rows to enforce the entity budget.
- Do not alter provider extraction/persistence semantics.
- Do not introduce new database tables.
- Do not modify unrelated documentation.
- Do not opportunistically refactor coordinator code outside the exact functions touched by these correctness fixes.

If any required fix appears to require one of the out-of-scope changes above, **STOP and report the dependency instead of broadening the PR.**

---

# Current-main facts that must be preserved

The coding agent must inspect current `main` before editing. The relevant implementation currently has these semantics:

- `CoordinatorPolicy._authorize_candidates()` computes the working set from:
  - `root_entity_ids`
  - `discovered_entity_ids`
- Current code rejects a non-root candidate when:
  - `len(working_set) >= max_entities`
- This is incorrect for an already-admitted entity at exact capacity.
- `authorize_pivot()` currently appends the pivot target to `investigated_entity_ids`.
- `apply_work_selection()` currently records `best_investigated_depth` when a provider work item becomes current.
- `EntityTraversalState.best_investigated_depth` is documented as the shallowest depth at which the entity was **actually investigated / entered execution**.
- The coordinator evaluator currently treats an entity-budget violation as a depth>0 pivot action where:
  - `entity_count >= max_entities`
- That exact-capacity comparison is inconsistent with the corrected semantics.

Do not assume file contents from this plan are more current than the branch. Re-read the files before changing them.

Primary files expected to be relevant:

```text
src/agentic_threat_investigator/app/orchestration/coordinator.py
src/agentic_threat_investigator/app/orchestration/models.py
src/agentic_threat_investigator/domain/investigation.py
src/agentic_threat_investigator/evaluation/coordinator.py

tests/unit/app/orchestration/test_coordinator_policy.py
tests/unit/app/orchestration/test_models.py
tests/unit/app/orchestration/test_models_bookkeeping.py
tests/unit/app/orchestration/test_graph.py
tests/unit/evaluation/test_coordinator_evaluator.py

tests/integration/test_coordinator_trajectory.py
```

Only modify additional files when directly required by the two correctness fixes.

---

# Required semantic invariants

The implementation must satisfy all of the following.

## Invariant A — deterministic entity admission

Define an investigation's **admitted entity set** deterministically.

Ordering:

1. unique `root_entity_ids`, in their existing order;
2. unique discovered entities, in durable traversal / first-discovery order;
3. do not use set/dict iteration to establish order.

Admission rule:

```text
admitted entities = first max_entities unique entities in that deterministic order
```

Examples:

```text
max_entities = 2
root = DOMAIN
discovered = IP

ordered working set = [DOMAIN, IP]
admitted = [DOMAIN, IP]

IP pivot is allowed.
```

```text
max_entities = 1
root = DOMAIN
discovered = IP

ordered working set = [DOMAIN, IP]
admitted = [DOMAIN]

IP remains persisted/discovered,
but IP pivot is rejected with ENTITY_BUDGET.
```

```text
max_entities = 3
roots = [DOMAIN_A, DOMAIN_B]
discoveries = [IP_A, IP_B]

ordered working set = [DOMAIN_A, DOMAIN_B, IP_A, IP_B]
admitted = [DOMAIN_A, DOMAIN_B, IP_A]

IP_A may pivot.
IP_B may not pivot.
```

A candidate already inside the admitted set must not be rejected merely because:

```text
len(root + discovered) == max_entities
```

or because later overflow entities have also been persisted.

## Invariant B — persistence is not admission

A provider may already have persisted/discovered an entity before the coordinator evaluates the next pivot.

Therefore:

```text
persisted Entity
        !=
admitted working-set Entity
```

Do not delete overflow entities.

Do not mutate historical Evidence or Relationship data to enforce `max_entities`.

The coordinator simply refuses to authorize expansion through an overflow entity.

## Invariant C — investigated means execution started

The lifecycle must be:

```text
candidate
  -> authorized pivot
  -> provider work queued
  -> provider work selected/current
  -> entity is now investigated
  -> provider execution
  -> outcome recorded
```

Therefore:

- `authorize_pivot()` MUST NOT add the entity to `investigated_entity_ids`.
- `apply_work_selection()` MUST add the selected work item's `entity_id` to `investigated_entity_ids` if absent.
- The same `apply_work_selection()` transition MUST continue recording `best_investigated_depth`.
- Re-selecting provider work for an already-investigated entity must not duplicate the entity ID.
- If an authorized pivot exists but execution never starts, the entity must not be represented as investigated.

## Invariant D — depth semantics remain unchanged

Do not change:

```text
root depth = 0
provider discovery during work depth D -> discovered entity minimum depth = D + 1
```

`best_investigated_depth` remains the shallowest depth at which execution actually started.

A shallower rediscovery must still permit a shallower pivot if the prior execution was only at a deeper depth.

## Invariant E — duplicate suppression remains intact

The correction must not cause re-execution of equivalent work.

Existing suppression for:

- pending provider work,
- current provider work,
- completed provider work,
- pending pivots,
- same-or-better investigated depth,

must continue to work.

## Invariant F — no accounting changes

PR 21B must not change these counters:

- `provider_calls_used` increments only for actual recorded provider execution outcomes.
- `replans_used` retains current semantics.
- `llm_calls_used` remains PR 20B ownership.

Authorization alone consumes none of these counters.

---

# Step-by-step implementation plan

## Step 0 — Establish a clean baseline

### Instructions

Before editing:

1. Checkout the PR 21B branch from the latest `main`.
2. Confirm there are no local modifications.
3. Re-read these files completely:
   - `coordinator.py`
   - `models.py`
   - `domain/investigation.py`
   - `evaluation/coordinator.py`
   - the coordinator policy unit tests
   - the orchestration model/bookkeeping unit tests
   - coordinator evaluator unit tests
   - `tests/integration/test_coordinator_trajectory.py`
4. Search the repository for:
   - `investigated_entity_ids`
   - `best_investigated_depth`
   - `max_entities`
   - `ENTITY_BUDGET`
   - `ENTITY_BUDGET_EXHAUSTED`
   - `authorize_pivot(`
   - `apply_work_selection(`
5. Record every write site for `investigated_entity_ids`.
6. Record every runtime comparison involving `max_entities`.

Do not start modifying code until the write sites and budget checks are known.

### Acceptance criteria

- The agent can list every location that writes `investigated_entity_ids`.
- The agent can list every location that enforces or evaluates `max_entities`.
- No source code has been modified yet.
- Existing tests are runnable.
- If the branch does not match the architecture described above, STOP and report the mismatch.

---

## Step 1 — Add failing unit tests for exact-capacity entity admission

### Goal

Pin the corrected entity-budget semantics before modifying production code.

### Instructions

In:

```text
tests/unit/app/orchestration/test_coordinator_policy.py
```

add focused tests for the following cases.

### Case 1.1 — discovered entity at exact capacity is eligible

Construct:

```text
max_entities = 2
root_entity_ids = [root_domain]
discovered_entity_ids = [discovered_ip]

traversal:
root_domain minimum_depth=0
discovered_ip minimum_depth=1

root domain already investigated at depth 0
discovered IP not investigated
```

Context must contain both persisted entities.

Provider planner must support the IP.

Expected:

```text
decision.action == AUTHORIZE_PIVOT
decision.pivots == one IP pivot
pivot.depth == 1
decision.work_items contains IP provider work
ENTITY_BUDGET is not a rejection
```

This test MUST fail against the current incorrect `>= max_entities` behavior before the production fix.

### Case 1.2 — first overflow discovery is rejected

Construct:

```text
max_entities = 2
root = root_domain
discoveries in traversal order:
  ip_a
  ip_b

root_domain already investigated
ip_a already investigated or otherwise exhausted
ip_b uninvestigated
```

Deterministic ordered set:

```text
[root_domain, ip_a, ip_b]
```

Admitted:

```text
[root_domain, ip_a]
```

Expected for `ip_b`:

```text
ENTITY_BUDGET rejection
stop_reason == ENTITY_BUDGET_EXHAUSTED
```

Ensure the result is not `NO_ELIGIBLE_PIVOTS` if entity budget is the sole actionable blocker.

### Case 1.3 — later overflow entity does not invalidate earlier admitted entity

Construct:

```text
max_entities = 2
root = root_domain
discoveries = [ip_a, ip_b]

ordered working set has 3 persisted/discovered entities.
ip_a is the second entity and therefore admitted.
ip_b is overflow.
root is already exhausted.
ip_a is eligible.
```

Expected:

```text
ip_a is authorized
```

This protects against any implementation that merely checks:

```python
len(working_set) > max_entities
```

globally and therefore blocks all non-root pivots when an overflow entity exists.

### Case 1.4 — multiple roots consume admission capacity deterministically

Construct:

```text
max_entities = 2
roots = [domain_a, domain_b]
discovery = ip_a
```

Expected admitted set:

```text
domain_a
domain_b
```

Expected:

```text
ip_a rejected ENTITY_BUDGET
```

Do not special-case roots as "free" entities. Roots count toward `max_entities`.

### Case 1.5 — duplicate IDs do not consume capacity twice

Construct a valid state where the same entity identity can appear through root/discovery bookkeeping without counting twice if current validation permits such representation.

If current domain validation forbids root/discovery duplication, test the admission helper directly with the closest valid representation instead.

Expected:

```text
capacity is based on unique entity IDs
```

### Acceptance criteria

- Tests exist for all four mandatory cases 1.1–1.4.
- Case 1.1 fails before the production fix.
- Case 1.3 protects against a naive global `len(working_set) > max_entities` implementation.
- No production code has been changed in this step.
- All unrelated coordinator-policy tests still pass or fail only because of the known incorrect semantics.

---

## Step 2 — Implement a deterministic admitted-entity helper

### Goal

Centralize entity-budget admission semantics in one small, pure helper.

### Instructions

Implement the smallest appropriate helper in:

```text
src/agentic_threat_investigator/app/orchestration/coordinator.py
```

Preferred behavior:

```python
_admitted_entity_ids(state: InvestigationState) -> tuple[UUID, ...]
```

or equivalent.

The helper must:

1. start with unique roots in `root_entity_ids` order;
2. then add discovered entities in durable traversal / first-discovery order;
3. include only IDs represented as roots/discoveries;
4. preserve deterministic ordering;
5. deduplicate by entity ID;
6. return at most `state.budget.max_entities` IDs.

Do not derive discovery ordering from:

```python
set(state.discovered_entity_ids)
```

Do not sort UUIDs as a substitute for first-discovery ordering.

Use the existing traversal metadata.

If a discovered entity lacks required traversal metadata, preserve the current fail-closed behavior. Do not silently assign it an arbitrary order.

If `max_entities` can validly be zero under the domain model, return an empty admitted tuple. If the domain model forbids zero, do not change the model in this PR.

### Implementation constraint

Do not create a second persistent "admitted entity" field in `InvestigationState`.

For PR 21B, admission is a deterministic derivation from:

```text
roots + traversal order + max_entities
```

This avoids a schema migration and keeps the PR narrow.

### Acceptance criteria

- The helper is pure.
- The helper performs no persistence/network/LLM/provider calls.
- Ordering is roots first, then first discovery order.
- IDs are unique.
- Result length never exceeds `max_entities`.
- Malformed traversal state continues to fail closed.
- Unit tests cover exact boundary, overflow, multiple roots, and deterministic order.

---

## Step 3 — Replace the incorrect candidate entity-budget check

### Goal

Authorize provider work for already-admitted entities even at exact capacity, while blocking persisted overflow discoveries.

### Instructions

In `CoordinatorPolicy._authorize_candidates()`:

Remove the current semantic pattern equivalent to:

```python
working_set = roots | discovered
if len(working_set) >= max_entities and candidate is non-root:
    reject ENTITY_BUDGET
```

Replace it with:

```text
candidate must be in the deterministic admitted entity set
```

The decision flow should remain ordered similarly to current policy.

Recommended sequence for a concrete candidate:

1. resolve entity / missing target;
2. deleted check;
3. pivot class;
4. depth check;
5. provider plan / duplicate-work removal;
6. already-investigated check;
7. duplicate-pivot check;
8. verify candidate belongs to root/discovered working universe;
9. verify candidate belongs to deterministic admitted entity set;
10. provider-budget check;
11. authorize.

A candidate that is persisted but not root/discovered remains `UNKNOWN_TARGET`.

A candidate that is root/discovered but falls outside admitted capacity becomes `ENTITY_BUDGET`.

Do not change the meaning of any other rejection reason.

### Important examples

Must allow:

```text
max_entities = 2
[root, discovered_ip]
candidate = discovered_ip
```

Must reject:

```text
max_entities = 2
[root, ip_a, ip_b]
candidate = ip_b
```

Must allow:

```text
max_entities = 2
[root, ip_a, ip_b]
candidate = ip_a
```

even though the total persisted/discovered count is 3.

### Acceptance criteria

- Step 1 tests now pass.
- Existing provider-budget tests remain unchanged.
- Existing depth-budget tests remain unchanged.
- Existing duplicate-pivot/work tests remain unchanged.
- Exact-capacity admitted entities are authorized.
- Overflow entities are rejected with `ENTITY_BUDGET`.
- Entity budget remains causal for `ENTITY_BUDGET_EXHAUSTED` when it is the sole blocker.
- No database code is changed.

---

## Step 4 — Add failing unit tests for investigated-state timing

### Goal

Pin the lifecycle semantics before editing model helpers.

### Instructions

Use:

```text
tests/unit/app/orchestration/test_models.py
```

or the most appropriate existing orchestration bookkeeping test file.

Add tests for:

### Case 4.1 — authorization does not mean investigated

Given:

```text
state with eligible entity
pivot_request
provider work items
```

Call:

```python
authorize_pivot(...)
```

Expected:

```text
pending_pivots includes pivot
pending_provider_work includes work
investigated_entity_ids DOES NOT include entity
best_investigated_depth remains None
```

This must fail against current `main`.

### Case 4.2 — selecting provider work marks the entity investigated

Starting from an authorized/queued state:

1. select the provider work using the existing queue-selection helper;
2. apply `apply_work_selection()` as production graph code does.

Expected:

```text
current_provider_work is selected item
investigated_entity_ids contains entity exactly once
traversal entry best_investigated_depth == selected.depth
pivot status transitions PENDING -> IN_PROGRESS where applicable
```

### Case 4.3 — selecting a second provider for same pivot does not duplicate entity ID

A pivot may schedule multiple providers.

After the first provider selection:

```text
investigated_entity_ids == [entity]
```

After a later provider for the same entity/depth is selected:

```text
investigated_entity_ids still contains one occurrence
```

### Case 4.4 — authorization followed by no execution remains uninvestigated

Construct a state after `authorize_pivot()` only.

Expected:

```text
entity absent from investigated_entity_ids
best_investigated_depth is None
```

This protects crash/resume semantics between authorization and selection.

### Case 4.5 — shallower execution updates best depth

Existing behavior must remain:

```text
prior best investigated depth = 3
new selected work depth = 1
result best investigated depth = 1
```

`investigated_entity_ids` remains deduplicated.

### Acceptance criteria

- Cases 4.1–4.5 exist.
- Case 4.1 fails before production change.
- Unit tests distinguish authorization from execution.
- Tests do not require PostgreSQL.

---

## Step 5 — Move `investigated_entity_ids` mutation to work selection

### Goal

Align `investigated_entity_ids` with `best_investigated_depth`.

### Instructions

In:

```text
src/agentic_threat_investigator/app/orchestration/models.py
```

modify `authorize_pivot()`:

- preserve pivot enqueueing;
- preserve provider-work enqueueing;
- preserve duplicate-work suppression;
- REMOVE addition to `investigated_entity_ids`.

Update its docstring so it no longer claims authorization prevents reinvestigation by marking the entity investigated.

Then modify `apply_work_selection()`:

- when `state.current_provider_work` is non-`None`,
- add `selected.entity_id` to `investigated_entity_ids` if absent;
- continue transitioning the matching pivot from `PENDING` to `IN_PROGRESS`;
- continue recording `best_investigated_depth`;
- return unchanged state only when there is truly no state change.

Be careful with current early-return logic.

Current logic returns the original state when:

```text
pivot status unchanged
AND traversal unchanged
```

After this PR, it must also account for:

```text
investigated_entity_ids changed
```

Use explicit booleans or equivalent so that a newly investigated ID is not lost merely because the traversal already had the same `best_investigated_depth`.

### Do not

- increment provider-call budget here;
- mark the pivot completed here;
- remove pending provider work here;
- record an outcome here.

Those belong to existing selection/outcome helpers.

### Acceptance criteria

- All Step 4 tests pass.
- Authorization alone leaves entity uninvestigated.
- First selected work adds entity once.
- Later work for same entity does not duplicate it.
- `best_investigated_depth` and investigated marker are established in the same execution-selection transition.
- No provider counter changes occur.
- Existing pivot PENDING→IN_PROGRESS behavior remains intact.

---

## Step 6 — Verify coordinator suppression semantics after the timing change

### Goal

Ensure moving the investigated marker does not accidentally create duplicate pivots/work.

### Instructions

Review:

```text
CoordinatorPolicy._investigated_at_or_better()
CoordinatorPolicy._equivalent_pivot_exists()
CoordinatorPolicy._work_exists()
```

Do not rewrite them unless tests prove a change is required.

Add focused unit tests covering this sequence:

### Case 6.1 — authorized-but-not-yet-selected pivot is suppressed by pending pivot/work

State:

```text
pivot already authorized
entity NOT in investigated_entity_ids
provider work pending
```

Expected:

```text
coordinator does not authorize the same pivot again
```

Suppression must come from existing pending pivot/work state, not from the prematurely-set investigated marker.

### Case 6.2 — selected/in-progress work is suppressed

State:

```text
entity investigated
current provider work exists
best investigated depth recorded
```

Expected:

```text
no duplicate authorization at same-or-worse depth
```

### Case 6.3 — completed work remains suppressed

Expected:

```text
same provider/entity/depth not reauthorized
```

### Case 6.4 — shallower rediscovery remains eligible

State:

```text
entity previously executed at depth 3
later rediscovered with minimum_depth 1
best_investigated_depth = 3
```

Expected:

```text
depth 1 pivot remains eligible if provider/pivot/work state otherwise permits
```

This is a regression guard against replacing execution-depth logic with a simple membership test.

### Acceptance criteria

- No duplicate pivot is created between authorization and execution.
- Current/pending/completed work continues to suppress equivalent work.
- Same-or-worse executed depth is suppressed.
- A newly available shallower depth is not falsely suppressed.
- No new state field is required.

---

## Step 7 — Correct the narrow evaluator entity-budget boundary

### Goal

Prevent the coordinator evaluator from flagging an exact-capacity admitted pivot as a budget violation.

### Instructions

In:

```text
src/agentic_threat_investigator/evaluation/coordinator.py
```

inspect the existing `ENTITY_BUDGET_VIOLATION` logic.

Current behavior uses a comparison equivalent to:

```text
entity_count >= max_entities
```

for depth>0 pivot actions.

At minimum, correct the exact-capacity boundary so:

```text
entity_count == max_entities
```

is not itself a violation.

Do **not** attempt the broader PR 21D redesign of policy-validity evaluation in this PR.

### Required unit tests

In:

```text
tests/unit/evaluation/test_coordinator_evaluator.py
```

add:

#### Case 7.1 — exact-capacity pivot is not a violation

```text
max_entities = 2
pivot action entity_count = 2
depth = 1
```

Expected:

```text
no ENTITY_BUDGET_VIOLATION
```

#### Case 7.2 — pivot with count above budget is a violation

```text
max_entities = 2
pivot action entity_count = 3
depth = 1
```

Expected:

```text
ENTITY_BUDGET_VIOLATION
```

### Important limitation to document in code/test comments

The full evaluator still does not independently reconstruct coordinator admission policy. That broader hardening belongs to PR 21D.

PR 21B only ensures the evaluator is not inconsistent with the corrected exact-capacity rule.

### Acceptance criteria

- Exact-capacity pivot actions are not flagged.
- Above-budget pivot actions are still flagged.
- No changes are made to `POLICY_INVALID_PIVOT`.
- No scenario schema changes are introduced.
- No evaluator architecture refactor occurs.

---

## Step 8 — Add focused PostgreSQL integration test: exact-capacity discovered pivot

### Goal

Prove that corrected budget semantics survive real persistence and coordinator graph execution.

### Instructions

Add a narrow integration test to:

```text
tests/integration/test_coordinator_trajectory.py
```

Reuse existing fixtures/services and production graph composition.

Do not build a new integration harness.

Test setup:

```text
max_entities = 2

root DOMAIN
discovered IP

both Entity rows persisted
InvestigationState persisted with:
  root_entity_ids = [root]
  discovered_entity_ids = [ip]
  traversal:
    root depth 0, already investigated
    ip minimum depth 1, not yet investigated
  root exhausted / no root work eligible
  budget max_entities = 2
```

Use an IP provider that is deterministic/offline and records whether it was called.

Run through the existing production coordinator graph or the narrowest real graph path that invokes:

```text
context loader
CoordinatorPolicy
coordinator transition persistence
provider work selection
dispatcher/provider executor
```

Expected:

1. IP pivot is authorized.
2. IP provider work is persisted/queued.
3. Work is selected/executed.
4. Durable state shows IP in `investigated_entity_ids`.
5. Durable traversal shows `best_investigated_depth == 1`.
6. No `ENTITY_BUDGET_EXHAUSTED` stop occurs before the IP execution.
7. No duplicate IP investigation marker exists.
8. Provider call count increments only after actual provider outcome recording.

Keep the downstream stopping condition deterministic and minimal. It is acceptable to use a fake analysis executor if needed to terminate the graph. The purpose of this test is the budget boundary and durable investigated transition, not PR 21C's full canonical trajectory.

### Acceptance criteria

- Test uses real PostgreSQL through existing `PostgresUnitOfWork`.
- No live network or live LLM is used.
- Exact-capacity IP pivot executes.
- Durable state matches the in-memory result.
- Test fails on the pre-21B entity-budget bug.
- Test does not introduce new production infrastructure.

---

## Step 9 — Add focused PostgreSQL integration test: overflow discovery is persisted but not pivoted

### Goal

Prove the important distinction:

```text
persisted != admitted
```

### Instructions

Add another narrow PostgreSQL integration test.

Setup:

```text
max_entities = 2
root = DOMAIN
discoveries in durable traversal order:
  ip_a
  ip_b
```

Persist all three Entity rows.

Persist investigation state with all three represented as root/discoveries.

Arrange state so:

- root is already exhausted/investigated;
- `ip_a` is admitted and already exhausted/investigated;
- `ip_b` is not investigated;
- `ip_b` has a valid provider path;
- no other blocker applies.

Run coordinator decision/transition through the real persisted path.

Expected:

```text
ip_b remains present in Entity repository
ip_b remains present in discovered_entity_ids
ip_b remains present in traversal
ip_b is NOT added to pending_pivots
ip_b work is NOT added to pending_provider_work
ip_b is NOT added to investigated_entity_ids
stop_reason == ENTITY_BUDGET_EXHAUSTED
```

Do not delete `ip_b`.

Do not mutate Evidence/Relationship provenance associated with it.

### Acceptance criteria

- Real PostgreSQL is used.
- Overflow Entity remains durable.
- Overflow discovery remains represented in investigation state.
- No pivot/provider work is authorized for it.
- Entity-budget stop is persisted when it is the sole blocker.
- Test makes no external calls.

---

## Step 10 — Add focused PostgreSQL integration test: authorization does not prematurely persist investigated status

### Goal

Protect crash/resume semantics at the authorization boundary.

### Instructions

Use the existing coordinator transition persistence path to persist an `AUTHORIZE_PIVOT` transition without selecting provider work.

The resulting durable state must contain:

```text
pending pivot
pending provider work
```

but must NOT contain the target in:

```text
investigated_entity_ids
```

and traversal must still show:

```text
best_investigated_depth is None
```

Then perform the normal work-selection transition.

After selection, verify durable state contains:

```text
investigated_entity_ids includes target
best_investigated_depth == selected depth
pivot status == IN_PROGRESS
```

If the current persistence API combines selection with another transition kind, use the exact existing transition mechanism. Do not invent a new transition type.

### Acceptance criteria

- Durable state distinguishes authorization from execution.
- Before selection: target not investigated.
- After selection: target investigated exactly once.
- Best execution depth changes at the same logical transition.
- No provider outcome is required to mark "execution started".
- No direct SQL is introduced.

---

## Step 11 — Update directly affected comments/docstrings only

### Goal

Avoid leaving incorrect semantics in source documentation without turning 21B into a documentation PR.

### Instructions

Update only comments/docstrings directly contradicted by the code changes.

At minimum inspect and correct:

- `authorize_pivot()` docstring.
- `apply_work_selection()` docstring.
- `EntityTraversalState` wording if necessary.
- comments around entity-budget enforcement in coordinator policy.
- test docstrings that say discovered expansion is always blocked at exact capacity.

Do not broadly edit:

```text
docs/PR_PLAN.md
docs/TESTING.md
docs/EVALUATION.md
```

Those are intentionally reserved for PR 21D unless a single sentence is now dangerously false and required for code correctness/reviewer understanding.

### Acceptance criteria

- No source comment says authorization itself means investigated.
- Entity budget comments describe deterministic admission, not "all non-root pivots blocked once size reaches max".
- No unrelated docs churn.

---

## Step 12 — Run targeted unit tests

Run the narrow tests first.

Suggested commands; adapt to repository tooling if exact invocation differs:

```bash
pytest -q tests/unit/app/orchestration/test_coordinator_policy.py
pytest -q tests/unit/app/orchestration/test_models.py
pytest -q tests/unit/app/orchestration/test_models_bookkeeping.py
pytest -q tests/unit/app/orchestration/test_graph.py
pytest -q tests/unit/evaluation/test_coordinator_evaluator.py
```

If the repository wrapper is required, use it instead of bypassing configured environment setup.

### Acceptance criteria

- All new tests pass.
- All pre-existing tests in touched unit-test modules pass.
- No test is skipped to make the PR green.
- No assertion is weakened merely to fit implementation behavior.
- No live API credentials are required.

---

## Step 13 — Run focused integration tests

Run:

```bash
pytest -q tests/integration/test_coordinator_trajectory.py
```

or the repository's supported integration wrapper targeting that file.

Then run the complete integration suite:

```bash
./integration-test.sh
```

if that remains the canonical repository command.

### Acceptance criteria

- New exact-capacity integration test passes.
- New overflow-persistence integration test passes.
- New authorization-vs-selection durability test passes.
- Existing canonical coordinator trajectory remains green.
- Existing provider persistence tests remain green.
- No live Internet access is required.
- No live LLM is required.

---

## Step 14 — Run the full quality gate

Use the repository's current canonical quality command.

Expected from the current project conventions:

```bash
./build.sh --qa
```

Do not assume older Black/isort/Pylint commands if the repository has migrated to Ruff. Use the tooling present on current `main`.

### Acceptance criteria

- Formatting/linting passes.
- Static typing passes.
- Unit tests pass.
- Coverage threshold remains satisfied.
- No quality gate is disabled or relaxed.
- No new blanket lint/type suppressions are introduced.
- Integration suite passes separately.

---

# Required unit-test matrix

The following cases are mandatory.

| ID | Test | Expected |
|---|---|---|
| U1 | root + IP, `max_entities=2`, IP candidate | IP authorized |
| U2 | root + IP-A + IP-B, `max_entities=2`, IP-B overflow | IP-B rejected ENTITY_BUDGET |
| U3 | root + IP-A + IP-B, `max_entities=2`, IP-A candidate | IP-A authorized |
| U4 | two roots + discovered IP, `max_entities=2` | discovered IP rejected |
| U5 | authorization only | entity not investigated |
| U6 | first provider work selected | entity marked investigated |
| U7 | second provider work same entity | investigated ID not duplicated |
| U8 | selected work | `best_investigated_depth` recorded |
| U9 | prior depth 3, new depth 1 | best depth becomes 1 |
| U10 | pending authorized pivot | duplicate pivot not reauthorized |
| U11 | completed/current equivalent work | duplicate work suppressed |
| U12 | evaluator entity_count == max | no entity-budget violation |
| U13 | evaluator entity_count > max | entity-budget violation |
| U14 | provider-call counter | unchanged by authorization/selection alone |
| U15 | replan counter | unchanged by these bookkeeping fixes |

---

# Required integration-test matrix

| ID | Test | Real PostgreSQL | External network | Expected |
|---|---|---:|---:|---|
| I1 | exact-capacity admitted discovered IP pivots | Yes | No | executes at depth 1 |
| I2 | overflow discovered entity remains persisted but cannot pivot | Yes | No | ENTITY_BUDGET_EXHAUSTED |
| I3 | authorization persisted before selection | Yes | No | target not investigated yet |
| I4 | selection persisted after authorization | Yes | No | target investigated + best depth set |
| I5 | existing canonical coordinator trajectory regression | Yes | No | remains green |

Do not turn I1–I4 into a new end-to-end test framework. Reuse `test_coordinator_trajectory.py` infrastructure.

---

# Detailed expected state transitions

## Exact-capacity admitted pivot

Before coordinator:

```text
max_entities = 2

root_entity_ids:
  [DOMAIN]

discovered_entity_ids:
  [IP]

traversal:
  DOMAIN:
    minimum_depth = 0
    best_investigated_depth = 0
  IP:
    minimum_depth = 1
    best_investigated_depth = None

investigated_entity_ids:
  [DOMAIN]
```

Coordinator decision:

```text
AUTHORIZE_PIVOT(IP depth=1)
provider work planned for IP
```

After authorization persistence:

```text
pending_pivots:
  IP depth=1 PENDING

pending_provider_work:
  provider/IP/depth=1

investigated_entity_ids:
  [DOMAIN]

IP.best_investigated_depth:
  None
```

After work selection:

```text
current_provider_work:
  provider/IP/depth=1

pivot:
  IP depth=1 IN_PROGRESS

investigated_entity_ids:
  [DOMAIN, IP]

IP.best_investigated_depth:
  1
```

After outcome:

```text
provider_calls_used += 1
current_provider_work = None
completed_provider_work includes item
```

The entity is not first marked investigated at outcome time; it is marked when execution starts.

---

# Overflow semantics example

Before coordinator:

```text
max_entities = 2

ordered unique entities:
  0 DOMAIN   root
  1 IP_A     first discovery
  2 IP_B     second discovery
```

Admitted:

```text
DOMAIN
IP_A
```

Overflow:

```text
IP_B
```

If IP_B is otherwise valid:

```text
Coordinator rejection:
  entity_id = IP_B
  reason = ENTITY_BUDGET
```

If it is the sole actionable blocked candidate:

```text
StopReason.ENTITY_BUDGET_EXHAUSTED
```

Durability after stop:

```text
Entity(IP_B) still exists
IP_B still in discovered_entity_ids
IP_B traversal metadata still exists
Evidence that discovered IP_B still exists
Relationships involving IP_B still exist
```

No destructive cleanup.

---

# STOP conditions for the coding agent

Stop implementation and report rather than improvising if any of these occur:

1. `max_entities` semantics in current `main` have already been redesigned and no longer match this plan.
2. A database schema migration appears necessary to implement deterministic admission.
3. Correct admission cannot be derived from roots + traversal order.
4. A discovered entity can exist without durable traversal ordering and current code intentionally permits that.
5. Moving the investigated marker requires changing provider-call accounting.
6. Moving the investigated marker requires changing LLM accounting.
7. Moving the investigated marker requires a new database transition kind.
8. A coordinator transition stored function explicitly requires authorized pivots to already appear in `investigated_entity_ids`.
9. Existing SQL validation treats `investigated_entity_ids` as authorization rather than execution state and changing that would require a broad persistence redesign.
10. Fixing exact-capacity semantics requires changing provider extraction or Evidence persistence.
11. Tests reveal `max_entities` has a documented meaning materially different from bounded unique entity admission.
12. A live external service is required for integration tests.
13. A live LLM is required for integration tests.
14. The fix would require generic dispatcher/task-union work.
15. The fix would require PR 22 RAG.
16. The fix would require redesigning the coordinator evaluator beyond the exact entity-budget boundary.
17. A quality gate must be disabled to make the PR pass.
18. Existing behavior becomes ambiguous between "authorized", "selected", and "completed" and cannot be represented with existing state fields.

If a STOP condition occurs, provide:

```text
- exact file/function
- current behavior
- why the plan cannot be followed safely
- smallest design decision needed from reviewer
```

Do not silently broaden scope.

---

# Files expected to change

Likely:

```text
src/agentic_threat_investigator/app/orchestration/coordinator.py
src/agentic_threat_investigator/app/orchestration/models.py
src/agentic_threat_investigator/evaluation/coordinator.py

tests/unit/app/orchestration/test_coordinator_policy.py
tests/unit/app/orchestration/test_models.py
  or existing equivalent bookkeeping test file
tests/unit/evaluation/test_coordinator_evaluator.py

tests/integration/test_coordinator_trajectory.py
```

Possibly, only if directly required:

```text
src/agentic_threat_investigator/domain/investigation.py
```

Do not change domain models merely to move code around. Only change them if a comment/docstring or validation rule directly conflicts with the corrected semantics.

---

# Files that should normally NOT change

```text
src/agentic_threat_investigator/app/orchestration/graph.py
src/agentic_threat_investigator/app/orchestration/dispatcher.py
src/agentic_threat_investigator/app/orchestration/composition.py
src/agentic_threat_investigator/app/orchestration/provider_executor.py

src/agentic_threat_investigator/app/evidence_analyst/**
src/agentic_threat_investigator/app/assessment_*.py
src/agentic_threat_investigator/infrastructure/providers/**

docs/PR_PLAN.md
docs/EVALUATION.md
docs/TESTING.md
```

If broad changes to these become necessary, invoke a STOP condition.

---

# Reviewer checklist

The reviewer should be able to answer **yes** to every item below.

## Entity budget

- [ ] Does the implementation derive admitted entities deterministically?
- [ ] Do roots count toward `max_entities`?
- [ ] Are discoveries ordered by durable first-discovery traversal order?
- [ ] Is an entity at the exact capacity boundary still eligible if admitted?
- [ ] Does a later overflow discovery remain in storage but fail pivot authorization?
- [ ] Can an earlier admitted entity still pivot even when later overflow entities exist?
- [ ] Is `ENTITY_BUDGET_EXHAUSTED` emitted only when entity capacity is actually causal?
- [ ] Is no Entity/Evidence/Relationship deleted for budget enforcement?

## Investigated semantics

- [ ] Does `authorize_pivot()` leave `investigated_entity_ids` unchanged?
- [ ] Does provider work selection add the entity to `investigated_entity_ids`?
- [ ] Does the same selection transition record `best_investigated_depth`?
- [ ] Is the investigated entity ID deduplicated?
- [ ] Does authorization without execution remain resumably uninvestigated?
- [ ] Does pending/current/completed work still suppress duplicate work?
- [ ] Does shallower rediscovery remain possible after deeper prior execution?

## Accounting

- [ ] Is provider budget unchanged until actual provider outcome recording?
- [ ] Is replan accounting unchanged?
- [ ] Is LLM accounting unchanged?

## Evaluation

- [ ] Does entity_count == max_entities avoid a false violation?
- [ ] Does entity_count > max_entities remain a violation?
- [ ] Has the PR avoided redesigning policy-invalid-pivot evaluation?

## Testing

- [ ] Are all required unit tests present?
- [ ] Are all required PostgreSQL integration tests present?
- [ ] Does the existing canonical coordinator trajectory still pass?
- [ ] Does `./build.sh --qa` pass?
- [ ] Does `./integration-test.sh` pass?
- [ ] Are there no live network/LLM dependencies?

---

# PR-level acceptance criteria

PR 21B is complete only when all criteria below are met.

1. `max_entities` is implemented as deterministic unique-entity admission capacity.
2. Roots consume capacity.
3. Discoveries consume remaining capacity in first-discovery order.
4. Exact-capacity admitted entities can be investigated.
5. Persisted overflow discoveries cannot be pivoted.
6. Persisted overflow discoveries are not deleted.
7. An admitted entity is not invalidated merely because later overflow discoveries exist.
8. `authorize_pivot()` no longer marks a target investigated.
9. Selecting provider work marks the entity investigated.
10. Work selection records the same entity's `best_investigated_depth`.
11. `investigated_entity_ids` contains no duplicates.
12. Pending authorized pivots remain protected against duplicate authorization.
13. Current and completed provider work remain protected against duplicate execution.
14. Shallower rediscovery remains eligible when the prior execution depth was deeper.
15. Provider-call accounting is unchanged.
16. Replan accounting is unchanged.
17. LLM accounting is unchanged.
18. Exact-capacity evaluator behavior is corrected.
19. Above-capacity evaluator behavior remains failing.
20. No generic evaluator redesign is included.
21. Focused unit tests pass.
22. Focused PostgreSQL integration tests pass.
23. Existing coordinator trajectory integration tests pass.
24. Full integration suite passes.
25. Full QA suite passes.
26. No quality threshold is weakened.
27. No database schema migration is introduced.
28. No new orchestration task type is introduced.
29. No PR 22 functionality is introduced.
30. No PR 21C/21D work is pulled into this PR.

---

# Expected PR description

Suggested concise PR description:

> PR 21B corrects two coordinator state-machine semantics left incomplete by PR 21. It defines `max_entities` as deterministic bounded admission over roots plus first-discovered entities, allowing provider work on already-admitted entities at exact capacity while preventing pivots through overflow discoveries. It also moves `investigated_entity_ids` bookkeeping from pivot authorization to provider-work selection so the investigated marker and `best_investigated_depth` both represent actual execution start. The PR includes focused unit tests and real-PostgreSQL integration coverage and intentionally excludes the broader canonical orchestration and evaluator-hardening work reserved for PR 21C/21D.

---

# What comes next

Do not implement these in PR 21B.

```text
PR 21B
  Coordinator correctness:
  - entity admission/budget semantics
  - investigated execution-state semantics
        |
        v
PR 21C
  Canonical production orchestration integration:
  - prove discovery -> persistence -> pivot -> provider round
  - analysis synchronization
  - production composition/bootstrap boundary as required
        |
        v
PR 21D
  Coordinator evaluation + documentation hardening:
  - true policy-validity evaluation
  - scenario/gate reconciliation
  - docs aligned with delivered behavior
        |
        v
PR 22
  Threat Research / RAG
```

PR 21B should remain small enough that a low-reasoning coding agent can execute it mechanically from this plan without making architecture decisions.
```