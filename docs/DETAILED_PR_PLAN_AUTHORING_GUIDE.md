# Detailed PR Plan Authoring Guide

## Purpose

This document defines the recommended structure, level of specificity, and authoring process for a **Detailed PR Execution Plan**.

It is intended for implementation PRs that will be executed by a coding agent, especially a lower-reasoning agent that performs well when given:

- a narrow architectural objective;
- an accurate description of the current codebase;
- explicit reuse requirements;
- concrete implementation sequencing;
- precise invariants;
- deterministic tests;
- clear acceptance criteria;
- explicit non-goals and STOP conditions.

The model is based on the planning approach used successfully for ATI PR 21B–21D and PR 22A onward.

A detailed PR plan is **not** a roadmap entry, design brainstorm, or general feature specification. It is an executable implementation contract.

---

# 1. Core principle

A good detailed PR plan should make the coding problem substantially more deterministic before implementation begins.

The coding agent should not need to make major architectural decisions while implementing the PR.

The plan should answer:

```text
Why does this PR exist?
What exactly is wrong or missing on current main?
What architecture already exists?
What must be reused?
What is the desired final behavior?
What files/components are likely involved?
What order should implementation follow?
What invariants must remain true?
How will each behavior be tested?
What is explicitly outside scope?
When must the coding agent STOP instead of improvising?
How will a reviewer determine that the PR is complete?
```

The desired effect is:

```text
architecture/reasoning
        happens primarily during planning

implementation
        becomes constrained execution

review
        verifies conformance to explicit invariants
```

---

# 2. Prerequisite: inspect current `main`

Never write a detailed PR plan solely from:

- `PR_PLAN.md`;
- an earlier architectural discussion;
- a previous PR plan;
- memory of the repository;
- assumptions about what preceding PRs implemented.

Before producing the plan, inspect fresh `main`.

For repository work, verify at minimum:

```text
relevant domain models
application services
ABCs/interfaces
repositories
database migrations
stored functions
configuration
production composition
tests
integration fixtures
documentation
preceding PR implementation
```

Also search for existing implementations of concepts the roadmap says should be added.

Example:

```text
Roadmap says:
    "add retrieval abstraction"

Current main already has:
    ResearchRetriever(ABC)

Detailed plan must say:
    reuse ResearchRetriever

It must NOT tell the coding agent to create:
    ThreatResearchRetriever
    RagRetriever
    VectorRetriever
    or another duplicate abstraction
```

A detailed plan is based on the **delta from current main**, not merely on the roadmap description.

---

# 3. Reconcile roadmap scope with current implementation

After inspecting `main`, determine whether the roadmap PR is still correctly scoped.

There are three possible outcomes.

## Outcome A — Scope remains appropriate

Proceed with one detailed PR plan.

## Outcome B — Much of the roadmap work already exists

Narrow the detailed plan to the missing work.

Do not reimplement existing architecture merely to match old roadmap wording.

## Outcome C — The roadmap PR contains multiple independent architectural concerns

Split the PR before writing the detailed plan.

A useful heuristic is:

> A coding-agent PR should normally have one dominant architectural problem.

For example:

```text
Bad monolithic scope:

storage
+ retrieval
+ LLM agent
+ orchestration
+ evaluation
```

Prefer:

```text
PR A — storage/retrieval foundation
PR B — LLM agent
PR C — orchestration integration
PR D — evaluation/docs hardening
```

This pattern reduces implementation ambiguity and makes regressions easier to isolate.

---

# 3A. Replanning an in-progress PR

A detailed plan may be written after implementation has already started. In that case, do not treat the roadmap or original plan as if no work exists.

Inspect the implementation branch as well as fresh `main`, then classify each originally planned capability:

| Classification | Meaning | Plan treatment |
|---|---|---|
| DONE + VERIFIED | implementation exists and required evidence has passed | preserve it; do not reimplement; include regression coverage |
| DONE, NOT VERIFIED | implementation exists but required acceptance evidence is missing | verify it before completion |
| PARTIAL | only part of the required behavior exists | describe the exact remaining delta |
| NOT STARTED | required behavior does not exist | provide normal implementation steps |
| BLOCKED | progress requires a decision, dependency, or unavailable environment | apply the plan's STOP rules |

For an in-progress PR, the plan must explicitly distinguish:

```text
what is already implemented
what has actually been verified
what remains to implement
what remains only to verify
what prior evidence is reusable
what evidence must still be produced
```

Do not instruct the coding agent to rewrite working code merely because the original plan described its creation. Do not treat a status report as proof by itself; reconcile its claims with the branch and available test evidence.

---

# 3B. Execution evidence and completion discipline

For every mandatory quality or acceptance gate, distinguish three different facts:

```text
test/code exists
    !=
test was executed
    !=
test passed in the required environment/topology
```

A gate is complete only when the required command has actually executed successfully in the required environment. Compilation, code inspection, a related test, a previous run against different code, or reasoning that a test "should pass" is not acceptance evidence.

Plans should classify test evidence where relevant:

```text
baseline evidence
    proves the starting branch/environment was healthy

regression evidence
    proves previously delivered behavior remains healthy

feature acceptance evidence
    proves the new capability itself works
```

**Regression evidence must not substitute for feature acceptance evidence.**

If a repository defines an authoritative test harness, name it and require it for acceptance. Distinguish what is tested from how the required topology is established. For example, if `scripts/e2e.sh` owns the production-path browser stack, a direct `npx playwright test` invocation against an arbitrary running stack is not equivalent acceptance evidence.

Include exact commands when command form, environment variables, browser/project selection, worker count, retry count, cycle count, or harness setup materially changes what is exercised. Otherwise, naming the repository-prescribed gate is sufficient.

For E2E/stability work, state explicitly:

- the authoritative harness;
- the real application components exercised;
- deterministic/fake substitutions and the exact boundary each replaces;
- browser/project matrix when required;
- worker/retry settings when required;
- stability-cycle count when required;
- whether direct lower-level test-runner invocation is diagnostic only or permitted acceptance evidence.

Avoid ambiguous phrases such as "fake LLM", "fake stack", or "run Playwright" when multiple deterministic mechanisms exist. Name the concrete implementation/configuration and boundary, for example:

```text
Python integration/evaluation:
    FakeLlmClient at the model boundary

Browser E2E:
    production worker
    ATI_LLM_DRIVER=deterministic
    deterministic fake-world provider data
    real API/database/frontend/browser path
```

These substitutions are not interchangeable.

---

# 3C. Required failure classification

When a mandatory gate fails, the plan should require the coding agent to classify the failure as one of:

1. introduced regression;
2. feature implementation defect;
3. deterministic pre-existing failure;
4. nondeterministic/flaky failure;
5. environment/harness failure.

A failure may be called pre-existing only after reproducing it on the relevant baseline/base commit or otherwise producing equivalent evidence. A failure may be called flaky only after evidence demonstrates nondeterminism. "Unrelated" is not a sufficient classification by itself.

The final implementation report must state unresolved failures explicitly. Do not hide them behind reruns, retries, or a green subset.

---

# 3D. Status is derived from acceptance

Keep these states separate:

```text
implementation status
test/evidence status
PR completion status
roadmap/documentation status
```

A feature can be implemented but unverified. A test can exist but be unexecuted. A PR is complete only when its mandatory acceptance gates pass.

Roadmap `[DONE]`, completion markers, release notes, or equivalent status documentation must be updated **after** the required acceptance gates pass. A documentation status marker is a consequence of completion; it is never evidence of completion.

---

# 4. Recommended document structure

A detailed PR plan should normally contain the following sections.

```text
Title
Purpose
Architectural invariants
Current-main facts
In-progress status/evidence reconciliation (when applicable)
Scope
Explicitly out of scope
Detailed implementation parts/steps
Test matrices
Integration/vertical-slice tests
Authoritative test harness / execution topology (when relevant)
Failure classification and completion evidence
Documentation updates
Expected files changed
Files that should normally not change
Explicit reuse requirements
STOP conditions
Recommended implementation sequence
Reviewer checklist
PR-level acceptance criteria
Suggested PR description
Dependency/next-PR context
Critical coding-agent rules
```

Not every PR requires every section, but omission should be deliberate.

---

# 5. Title

Use an exact PR identifier and a narrow capability description.

Example:

```markdown
# PR 22A — Research Storage, Corpus Ingestion, and Retrieval Foundation
```

Avoid vague titles such as:

```text
RAG improvements
Coordinator updates
Misc fixes
Research work
```

The title should communicate the dominant architectural concern.

---

# 6. Purpose

The Purpose section explains **why this PR exists** and what architectural problem it closes.

It should normally include:

1. what preceding PRs delivered;
2. what remains incomplete or incorrect;
3. what this PR will establish;
4. what major future PR depends on it.

Example pattern:

```markdown
## Purpose

PR X completes the application-level execution seam introduced by PR Y.

Current main already provides A, B, and C. It does not yet provide D.

PR X therefore adds D without redesigning A/B/C.

The dominant architectural concern is:

> [one-sentence invariant/problem statement]
```

The Purpose section should make it impossible to mistake the PR for a broader feature phase.

---

# 7. Architectural invariants

State the rules that must remain true regardless of implementation details.

These are more important than class names.

Examples:

```text
One UnitOfWork represents one real PostgreSQL transaction.

Providers retrieve.
Collectors coordinate retrieval.
Repositories persist.
Application workflows decide persistence.
Agents decide investigative actions within policy.

A pivot may execute only if the target was already admitted through
authorized discovery and passes deterministic pivot policy.

Retrieved contextual knowledge is not source Evidence.

A persisted analytical result must retain provenance even if the
active retrieval index is rebuilt.
```

Use diagrams where they clarify ownership:

```text
Coordinator
    decides WHAT work is authorized
          ↓
TaskDispatcher
    decides HOW/WHERE it executes
          ↓
WorkExecutor
    performs the work
```

Invariants give the coding agent a way to resolve small implementation choices without inventing architecture.

---

# 8. Current-main facts

This section is essential for coding-agent plans.

Document the important implementation facts discovered during repository inspection.

Include:

- exact files;
- relevant classes/functions;
- current behavior;
- existing abstractions;
- important limitations;
- preceding PR semantics.

Example:

```markdown
## Existing retrieval abstraction

`src/.../app/research.py`

Already contains:

```python
class ResearchRetriever(ABC):
    @abstractmethod
    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        ...
```

**Do not create another retrieval ABC.**
```

This section prevents the agent from reasoning from stale architecture.

Use code snippets only for the contractually important parts.

Do not dump entire source files.

---

# 9. Scope

Define what the PR owns.

Prefer capability-oriented subsections.

Example:

```markdown
## In scope

### A. Durable citation identity
...

### B. Immutable research-result persistence
...

### C. Controlled re-indexing
...
```

Each item should correspond to the PR's dominant concern.

If the in-scope section becomes a list of several unrelated systems, reconsider whether the PR should be split.

---

# 10. Explicitly out of scope

This section is mandatory for agent-executed plans.

State adjacent work that the coding agent might otherwise reasonably attempt.

Example:

```markdown
## Explicitly out of scope

PR X must not add:

- Coordinator graph changes;
- report generation;
- LLM prompts;
- distributed task infrastructure;
- generic evaluation framework;
- unrelated refactors;
- new data sources;
- API endpoints.
```

Include future PR ownership where useful:

```text
PR 22B owns Research Agent execution.
PR 22C owns Coordinator integration.
PR 22D owns research evaluation.
```

This makes the PR boundary operational rather than aspirational.

---

# 11. Detailed implementation sections

Break implementation into numbered Parts and Steps.

Recommended hierarchy:

```text
Part 1 — Domain contract
    Step 1
    Step 2

Part 2 — Persistence
    Step 3
    Step 4

Part 3 — Application service
    Step 5

Part 4 — Production composition
    Step 6

Part 5 — Tests
```

Each Step should specify:

```text
where
what
why
required behavior
constraints
acceptance criteria
```

Example:

```markdown
## Step 7 — Update `PgVectorResearchRetriever`

Modify the existing retriever only.

Its result mapping must expose:

- citation identity;
- document identity;
- source-record identity;
- chunk sequence.

Do not change:

- cosine ranking semantics;
- embedding compatibility filtering;
- source filters;
- result limits;
- empty-result behavior.
```

This is preferable to:

```text
Update retriever to support citations.
```

---

# 12. Separate semantic identity from persistence identity

Whenever a PR involves persistence, explicitly identify different forms of identity.

For example:

```text
row ID
    = persistence identity

semantic key
    = logical object identity

content hash
    = representation/change identity

external source ID
    = upstream identity
```

Do not let the coding agent infer these distinctions.

This is especially important for:

- append-only records;
- replaceable indexes;
- history tables;
- relationships;
- observations;
- cached/derived data;
- versioned artifacts.

---

# 13. Define ownership boundaries

For every important object, say who creates it and who persists it.

Example:

```text
EvidenceProvider
    creates normalized Evidence

RelationshipExtractor
    creates RelationshipAssertion

Application persistence service
    resolves/upserts Entity/Relationship
    appends RelationshipObservation

Evidence Analyst
    creates structured analytical decision

Application layer
    owns persisted Assessment IDs
```

Ownership ambiguity is a common source of agentic implementation drift.

---

# 14. Transaction boundaries

For database work, state transaction semantics explicitly.

Example:

```text
load context in short UoW
    ↓
close transaction
    ↓
external HTTP / embedding / LLM I/O
    ↓
validate result
    ↓
open short UoW
    ↓
persist atomically
```

If external I/O must remain outside a transaction, say so repeatedly where relevant.

Also state atomicity requirements:

```text
checkpoint says N
iff
all records through N are committed
```

The coding agent should never have to invent transaction semantics.

---

# 15. External boundaries and fakes

Distinguish between:

```text
production architecture
```

and:

```text
deterministic test substitution
```

Preferred rule:

> Fake the external or nondeterministic boundary, not the ATI architecture being tested.

Example:

```text
Production:
real source adapter
 -> real parser
 -> real persistence
 -> real pgvector retrieval
 -> real LLM adapter

Automated test:
local fixture in real upstream format
 -> same production parser
 -> same persistence
 -> same pgvector retrieval
 -> FakeLlmClient at model boundary
```

Avoid introducing a parallel fake architecture such as:

```text
FakeThreatSource
FakeRetriever
FakePersistence
```

for a canonical integration test if doing so bypasses the production path the test is supposed to validate.

Lightweight fakes remain appropriate for isolated unit tests.

---

# 16. Verify external framework contracts

If the PR depends on:

- LangChain;
- OpenAI SDK;
- SQLAlchemy;
- pgvector;
- FastAPI;
- a third-party API;
- a data-source schema;

verify the exact current contract before finalizing implementation instructions.

Prefer:

```text
installed dependency source/API
official documentation
current upstream schema
```

Do not write implementation instructions from remembered APIs.

Add a STOP condition when the required public contract is unavailable.

---

# 17. Deterministic behavior tables

For policy/state-machine work, define cases in tables.

Example:

| Case | Input | Expected |
|---|---|---|
| exact entity capacity | pivot already admitted | allowed |
| entity overflow | new entity | rejected |
| repeated pivot | already investigated at equal/better depth | skipped |
| unchanged evidence | analysis already performed | no repeated analysis |

Tables are particularly effective for low-reasoning coding agents because they convert policy into finite cases.

---

# 18. Unit test matrix

Specify important unit cases explicitly.

Use stable IDs when useful:

| ID | Case | Expected |
|---|---|---|
| C1 | valid input | accepted |
| C2 | duplicate identity | rejected |
| C3 | missing provenance | rejected |
| C4 | exact budget capacity | legal |
| C5 | budget overflow | rejected |

Benefits:

- coding agent can map implementation to tests;
- reviewer can detect missing cases;
- plan discussion can refer to a stable case ID;
- future fixup plans can identify regressions precisely.

Do not attempt to enumerate every trivial test.

Enumerate behavioral boundaries.

---

# 19. Integration and vertical-slice tests

A detailed plan should distinguish unit correctness from production-path correctness.

A vertical slice should exercise as much real application architecture as practical.

Example:

```text
real-format fixture
    ↓
production parser
    ↓
application service
    ↓
real PostgreSQL stored functions/repositories
    ↓
real pgvector retrieval
    ↓
structured result
```

Fake only external boundaries required for determinism.

State exact assertions.

Do not merely say:

```text
add integration tests
```

---

# 20. Failure behavior

Define how failures behave.

Examples:

```text
malformed graph output
    -> typed lifecycle error
    -> not raw KeyError

missing investigation
    -> typed InvestigationNotFoundError

provider HTTP failure
    -> bounded provider outcome
    -> no partial persistence

invalid citation
    -> validation failure
    -> no ResearchResult persistence
```

Also specify cancellation behavior for async code:

```text
asyncio.CancelledError propagates
```

unless architecture explicitly requires otherwise.

---

# 21. Idempotency

If the operation can be retried, define idempotency explicitly.

Questions to answer:

```text
What identifies the operation?
What is safe to repeat?
What is append-only?
What is replaceable?
What is deduplicated?
What changes when inputs change?
What remains stable?
```

Example:

```text
same document + same embedding identity
    -> no chunk replacement

same document + new embedding identity
    -> re-embed/replace derived chunks

semantic citation identity
    -> remains stable across pure re-embedding
```

---

# 22. Database migrations and stored functions

When relevant, specify:

- expected migration behavior;
- derived vs authoritative data;
- backfill strategy;
- uniqueness constraints;
- FK behavior;
- function versioning convention;
- whether old functions remain immutable.

Never instruct the coding agent to edit previously shipped versioned SQL in place if the repository uses immutable function versions.

If a migration may safely discard derived data, say so.

Example:

```text
DocumentChunk vectors are derived and rebuildable.
SourceRecord and Investigation data are authoritative and must not be discarded.
```

---

# 23. Documentation updates

Name the exact docs that should change and what each should say.

Example:

```text
ARCHITECTURE.md
    ownership and lifecycle

DATABASE.md
    schema/transaction semantics

TESTING.md
    deterministic fixture and vertical-slice rules

EVALUATION.md
    delivered metrics only

PR_PLAN.md
    completion status only
```

Avoid broad:

```text
update documentation
```

Also specify docs that should **not** be expanded into future architecture.

---

# 24. Expected files changed

Provide a likely file map.

Example:

```text
domain/foo.py
app/foo_service.py
app/persistence/repositories.py
infrastructure/persistence/postgresql/foo_repository.py
new migration
tests/unit/...
tests/integration/...
docs/...
```

Label it as expected rather than mandatory when current implementation may justify a nearby location.

This helps the coding agent recognize scope drift.

---

# 25. Files that should normally not change

This is highly effective for constrained implementation.

Example:

```text
The PR should not normally require behavioral changes in:

app/orchestration/coordinator.py
app/orchestration/graph.py
domain/assessment.py
api/**
evaluation/**
```

If the coding agent believes one must change, it should evaluate a STOP condition rather than casually editing it.

---

# 26. Explicit reuse requirements

List existing abstractions/components that must be reused.

Example:

```text
Reuse:

UnitOfWork
ResearchRetriever
EmbeddingClient
DocumentIndexingService
PgVectorResearchRetriever
TaskDispatcher
InvestigationRunner
```

Then state:

```text
Do not duplicate them under new feature-specific names.
```

This is especially important in mature codebases where an agent may prefer creating a new local abstraction instead of understanding the existing one.

---

# 27. STOP conditions

STOP conditions are one of the most important parts of a low-reasoning coding-agent plan.

They define when the coding agent must stop implementation and request an architectural decision rather than improvise.

Examples:

```text
STOP if:

1. required behavior needs a Coordinator redesign;
2. a migration would destroy authoritative data;
3. the existing abstraction cannot represent the required operation;
4. implementation requires a future-PR feature;
5. the public third-party API cannot satisfy the planned contract;
6. a long PostgreSQL transaction around external I/O appears necessary;
7. a new generic framework appears necessary;
8. tests require live Internet;
9. scope requires weakening QA or coverage gates;
10. current main already implements the planned capability differently.
```

Specify the report format:

```text
When stopping, report:

file/function/schema
current behavior
required invariant
why current architecture cannot satisfy it
smallest reviewer decision needed
```

STOP conditions prevent a coding agent from turning uncertainty into architecture.

---

# 28. Recommended implementation sequence

Give the coding agent an ordered execution path.

Example:

```text
Phase 0 — Baseline
Phase 1 — Pure domain changes
Phase 2 — Persistence
Phase 3 — Application service
Phase 4 — Production adapter
Phase 5 — Integration path
Phase 6 — Docs/full QA
```

Within Phase 0:

```text
1. re-read current files;
2. identify migration head;
3. run targeted baseline tests;
4. run relevant integration tests;
5. record green baseline;
6. only then edit.
```

This prevents the agent from mistaking pre-existing failures for its own regressions.

---

# 29. Reviewer checklist

Create a checklist grouped by architectural concern.

Example:

```markdown
## Persistence

- [ ] one UoW = one PostgreSQL transaction
- [ ] no external I/O inside transaction
- [ ] repository ABC reused
- [ ] rollback tested

## Scope

- [ ] no Coordinator changes
- [ ] no report generation
- [ ] no future evaluator framework

## Provenance

- [ ] every claim cites stable provenance
- [ ] no source Evidence invented from contextual research
```

The checklist should be usable independently of the implementation narrative.

---

# 30. PR-level acceptance criteria

End with a numbered, exhaustive-but-focused completion list.

Example:

```text
PR is complete only when:

1. domain model exists;
2. invalid provenance is rejected;
3. persistence round-trips;
4. rollback works;
5. canonical integration path works;
6. idempotency is proven;
7. no future-PR behavior is introduced;
8. docs are reconciled;
9. ./build.sh --qa passes;
10. ./integration-test.sh passes.
```

These criteria become the final contract for both coding agent and reviewer.

Group completion gates by concern when the PR has multiple test layers, for example:

```text
Implementation
Targeted/unit tests
Integration/vertical slice
E2E
Stability/stress
Regression
Repository QA
Documentation/status
```

For each nontrivial gate, make clear what constitutes evidence. A required test that exists but has not run is **NOT TESTED**, not PASS. A related regression suite passing does not prove a new feature-specific acceptance journey.

Do not allow retries to conceal a required first-attempt or stability guarantee. If acceptance requires `retries=0`, a later rerun can diagnose the failure but cannot retroactively make the failed acceptance run green.

Prefer objective statements.

Avoid:

```text
implementation is clean
tests are good
architecture is robust
```

unless accompanied by measurable meaning.

---

# 31. Suggested PR description

Provide a short ready-to-use PR description.

It should summarize:

```text
what was added
what existing architecture was reused
what important invariant was established
what is explicitly not included
```

This is useful both for the coding agent and later review.

---

# 32. Dependency and next-PR context

When the PR is one part of a series, show where it fits.

Example:

```text
PR 22A
foundation
   ↓
PR 22B
agent
   ↓
PR 22C
orchestration
   ↓
PR 22D
evaluation
```

This reinforces why adjacent features must not leak into the current PR.

---

# 33. Critical coding-agent rules

End with a few memorable rules.

Examples:

> **Do not rebuild infrastructure that already exists on `main`.**

> **Do not turn uncertainty into a new abstraction. STOP when the plan requires an architectural decision.**

> **Fake external boundaries, not the production architecture being tested.**

> **Preserve transactional and provenance invariants even if a shortcut would reduce code.**

These should summarize the highest-risk failure modes.

---

# 34. Level of specificity

A detailed PR plan should be highly specific about:

```text
behavior
ownership
invariants
state transitions
persistence semantics
transaction boundaries
test cases
scope
failure behavior
reuse
```

It may be less prescriptive about:

```text
private helper names
minor file organization
local refactoring details
exact internal algorithms where multiple implementations satisfy the same contract
```

The goal is not to write the code in prose.

The goal is to remove architectural ambiguity.

---

# 35. What not to put in a detailed PR plan

Avoid:

## Speculative future architecture

Do not design three future releases merely because the current PR creates an extension seam.

## Unnecessary implementation trivia

Do not prescribe every variable name or every assertion.

## Broad cleanup

Avoid:

```text
while here, refactor...
modernize...
clean up...
generalize...
```

unless required for the PR invariant.

## Generic best practices without repository context

Prefer:

```text
Use the existing UnitOfWork and versioned stored-function convention.
```

over:

```text
Follow database best practices.
```

## Unbounded optional work

Avoid:

```text
optionally improve...
consider adding...
if time permits...
```

A coding-agent execution plan should have deterministic scope.

---

# 36. Plan sizing and PR splitting heuristic

Before finalizing a detailed plan, ask whether the coding agent must solve more than one major architectural question.

Warning signs:

```text
new persistence model
+ new LLM agent
+ new state-machine branch

new API
+ new frontend
+ new background scheduler

new provider framework
+ several provider implementations
+ evaluation framework
```

Split when failures in one concern would make another concern difficult to review independently.

A useful pattern is:

```text
A — deterministic foundation
B — intelligent/external execution
C — orchestration integration
D — evaluation/docs hardening
```

Not every feature requires A/B/C/D, but it is a strong default for complex agentic systems.

---

# 37. Fixup plans

When review finds defects after implementation, do not rewrite the original detailed plan.

Create a narrow fixup plan.

A fixup plan should contain:

```text
review finding
exact current-main defect
required invariant
minimal code changes
regression tests
explicit non-goals
acceptance criteria
```

Example:

```text
PR 21C2
    malformed graph output normalization only

not:
    redesign InvestigationRunner
```

Fixups should be substantially narrower than the originating PR.

---

# 37A. Follow-up plans for partially implemented or stopped PRs

When implementation stops partway through a PR and work will continue on the same PR, create a follow-up plan rather than pretending the original plan is unexecuted.

A follow-up plan must:

1. inspect fresh `main` and the current implementation branch;
2. reconcile any coding-agent status/STOP report with the actual branch;
3. inventory DONE + VERIFIED, DONE NOT VERIFIED, PARTIAL, NOT STARTED, and BLOCKED work;
4. preserve verified implementation unless a demonstrated defect requires change;
5. identify the exact remaining implementation delta;
6. identify feature-specific acceptance evidence still missing;
7. distinguish previously passed regression gates from new feature acceptance gates;
8. carry forward applicable architectural invariants, non-goals, reuse rules, and STOP conditions;
9. define the exact conditions under which the PR may finally be marked complete.

Do not inflate the follow-up plan by restating already completed implementation instructions as new work. Include enough existing-state detail that a low-reasoning agent knows what must remain unchanged.

---

# 38. Review process after implementation

Review the implementation against:

```text
current main
+
detailed PR plan
+
architectural invariants
+
tests
```

Do not review only the diff mechanically.

Verify:

1. required behavior exists;
2. existing architecture was reused;
3. STOP-boundary features did not leak in;
4. tests actually exercise the intended production path;
5. negative/boundary cases exist;
6. documentation matches delivered behavior;
7. acceptance criteria are satisfied.

If the implementation deviates but is architecturally superior, evaluate the deviation explicitly rather than declaring noncompliance solely because a suggested private implementation detail changed.

Behavioral and architectural contracts outrank incidental naming.

---

# 39. Reusable template

The following template can be copied for a new detailed PR plan.

```markdown
# PR X — <Narrow title>

## Purpose

<What exists, what is missing, why this PR exists.>

The dominant architectural concern is:

> **<one-sentence invariant/problem>**

---

# Architectural invariants

- ...
- ...

```text
<ownership/data-flow diagram>
```

---

# Current-main facts that must be respected

## Existing <component>

`path/to/file.py`

Current behavior:

```python
...
```

**Reuse this. Do not create a duplicate abstraction.**

---

# Scope

## In scope

### A. <capability>
- ...

### B. <capability>
- ...

---

# Explicitly out of scope

PR X must not add:

- ...
- ...

If implementation requires one of these, STOP.

---

# Part 1 — <concern>

## Step 1 — <action>

Location:

```text
path/to/file.py
```

Required behavior:

- ...
- ...

Do not:

- ...
- ...

### Acceptance criteria

- ...
- ...

---

# Part 2 — <concern>

## Step 2 — <action>

...

---

# Unit test matrix

| ID | Case | Expected |
|---|---|---|
| U1 | ... | ... |
| U2 | ... | ... |

---

# PostgreSQL / integration test matrix

## I1 — <scenario>

Exercise:

```text
A
 -> B
 -> C
```

Assert:

- ...
- ...

---

# Test execution topology and acceptance evidence

Authoritative harness:

```text
<repository-prescribed command/harness, if applicable>
```

Required topology/substitutions:

- ...

Feature acceptance evidence:

- ...

Regression evidence:

- ...

Stability/stress evidence, if applicable:

- ...

Direct lower-level runner invocation is:

```text
<acceptance evidence / diagnostic only / not applicable>
```

---

# Failure classification

For every failing required gate, classify and provide evidence:

```text
introduced regression
feature defect
pre-existing deterministic failure
flaky/nondeterministic failure
environment/harness failure
```

---

# Failure and cancellation behavior

- ...
- ...

---

# Idempotency and retry semantics

- ...
- ...

---

# Documentation updates

## `docs/ARCHITECTURE.md`
- ...

## `docs/TESTING.md`
- ...

---

# Expected production files changed

```text
...
```

---

# Files that should normally NOT change

```text
...
```

---

# Explicit reuse requirements

Reuse:

```text
...
```

Do not duplicate these abstractions.

---

# STOP conditions

Stop and report if:

1. ...
2. ...
3. ...

When stopping, report:

```text
file/function/schema
current behavior
required invariant
smallest architecture decision needed
```

---

# Recommended implementation sequence

## Phase 0 — Baseline

1. Re-read current main.
2. Run targeted tests.
3. Record baseline green.

## Phase 1 — Domain
...

## Phase 2 — Persistence
...

## Phase 3 — Integration
...

## Phase 4 — Docs/full QA
...

---

# Reviewer checklist

## Architecture

- [ ] ...

## Persistence

- [ ] ...

## Scope

- [ ] ...

---

# PR-level acceptance criteria

PR X is complete only when:

## Implementation
1. ...

## Targeted/unit tests
2. ...

## Integration / feature acceptance
3. ...

## E2E / stability, when applicable
4. required feature-specific journey passes through the authoritative harness;
5. required stability cycles pass with the specified workers/retries/browser matrix;

## Regression / repository QA
6. relevant regression suites pass;
7. full QA passes;

## Documentation/status
8. docs match delivered behavior;
9. roadmap/completion status is updated only after gates 1-8 pass;
10. no unresolved STOP condition or unexplained required-gate failure remains.

---

# Suggested PR description

> <Concise PR description.>

---

# Sequence after PR X

```text
PR X
   ↓
PR Y
```

Critical coding-agent rules:

> **<rule 1>**

> **<rule 2>**
```

---

# 40. Compact authoring checklist

Before delivering a detailed PR plan, verify:

- [ ] Fresh `main` was inspected.
- [ ] For an in-progress/follow-up plan, the implementation branch and status report were reconciled with actual code/evidence.
- [ ] Existing work is classified as DONE + VERIFIED, DONE NOT VERIFIED, PARTIAL, NOT STARTED, or BLOCKED where applicable.
- [ ] The roadmap scope was reconciled with actual implementation.
- [ ] Existing abstractions are explicitly identified.
- [ ] The PR has one dominant architectural concern.
- [ ] Invariants are explicit.
- [ ] Ownership boundaries are explicit.
- [ ] Transaction boundaries are explicit where relevant.
- [ ] Production vs test/fake boundaries are explicit.
- [ ] Each deterministic/fake substitution is named precisely; ambiguous "fake" terminology is avoided.
- [ ] The authoritative test harness/execution topology is named where relevant.
- [ ] Exact commands/options are specified when invocation semantics affect acceptance.
- [ ] External API assumptions were verified where relevant.
- [ ] Scope and non-goals are explicit.
- [ ] Implementation is broken into ordered steps.
- [ ] Boundary cases have deterministic tests.
- [ ] At least one production-path vertical slice exists where appropriate.
- [ ] Failure/idempotency semantics are specified.
- [ ] Expected files and normally-unchanged files are listed.
- [ ] Existing components that must be reused are listed.
- [ ] STOP conditions prevent architectural improvisation.
- [ ] Reviewer checklist exists.
- [ ] Objective PR-level acceptance criteria exist.
- [ ] Baseline, regression, and feature-acceptance evidence are distinguished where relevant.
- [ ] Required stability/stress evidence is explicit where relevant.
- [ ] Required-gate failures must be classified with evidence before being called pre-existing/flaky/unrelated.
- [ ] Roadmap/DONE status is explicitly downstream of successful acceptance gates.
- [ ] Full repository QA gates are named.
- [ ] Future PR responsibilities are not accidentally absorbed.

---

# Final standard

A successful detailed PR plan should let a coding agent spend most of its effort on **implementation**, not architecture discovery.

The plan is sufficiently detailed when a reviewer can ask:

> "Did the implementation satisfy this contract?"

rather than:

> "What architecture did the coding agent decide to build?"

That is the standard.
