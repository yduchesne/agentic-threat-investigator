# Testing

As of this writing, ATI comprises more than 5,000 unit tests, and around 800 integration tests. 

## Unit Testing

Unit testing has been performed agressively, with an 85% test coverage target (enforced through a pre-commit hook).

At the core, unit testing rests on the notion of interface, which are used at system/dependency boundaries. This allows introducing mocks while keeping domain and application logic real: Mock boundaries, not internals.

The 85% threshold is therefore only a backstop; the more important characteristic is how the code has been structured to make meaningful isolation possible.

The following principles constitute the unit testing philosophy adopted for ATI.

### 1. Interfaces define the natural mocking seams

ATI deliberately puts interfaces (modeled in code using Python ABCs - i.e.: from Python's `abc` module) around capabilities whose implementations involve infrastructure, nondeterminism, or independently testable behavior.

Examples include:

- `LlmClient`
- `ResearchRetriever`
- `ResearchExecutor`
- `ResearchRequestPlanner`
- `ProviderWorkPlanner`
- `TaskDispatcher`
- `WorkExecutor`
- `EvidenceProvider`
- `EmbeddingClient`
- `UnitOfWork` / repositories
- ...

Production code depends on these abstractions rather than infrastructure implementations:

```
ResearchAgent
   │
   ├── ResearchRetriever
   ├── LlmClient
   ├── ResearchResultPersistenceService
   └── LlmAccountingService
```

Consequently, a `ResearchAgent` unit test doesn't need:

- Postgres
- OpenAI
- LangChain
- real embeddings
- etc.

Those are outside the unit under test. They are replaced by mocks/fakes when unit testing.

### 2. Prefer purpose-built fakes/stubs over deep mocking

An important ATI pattern is that ATI often has explicit deterministic implementations such as:

- `FakeResearchExecutor`
- `FakeLlmClient`
- `MappingProviderWorkPlanner`
- deterministic/fake providers
- etc.

This was deemed preferable to deep `MagigMock` object graphs: A reusable fake when useful; a simple stub when only canned behavior is required; Mock/AsyncMock when interaction verification proves necessary and/or where mocking doesn't require a complicated setup. 

There is no architectural objection to conventional mocking.

> Another factor that has favored fakes is the fact that AI is generating their implementation, which is much faster.

### 3. Pure domain logic needs no mocks

A substantial amount of ATI is deliberately "pure" - not relying on dependencies outside of the unit:

- Entity models
- Evidence models
- Relationship models
- InvestigationState
- Assessment
- ResearchResult
- validation
- state-transition functions
- extraction 
- policy calculations
- fingerprinting
- request planning

This allows unit testing without any mocking.

### 4. Each unit gets tested separately, with fakes/mocks at the boundary

Given:

```
ResearchAgent(Class)
       │
       ▼
LlmClient(Interface)
       │
       ▼
LangChainLlmClient(Class)
       │
       ▼
BaseChatModel(Mock/Fake)
```

Then the `ResearchAgent` unit is tested against a `FakeLlmClient`; the `LangChainLlmClient` is tested against a mock/fake `BaseChatModel`.


### 5. Test the public/observable contract rather than internal logic/state

Given:

- `InvestigationState`
- `CoordinatorPolicyContext`
- deterministic planner responses

Expect:

```python
  CoordinatorDecision(
      action=REQUEST_RESEARCH,
      ...
  )
```

Not: 

```
assert coordinator._foo.called_once()
assert coordinator._bar.call_count == 2
```

### 6. Test both the happy/unhappy paths

ATI's unit tests do not just exercise happy paths. A large part of the value comes from testing fail-closed behavior. For example, if the `Coordinator` encounters exhausted budget, the expectation is that pivoting stops. A test should verify that expectations.

In other words, the unhappy path isn't just including exceptions/errors, it is also comprising expected negative outcomes that don't lead to hard failures.

### 7. Dependency injection has a dual role

Dependency injection, where dependencies are externally instantiated and passed to units, has a dual role:

1. It contributes to a modular architecture where concise, specialized units exercise compact logic and where the use of interfaces allows shielding dependents from concrete implementations.
2. It eases the introduction of mocks/fakes, where interfaces document a public contract against which expectations are tested.

## Integration Testing

Integration testing in ATI plays a key rule in ensuring quality. Strict principles have been followed; a rich text fixture system has been put in place to provide a realistic suite of scenarios, reflecting ATI's businss logic.

### Principles

ATI has an exhaustive suite of integration tests. The following describes the principles that guided their implementation.

#### 1. Test againt real, local, containerize infrastructure

Where unit tests deliberately isolate dependencies, through fakes/mocks, integration tests deliberately cross system boundaries. The dependency on Postgres for application data storage, and the fact that application logic exists in stored function, requires this approach:

```
Integration test

Application service
      │
      ▼
Repository / UoW
      │
      ▼
real PostgreSQL
      │
      ▼
stored functions / schema
```

#### 2. External services remain controlled

Crossing ATI architectural boundaries does not mean that integration tests should call arbitrary production services.

For example, a Research Agent integration trajectory can use:

```
ResearchAgent
     │
     ├── real ResearchRetriever
     │       ↓
     │    real pgvector
     │       ↓
     │    real PostgreSQL
     │
     ├── FakeLlmClient
     │
     └── real persistence
             ↓
          PostgreSQL
```

In such a case, the integration test uses a fake implementation of the `LlmClient` interface, to reduce the impact of non-determinism on testing outcome, and to keep AI costs under control (AI testing has its on form of integration testing).

The same strategy has been applied when testing with `EvidenceProviders`: fake implementations have been introduced, to avoid hitting the dependencies directly in the context of integration testing (which may result in violiating the limits of those systems and potentially subjects the integration tests to external maintenance windows and outages).

Note that, in this case, when faking external HTTP services (for example), the fake implementations constist of in-memory HTTP servers mimicking the API contracts of those services.

> This is again a technique favored by AI's code generation speed.

#### 3. Integration tests validate contracts between layers

Integration tests have a different focus, compared to unit tests, and that focus justifies their extended scope:

- Unit tests try to answer: Does this component behave correctly given its dependencies' contractual behavior?
- On the other hand, integration tests focus on component assembly: Do these real components actually satisfy one another's contracts when assembled?

An integration test can expose mismatches such as UUID handling, enum representation, JSON serialization, timestamps, versioning, transaction behavior, constraints, or stored-function signatures that isolated unit tests cannot.

#### 4. Transaction boundaries deserve explicit testing

Transactions, abtracted through the `UnitOfWork` interface, consitute an important part of ATI's data persistence. Where ATI intentionally separates transactions from external I/O, integration tests verify that separation rather than merely testing happy-path data insertion.

#### 5. Integration tests include the unhappy paths

As with unit tests, ATI's fail-closed design makes negative integration tests important. These often reveal architectural defects that happy-path integration tests miss.

#### 6. Determinism still matters

Despite ATI being an agentic system, integration test pipeline stability remains important.

ATI deliberately provides deterministic seams so that we can exercise large portions of the real system while controlling nondeterministic edges:

```
             Real ATI stack
                  │
       ┌──────────┼───────────┐
       │          │           │
       ▼          ▼           ▼
   real DB    real app     real graph
   pgvector     logic       workflow
       │          │           │
       └──────────┼───────────┘
                  │
           controlled edges
                  │
          ┌───────┴────────┐
          ▼                ▼
      Fake LLM       fake/scripted
                      providers
```

A concrete example of that is `FakeLlmClient`, which allows 

#### 7. Integration tests and E2E tests serve different purposes

An integration test can deliberately tests a slice of the system without launching the entire stack - e.g.: `Repository → stored functions → PostgreSQL` or `LangGraph → Coordinator → fake executor`.

Testing the full system belongs to E2E testing.

### Fixtures

evals/scenarios/
├── analyst/
│   ├── malicious_ioc_direct_evidence.json
│   ├── conflicting_reputation.json
│   ├── stale_evidence.json
│   ├── geolocation_context.json
│   └── ...
│
├── coordinator/
│   ├── 01_domain_discovers_ip.json
│   ├── 05_depth_limit.json
│   ├── 08_sufficient_evidence_stop.json
│   ├── 12_cycle_suppression.json
│   ├── 13_malware_research_marker.json
│   └── ...
│
├── research/
│   ├── retrieval/
│   └── synthesis/
│
└── report_writer/
    ├── 01_rpt_s01_clearly_malicious.json
    ├── 03_rpt_s03_conflicting_evidence.json
    ├── 07_rpt_s07_verdict_override_attempt.json
    └── ...
