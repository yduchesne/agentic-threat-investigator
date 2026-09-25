# Testing

As of this writing, ATI comprises more than 5,000 unit tests, and around 800 integration tests. Those integration tests share common infrastructure with agent evaluation tests (AKA "evals").

- [Core Concepts](CORE_CONCEPTS.md): Presents core concepts such as `Entity`, `Evidence`, etc.
- [Investigations](INVESTIGATIONS.md): Goes over the investigation workflow, especially the notion of __pivoting__.
- [Agentic Architecture](AGENTIC.md): Goes deeper than this document in the details of the different agents and the use of `LangChain`/`LangGraph`.
- [LangSmith](LANGSMITH.md): Documents specifically how `LangSmith` is used in the context of observability and evaluation. This goes further into how evals are structure and how they have infrastructure in common with integration tests.

## Unit Testing

Unit testing has been implemented agressively, with an 85% test coverage target (enforced through a pre-commit hook).

At the core, unit testing rests on the notion of interface, which are used at system/dependency boundaries. This allows introducing mocks while keeping domain and application logic real: mock boundaries, not internals.

### Principles

The following principles constitute the unit testing philosophy adopted for ATI.

#### 1. Interfaces define the natural mocking seams

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

#### 2. Prefer purpose-built fakes/stubs over deep mocking

An important ATI pattern is that ATI often has explicit deterministic implementations such as:

- `FakeResearchExecutor`
- `FakeLlmClient`
- `MappingProviderWorkPlanner`
- deterministic/fake providers
- etc.

This was deemed preferable to deep `MagigMock` object graphs: A reusable fake when useful; a simple stub when only canned behavior is required; Mock/AsyncMock when interaction verification proves necessary and/or where mocking doesn't require a complicated setup. 

There is no architectural objection to conventional mocking.

> Another factor that has favored fakes is the fact that AI is generating their implementation, which is much faster.

#### 3. Pure domain logic needs no mocks

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

#### 4. Each unit gets tested separately, with fakes/mocks at the boundary

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

#### 5. Test the public/observable contract rather than internal logic/state

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

#### 6. Test both the happy/unhappy paths

ATI's unit tests do not just exercise happy paths. A large part of the value comes from testing fail-closed behavior. For example, if the `Coordinator` encounters exhausted budget, the expectation is that pivoting stops. A test should verify that expectations.

In other words, the unhappy path isn't just including exceptions/errors, it is also comprising expected negative outcomes that don't lead to hard failures.

#### 7. Dependency injection has a dual role

Dependency injection, where dependencies are externally instantiated and passed to units, has a dual role:

1. It contributes to a modular architecture where concise, specialized units exercise compact logic and where the use of interfaces allows shielding dependents from concrete implementations.
2. It eases the introduction of mocks/fakes, where interfaces document a public contract against which expectations are tested.

### File System Layout

The unit tests are under the [tests/unit](../../tests/unit/) directory. The are subdivided according to the layer of the application they target:

```
tests/unit/
├── api
├── app
├── config
├── conftest.py
├── domain
├── evaluation
├── infrastructure
├── observability
├── telemetry
```

Certain test suites are present under the `tests/unit` directory, directly.

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

### File System Layout

The integration tests are present under the [tests/integration](tests/integration) directory.

### Fixtures

The codebase has different types of fixtures: they can be programmatic or "static" (based on configuration files); they can be destined to "traditional" integration tests or to agent evals. The following table lists the fixture directories and what they correspond to:

| Location                                           | What it represents                 | Typical purpose                                            |
| -------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------- |
| [tests/fixtures/](../../tests/fixtures/)           | Static test input artifacts        | Feed real parsers, ingestion, indexing, GEO datasets, etc. |
| [tests/support/*fixtures.py](../../tests/support/) | Programmatic test builders/doubles | Construct controlled domain/provider/query inputs          |
| [evals/scenarios/](../../evals/scenarios/)         | Versioned evaluation scenarios     | Describe semantic/behavioral worlds and expected outcomes  |

#### Programmatic Fixtures

The fixtures under `tests/support/` are not simple static config files. They are in fact Python code:

```
tests/support/
├── abuseipdb_fixtures.py
├── evidence_batch_fixtures.py
├── extraction_fixtures.py
├── geoint_fixtures.py
├── orchestration_fixtures.py
├── provider_executor_fixtures.py
├── query_fixtures.py
├── threatfox_fixtures.py
├── urlhaus_fixtures.py
└── ...
```

Those are fixture builders/test doubles. Some support unit tests, some integration tests, and some both.

#### "Tradtional" Fixtures

Certain fixtures are not meant for agent evaluation (at least, not directly). They are used to fake external dependencies, as the diagram below shows:

```
tests/fixtures/
├── geoint/
│   ├── corpus_small.jsonl
│   ├── corpus_synthetic_edge.jsonl
│   ├── geonames/
│   │   ├── admin1CodesASCII.txt
│   │   ├── cities1000.txt
│   │   └── countryInfo.txt
│   └── natural_earth/
│       ├── ne_admin1.geojson
│       └── ne_countries.geojson
│
├── mitre_attack/
│   ├── enterprise_attack_small.json
│   ├── enterprise_attack_hostile_small.json
│   ├── enterprise_attack_tie_small.json
│   └── enterprise_contradiction_small.json
│
└── openapi_v1.json
```

#### Evals

The files under under `evals/scenarios` are agent evaluation scenarios and are paired with corresponding Python code. Together, they form fixtures (although the Python code in question may also be called "fixture", in this documentation, depending on context). The repository has explicit evaluation corpora for several targets:

```
evals/scenarios/
├── analyst/          # Evidence Analyst eval scenarios
├── coordinator/      # Coordinator policy/trajectory eval scenarios
├── research/
│   ├── retrieval/
│   └── synthesis/    # Research/RAG eval scenarios
├── report_writer/    # Report Writer eval scenarios
├── geoint/           # GEOINT semantic + lifecycle eval scenarios
└── investigation/    # full-investigation eval scenarios
```

Those scenarios have corresponding integration tests:

```
tests/integration/
├── test_evaluation_analyst_runner.py
├── test_evaluation_coordinator_runner.py
├── test_evaluation_research_runner.py
├── test_evaluation_report_writer_runner.py
├── test_evaluation_investigation_runner.py
├── test_evidence_analyst_evaluation.py
├── test_research_evaluation.py
├── test_research_retrieval_evaluation.py
├── test_geoint_evaluation.py
└── ...
```

For example, there are multiple investigation test scenarios, which test the whole investigation flow:

```
evals/scenarios/investigation/
├── 01_inv_s01_malicious_multi_source.json
├── 02_inv_s02_benign.json
├── 03_inv_s03_inconclusive_sparse.json
├── 04_inv_s04_conflicting_evidence.json
├── 05_inv_s05_research_required.json
└── 06_inv_s06_cycle_duplicate_bounded.json
```

The following integration test runs the above scenario files (it is a multi-scenario test runner):

```
tests/integration/test_evaluation_investigation_runner.py
```

The above highlight different types of evals: targeted/focused ones; investigation-scoped ones. The focused ones exist for specific agentic components of the system:

- Evidence Analyst
- Coordinator
- Research Agent
- Report Writer

The investigation-scoped ones run the full investigation flow and attempt to catch issues such as:

- Too many pivots
- Duplicate work
- Wrong research timing
- Wrong terminal Assessment
- Excessive LLM calls
- Provenance lost

The execution flow, for a given investigation eval scenario, is as follows:

```
Investigation JSON scenario
          │
          ▼
strict typed loader
          │
          ▼
repository-owned fixture world
          │
          ▼
run-scoped Investigation materialization
          │
          ▼
production LocalInvestigationRunner
          │
          ▼
production Coordinator graph
          │
     ┌────┴────┐
     ▼         ▼
 Evidence     Research
 Analyst       Agent
     │
     └────┬────┘
          ▼
 terminal InvestigationState
          │
          ▼
 current Assessment
          │
          ▼
 production ReportWriter
          │
          ▼
 persisted InvestigationReport
          │
          ▼
 authoritative durable snapshot
 + structured trajectory actions
          │
          ▼
 InvestigationEvaluator
          │
          ▼
 common EvaluationRunner
          │
          ▼
    PASS / FAIL / ERROR
```

##### GEOINT Evals

The fixtures under `evals/scenarios/geoint/*` are GEOINT evaluation scenarios.

`tests/integration/test_geoint_evaluation.py` then exercises those scenarios against real infrastructure and production behavior.

The GEOINT JSON files are not simply data fixtures for PostgreSQL integration tests. They form a GEOINT evaluation corpus, and integration tests prove that the corpus can be materialized and evaluated correctly through real ATI components.

##### Eval Scenario Structure

As mentioned earlier, scenarios are kept under he files under under `evals/scenarios`. A scenario is essentially a declarative specification of an evaluation case:

```
Scenario
├── identity / documentation
├── fixture-world reference
├── starting condition
└── expected outcome envelope
```

Scenarios are kept in JSON files. Each such scenario is paired with a fixture, in Python. The scenario is meant to declare what needs to be verified and what the expectations are. The fixture describes a "fake world" against which the scenario is tested. That fake world defines `Entities`, `Evidence` and other objects relevant to the scenario.

The following sub-sections explain the above scenario structure, focusing on the main fields, and using an investigation scenario as an example. 

###### 1. Top-Level

Simplified, the file looks like:

```JSON
{
  "id": "inv-s01-malicious-multi-source",
  "version": 1,

  "specification": { ... },

  "fixture": "f02-malicious-multi-source",

  "root": { ... },

  "expected": { ... }
}
```

Schematically:

```
InvestigationScenario
│
├── id
├── version
├── specification
├── fixture
├── root
└── expected
```

###### 2. `id` and `version`

```JSON
"id": "inv-s01-malicious-multi-source",
"version": 1
```

These establish the stable identity of the scenario.

- The ID is deliberately semantic rather than an arbitrary UUID. The schema constrains it to a bounded lowercase identifier.
- `version` allows the evaluation corpus to evolve without silently changing the meaning of an existing scenario.

The combination of `id` and `version` constitutes the identity of the scenario: 

```
inv-s01-malicious-multi-source@1
```

###### 3. `specification`

The specification explains why the scenario exists. It isn't the machine-verifiable assertion section. Rather, it provides human-readable evaluation specification and traceability metadata.

```JSON
"specification": {
  "title": "Malicious multi-source domain end-to-end",

  "description":
    "A malicious update-delivery domain correlated across DNS, ...",

  "target": "investigation",

  "purpose":
    "Verify the complete production end-to-end path...",

  "operational_relevance":
    "Malicious multi-source domains are ...",

  "regression_risk":
    "The Coordinator could skip the malware research lifecycle...",

  "expected_behavior": {
    "required": [ ... ],
    "forbidden": [ ... ]
  },

  "tags": [
    "malicious",
    "multi-source",
    "research-required"
  ],

  "architecture_refs": [
    "coordinator-policy",
    "provider-execution",
    "evidence-analyst",
    "research-agent",
    "assessment-faithful-reporting"
  ]
}
```

The fields are explained below:

- `target`: what is being evaluated.
- `purpose`: the question is this scenario answering.
- `operational_relevance`: why this case matters operationally.
- `regression_risk`: the type of failure this scenario is intended to detect.
- `expected_behavior`: the human-readable required/forbidden behavior.
- `architecture_refs`: the architectural contracts it exercises.

###### 4. `fixture`

This references a repository-owned fixture world. For example, given the following scenario": 

```JSON
"fixture": "f02-malicious-multi-source",
"root": {
	"entity_label": "root_domain",
  	"entity_type": "domain",
  	"value": "update-package.test"
}
```

Then the following fixture Python object is resolved:

```python
InvestigationFixture(
    name="f02-malicious-multi-source",
    enabled_providers=(
        SourceId.GOOGLE_PUBLIC_DNS,
        SourceId.RDAP,
        SourceId.THREATFOX,
        SourceId.ABUSEIPDB,
    ),

    world_entities={
        "root_domain": (
            EntityType.DOMAIN,
            "update-package.test"
        ),
        "resolved_ip": (
            EntityType.IP_ADDRESS,
            "203.0.113.81"
        ),
        "malware_family": (
            EntityType.MALWARE,
            "malware.badloader_v2"
        ),
    },
    ...
)
```

###### 5. `root`

The `root_*` fields designate the `Entity` at which pivoting starts - it is the initial condition:

```JSON
"root": {
  "entity_label": "root_domain",
  "entity_type": "domain",
  "value": "update-package.test"
}
...
```

###### 6. `expected`

This holds the machine-verifiable data. This section doesn't prescribe one exact execution trace. It specifies constraints that a valid execution must satisfy. The value of the `expected` field is corresponds to a JSON graph with multiple fields:

```
expected
├── terminal
├── assessment
├── evidence
├── relationships
├── research
├── report
├── trajectory
└── efficiency
```

__6.1. `terminal`__

Indicates the final state of the investigation. Below: the investigation must terminate successfully because evidence became sufficient.

```JSON
"terminal": {
  "status": "completed",
  "stop_reason": "sufficient_evidence"
}
```

__6.2. `assessment`__

Indicates the state of the final `Assessment` produced by the `Evidence Analyst`. Below: he final `Assessment` must therefore have `verdict` -> `MALICIOUS`, etc.

```JSON
"assessment": {
  "verdict": "malicious",
  "confidence": "high",

  "required_findings": [
    "reputation:supporting"
  ],

  "forbidden_findings": []
}
```

Notice that the `assessment` object doesn't contain prose string, but rather well-known identifiers/semantic labels. For example, above, `required_findings` contains `reputation:supporting`, not `The IP has a bad reputation`.

__6.3. `evidence`__

This verifies that actual investigation execution reached the required intelligence sources and discovered the required entities.

```JSON
"evidence": {
  "required_sources": [
    "urn:ati:source:google_public_dns",
    "urn:ati:source:rdap",
    "urn:ati:source:threatfox",
    "urn:ati:source:abuseipdb"
  ],

  "required_entity_labels": [
    "resolved_ip",
    "malware_family"
  ],

  "forbidden_entity_labels": []
}
```

Again, semantic labels are used: `resolved_ip`, `malware_family`.

__6.4. `relationships`__

Indicates which relationships pivoting is expected to have surfaced. Example:

```JSON
"relationships": {
  "required": [
    "urn:ati:relationship:dns:resolves_to",
    "urn:ati:relationship:threat:associated_with"
  ],
  "forbidden": []
}
```

__6.5. `research`__

The `Coordinator` must have recognized the discovered malware entity as `RESEARCHABLE` and caused the Research Agent lifecycle to execute for it:

```JSON
"research": {
  "required_subject_labels": [
    "malware_family"
  ],
  "forbidden_subject_labels": []
}
```

__6.6. `report`__

Verifies that a report exists and remains faithful to the final `Assessment`:

```JSON
"report": {
  "required": true,
  "verdict": "malicious",
  "confidence": "high",

  "required_finding_ordinals": [1],
  "forbidden_finding_ordinals": [],

  "min_narrative_statements": 0,
  "max_narrative_statements": 5
}
```

__6.7. `trajectory`__

This field allows constraining how ATI go to the final investigation state. This verifies orchestration behavior, ensuring that ATI can't accidentally get the expected final verdict while bypassing important workflow contracts.

```JSON
"trajectory": {
  "required_actions": [
    "urn:ati:action:provider_query",
    "urn:ati:action:pivot_executed",
    "urn:ati:action:research_requested",
    "urn:ati:action:assessment_requested",
    "urn:ati:action:investigation_stopped"
  ],

  "forbidden_actions": [],

  "required_research": [
    "malware_family"
  ],

  "forbidden_research": [],

  "max_depth": 2,
  "termination_required": true
}
```

The scenario therefore evaluates both outcome and trajectory:

```
              Investigation evaluation
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
         Outcome                Trajectory
             │                     │
     Assessment correct?      Pivoted correctly?
     Evidence correct?        Research invoked?
     Report correct?          Bounded depth?
                               Terminated?
```

__6.8. `efficiency`__

Allows defining hard behaviorial bounds that pertain to how much "effort" the system spends on an investigation, before that investigation reaches its final state:

```JSON
"efficiency": {
  "max_provider_calls": 20,
  "max_llm_calls": 12,
  "max_replans": 3,
  "max_pivots": 6,
  "max_duplicate_provider_calls": 0,
  "max_duplicate_entity_investigations": 0,
  "max_total_actions": 60
}
```