# Agentic Architecture

ATI uses AI agents for specialized tasks in the context of cyber threat intelligence investigations (the investigation workflow is described in more details in the [Investigations](INVESTIGATIONS.md) document). The agents are listed below:

| Agent                               | Purpose                                                                                                             | Primary input                                                                                                                      | Primary output                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| **Evidence Analyst**                | Interpret the accumulated evidentiary case and determine what the evidence supports                                 | `EvidenceAnalystInput`: normalized Evidence observations, Relationship observations, bounded GEOINT/context, investigation context | Versioned `Assessment` + `AnalysisDisposition` |
| **Threat Research / Context Agent** | Perform bounded contextual research about researchable entities such as malware, ATT&CK techniques, vulnerabilities | `ResearchAgentRequest` + retrieved RAG document chunks                                                                             | `ResearchResult`                               |
| **Report Writer**                   | Turn the completed investigation into a coherent human-readable report without changing its analytical conclusions  | Current/final `Assessment` + supporting investigation material + contextual research                                               | Final `Report`                                 |

## References

- [Core Concepts](CORE_CONCEPTS.md): Presents core concepts such as `Entity`, `Evidence`, etc.
- [Investigations](INVESTIGATIONS.md): Goes over the investigation workflow, especially the notion of __pivoting__.
- [Testing](TESTING.md): Describes the different forms of testing in ATI (including agent evals).
- [LangSmith](LANGSMITH.md): Documents specifically how `LangSmith` is used in the context of observability and evaluation.

## Architecture at a Glance

The following diagram provides a high-level view of the architecture - more details will be offered in the ulterior sections of this document:

```
                         ┌──────────────────┐
                         │ Investigation    │
                         │ State            │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Coordinator    │
                         │ deterministic    │
                         │ policy           │
                         └────────┬─────────┘
                                  │
          ┌───────────────────────┼────────────────────────┐
          │                       │                        │
          ▼                       ▼                        ▼
 ┌─────────────────┐     ┌─────────────────┐      ┌─────────────────┐
 │ Provider Work   │     │ Evidence        │      │ Threat Research │
 │                 │     │ Analyst Agent   │      │ Agent           │
 │ deterministic   │     │                 │      │                 │
 │ acquisition     │     │ LLM reasoning   │      │ bounded RAG     │
 └────────┬────────┘     └────────┬────────┘      └────────┬────────┘
          │                       │                        │
          ▼                       ▼                        ▼
 Evidence / Entities         Assessment +             ResearchResult
 / Relationships             Disposition                   │
          │                       │                        │
          └───────────────────────┼────────────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Coordinator    │
                         │ continue / stop  │
                         └────────┬─────────┘
                                  │
                              STOP│
                                  ▼
                         ┌──────────────────┐
                         │ Report Writer    │
                         │ Agent            │
                         │                  │
                         │ LLM synthesis    │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Final Report   │
                         └──────────────────┘


      LangGraph = stateful orchestration / transitions / routing
      LangChain = LLM, structured-output and retrieval building blocks
```

As explained in the [Investigations](INVESTIGATIONS.md) document, the investigative workflow is iterative and the `Evidence Analyst` may be called multiple times, in the context of pivoting.


ATI's overarching theme is: __bounded agentic reasoning inside deterministic orchestration__. Specialized agents perform interpretation, contextual research, and synthesis; but they do not form a swarm of autonomous agents. 

`LangGraph` provides the durable workflow structure around those capabilities, while `LangChain` provides much of the machinery used to implement the individual LLM/RAG operations.

## The `LlmClient` interface

The intent from the beginning was to maximize unit testing coverage, including interactions with the LLM. To that end, the `LlmClient` interface has been introduced. An implementation exists that wraps the `LangChain` framework: `LangChainLlmClient`. The following illustrates the layering this implies:

```
ResearchAgent
     │
     ▼
  LlmClient               ← ATI application interface
     │
     ▼
LangChainLlmClient        ← infrastructure implementation
     │
     ▼
BaseChatModel             ← LangChain abstraction
     │
     ▼
OpenAI-compatible model
```

Concretely, this means that all agent code is shielded from direct LLM interactions. This not only maximizes unit testing opportunities, but also ensures that nitty-gritty LLM interaction code doesn't perspire into application logic.

## The Agents in Detail

This section presents each ATI agent in more details. For each agent, it provides: purpose, input, output.

### `Evidence Analyst`

The purpose of the `Evidence Analyst` agent is to help determine whether more evidence is needed for a given `Entity` (an IP address, a domain name...), in the context of pivoting.

The agent takes in an `EvidenceAnalystInput` object as input and produces as output: an `Assessment`; an `AnalysisDisposition`. This is illustrated below:

```
EvidenceAnalystInput
├── investigation context
├── Evidence observations
├── associated Entities
├── Relationship observations
└── bounded GEOINT context
            │
            ▼
      Evidence Analyst
            │
            ├── Assessment
            │     ├── verdict
            │     ├── confidence
            │     ├── findings + provenance
            │     ├── limitations
            │     ├── unresolved questions
            │     └── recommended next steps
            │
            └── AnalysisDisposition
                  ├── SUFFICIENT
                  ├── NEEDS_MORE_EVIDENCE
                  └── EXHAUSTED
```

- The `Assessment` is the analytical product;
- the disposition is the machine-oriented signal consumed by orchestration (i.e.: by the `Coordinator`)

As explained in the [Investigations](INVESTIGATIONS.md) document, the `Evidence Analyst` can run multiple times during one investigation.

### `Threat Research Agent`

The purpose of the `Threat Research Agent` (AKA `Research Agent`) is to retrieve contextual information from ATI's research corpus about the `Entity` currently under examination (i.e.: currently being pivoted on). The agent uses `RAG` to retrieve relevant documents from its underlying vector database. The database has been populated out-of-band through a batch data source. For example, one such source is the MITRE ATT&CK material.

The agent receives a `ResearchAgentRequest` as input. It in turn produces a `ResearchResult`. That result is context, not `Evidence`. The `Research Agent` does not establish the investigation's maliciousness verdict.

Here's an example, schematized flow:

```
MALWARE: Emotet
        │
        ▼
ResearchAgentRequest
        │
        ▼
ResearchRetriever
        │
        ▼
bounded document chunks
        │
        ▼
Threat Research Agent
        │
        ▼
ResearchResult
```

### `ResearchRetriever`: Not an Agent (and not a Tool)

To be clear, it would seem that the `ResearchRetriever` could be an agent, or even a tool. But, it is neither. It is an object that is passed to the `ResearchAgent` at construction time. Conceptually:

```python
class ResearchAgent:
    def __init__(
        self,
        retriever: ResearchRetriever,
        llm: ...
    ):
        self._retriever = retriever
        self._llm = llm
```

> Note that `llm`, in the above, is an instance of the aforementioned `LlmClient` interface.

The `ResearchAgent` is not a LangChain-registered object or function: it interacts directly with the LLM, leveraging the retriever for obtaining the research fragments, and then building a prompt using them, which is passed to the LLM. Conceptually:

```python
async def research(self, request: ResearchAgentRequest):
    chunks = await self._retriever.retrieve(...)

    prompt = build_prompt(
        request=request,
        chunks=chunks,
    )

    result = await self._llm.invoke(prompt)

    return result
```

Document retrieval happens __before__ LLM invocation. The agent's prompt commands the following (approximately):

> Given this research subject, research question, and these retrieved source passages, identify the relevant contextual facts, synthesize them into concise claims, and associate each claim with the supplied citations. Do not introduce facts unsupported by the supplied material. Do not produce threat verdicts, confidence judgments, Evidence, or Relationships.

### `Report Writer`

The purpose of the `Report Writer` is to produce a human-readable report, in prose, as the result of the investigation. It takes a well-structured input and generates a plain-English report.

The agent's input is composed of:

- The final/last `Assessment` produced by the `Evidence Analyst`.
- Any relevant `Evidence` and `Relationship` data.
- Any `ResultResults` stemming from the `Research Agent`.

Succinctly summarized, the corresponding flow is as follows:

```
Final/current Assessment
Evidence / Relationships
ResearchResults
other bounded investigation context
             │
             ▼
       Report Writer
             │
             ▼
        Final Report
```

The agent is a synthesis one, not another analyst. Given the following, provided by the `Evidence Analyst`:

```
Verdict = SUSPICIOUS, confidence = MEDIUM
```

The `Report Writer` will explain the above conclusion. It will not change the interpretation (for example, upgrading the verdict to `MALICIOUS` and/or the `confidence` to `HIGH`).

## The `Coordinator`: Not an Agent

The `Coordinator` component is not an agent; it does not itself interact with an LLM. Its drives the investigtion workflow deterministically, according to its `CoordinatorPolicy`.

```
             Agentic capabilities
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
    Evidence       Threat       Report
    Analyst        Research     Writer
     Agent          Agent        Agent

                     ▲
                     │
              orchestrated by
                     │
                     ▼
             CoordinatorPolicy
             (deterministic)
```

### `CoordinatorPolicy`: Determinisc Decision Engine

The `CoordinatorPolicy` is in fact a class in the system that has no state of its own, other than the dependencies on the `ProviderWorkPlanner` and `ResearchRequestPlanner`. Whenever it is invoked, it takes as input an ongoing `InvestigationState` andd a `CoordinatorPolicyContext`:

```
CoordinatorPolicy
│
├── dependencies
│   ├── ProviderWorkPlanner
│   └── ResearchRequestPlanner [optional]
│
└── decide(
       state: InvestigationState,
       context: CoordinatorPolicyContext
    ) -> CoordinatorDecision
```

The `CoordinatorPolicy` deliberately has no persistence, network, clock, provider execution, or LLM access. Given an authoritative snapshot, it chooses exactly one next action.

The `CoordinatorPolicyContext`, is one input of `CoordinatorPolicy`. It has the following structure:

```
CoordinatorPolicyContext
├── entities
├── missing_entity_ids
├── current_assessment
├── analysis_disposition
└── analyzed_evidence_ids
```

The `InvestigationState` input carries the durable workflow state: pending provider work, discovered entities, traversal state, research requirements/executions, budgets, stop reason, etc. It holds persistent data that is potentially updated (and committed to the database) in the context of an investigation.

The output of `CoordinatorPolicy` is a `CoordinatorDecision`:

```
CoordinatorDecision
├── action
├── work_items
├── pivots
├── research_entity_ids
├── research_request
├── stop_reason
├── rejections
└── consumes_replan
```

The `action` field may take the following values:

```
EXECUTE_PROVIDER_WORK
REQUEST_ANALYSIS
AUTHORIZE_PIVOT
REQUEST_RESEARCH
STOP
```

The `CoordinatorDecision` concerns pivoting (on a newly discovered `Entity`); retrieving research content for the `Entity` being examined/pivoted on; triggering analysis; fetching evidence; etc. It is determined as follows:

```
CoordinatorPolicy.decide()
        │
        ├─ already stopped?
        │      └─ STOP
        │
        ├─ pending provider work?
        │      └─ EXECUTE_PROVIDER_WORK
        │
        ├─ newly discovered RESEARCHABLE entities?
        │      └─ AUTHORIZE_PIVOT
        │          + research_entity_ids
        │
        ├─ new/unanalyzed Evidence?
        │      └─ REQUEST_ANALYSIS
        │
        ├─ due contextual research?
        │      └─ REQUEST_RESEARCH
        │
        ├─ disposition == SUFFICIENT?
        │      └─ STOP
        │
        ├─ disposition == NEEDS_MORE_EVIDENCE?
        │      └─ attempt another bounded pivot round
        │
        ├─ disposition == EXHAUSTED?
        │      └─ try remaining eligible candidates
        │
        └─ otherwise
               └─ try eligible candidates
```
Candidate authorization then applies deterministic constraints such as traversal depth, entity budget, provider-call budget, duplicate suppression, prior investigation depth, entity type, and provider applicability.

> See the [Investigations](INVESTIGATIONS.md) document for more details on the investigation workflow.
> A "candidate" is a newly discovered `Entity`, as part of the workflow.

### Planners: Specialized Task Dispatchers

`CoordinatorPolicy` delegates two narrower planning decisions rather than knowing all implementation details itself.

#### `ProviderWorkPlanner`

It determines what work should be done, given the currently investigated `Entity`. The work essentially consists of fetching `Evidence` from `EvidenceProviders`. Conceptually, it has the following interface:

```
class ProviderWorkPlanner(ABC):

    @abstractmethod
    def plan(
        self,
        *,
        entity: CoordinatorEntityView,
        depth: int,
        state: InvestigationState,
    ) -> tuple[ProviderWorkItem, ...]:
        ...
```

Its input is an `InvestigationState` and the current visit depth of ATI's knowledge graph. It returns a collection of `ProviderWorkItem` instances. Each represents a unit of work to be eventually executed, for the current `Entity`.

At a glance, the `ProviderWorkPlanner` workflow is as follows:

```
Candidate Entity
       +
InvestigationState
       +
Traversal depth
       │
       ▼
ProviderWorkPlanner
       │
       │ deterministic provider applicability
       │ and work planning
       ▼
ProviderWorkItem(s)
       │
       ├── provider: SourceId
       ├── entity_id: UUID
       └── depth: int
```

And, zooming in on `ProviderWorkItem` creation, we have the following:

```
Entity
  type  = IP_ADDRESS
  value = 203.0.113.42

depth = 1
       │
       ▼
ProviderWorkPlanner
       │
       ├── Google DNS supports IP_ADDRESS? ───── yes
       ├── RDAP supports IP_ADDRESS? ─────────── yes
       ├── IPinfo supports IP_ADDRESS? ───────── yes
       ├── AbuseIPDB supports IP_ADDRESS? ────── yes
       ├── ThreatFox supports IP_ADDRESS? ────── yes
       ├── URLhaus supports IP_ADDRESS? ──────── yes
       └── ...
       │
       ▼
(
  ProviderWorkItem(
      provider=GOOGLE_DNS,
      entity_id=<IP entity ID>,
      depth=1
  ),

  ProviderWorkItem(
      provider=RDAP,
      entity_id=<IP entity ID>,
      depth=1
  ),

  ProviderWorkItem(
      provider=IPINFO,
      entity_id=<IP entity ID>,
      depth=1
  ),

  ...
)
```

#### `ResearchRequestPlanner`

The `ResearchRequestPlanner` determines whether the currently investigated `Entity` warrants retrieving relevant research content. It has the following interface:

```
class ResearchRequestPlanner(ABC):

    @abstractmethod
    def plan(
        self,
        *,
        investigation: InvestigationState,
        entity: CoordinatorEntityView,
    ) -> PlannedResearchRequest:
        ...
```

Unsuprisingly, it takes an `InvestigationState` as input. It providers a `PlannedResearchRequest` in return, which has the following structure:

```
PlannedResearchRequest
├── request: ResearchAgentRequest
└── context_fingerprint: str
```

The workflow surrounding the creation of a `PlannedResearchRequest` is as follows:

```
RESEARCHABLE Entity
       +
Investigation context
       │
       ▼
ResearchRequestPlanner
       │
       │ deterministic planning
       ▼
PlannedResearchRequest
       │
       ├── ResearchAgentRequest
       │      ├── subject Entity
       │      ├── query
       │      ├── source constraints
       │      ├── document-type constraints
       │      ├── entity constraints
       │      └── retrieval limit
       │
       └── context_fingerprint
```

Just like `ProviderWorkPlanner`, the `ResearchRequestPlanner` performs planning, not execution. It returns work to be done in the future.

### Planner Summary

There is a symmetry (albeit imperfect) between  `ProviderWorkPlanner` and `ResearchRequestPlanner`:


Provider path:

```
Candidate Entity
       +
InvestigationState
       +
depth
       │
       ▼
ProviderWorkPlanner
       │
       ▼
ProviderWorkItem(s)
       │
       ▼
EvidenceProvider(s)
       │
       ▼
ProviderResult
```

Research path:

```
RESEARCHABLE Entity
       +
InvestigationState
       │
       ▼
ResearchRequestPlanner
       │
       ▼
PlannedResearchRequest
       │
       ▼
Research Agent
       │
       ▼
ResearchResult
```

Both planners are therefore deterministic planning components sitting between `CoordinatorPolicy` and execution. Neither planner performs the work it plans.

## `LangChain` & `LangGraph`

`CoordinatorPolicy` decides what should happen next; `LangGraph` executes and routes that decision; `LangChain` provides the LLM/RAG machinery used inside the agent executions.

`LangGraph` is therefore the execution glue between the deterministic `Coordinator` and ATI's agents/providers. Here is a conceptual execution model:

```
                    InvestigationState
                           │
                           ▼
                  ┌──────────────────┐
                  │ LangGraph        │
                  │ coordinator node │
                  └────────┬─────────┘
                           │
                           ▼
                  CoordinatorPolicy
                     .decide(...)
                           │
                           ▼
                  CoordinatorDecision
                           │
             LangGraph examines action
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
EXECUTE_PROVIDER_WORK REQUEST_ANALYSIS   REQUEST_RESEARCH
       │                   │                   │
       ▼                   ▼                   ▼
 provider execution   Evidence Analyst    Research Agent
       │                   │                   │
       ▼                   ▼                   ▼
 ProviderResult       Assessment +        ResearchResult
                     Disposition
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                     persisted state
                           │
                           ▼
                    Coordinator again
                           │
                           ⋮
                           │
                          STOP
                           │
                           ▼
                      Finalization
```

### LangGraph Nodes

The `Coordinator` doesn't perform such direct calls: `EvidenceAnalyst->analyze(...)` or `ResearchAgent->research(...)`. It rather returns a declarative decision describing the next action, which LangGraph routes (for execution) to the responsible node.

> A `LangGraph` node is an executable step in a workflow graph. In ATI, a node is essentially a Python function that `LangGraph` invokes when execution reaches that point in the investigation.

Conceptually, ATI's execution graph (as per `LangGraph`) is as follows:

```
                ┌─────────────┐
                │ coordinator │
                └──────┬──────┘
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
 authorize_pivot     analyze          research
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                  coordinator
```


A node is just a Python function. For example:

```Python
async def analyze_node(state):
    result = await evidence_analyst.analyze(...)

    # persist/update state

    return updated_state
```

`LangGraph` is responsible for invoking that function when graph execution reaches `analyze`. ATI constructs its graph as shown below (the code is a simplication):

```Python
graph.add_node("coordinator", coordinator_node)
graph.add_node("analyze", analyze_node)
graph.add_node("research", research_node)
graph.add_node("authorize_pivot", authorize_pivot_node)
```

`coordinator_node`, `analyze_node`, etc., are Python function objects.

#### Nodes are not Agents

A node can invoke an agent:

```
┌────────────────────────┐
│ LangGraph analyze node │
└───────────┬────────────┘
            │ invokes
            ▼
┌────────────────────────┐
│ Evidence Analyst Agent │
└────────────────────────┘
```

Is can also just as easily execute deterministic application logic:

```
┌───────────────────────────────┐
│ LangGraph authorize_pivot node│
└───────────────┬───────────────┘
                │
                ▼
       Apply CoordinatorDecision
       update InvestigationState
       persist transition
```

or:

```
execute_work node
      │
      ▼
EvidenceProvider
```

#### Edges: Routes between Nodes

`LangGraph` combines nodes with edges. A node consists of WHAT is executed; an edge determines WHERE execution goes next (to which node). For example:

```
                  coordinator
                       │
              CoordinatorDecision
                       │
              conditional routing
                       │
       ┌───────────────┼──────────────┐
       │               │              │
REQUEST_ANALYSIS  REQUEST_RESEARCH  AUTHORIZE_PIVOT
       │               │              │
       ▼               ▼              ▼
    analyze         research     authorize_pivot
       │               │              │
       └───────────────┼──────────────┘
                       ▼
                  coordinator
```

The `Coordinator` node obtains the `CoordinatorDecision`. A conditional edge/router examines something such as `decision.action` and selectes the next node:

```
LangGraph
   │
   ▼
coordinator node
   │
   ├── load/build authoritative policy context
   │
   ▼
CoordinatorPolicy.decide(
    InvestigationState,
    CoordinatorPolicyContext
)
   │
   ▼
CoordinatorDecision
   │
   ▼
return graph state
   │
   ▼
LangGraph conditional routing
```

In summary:

- `CoordinatorPolicy` -> decision-making logic
-  Coordinator node -> LangGraph execution step that invokes `CoordinatorPolicy`
- `CoordinatorDecision` -> typed result describing what should happen next.

### Tools

ATI agents to dot make use of tools: rather, they are deterministically invoking dependencies as needed, without the mediation of an LLM. This approach was illustrated when discussing the `Research Agent`, further above. This conservative approach was chosen to minimize non-deterministic drift. AI, on the other hand, is leveraged for analysis, synthesis, summarization.