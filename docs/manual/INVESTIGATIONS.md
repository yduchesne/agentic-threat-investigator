# Investigations

Investigations conducted autonomously by agents are the bread and butter of the system. An investigation is conducted through AI, but initiated by an external, deterministic trigger (for example, a user initiating the investigation).

Furthermore, in the course of conducting an investigation, AI agents are not "inventing" facts: they are tapping into deterministically generated evidence (see [Core Concepts](CORE_CONCEPTS.md)).

This document describes the investigation workflow, with some insights into the internals. The objective is for the reader to grasp the main stages of an investigation, without delving into coding details.

> Although this document is human-written - and human-maintained, AI has been leveraged to produce diagrams and generate content excerpts.

## References

- [Core Concepts](CORE_CONCEPTS.md): Presents core concepts such as `Entity`, `Evidence`, etc.
- [Agentic Architecture](AGENTIC.md): Goes deeper than this document in the details of the different agents and the use of `LangChain`/`LangGraph`.
- [Testing](TESTING.md): Describes the different forms of testing in ATI (including agent evals).
- [LangSmith](LANGSMITH.md): Documents specifically how LangSmith is used in the context of observability and evaluation.

## Investigation Trigger

An investigation is triggered by an inquiry regarding an entity. For example, the `evil.com` domain could be such an entity (see [Core Concepts](CORE_CONCEPTS.md) for more details regarding the notion of `Entity` in the context of ATI).

In ATI, an `Investigation` preserves the state involved in an analysis that eventually results in a `Report`. Initially, the sole state consists of the `Entity` that resulted in the investigation being triggered.

## Pivoting

Pivoting is the cornerstone of CTI analysis using facts about infrastructure, threats, and so forth. It is the process by which an investigation expands from one known entity to other entities discovered through evidence. ATI performs pivoting automatically progressively investigating the surrounding infrastructure and context.

From an initial `Entity` (for example, the `evil.com` domain), the goal is to obtain a greature picture of the situation. For example: from `evil.com`, what additional observations can we make? We could find that the domain resolves to the `203.0.113.42` IP address, that the address has been used to deliver malware in the past, or to host command-and-control infrastructure. Or we can find, through DNS registrar information, that the domain name is registered with a known threat actor...

Pivoting leverages ATI's knowledge graph. For exmple, in `evil.com --RESOLVES-TO--> 203.0.112.42`, the IP address becomes an entity on which we would want to pivot. Pivoting, in essence, is graph traversal. The initial entity (`evil.com`) is the "root entity" of the traversal, at depth 0. `Investigation` (more precisely, it is
`InvestigationState`) has a `root_entity_ids` field to preserve such IDs. It also has a `discovered_entity_ids` field to keep the IDs of the entities discovered along the way, through pivoting. The following illustrates this process:

```
evil.come                    depth 0
    │
    │ DNS A
    ▼
203.0.113.42                 depth 1
    │
    │ RDAP / IPinfo / AbuseIPDB ...
    ▼
additional discoveries       depth 2
```

### Agents in Charge of Pivoting

Two components are involved in pivoting:

- __Evidence Analyst__ (an agent): It is in charge of determining whether more evidence is needed or not. It produces an
  `AnalysisDisposition`, which can be one of the following:
  - `SUFFICIENT`: Stop the investigation.
  - `NEEDS_MORE_EVIDENCE`: Authorizes another pivot, subject to deterministic policy.
  - `EXHAUSTED`: Try remaining eligible candidate; stop if none exists.
- __Coordinator__ (not an agent): It is in charge have taking into account the `AnalysisDisposition`, together with hard-set, per investigation bounds:
  - `max_depth`: The maximum depth of the traversal, in terms of number of edges from the root (defaults to 2).
  - `max_entities`: The maximum number of entities to pivot on (defaults to 10).
  - `max_provider_calls`: The maximum number of live evidence provider calls allocated (defaults to 40).
  - `max_replans`: TBD (defaults to 3).
  - `max_llm_calls`: The maximum number of LLM requests (defaults to 10).

Note that the `Coordinator` is an archictural role, not an actual class or interface of the system. That role is played by two components: 1) The `coordinator_node` function that is registered with `LangGraph` as a `Node` in that framework; 2) the `CoordinatorPolicy`, which is in fact the decision engine that this document refers to most of the time, when mentioning the `Coordinator`. The following schema illustrates this:

```
coordinator_node
       │
       ├── load CoordinatorPolicyContext
       │
       ▼
CoordinatorPolicy.decide(...)
       │
       ▼
CoordinatorDecision
       │
       ▼
store decision in LangGraph state
       │
       ▼
LangGraph routes to next node
```

> See the [Agent Architecture](AGENTIC.md) document for more details on the agent configuration and the role played by `LangGraph`.

When deeming pivoting complete, the `Coordinator` supplies a `stop_reason` (a field of the `Investigation`), which will be set to `DEPTH_LIMIT_REACHED`, `ENTITY_BUDGET_EXHAUSTED`, `PROVIDER_BUDGET_EXHAUSTED`, `REPLAN_LIMIT_REACHED`, etc., according to the actual real reason for stopping.

### Pivot Determination

To follow up on the previous section: the `Evidence Analyst` examines the accumulated evidence and produces an `Assessment` (which is more the topic of the _Final Analysis_ section, towards the end of this document). It also generates an analytical conclusion about the sufficiency of the evidence, through an `AnalystDisposition`. For example:

```
Evidence:
  DNS observations
  RDAP registration
  AbuseIPDB reputation
  ThreatFox observations
       │
       ▼
Evidence Analyst
       │
       ▼
AnalysisDisposition.SUFFICIENT
```

When the disposition is `SUFFICIENT`, the `Evidence Analyst` adds a new corresponding `Entity` ID to the `InvestigationState`'s `discovered_entities`. The `Evidence Analyst` is __NOT__ making a pivot decision.

TBD: how does the `Evidence Analyst` evaluates whether or not more evidence is needed?

The `Coordinator` then examines the `AnalystDisposition` and each `discovered_entities`. It stops the investigation if the disposition is `NEEDS_MORE_EVIDENCE`. Otherwise, for each discovered entity, it answers the following questions and stops or allows the investigation, accordingly:
- Does the Entity actually exist?
- Has it been deleted?
- Is its Entity type supported for pivoting?
- Is it within max_depth?
- Are there applicable live evidence providers for that Entity?
- Has equivalent provider work already happened?
- Has this Entity already been investigated at the same or a better depth?
- Is an equivalent pivot already pending?
- Is the Entity within the `max_entities` admission budget?
- Is there enough remaining `max_provider_calls` capacity?
- etc. (see the previous section regarding the hard-set bounds that are examined by the `Coordinator`).

Furthermore, another condition may occur: graph exhaustion (TBD: is the Evidence Analyse also determining this through the EXHAUSTED disposition?). ATI may still want more evidence, but every known `Entity` may have been investigated, be unsupported, have no applicable provider, be a duplicate, etc. In that case, there simply isn't another legitimate edge of the investigation to follow.

Worthy of note: based on the above, we can see that the current implementation is stronger on boundedness and validity (therefore, favors determinism) than on sophisticated pivot value scoring. The `Coordinator`'s deterministic policy decides whether a proposed expansion is permissible and executable. The coordinator processes entities in discovery order and authorizes the first eligible pivot. It is __NOT__ currently doing something like:

```
candidate A → expected information gain 0.91
candidate B → expected information gain 0.34
candidate C → expected information gain 0.72

choose A
```

> ATI could be made substantially more agentic, eventually, not by letting the LLM invent arbitrary targets, but by letting an analytical/planning layer rank already-provenanced candidate Entities according to expected investigative value, while deterministic policy remains the authorization boundary.

There is one last step involved in pivoting determination: the `Coordinator` checks whether `EvidenceProviders` are available for the pivote candidate (i.e.: the next `Entity` to pivot on). If none apply, then the pivoting is suppressed for the entity. See this section, further below, for more details on this flow: _Evidence Gathering: Planning & Execution_.

If the `Coordinator` decides that pivoting may continue, it creates a new `PivotRequest` (among others):

```
PivotRequest
├── entity_id
├── reason
├── depth
└── status
```

This initiates pivoting, along with the evidence gathering done for that pivot operation (a process further described in this section, further below: _Evidence Gathering: Planning & Execution_).

In summary:

- The `Evidence Analyst` evaluates the accumulated evidence and reports whether it is sufficient for the investigation's analytical objective. It does not select or authorize pivots.
- The `Coordinator` consumes that assessment as one input to the investigation workflow. When additional evidence is needed, it evaluates the known, evidence-discovered entities and determines whether an eligible pivot can be authorized under the deterministic traversal and budget policies.

### Entity Discovery and `EntityTraversalState`

As mentioned earlier, in the course of investigations, the `Evidence Analyst` agent is in charge of determine what entities to pivot on next.

This is an evidence-backed, deterministic process: for an entity to be eligible for pivoting, it must be: a) associated with `Evidence`; b) linked through the source entity by a `Relationship` (in ATI's knowledge graph).

Information about each entity, in the context of graph traversal, is kept in `EntityTraversalState` objects. Such an object records an `Entity`'s position and investigation history within a particular investigation's pivot traversal.

> `EntityTraversalState` is implemented at the database level as a JSON blob of `Investigation`.

It preserves deterministic discovery order, the shortest known depth from a root, and the shallowest depth at which the `Entity` has actually been investigated.

An `EntityTraversalState` records this explicitly with `entity_id`, `first_discovery_ordinal`, `minimum_depth`, and `best_investigated_depth`:

| Field                     | Meaning                                                             |
| ------------------------- | ------------------------------------------------------------------- |
| `entity_id`               | Which Entity this traversal state describes (i.e.: the ID of the `Entity`) |
| `first_discovery_ordinal` | When this Entity was first discovered relative to other Entities    |
| `minimum_depth`           | Shortest currently known discovery path from a root                 |
| `best_investigated_depth` | Shallowest depth at which ATI has actually investigated this Entity |

The following sub-sections offer more details about the fields of `EntityTraversalState`.

#### `first_discovery_ordinal`

This field preserves deterministic discovery order.

Suppose the investigation starts with one domain and provider results discover entities in this order:

```
evil.example                  ordinal 0   root

203.0.113.42                  ordinal 1   discovered first
ns1.example.net               ordinal 2   discovered second
AS64500                       ordinal 3   discovered third
```

The values are, therefore:

```
evil.example       first_discovery_ordinal = 0
203.0.113.42       first_discovery_ordinal = 1
ns1.example.net    first_discovery_ordinal = 2
AS64500            first_discovery_ordinal = 3
```

The ordinal does not change if the `Entity` is discovered again.

This matters because the `Coordinator` needs deterministic candidate ordering. Roots are considered first; discovered Entities then follow their durable first-discovery order. ATI therefore doesn't depend onincidental Python set ordering or database row order when deciding which eligible entities to consider next.

#### `minimum_depth`

This records the shortest known traversal distance from a root `Entity`.

Roots have depth 0. An `Entity` discovered while investigating a depth-0 `Entity` gets depth 1; something discovered from that `Entity` gets depth 2, etc.

For example:

```
evil.example                    depth 0
      │
      ▼
203.0.113.42                    depth 1
      │
      ▼
some-other-entity               depth 2
```

The important word is __minimum__. An `Entity` can be discovered through several paths:

```
                    evil.example
                    /          \
                   /            \
                IP-A           DOMAIN-B
                 │                │
                 ▼                ▼
               IP-C            IP-D
                                  │
                                  ▼
                                IP-C
```

Perhaps ATI initially discovers `IP-C` through a path that puts it at depth 3. Later, another provider reveals a shorter path putting the same `Entity` at depth 2.

Its traversal state changes from:

```
minimum_depth = 3
```

To:

```
minimum_depth = 2
```

This is also the depth against which `max_depth` pivot policy is evaluated.

The first-discovery ordinal remains unchanged.

#### `best_investigated_depth`

This field is subtly different from `minimum_depth`:

- `minimum_depth` answers: What is the shallowest path by which ATI now knows about this `Entity`?
- `best_investigated_depth` answers: At what shallowest depth has ATI actually executed an investigation of this `Entity`?

Those values may differ. Consider this sequence:

1. ATI first discovers IP `203.0.113.42` at depth 3:
  - `minimum_depth`: 3.
  - `best_investigated_depth`: `None`.
2. ATI pivots to IP `203.0.113.42` and calls live evidence providers for it:
 - `minimum_depth`: 3.
 - `best_investigated_depth`: 3.
3. ATI later discovers a shorter path to `203.0.113.42`:
 - `minimum_depth`: 1.
 - `best_investigated_depth`: 3.

In #3, above, the `minimum_depth` has decreased: given `max_depth` is 2, then that increases our traversal budget, as well. This de facto allows IP `203.0.113.42` to be pivoted on (and investigated) again. The rationale for ATI is: "IP `203.0.113.42` has been investigated at depth 3 previously, but it is now known that it is reachable at depth 1. That IP has not yet been investigated as a depth-1 pivot, and doing so can enable valid downstream expansion that was unavailable from depth 3."

That is what `best_investigated_depth` preserves.

After ATI executes the newly eligible depth-1 pivot:

```
minimum_depth           = 1
best_investigated_depth = 1
```

A subsequent discovery of IP `203.0.113.42` at depth 2 or 3 does not justify another pivot, because ATI has already investigated it at a better (shallower) depth.

#### `mininum_depth` and `best_investigated_depth` vs Pivoting Decisions

`minimum_depth` and `best_investigated_depth` are kept separately because an `Entity` may later be rediscovered through a shorter path.

For example, ATI may initially discover and investigate an `Entity` at depth 3, then later discover that the same `Entity` is reachable from the root at depth 1. Its `minimum_depth` therefore becomes 1, while its `best_investigated_depth` remains 3.

The shallower rediscovery may make the `Entity` eligible for another pivot. This is important because pivot depth constrains subsequent traversal: investigating the `Entity` from depth 1 can permit downstream discoveries within the investigation's `max_depth` that would not have been reachable when the `Entity` was investigated at depth 3.

After the depth-1 pivot executes, `best_investigated_depth` becomes 1, and rediscoveries at depth 1 or greater can be suppressed.

The two fields are used by the `Coordinator` to determine whether pivoting should be performed, for a given `Entity`:

| `minimum_depth` | `best_investigated_depth` | Coordinator interpretation                                      |
| --------------: | ------------------------: | --------------------------------------------------------------- |
|               2 |                    `None` | Never investigated → eligible, subject to other rules           |
|               2 |                         1 | Already investigated at a better depth → suppress               |
|               1 |                         3 | Previously investigated only at a worse depth → may pivot again |

The `best_investigated_depth` is used in case #3 above: if the entity has already been investigated, at shallower or equal depth to `mininum_depth`, then pivoting is suppressed. If not, it is allowed.

### `PivotClass`

The `PivotClass` is a Python enum which is defined as follows:

```python
class PivotClass(str, Enum):
    PIVOTABLE = "pivotable"
    ENRICHABLE = "enrichable"
    RESEARCHABLE = "researchable"
```

Entity types are pre-assigned a `PivotClass` in the system, as the table below shows:

| Entity type        | Pivot class    | Intended treatment                                                            |
| ------------------ | -------------- | ----------------------------------------------------------------------------- |
| `DOMAIN`           | `PIVOTABLE`    | Normal investigative pivot/provider expansion                                 |
| `IP_ADDRESS`       | `PIVOTABLE`    | Normal investigative pivot/provider expansion                                 |
| `URL`              | `PIVOTABLE`    | Normal investigative pivot/provider expansion                                 |
| `NETWORK_PREFIX`   | `ENRICHABLE`   | Gather relevant enrichment without treating it as an ordinary recursive pivot |
| `ASN`              | `ENRICHABLE`   | Enrich, but don't recursively expand it like an IOC                           |
| `ORGANIZATION`     | `ENRICHABLE`   | Enrich, but don't recursively expand it like an IOC                           |
| `MALWARE`          | `RESEARCHABLE` | Send to contextual research                                                   |
| `ATTACK_TECHNIQUE` | `RESEARCHABLE` | Send to contextual research                                                   |
| `VULNERABILITY`    | `RESEARCHABLE` | Send to contextual research                                                   |

The classification controls what ATI should do when an `Entity` is discovered, in the course of an investigation. The following sub-sections describe each `PivotClass` and in which context they apply.

#### `PIVOTABLE`

For a `PIVOTABLE` entity, the normal recursive investigation mechanism - described earlier - applies:

```
DOMAIN evil.example
       │
       │ DNS evidence
       ▼
IP_ADDRESS 203.0.113.42
       │
       │ PIVOTABLE
       ▼
Run applicable providers
       │
       ▼
more evidence / entities / relationships
       │
       ▼
possibly pivot again
```

Domains, IP addresses and URLs are the primary objects through which ATI traverses threat infrastructure.

#### `ENRICHABLE`

Suppose IPinfo tells ATI:

```
203.0.113.42
      │
      ▼
    AS64500
```

An ASN is useful context. ATI may want information about it. But treating it like a normal recursive pivot could lead to explosive graph expansion:

```
AS64500
   │
   ├── thousands of prefixes
   │       ├── millions of IPs
   │       └── ...
   └── organizations...
```

So ASN, NETWORK_PREFIX, and ORGANIZATION are ENRICHABLE: useful investigative context, but not ordinary recursive IOC pivots.

#### `RESEARCHABLE`

Consider evidence that discovers:

```
MALWARE
  "Emotet"
```

ATI does not treat "Emotet" like an IP address and ask its infrastructure providers to recursively enumerate everything related to Emotet.

Instead, the Coordinator recognizes:

```
EntityType.MALWARE
        │
        ▼
PivotClass.RESEARCHABLE
        │
        ▼
mark research required
        │
        ▼
Threat Research / Context Agent
        │
        ▼
bounded RAG contextual research
```

The same applies to `ATTACK_TECHNIQUE` and `VULNERABILITY`.

The research might provide context such as what a malware family is, what a particular MITRE ATT&CK technique represents, or relevant information concerning a vulnerability. That context can inform the investigation and eventually the `Evidence Analyst` (or a human analyst), but it does not cause unrestricted graph traversal.

#### Summary

ATI classifies Entity types according to how they may participate in investigation expansion. `PIVOTABLE` entities—domains, IP addresses, and URLs—can drive ordinary provider-based investigative traversal. `ENRICHABLE` entities—network prefixes, ASNs, and organizations—may receive contextual enrichment but do not drive unrestricted recursive expansion. `RESEARCHABLE` entities—malware, attack techniques, and vulnerabilities—are handled through bounded contextual research rather than ordinary provider pivoting.

This classification is particularly important because it prevents pivoting from becoming unbounded graph crawling: ATI isn't trying to follow every possible connection. Rather, it assigns different traversal semantics to different kinds of nodes.

### Evidence Gathering: Planning and Execution

As was alluded to previously, the `Coordinator` will check, for a given candidate entity to pivot on, whether `Evidence` can be obtained. It does so after it has examined its hard-set limits (`max_depth`, etc.), and after the examination has passed. Once `Evidence` gathering could be confirmed, it is put into action. The following sub-sections explain this workflow.

#### 1. The Coordinator proceeds to planning


To determine whether `Evidence` gathering work can be done for a given `Entity`, the `Coordinator` first checks the `PivotClass` of the `Entity`: `PIVOTABLE` and `ENRICHABLE` entities go through the process described below (`RESEARCHABLE` entities are handled as part of the process described in section #6 further below: _The Coordinator initiates `RESEARCHABLE` processing_).

Then, the `Coordinator` interacts with an instance of the `ProviderWorkPlanner` interface. The production implementation is `RegistryProviderWorkPlanner`: at a high level, it contains a mapping of `EntityType` to `EvidenceProvider`.

A work planner result could conceptually be the following:

```
Candidate Entity
203.0.113.42
       │
       ▼
ProviderWorkPlanner
       │
       │ asks each enabled EvidenceProvider:
       │ provider.supports(entity)?
       │
       ├── Google DNS ── yes
       ├── RDAP ───────── yes
       ├── AbuseIPDB ──── yes
       ├── ThreatFox ──── yes
       ├── URLhaus ────── yes
       ├── IPinfo Lite ── yes
       └── DB-IP ──────── yes
```

For every applicable provider it produces a `ProviderWorkItem`:

```python
class ProviderWorkItem(BaseModel):
    provider: SourceId
    entity_id: UUID
    depth: int
```

The identity of such a workflow item is represented by exactly: `(provider, entity_id, depth)`.

So, for the example, planning might conceptually produce:

```
ProviderWorkItem(GOOGLE_PUBLIC_DNS, <ip_entity_id>, depth=1)
ProviderWorkItem(RDAP,              <ip_entity_id>, depth=1)
ProviderWorkItem(ABUSEIPDB,         <ip_entity_id>, depth=1)
ProviderWorkItem(THREATFOX,         <ip_entity_id>, depth=1)
ProviderWorkItem(URLHAUS,           <ip_entity_id>, depth=1)
ProviderWorkItem(IPINFO_LITE,       <ip_entity_id>, depth=1)
ProviderWorkItem(DBIP_CITY_LITE,    <ip_entity_id>, depth=1)
```
These are not provider calls yet. They are durable descriptions of work that could be queued.

The object deliberately does not contain the Entity value, provider object, HTTP client, credentials, etc. Those are resolved at execution time.

#### 2. The Coordinator authorizes a `PivotRequest` together with the work items

If provider planning returns no work, then pivoting is suppressed. Provided the `Coordinator`'s hard-set limits have passed verification (which they have, if we're at this stage), the `Coordinator` creates a `PivotRequest` for the entiy in question:

```python
PivotRequest(
    entity_id=<ip_entity_id>,
    reason="eligible_pivot",
    depth=1,
    status=PivotStatus.PENDING,
)
```

> One `PivotRequest` may therefore correspond to several `ProviderWorkItems`.

At this point, the `Coordinator` updates the `InvestigationState`, adding to its `pending_pivots` and `pending_provider_work` fields the just created `PivotRequest` and `ProviderWorkItems`.

De facto, this update constitutes a "pivot authorization". This authorization does not yet mean the `Entity` has been investigated.

#### 3. `ProviderWorkItems` are selected for execution

After pivot authorization, orchestration (TBD: describe what "orchestration" means, what executes it) proceeds to work selection. This occurs on a FIFO basis:

```python
return pending_provider_work[0]
```

This officialy starts the pivot and is entirely deterministic: No LLM decision, no new pivot scoring.

When the first `ProviderWorkItem` in the queue is selected, the corresponding `PivotRequest` is found by:
- Same `Entity` ID;
- same depth.

The status of the `PivotRequest` is then updated, from `PENDING` to `IN_PROGRESS`.

At this point, ATI also:

- Adds the `Entity` ID to `investigated_entity_ids` of `InvestigationState`;
- sets `current_provider_work` as the selected `ProviderWorkItem` - also in `InvestigationState`;
- records the executed depth in `EntityTraversalState.best_investigated_depth`.

This last point confirms that `best_investigated_depth` changes when provider work actually begins, not merely when a pivot is proposed or authorized.

#### 4. The next `ProviderWorkItem` is dispatched for execution

The orchestration then dispatches the selected work item, internally, to a work dispatcher/executor abstraction (TBD: explain this in more details in another section).

The executor resolves the actual Entity and actual provider implementation and executes the provider. Conceptually:

```
ProviderWorkItem
      │
      ▼
Dispatcher
      │
      ├── resolve Entity <ip_entity_id>
      │
      └── resolve RDAP provider
                │
                ▼
       provider.investigate(...)
                │
                ▼
           ProviderResult
                │
                ▼
        extraction/persistence
```

The resulting `ProviderExecutionOutcome` contains the operational result, including discovered Entity IDs, Evidence IDs, Relationship IDs and errors as applicable.

#### 5. The `ProviderExecutionOutcome` is processed

This phase consists of a few steps:

1. The executed item moves from `pending_provider_work` to `completed_provider_work` (in `Investigation State`).
2. Clears `current_provider_work` (ibid).
3. Merges newly produced IDs into the investigation:
    - `evidence_ids`
    - `relationship_ids`
    - `discovered_entity_ids`
4. updates traversal metadata for discoveries, records errors if necessary, and increments the following exactly once: `budget.provider_calls_used` (TBD: need more doc).

Then, orchestration returns to the `Coordinator`.


#### 6. The Coordinator initiates `RESEARCHABLE` processing

It is useful to be aware of the finer details of the research collection process. Entities that are `RESEARCHABLE` are have their IDs added to the `research_entity_ids` field of the `InvestigationState` - This section still does not go fully into such details, since the inner workings of the agents is explained more deeply in the [Agentic Architecture](AGENTIC.md) document.

Suppose provider work against IP `203.0.113.42` discovers the following `Evidence`:

```
Entity M-1
type = MALWARE
value = "Emotet"
```

Because `MALWARE` is `RESEARCHABLE`, the `Coordinator` ensures that the entity is enlisted in a `research_required_for_entity_ids` set, which is persisted in the `InvestigationState`. Those `Entity` IDs are eventually used to produde a `PlannedResearchRequest`, targeted at the `Research Agent`. That agent retrieves the relevant research using `RAG` (which is abstracted by the
`ResearchRetriever`). The result of research execution, for a given entity, is kept in the `research_executions` field (which contains `ResearchExecutionState` records) of the `InvestigationState`.

Each `ResearchExecutionState` record tracks the orchestration lifecycle of one exact research context for one researchable `Entity`.

The above succinctly describes a multi-step process that involves separate database transactions:

```
Discover M-1
    ↓
DECIDE: M-1 requires research
    ↓
PERSIST that requirement
    ↓
COMMIT
    ↓
later determine exact research context
    ↓
PERSIST research execution authorization
    ↓
COMMIT
    ↓
perform RAG/LLM work
```

If ATI simply went directly from discovering M-1 to calling the `Research Agent`, a crash could occur between those operations and lose the fact that research was required.

In summary: provider work (evidence collection) and threat research are parallel forms of investigative work selected according to entity semantics. Research isn't a post-processing step automatically run after every `ProviderWorkItem`. A `RESEARCHABLE` entity is routed to the `Research Agent` instead of through ordinary provider work. The following diagram attempts to capture this distinction:

```
                  discovered Entity
                         │
                         ▼
                     PivotClass
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
     PIVOTABLE       ENRICHABLE     RESEARCHABLE
          │              │              │
          └──────┬───────┘              │
                 ▼                      ▼
       ProviderWorkPlanner       Research-required
                 │                      │
                 ▼                      ▼
        ProviderWorkItem(s)       Research Agent
```

#### 7. Remaining work for the pivot is executed

Suppose the original pivot had seven applicable providers. After RDAP finishes, the following investigation state is observed:

```
Pivot IP-C depth=1
status = IN_PROGRESS

completed_provider_work:
    RDAP(IP-C,1)

pending_provider_work:
    AbuseIPDB(IP-C,1)
    ThreatFox(IP-C,1)
    URLhaus(IP-C,1)
    IPinfo(IP-C,1)
    DB-IP(IP-C,1)
    ...
```

The Coordinator sees pending provider work and returns `EXECUTE_PROVIDER_WORK`.

The next FIFO item gets selected and executed, as per the dequeuing/processing described above.

The `Coordinator` does not create a new PivotRequest for every provider: They are all work belonging to the same logical pivot.

#### 8. The work is drained: the pivot completes

After each provider outcome, ATI determines whether the `IN_PROGRESS` pivot (i.e.: `PivotRequest`) has any pending or current `ProviderWorkItem` with the same `(entity_id, depth)`.

As long as work remains, the pivot remains `IN_PROGRESS`. Once no matching work remains, the pivot's status is updated to `COMPLETED`.

> A completed pivot does not mean every provider returned "successful" evidence.

#### Summary

The whole process can be schematized as follows:

```
              Discovered Entity
                     │
                     ▼
                 Coordinator
                     │
              candidate eligible?
                     │
                     ▼
             ProviderWorkPlanner
                     │
           provider.supports(entity)
                     │
                     ▼
       ┌────────────────────────────┐
       │ ProviderWorkItem(provider A)│
       │ ProviderWorkItem(provider B)│
       │ ProviderWorkItem(provider C)│
       └────────────────────────────┘
                     │
              all policy/budget
                checks pass
                     │
                     ▼
               PivotRequest
                 PENDING
                     │
                     │ AUTHORIZE_PIVOT
                     ▼
       ┌─────────────────────────────┐
       │ pending_pivots              │
       │   Pivot(Entity, depth)      │
       │                             │
       │ pending_provider_work       │
       │   Provider A                │
       │   Provider B                │
       │   Provider C                │
       └─────────────────────────────┘
                     │
                     ▼
             FIFO work selection
                     │
                     ├── Pivot → IN_PROGRESS
                     ├── mark Entity investigated
                     └── best_investigated_depth
                     │
                     ▼
             execute Provider A
                     │
                     ▼
              record outcome
                     │
                     ▼
             execute Provider B
                     │
                     ▼
              record outcome
                     │
                     ▼
             execute Provider C
                     │
                     ▼
              record outcome
                     │
              no matching work left
                     ▼
               PivotRequest
                COMPLETED
```

## Final Analysis

Once the investigation has no further eligible pivots/provider work, ATI moves toward final analysis and then reporting.

The key point is that “pivoting is finished” does not itself mean “write the report immediately.” The `Coordinator` still needs a final analytical disposition over the complete evidence set.

As we have seen earlier, analysis (performed by the `Evidence Analyst`, but supervised by the `Coordinator` in the context of pivoting) actually happens throughout the investigation, rather than only once at the end. Eventually one of two broad situations occurs:

1. If the Evidence Analyst returns `SUFFICIENT`, the `Coordinator` decides that further collection isn't justified and stops investigative expansion. The resulting `Assessment` becomes the analytical basis for reporting.
2. If the Analyst returns `NEEDS_MORE_EVIDENCE` or `EXHAUSTED`, but the `Coordinator` determines that there are no eligible remaining pivots/provider paths (or a budget has been exhausted), collection also terminates. ATI then has to report based on the evidence actually obtained, including its limitations.

The following diagram represents the above flow:

```
             ┌───────────────────────┐
             │   Provider collection │
             └───────────┬───────────┘
                         ▼
                 Evidence Analyst
                         │
              AnalysisDisposition
                         │
              ┌──────────┴──────────┐
              │                     │
      more evidence useful     sufficient /
              │               no path left
              ▼                     │
         Coordinator                │
              │                     │
       eligible pivot?              │
         │         │                │
        yes        no ──────────────┤
         │                          │
         ▼                          ▼
ProviderWorkItems              Assessment
         │                          │
         └──── evidence ────────────┘
                                    ▼
                              Report Writer
                                    │
                                    ▼
                               Final Report
```

The "final analysis" is, in fact the last analysis pass done by the `Evidence Analyst` At every pass, the `Evidence Analyst` is given an `EvidenceAnalystInput`, which is a well-structured view of the `InvestigationState`, containing only the elements needed from it (and where all raw JSON payload data has been converted to Pydantic class instances).

That well-structured view is what the `Evidence Analyst` uses to build an `Assessment`, which conceptually consists of the following:

```
Assessment
├── id
├── investigation_id
├── verdict
├── confidence
├── summary
├── analyzed_evidence_ids
├── findings[]
├── limitations[]
├── unresolved_questions[]
├── recommended_next_steps[]
├── version
└── timestamps / deletion metadata
```

The `verdict` field may be set to either:

```
BENIGN
SUSPICIOUS
MALICIOUS
INCONCLUSIVE
```

The `confidence` field may take either one of the following:

```
LOW
MEDIUM
HIGH
```

For example:

```
Assessment
    verdict = SUSPICIOUS
    confidence = MEDIUM

    summary =
        "The infrastructure exhibits multiple reputation
         and association indicators consistent with
         malicious activity, but attribution remains
         insufficiently supported."

    findings =
        [ ... provenance-backed findings ... ]

    limitations =
        [ ... ]

    unresolved_questions =
        [ ... ]

    recommended_next_steps =
        [ ... ]
```

> Evidence is what sources told ATI. An Assessment is ATI's interpretation of that evidence.


## Reporting

The last `Assessment` produced by the `Evidence Analyst`, as well as supporting Evidence/relationships, and contextual research results, are provided to the `Report Writer` agent. That agent has a constrained role, limited to synthesis and presentation, not further investigation or analytical decision-making. It uses the LLM to construct the report.

> Although the `Report Writer` is an LLM-backed agent, it is not an autonomous investigative agent. It cannot call providers, pivot to new entities, alter the Assessment verdict/confidence, or introduce unsupported findings.

## Summary

At a high-level, the previous sections presented the following end-to-end workflow:

```
┌─────────────────────────────┐
│      Investigation Start    │
│  Root Entity + Objective    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│         Coordinator         │
│  deterministic policy /     │
│  orchestration decisions    │
└──────────────┬──────────────┘
               │
               │ select eligible entity
               ▼
┌─────────────────────────────┐
│      ProviderWorkPlanner    │
│ Which providers support it? │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│      ProviderWorkItems      │
│ DNS / RDAP / Threat Intel / │
│ Reputation / Geo / etc.     │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│        Deterministic Processing         │
│                                         │
│  Normalize → EvidenceObservations       │
│            → Entities                   │
│            → RelationshipObservations   │
│            → GEO resolution as needed   │
└───────────────────┬─────────────────────┘
                    │
                    ▼
          ┌─────────────────────┐
          │     Coordinator     │◄──────────────────────┐
          └──────────┬──────────┘                       │
                     │                                  │
          ┌──────────┴──────────┐                       │
          │                     │                       │
          ▼                     ▼                       │
   New Evidence?        RESEARCHABLE Entity?            │
          │                     │                       │
          │ yes                 │ yes                   │
          ▼                     ▼                       │
┌──────────────────┐   ┌─────────────────────┐          │
│ Evidence Analyst │   │ Mark Research       │          │
│      Agent       │   │ Required            │          │
└────────┬─────────┘   └──────────┬──────────┘          │
         │                        │                     │
         ▼                        │                     │
┌──────────────────┐              │                     │
│   Assessment     │              │                     │
│                  │              │                     │
│ • verdict        │              │                     │
│ • confidence     │              │                     │
│ • findings       │              │                     │
│ • limitations    │              │                     │
│ • questions      │              │                     │
└────────┬─────────┘              │                     │
         │                        │                     │
         │ + AnalysisDisposition  │                     │
         ▼                        ▼                     │
┌─────────────────────────────────────────┐             │
│               Coordinator               │             │
│                                         │             │
│  • SUFFICIENT                           │             │
│  • NEEDS_MORE_EVIDENCE                  │             │
│  • EXHAUSTED                            │             │
│  • due contextual research              │             │
└───────┬───────────────────┬─────────────┘             │
        │                   │                           │
        │ research due      │ more collection           │
        ▼                   ▼                           │
┌──────────────────┐  ┌──────────────────────┐          │
│ Threat Research  │  │ Pivot / Enrichment   │          │
│      Agent       │  │ Candidate Selection  │          │
│                  │  └──────────┬───────────┘          │
│ bounded RAG      │             │                      │
└────────┬─────────┘             │                      │
         │                       │                      │
         ▼                       │                      │
┌──────────────────┐             │                      │
│ ResearchResult   │             └──────────────────────┘
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────┐
│         Coordinator         │
│                             │
│ Continue or terminate?      │
└──────────────┬──────────────┘
               │
               │ STOP
               ▼
┌──────────────────────────────────────┐
│    Final / Current Assessment        │
│                                      │
│ Authoritative analytical conclusion  │
└───────────────────┬──────────────────┘
                    │
                    │ + Evidence
                    │ + Relationships
                    │ + ResearchResults
                    ▼
┌──────────────────────────────────────┐
│         Report Writer Agent          │
│                                      │
│ Synthesis / presentation only        │
│ Does not change Assessment           │
└───────────────────┬──────────────────┘
                    │
                    ▼
             ┌──────────────┐
             │ Final Report │
             └──────────────┘
```

The system has three distinct control/intelligence layers:

```
          ┌─────────────────────────┐
          │      Coordinator        │
          │ "What happens next?"    │
          └────────────┬────────────┘
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
  Deterministic    LLM Analysis     LLM Research
   Collection
       │               │                │
 Providers +       Evidence         Threat Research
 Extractors        Analyst          Agent
       │               │                │
       ▼               ▼                ▼
   Evidence         Assessment      ResearchResult
 Relationships     + Disposition
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                   Coordinator
                       │
                   iterate/stop
                       │
                       ▼
                  Report Writer
                       │
                       ▼
                  Final Report
```

- The `Coordinator` owns workflow;
- the `Evidence Analyst` owns evidence interpretation; 
- the `Research Agent` owns contextual research;
- the `Report Writer` owns presentation. 

Providers and extractors remain deterministic evidence-acquisition machinery rather than analytical agents.