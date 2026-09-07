# Agentic Threat Investigator --- Implementation / PR Plan

## Delivery principle

Implement ATI in small, reviewable increments. Every PR must preserve
repository quality gates and add tests appropriate to the new behavior.

Do not allow coding agents to invent major architecture contrary to the
authoritative documentation.

------------------------------------------------------------------------

## PR 1 --- Repository bootstrap and development environment \[DONE\]

## PR 2 --- Core domain model \[DONE\]

## PR 3 --- Database migrations and repository contracts \[DONE\]

## PR 4 --- Local identity/authentication \[DONE\]

## PR 5 --- Audit and history \[DONE\]

## PR 6 --- PostgreSQL batch persistence \[DONE\]

## PR 7 --- SecretsResolver implementation and integration \[DONE\]

## PR 8 --- Batch source/ingestion framework \[DONE\]

## PR 9 --- MITRE ATT&CK ingestion \[DONE\]

## PR 10 --- Documents/chunks/embeddings \[DONE\]

## PR 11 --- RAG retrieval \[DONE\]

## PR 12 --- Live provider framework + RDAP + Google DNS \[DONE\]

The completed PRs retain their existing repository scope and contracts.

------------------------------------------------------------------------

# Remaining evidence-source integrations

Each remaining source gets its own PR. Every source PR is a complete,
independently reviewable vertical slice and, where applicable, includes
configuration, secret handling, normalization, typed Evidence, entity
discovery, relationship inputs, typed failures, quota/rate behavior,
deterministic fixtures, tests, and documentation.

## PR 13 --- IPinfo Lite provider \[DONE\]

Deliver:

-   IPinfo Lite integration;
-   IP-address support;
-   authentication through bootstrap-resolved credentials where
    required;
-   network/ASN/organization normalization;
-   normalized `NETWORK` evidence;
-   deterministic extraction of eligible ASN/network/organization facts;
-   provider error mapping;
-   rate/quota handling;
-   synthetic response fixtures;
-   deterministic provider tests.

All PR 13 provider tests use deterministic synthetic responses only.
Live IPinfo contract testing is outside PR 13 and requires a separately
approved future change.

No analytical verdict logic belongs in the provider.

## PR 14 --- DB-IP City Lite geolocation integration \[DONE\]

Deliver:

-   DB-IP City Lite local MMDB integration;
-   artifact-location configuration using URI semantics;
-   storage/artifact abstraction integration;
-   local artifact validation;
-   IP-address lookup;
-   normalized `GeoLocation`;
-   normalized `GEOLOCATION` evidence;
-   country/region/city/approximate
    latitude/longitude/precision/provider fields;
-   behavior for missing/unknown/private/reserved addresses;
-   deterministic MMDB fixture or test dataset;
-   unit/integration tests.

Geolocation remains contextual evidence in v0.1. Do not introduce
PostGIS, general-purpose GEOINT entities, spatial pivoting, or physical
attacker-location inference.

## PR 15 --- AbuseIPDB provider

Deliver:

-   AbuseIPDB integration;
-   IP-address support;
-   credential resolution through the established bootstrap mechanism;
-   normalized `REPUTATION` evidence;
-   provider reputation/abuse scores retained as source facts;
-   relevant report/count/category/time facts;
-   rate-limit/quota and authentication/error behavior;
-   deterministic fixtures and tests.

All PR 15 AbuseIPDB provider tests use deterministic synthetic responses
only. Live AbuseIPDB contract testing is outside PR 15 and requires a
separately approved future change.

Provider scores do not directly determine ATI assessment confidence. No
AbuseIPDB hit does not imply `BENIGN`. [DONE]

## PR 16 --- ThreatFox provider

Deliver:

-   ThreatFox integration;
-   supported IOC lookup forms;
-   source-specific normalization;
-   normalized `THREAT_INTELLIGENCE` evidence;
-   IOC-to-malware discovery where supported;
-   `MALWARE` entity discovery;
-   inputs for deterministic `ASSOCIATED_WITH` relationships;
-   source timestamps/reference identifiers;
-   typed errors;
-   malicious IOC and no-result fixtures;
-   canonical AsyncRAT fixture support;
-   deterministic provider tests;
-   optional live contract tests.

Canonical trajectory:

``` text
domain
  ↓
DNS
  ↓
IP
  ↓
ThreatFox
  ↓
malware entity
  ↓
Threat Research RAG
```

The provider supplies evidence, not the ATI verdict.

## PR 17 --- URLhaus provider

Deliver:

-   URLhaus integration;
-   supported URL/host/IOC queries;
-   normalized `THREAT_INTELLIGENCE` evidence;
-   URL/infrastructure entity discovery where supported;
-   relevant payload/malware/source metadata normalization;
-   typed errors;
-   rate/quota behavior where applicable;
-   deterministic fixtures and tests;
-   optional live contract tests.

------------------------------------------------------------------------

# Investigation engine

## PR 18 --- Investigation persistence and relationship construction

Deliver Investigation persistence, Evidence persistence, deterministic
relationship extraction, stable Relationship identity, immutable
`RelationshipObservation`, discovered-entity processing, atomic
provider-result persistence, history/version invariants, and integration
tests.

## PR 19 --- LangGraph investigation skeleton

Deliver typed `InvestigationState`, coordinator graph, provider/tool
execution nodes, working-set/queue mechanics, budgets/counters,
persisted observable timeline actions, deterministic fake providers/LLM,
and the initial deterministic evaluation framework.

Do not persist or expose chain-of-thought.

## PR 20 --- Evidence Analyst

Deliver `LlmClient` ABC and LangChain implementation, structured
Evidence Analyst output, typed `Assessment`, supporting/contradicting
evidence references, limitations/unresolved questions/next steps,
deterministic citation validation, fake-LLM tests, and agent-level
evaluations.

## PR 21 --- Adaptive pivots and stopping

Deliver evidence-driven pivot requests, deterministic pivot-policy
validation, depth/entity/provider/replan/LLM budgets, duplicate
suppression, stopping rules/reasons, canonical investigation trajectory,
and coordinator trajectory evaluations.

Every autonomous pivot must have provenance to user input or observed
evidence. LLM-selected pivots must reference already-existing eligible
entity IDs.

## PR 22 --- Threat Research RAG agent

Deliver conditional research triggering for discovered malware/ATT&CK
techniques/vulnerabilities, Research Agent, RAG claim/chunk citations,
persisted research results, retrieval/synthesis evaluations, and
no-relevant-context behavior.

RAG supplies contextual research, not live IOC facts.

## PR 23 --- Report Writer and investigation API

Deliver structured reports, Report Writer, report
persistence/versioning, `/api/v1` investigation and subresource
endpoints, asynchronous semantics, cursor pagination, stable errors,
idempotency, and resource version/history exposure where appropriate.

The Report Writer cannot alter the Evidence Analyst verdict/confidence
or introduce unsupported facts.

## PR 24 --- Analyst frontend

Deliver the React/TypeScript application, investigation
list/create/detail flows, Overview, Evidence, Relationships, Research,
Timeline and Report views, React Flow relationship visualization, and
polling.

Keep the interface evidence-centric rather than chat-centric.

## PR 25 --- Geolocation map

Deliver:

-   Map tab;
-   Leaflet integration;
-   plotting v0.1 approximate IP geolocations;
-   multi-IOC visualization;
-   provenance/precision display;
-   geographic disclaimer;
-   correlation-oriented presentation without implying physical attacker
    location.

This is contextual geolocation visualization, not general GEOINT.
PostGIS and spatial investigation remain deferred.

## PR 26 --- Monitors, diffs, findings, jobs and administration

Deliver Monitor persistence, scheduler, normal Investigation execution
from monitors, snapshot/diff logic, material Finding generation,
findings inbox, PostgreSQL-backed jobs, basic administration/system UI,
and operational visibility.

Code determines deterministic differences; AI may determine materiality.

## PR 27 --- Evaluation and release hardening

Expand and harden the evaluation framework introduced with the agent
PRs.

Deliver:

-   approximately 30--50 curated scenarios;
-   deterministic invariant evaluators;
-   agent behavioral evaluations;
-   end-to-end trajectory evaluations;
-   optional model-assisted semantic judges;
-   adversarial prompt-injection/content scenarios;
-   canonical malicious-domain/IP/malware trajectory;
-   release gates and stability runs;
-   performance/cost/latency reporting where appropriate;
-   licensing/source-term checks;
-   documentation review and release checklist.

Hard failures include invented or policy-invalid pivots, budget
violations, nontermination, invalid citations, unsupported material
claims, report-verdict mutation, persistence invariant violations, and
unacceptable canonical-scenario outcomes.

------------------------------------------------------------------------

# v0.1 release boundary

v0.1 includes IOC investigation/enrichment, adaptive LangGraph
investigation, typed entities/relationships/evidence, bounded traversal,
PostgreSQL relational graph representation, relationship provenance,
approximate city-level IP geolocation, multi-IOC map visualization,
ASN/network/registration profiling, reputation and malware intelligence,
curated threat-research RAG, evidence-backed assessment,
reports/history, local auth/audit, monitors/findings, and deterministic
tests/evaluations.

v0.1 explicitly excludes general-purpose GEOINT, PostGIS-backed spatial
investigation, spatial entities/observations and spatial pivoting,
deep/general graph traversal, graph databases, unrestricted ASN
expansion, ontology/inference, threat-actor/campaign attribution,
commercial CTI feeds, paid passive DNS, AWS/customer telemetry, SIEM/EDR
integration, and automated remediation.

General geospatial intelligence, spatial entities/observations,
PostGIS-backed spatial queries, spatial/temporal correlation, and
agent-directed geographic investigation are candidates for v0.2 and
should be designed as a coherent capability rather than retrofitted into
v0.1 geolocation.
