# Agentic Threat Investigator — Product Specification

## Purpose

Agentic Threat Investigator (ATI) is an open-source, analyst-oriented threat investigation system demonstrating production-quality agentic engineering applied to cybersecurity.

ATI accepts one or more indicators and autonomously gathers evidence, discovers related infrastructure, performs bounded investigative pivots, retrieves relevant threat-research context, assesses the evidence, and produces a provenance-backed report.

ATI is not intended to be merely an IOC lookup aggregator. Its defining behavior is the ability to decide what to investigate next, adapt the execution path to evidence discovered at runtime, and stop within explicit budgets.

## Core product question

> Given one or more indicators, what are they, are they suspicious, what infrastructure and threat intelligence are associated with them, what evidence supports the assessment, and what should an analyst investigate next?

## v0.1 goals

v0.1 demonstrates:

- Tool calling through typed provider interfaces.
- Stateful LangGraph orchestration.
- Dynamic investigation planning and replanning.
- Evidence collection and provenance.
- Evidence-backed runtime pivots.
- RAG over curated threat-research sources.
- Typed entities and relationships.
- Approximate city-level IP geolocation and map visualization.
- Evidence-based verdict and confidence.
- Contradiction and limitation handling.
- Persistent investigation history.
- Scheduled monitors and findings.
- Auditing and local authentication.
- Deterministic testing and LLM evaluation.
- Agent and LLM observability.

## v0.1 use cases

### IOC investigation

Investigate a domain, IP address, or URL using applicable infrastructure and threat-intelligence providers.

### Maliciousness assessment

Produce one of:

- `benign`
- `suspicious`
- `malicious`
- `inconclusive`

with LOW, MEDIUM, or HIGH confidence and explicit supporting and contradicting evidence.

Absence of malicious evidence does not imply a benign verdict.

### Infrastructure profiling

Identify relevant IP addresses, domains, network prefixes, ASNs, organizations, registration data, and approximate geography.

### Relationship discovery

Persist normalized relationships such as:

- domain resolves to IP
- IP belongs to network prefix
- prefix announced by ASN
- prefix registered to organization
- indicator associated with malware
- malware uses ATT&CK technique

### Threat-context research

Use RAG to explain concepts discovered during the investigation.

Tools answer:

> What do we know about this specific indicator?

RAG answers:

> What does the threat-research corpus tell us about what we observed?

RAG does not establish live IOC facts or independently determine maliciousness.

### Next-step investigation

The Coordinator may pivot to evidence-discovered indicators when the pivot is relevant, policy-compliant, and within budget.

### Reporting

Generate a structured analyst report containing the assessment, evidence, infrastructure, relationships, threat context, contradictions, limitations, unresolved questions, and recommended next steps.

### Correlation and history

Support multi-IOC correlation, bounded infrastructure clustering, historical investigation review, and comparison of investigations.

### Monitoring

Allow analysts to monitor indicators. A scheduled monitor creates a normal investigation, compares the result with the prior state, and generates a finding when a meaningful change occurs.

## Canonical v0.1 flow

The canonical scenario is `malicious_domain_with_ip_and_malware_pivot`.

1. Analyst submits a DOMAIN.
2. Google Public DNS and RDAP are queried.
3. DNS discovers an IP address.
4. ATI persists the entities, evidence, `RESOLVES_TO` relationship, and observation.
5. The Coordinator evaluates and approves an IP pivot.
6. ATI queries applicable IP/network/reputation/threat-intelligence sources.
7. Network, ASN, organization, registration, and geolocation context are created.
8. ThreatFox identifies a malware association.
9. The Coordinator requests threat research for the malware.
10. RAG retrieves relevant ATT&CK/CISA material.
11. The Evidence Analyst produces a typed assessment.
12. The Report Writer produces the analyst report.
13. The UI presents the graph, map, evidence, research, timeline, assessment, and report.

## Explicit v0.1 boundaries

Included:

- IOC investigation and enrichment.
- Adaptive LangGraph orchestration.
- Typed evidence/entities/relationships.
- Shallow bounded relationship traversal.
- PostgreSQL relational relationship model.
- Historical relationship observations.
- Approximate city-level IP geolocation.
- Map visualization.
- RAG over curated public threat research.
- Assessment, reports, monitoring, findings, audit, and local authentication.

Excluded:

- Apache AGE or another graph database.
- Deep or general-purpose graph traversal.
- Graph algorithms/community detection.
- Ontology/inference engine.
- Threat-actor attribution.
- Campaign attribution.
- Commercial CTI feeds.
- Paid passive DNS.
- Paid geolocation or VPN/proxy identification.
- AWS/customer telemetry.
- SIEM/EDR integrations.
- Automated remediation.
- Chat-centric primary UX.

## Product principles

1. Evidence is distinct from interpretation.
2. Every material analytical claim must be traceable to evidence or cited research.
3. Every autonomous pivot must trace back to user input or observed evidence.
4. Agent behavior is bounded by deterministic policy and budgets.
5. Structured contracts govern machine decisions.
6. Historical observations are preserved.
7. Geography is contextual evidence, not a maliciousness signal.
8. Investigation execution remains functional if external observability is unavailable.
9. The user interface exposes observable actions and reasons, never hidden chain-of-thought.
