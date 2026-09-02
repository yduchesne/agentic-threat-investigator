# Agentic Threat Investigator — Frontend Scope

## Objective

The v0.1 frontend is a desktop-first analyst workbench focused on investigation visibility, provenance, relationships, geography, monitoring, and conclusions.

It is not a chat-first interface.

Technology:

- React;
- TypeScript;
- React Flow;
- Leaflet;
- a restrained component library selected during frontend bootstrap.

TypeScript uses strict static typing.

## Primary screens

### Investigations

Capabilities:

- list recent investigations;
- filter by status;
- create an investigation;
- show root IOC(s), objective, status, verdict/confidence when available, and timing;
- navigate to investigation detail.

### Investigation Detail

Tabs:

1. Overview
2. Evidence
3. Relationships
4. Map
5. Research
6. Timeline
7. Report

This is the centerpiece of the product.

### Findings

Inbox-style monitor findings.

Show:

- workflow status;
- concise meaningful-change summary;
- originating monitor;
- originating investigation;
- navigation to evidence/details.

Support new/acknowledged/dismissed workflow.

### Monitors

Support:

- list;
- create/edit;
- enable/disable;
- soft delete;
- last run;
- next run;
- status;
- linked findings.

Avoid a complex cron-builder in v0.1.

### System / Admin

Minimal views for:

- user administration;
- provider/configuration status visibility;
- job/ingestion status;
- basic health information.

This is not a SIEM-style operations console.

## Investigation Overview

Show:

- root indicators;
- objective;
- status;
- current/final verdict;
- confidence;
- important entities;
- limitations;
- recommended next steps.

## Evidence

Present structured evidence with:

- source;
- subject;
- evidence type;
- observed/retrieved time;
- normalized facts;
- provenance.

Do not show raw provider payloads by default.

## Relationships

Use React Flow.

Nodes represent canonical entities.

Edges represent ATI relationship URNs but display readable labels.

Selecting a node/edge opens details with linked evidence/provenance.

The graph is a bounded visualization of the investigation, not a general graph explorer.

## Map

Use Leaflet.

Show approximate geolocation for relevant IP entities.

Display city/region/country/coordinates when available and source/precision.

Always include a clear qualification equivalent to:

> Approximate IP geolocation; this does not identify the physical location of an attacker or device.

Map markers link back to entity/evidence details.

## Research

Keep RAG research visually distinct from live evidence.

Show:

- research subject;
- summary;
- claims;
- citations;
- source document/chunk information.

The analyst can inspect the source supporting a research claim.

## Timeline

Show observable workflow history such as:

```text
Investigation started
Google DNS queried
IP discovered
Pivoted to discovered IP
ThreatFox returned malware association
Threat research requested
Assessment produced
Report completed
```

Show concise action reasons where useful.

Never display hidden chain-of-thought, scratchpads, raw prompts, or LangGraph internals.

## Report

Present the analyst-facing report:

- executive summary;
- verdict/confidence;
- supporting evidence;
- contradicting evidence;
- infrastructure;
- threat context;
- limitations;
- unresolved questions;
- recommended next steps.

## Investigation creation

Keep v0.1 simple:

```text
Indicator(s)
Objective
[Start Investigation]
```

No large wizard.

## Progress

v0.1 uses polling of investigation/timeline endpoints while PENDING/RUNNING.

WebSockets are not required.

## Explicit exclusions

Not v0.1:

- chat as primary UX;
- arbitrary/deep graph traversal;
- drag/drop graph editing;
- raw SQL/query consoles;
- raw provider payload UI by default;
- prompt/model-tuning UI;
- embedded LangSmith trace viewer;
- advanced RBAC editor;
- dashboard builder;
- threat-actor/campaign workbench;
- case/ticket management;
- collaboration/comments;
- Slack/email integration;
- mobile-first design.

## Visual semantic rule

Evidence, research context, and ATI assessment must remain visibly distinct.

The frontend must never present source facts and LLM interpretation as one undifferentiated stream.
