# Agentic Threat Investigator — Frontend Scope

## Table of contents

- [Objective](#objective)
- [Primary screens](#primary-screens)
  - [Investigations](#investigations)
  - [Investigation Detail](#investigation-detail)
  - [Findings](#findings)
  - [Monitors](#monitors)
  - [System / Admin](#system-admin)
- [Investigation Overview](#investigation-overview)
- [Evidence](#evidence)
- [Relationships](#relationships)
- [Map](#map)
- [Research](#research)
- [Timeline](#timeline)
- [Report](#report)
- [Investigation creation](#investigation-creation)
- [Progress](#progress)
- [Explicit exclusions](#explicit-exclusions)
- [Visual semantic rule](#visual-semantic-rule)

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
5. Geographic context (GEOINT)
6. Research
7. Timeline
8. Report

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

### Graph context and filters (PR 31G)

The Graph view distinguishes Investigation-supported topology from broader
known topology and exposes bounded server-side filters. The committed graph
context has exactly one authority: the Graph route URL search parameters
(`graph_scope`, `graph_entity_type`, `graph_relationship_type`,
`graph_source`, `graph_observed_from`, `graph_observed_to`). Draft edits live
in a transient local form and never issue a request before Apply; Apply and
Clear each perform exactly one route commit, and refresh / browser
Back/Forward reconstruct the same request from the URL. The routed Graph page
and `RelationshipGraph` stay mounted across query-parameter-only changes;
dragging/selection remain transient presentation state that never touches the
URL or the query key.

- **Scopes**: `investigation` (default) vs `known`. Investigation shows only
  Relationships supported by Evidence admitted to this Investigation; Known
  shows broader globally known live Relationships around the
  Investigation-visible focal Entity.
- **Server-side filters**: connected (counterparty) Entity type, canonical
  Relationship type, exact `RelationshipObservation.source`, and half-open
  `observed_at` bounds. Filtering happens server-side before bounding;
  `truncated` stays truthful and the client never post-filters.
- **Expansion inheritance and reset**: every one-hop expansion inherits the
  complete committed context; changing any scope/filter aborts stale
  in-flight expansion and resets accumulated graph state.
- **Known-only presentation**: a known-only edge (`investigation_observation_count == 0`)
  is never presented as Investigation-discovered. Its accessible list entry
  shows `Known to ATI; not admitted to this Investigation`; Investigation-
  supported edges show `Supported by this Investigation`; edge detail shows
  exact matching-observation and matching-in-this-Investigation counts.

## Map

Use Leaflet.

Show approximate geolocation for relevant IP entities.

Display city/region/country/coordinates when available and source/precision.

Always include a clear qualification equivalent to:

> Approximate IP geolocation; this does not identify the physical location of an attacker or device.

Map markers link back to entity/evidence details.

### Geographic context (GEOINT)

Show the bounded PR 26D canonical geographic summary for the Investigation: entities with geographic context, observations, canonical Locations, type/precision counts and top Locations, with the persistent semantic disclaimer that shared or nearby locations do not establish a cyber relationship, ownership, coordination, targeting, or attribution.

Map markers plot only the currently loaded top Locations' representative coordinates (never all pages) with neutral markers; an always-available non-map table covers every map action. Entities show Investigation-relative current context and pageable immutable observation history; Locations expose scoped Entities/observations with the exact/contained controller (server-owned containment, `containment_applied` rendered honestly). Every observation reaches its exact Evidence through the returned `evidence_id`; geographic exploration uses PR 31F-8 canonical Investigation-scoped routes (`/geoint/entities/:entityId`, `/geoint/locations/:locationId/entities|observations`, exact Evidence and observation routes) — the former encoded PivotWorkspace host is retired.

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
- supporting Findings;
- contradicting Findings;
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
