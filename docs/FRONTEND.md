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
- [GEOINT](#geoint)
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
4. GEOINT (MAP | TABLE)
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

### Bounded multi-hop traversal (PR 31H)

The Graph view adds one URL-backed committed depth (`graph_depth`) that
selects exactly one server operation: depth 1 (absent parameter, the
backward-compatible default) uses the existing one-hop neighborhood endpoint;
depth 2/3 use the dedicated bounded traversal endpoint (`.../traversal`).
Depth is hop distance from the focal Entity; the server hard-bounds 1..3 and
the traversal inherits the exact PR 31G scope and every optional filter at
every frontier.

- **URL is the committed depth authority**: absent or malformed `graph_depth`
  canonicalizes to depth 1; depth 1 serializes as absent; depth 2/3 serialize
  canonically; refresh and browser Back/Forward reconstruct the committed
  depth. `graphDepthActive()` is a narrow depth predicate distinct from
  `graphContextActive()` (optional filters).
- **Draft/Apply lifecycle**: the depth selector is part of the browser-local
  graph draft; editing the draft issues no request, Apply performs one route
  commit, and Clear returns to depth 1 with Investigation scope and no
  optional filters.
- **One server operation at a time**: depth 1 enables the neighborhood hook,
  depth 2/3 the traversal hook; the two TanStack Query keys are distinct and
  never share cache entries, so stale prior-depth responses cannot overwrite
  the current state and the two never race.
- **Traversal root + explicit one-hop expansion**: the depth 2/3 server
  result seeds the root topology and explicit node expansion continues to use
  the existing one-hop endpoint under the same committed context. Changing
  the root depth is a root semantic change: accumulated expansion state
  resets and stale prior-root expansion results are discarded.
- **No route/Graph remount**: depth changes are query-only navigation on the
  same Graph route; the Investigation shell and `RelationshipGraph` stay
  mounted (`key=`-style remounts, second router/stores and URL write-back
  effects are prohibited).
- **Presentation**: `RelationshipGraph` is reused as-is; nodes are placed on
  deterministic minimum-distance rings (focal center, hop 1 at the historical
  radius, deeper hops on outer rings with Entity UUID tie-breakers), the
  `truncated` cue is reused per operation, and the bound never implies
  topology exhaustion beyond the requested depth.

### Bounded path finding (PR 31I)

The Graph view adds an analyst-driven path mode that requests bounded,
deterministic simple paths between two canonical Entities already
represented in the graph workbench.

- **Path mode is transient workbench state**: entering path mode, selecting
  the source and target Entities (plain canvas node clicks — first click
  source, second click target, clicks on an already-selected endpoint
  deselect it) and adjusting the path-owned depth/path-count bounds are all
  local React state and never issue a request; only the explicit *Find
  paths* action enables the server request (exactly one per Find). No
  second durable or URL-backed store exists and no new navigation stack is
  created.
- **Committed context inheritance**: a path request inherits the committed
  graph context (scope, direction, Entity/Relationship type filters,
  observation source and half-open interval) exactly; path finding uses its
  own bounded max depth (default 4, max 6) and path count (default 10, max
  25) and never accidentally reuses the committed `graph_depth`. Only the
  committed (applied) context is sent — uncommitted draft values never
  reach the request.
- **Distinct TanStack path query**: `useGraphPaths` uses a dedicated
  `graphPathKey` that contains the Investigation ID, both endpoint Entity
  IDs, direction, the committed context and the path bounds, so a path
  result can never share a cache identity with the neighborhood/traversal
  topology and any committed context change issues a fresh request.
  AbortSignal is propagated; an aborted request is a normal cancellation,
  never a semantic error.
- **Stale-result protection**: a committed graph-context change deterministically
  clears the displayed path result and both endpoint selections (the simple
  option the PR 31I plan explicitly allows), so a stale prior-context
  response can never render. Bounds/endpoint edits also clear the displayed
  result until the next explicit Find.
- **Canonical rendering and highlighting**: the returned nodes/edges render
  through the existing `RelationshipGraph` (deterministic layout, no second
  renderer); a result panel offers *All returned paths* or a deterministic
  individual path choice with ordinal and hop count, and the selected path
  is visually isolated — participating relationships/nodes are emphasized
  while the remaining returned topology is dimmed — using canonical IDs only
  and without any refetch. The no-connection state is explicit (both
  endpoints visible but no eligible path) and a truthful truncation notice
  appears when additional qualifying paths existed beyond the requested
  bound.
- **Exit restores the ordinary graph without reload**: leaving path mode
  is local state only; the ordinary root neighborhood/traversal result and
  accumulated one-hop expansions return unchanged, one-hop interactive
  expansion keeps working, and the Graph route/Investigation shell never
  remounts.

### Focal-Entity exploration (PR 35-8)

`entity_id` on the Relationship History/Graph route is the single
URL-backed focal Entity. It is **not** the Investigation's triggering/root
Entity: exploration may change focal identity without changing Investigation
provenance or triggering Entities. There is no parallel client-side focal
state and no second focal store.

- **Explore vs Expand**: right-clicking a canonical non-focal Entity vertex
  opens a lightweight, pointer-adjacent graph context menu whose *Explore*
  command makes that Entity the new URL-backed focal Entity. The menu is
  ordinary positioned content (no portal, backdrop, focus trap, body lock or
  persistent pointer shield) that does not shift the canvas and dismisses on
  Explore, Escape, outside pointer, retarget, root change or unmount. The
  focal node offers no Explore menu. *Expand* stays a distinct, additive
  topology operation (one-hop known/outgoing/incoming) that keeps the current
  focal root. Ordinary left-click keeps its existing selection/path
  semantics and never re-roots.
- **One canonical lateral transition with a contextual Back**: the focal
  change is a pure URL transition that sets the new canonical `entity_id`,
  preserves `view`, direction, relationship type/source, observed range and
  the graph/temporal context, and clears the focal-relative transient state
  (opaque observation cursor, `selected` detail and the focal-relative
  `counterparty_entity_id`, plus the browser-local observation back-stack).
  Unlike sibling EVOLUTION <-> GRAPH navigation (which preserves context), a
  focal Explore is a genuine contextual re-root: it pushes the **exact
  preceding Graph location** onto the existing bounded NavigationContext
  ahead of any older ancestors, so repeated exploration unwinds
  `C -> B -> A` and `< Back` restores the exact prior pathname/search/hash,
  including `view=graph`, focal ID, graph filters and temporal state.
- **Whole-workspace re-root**: the new `entity_id` re-roots the observation
  query, graph neighborhood/traversal, focal node styling/layout,
  focal-relative edge direction/counterparty presentation, the focal
  Relationships target and the focal indicator. Accumulated expansion, path
  request/endpoints, selected node/edge, provenance panel and graph-action
  selection are reset deterministically; refresh/share of the URL
  reconstructs the explored focal Entity.
- **Canonical focal presentation**: both the History and Graph views render
  `Focal entity: <canonical value>` directly below the title, and the
  Relationships table renders the same indicator when it is entered with
  `entity_id`. The value comes from the exact Investigation-scoped canonical
  Entity projection (the graph neighborhood focal node), never from a UUID,
  never inferred from observation/relationship rows, and never fabricated.
  The value is a link to the generic Entity details surface.
- **Generic Entity details**: `/investigations/:id/entities/:entityId` is a
  read-only Exact Entity surface (value, type and canonical copyable ID). It
  is not the GEOINT Entity page and is not an Entity intelligence dashboard.
- **Bounded contextual navigation reuses the existing stack**: the Graph's
  *Open relationships table for focal entity* link and both focal value links
  push the exact current location onto the existing bounded navigation
  context, so `< Back` restores the exact originating graph/history or focal
  Relationships state one level at a time. Entity details opened from a
  direct URL fall back to the Investigation Relationships table filtered by
  that Entity. No second Back stack or `history.back()` mechanism exists.

## GEOINT

Geographic investigation is one first-class Investigation capability. It
exposes exactly two URL-owned presentation sub-views, `MAP` and `TABLE`:
`/investigations/:id/geoint` deterministically enters `MAP`, the legacy
`/investigations/:id/map` URL is a compatibility redirect to
`/geoint/map`, and `/investigations/:id/geoint/table` is the analytical
TABLE. Both sub-views stay Investigation-scoped, evidence-backed, bounded
and non-attributive; their cardinalities may differ because they project
the existing bounded IP-geolocation and canonical GEOINT datasets
without silently unifying them.

### MAP

Use Leaflet over the bounded current IP-geolocation projection.

Show approximate geolocation for relevant IP entities.

Display city/region/country/coordinates when available and source/precision.

Always include a clear qualification equivalent to:

> Approximate IP geolocation; this does not identify the physical location of an attacker or device.

Map markers link back to entity/evidence details, and the always-available
non-map list keeps coordinate-less records inspectable with their exact
`evidence_id` provenance. The MAP presentation never scans generic Evidence
pages and never substitutes an Evidence-list lookup for the geolocation
projection.

### TABLE

Show the bounded PR 26D canonical geographic summary for the Investigation: entities with geographic context, observations, canonical Locations, type/precision counts and top Locations, with the persistent semantic disclaimer that shared or nearby locations do not establish a cyber relationship, ownership, coordination, targeting, or attribution.

TABLE is the non-map analytical presentation: it owns the bounded summary,
the Top Locations neutral table and the typed `Explore` actions, and it
never embeds a second Leaflet map. Entities show Investigation-relative
current context and pageable immutable observation history; Locations
expose scoped Entities/observations with the exact/contained controller
(server-owned containment, `containment_applied` rendered honestly). Every
observation reaches its exact Evidence through the returned `evidence_id`;
geographic exploration uses PR 31F-8 canonical Investigation-scoped routes
(`/geoint/entities/:entityId`,
`/geoint/locations/:locationId/entities|observations`, exact Evidence and
observation routes) — the former encoded PivotWorkspace host is retired.

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
