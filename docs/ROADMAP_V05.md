# ATI — v0.5 Roadmap

> **Planning status — PROPOSED TARGET / PR 31 SERIES**
>
> This document is authoritative for the planned ATI v0.5 graph-exploration
> series. The PR 30 evaluation series is preserved in `ROADMAP_V04.md`.

## Purpose

ATI v0.5 adds an interactive, Maltego-like graph-exploration experience over
ATI's existing authoritative relational knowledge model. The series does not
introduce a graph database. `Entity` and `Relationship` remain the canonical
graph topology, while `RelationshipObservation` remains the temporal and
evidentiary record explaining when and why a relationship is known.

The graph is a read and interaction surface over ATI's existing evidence-backed
model:

```text
Entity ───── Relationship ─────► Entity
                 │
                 ▼
       RelationshipObservation
                 │
                 ▼
              Evidence
```

The initial implementation uses ordinary PostgreSQL joins for one-hop
exploration and bounded recursive CTEs for multi-hop/path operations. Apache
AGE or another graph persistence technology is explicitly not required by this
series and should only be reconsidered if measured graph-query or graph-analytics
requirements justify the additional persistence dependency.

## Series decomposition

| PR | Scope | Principal result |
|---|---|---|
| **31A** | Graph read model and repository contract | Stable frontend-independent graph-query boundary over existing ATI domain identities [DONE] |
| **31B** | PostgreSQL one-hop graph queries | Efficient incoming/outgoing neighborhood reads with relationship observation summaries |
| **31C** | Graph API | REST surface for graph neighborhoods and relationship detail |
| **31D** | Basic interactive graph UI | First Maltego-like visualization with pan/zoom/layout, Functional node dragging, and node/edge selection over the canonical graph API [DONE] |
| **31E** | Interactive graph expansion | Analyst-driven expansion of already-known graph relationships via the same one-hop endpoint, canonical client merge, PivotMenu local actions [DONE] |
| **31F** | Evidence drill-down | Relationship -> observation -> evidence navigation from the graph [DONE] |
| **31G** | Filtering and investigation context | Manage larger graphs without confusing global knowledge with investigation provenance |
| **31H** | Bounded multi-hop traversal | Depth-limited recursive exploration using PostgreSQL recursive CTEs |
| **31I** | Path finding | Bounded connection discovery between analyst-selected entities |
| **31J** | Temporal graph exploration | Explore topology through RelationshipObservation time semantics |
| **31K** | Graph-driven investigation actions | Launch ATI research/investigation actions directly from graph entities |
| **31F-1** | UI correctness and human-readable analyst presentation | Analyst-facing i18n labels before raw codes on Timeline/relationship surfaces [DONE] |
| **31F-2** | Investigation failure diagnostics | Bounded, sanitized root-cause `error_message` on failure Timeline events, fatal-stop propagation, safe detail presentation [DONE] |
| **31F-4** | Appearance preferences and multi-theme analyst workbench | Browser-local Light/Dark/Wargames/Control Room appearances over centralized semantic MUI tokens; presentation only [DONE] |
| **31F-5** | Investigation workspace UX correctness and human-readable analyst presentation | Shared detail/pivot lifecycle focus hygiene, topmost-only nested Escape, Overview/Report separation, human-readable Entity and support references, bounded support presentation resolver, date/time label shrink, Firefox + Chromium overlay journeys [DONE] |
| **31F-6** | Conservative in-flow analyst resource list/detail + in-flow URL-backed Pivot workbench | Ordinary AnalystTable resources use list/detail alternative views; the Pivot workbench is ordinary in-flow content with inline Pivot actions and cross-browser physical-pointer coverage (acceptance-qualified, see PR report) [DONE] |

## PR 31A — Graph read model and repository contract [DONE]

Define the application-facing graph contract without changing ATI persistence.
Introduce stable graph node, edge, and graph-result types whose identities map
directly to canonical `Entity` and `Relationship` records. A rendered edge
represents one canonical Relationship, not one RelationshipObservation.

Introduce a graph-query repository abstraction with one-hop neighborhood
semantics, direction, and optional relationship-type filtering. Keep the
contract independent of FastAPI and any frontend graph library. Preserve ATI's
stored-function persistence boundary and do not introduce Cypher, Apache AGE,
or a second graph-specific source of truth.

PR 31A establishes the architectural rule for the whole series: ATI's
relational model remains authoritative and graph exploration is a read-side
projection of that model.

## PR 31B — PostgreSQL one-hop graph queries [DONE]

Implement the PR 31A graph read contract against PostgreSQL using the
existing analyst-facing direct SQLAlchemy query-service architecture (not
stored functions; the pre-v0.5 roadmap wording is stale relative to
current-main analyst read queries) and the existing `Entity`,
`Relationship`, and `RelationshipObservation` model, plus the exact
`InvestigationEvidence` / `EvidenceObservationEntity` admission primitives.
Support incoming, outgoing, and bidirectional one-hop neighborhoods plus
relationship-type filtering.

Edges carry Investigation-scoped observation summaries, including
observation count and first/last observed timestamps where semantically
valid. Focal Entity visibility, edge visibility, and edge observation
summaries all derive from exact InvestigationEvidence admission. Existing
indexes cover the SOURCE/TARGET adjacency, entity-association, and admission
access paths; no schema migration was required.

This PR provides the efficient primitive used by interactive expansion; it
does not yet add recursive traversal or a UI.

## PR 31C — Graph API [DONE]

Expose the graph read model through a frontend-independent FastAPI surface.
Delivered: an Entity-neighborhood endpoint
(`GET /api/v1/investigations/{investigation_id}/graph/entities/{entity_id}/neighborhood`)
with direction and relationship-type filters plus a bounded limit.

Relationship detail for later evidence drill-down already exists on main
(`GET /relationships/{relationship_id}` and the `relationship_id`-filtered
RelationshipObservation listing), so PR 31C reuses those endpoints rather
than adding a duplicate graph Relationship resource; graph edge
`relationship_id` values resolve through them.

Wire DTOs are explicit and versionable. Database rows, recursive SQL
concepts, and Cytoscape/Sigma/React Flow-specific structures never cross
the application contract.

## PR 31D — Basic interactive graph UI [DONE]

PR 24E supplied an earlier Relations-page-backed interactive graph
(`RelationshipGraph` over `@xyflow/react`, see `docs/ARCHITECTURE.md`);
31D migrated and completed that surface over the canonical v0.5 graph API
instead of creating a second graph screen.

The Graph view is now a faithful, read-only client of the PR 31C endpoint
(`GET /api/v1/investigations/{investigation_id}/graph/entities/{entity_id}/neighborhood`):

- one bounded ``GraphNeighborhoodResponse`` is the sole topology payload;
  the Relationships page never feeds the canvas;
- nodes carry exact server Entity metadata (``entity_id``, ``entity_type``,
  ``value``, ``display_name``) with entity-type differentiation that is never
  color-only;
- one ``GraphEdgeResponse`` is one rendered edge with its exact observation
  summary (count, first/last observed; null values stay unavailable and are
  never substituted with retrieval times);
- pan, zoom, fit-to-screen, node/edge selection, Relationship labels, and the
  accessible non-spatial edge list are preserved;
- node dragging is functional through React Flow's controlled change path,
  stays browser-local, and is never persisted;
- the API ``truncated`` flag drives the bounded-neighborhood notice; an
  isolated focal Entity renders as a successful focal-only graph;
- graph failures offer Retry without any Relationships-list fallback;
- direction, relationship type and limit map onto the canonical query;
  Evolution-only filters never reach the graph endpoint;
- expansion (PR 31E), Evidence drill-down (PR 31F), provider/acquisition
  behavior, saved layouts, and graph persistence remain out of scope.

Canonical Entity/Relationship IDs remain authoritative; React Flow node/edge
IDs, coordinates, selection, and drag positions are browser-only presentation
state.

## PR 31E — Interactive graph expansion [DONE]

Turn the visualization into an exploration tool. Allow an analyst to
select an Entity in the existing Pivot menu and expand by known,
outgoing, or incoming one-hop relationships. Each expansion requests an
incremental one-hop neighborhood through the same PR 31C graph endpoint
and merges the returned nodes and edges into the current client-side
graph by canonical Entity/Relationship IDs without duplicating canonical
identities, replacing stale duplicate field values, and preserving the
original focal Entity and existing (dragged) node positions.

Expansion means "show more of ATI's already-known graph"; it does not
perform provider acquisition or start a new investigation. The expansion
actions are explicit local/context commands hosted by the existing
Pivot menu — never PivotSteps, never URL-serialized, never blocked by
Pivot depth — while URL-backed navigation pivots keep their exact
semantics. Deterministic merge/selection behavior is preserved, one
request runs per explicit action with the existing neighborhood limit,
and failures/truncation are surfaced honestly without falling back to
Relationships APIs.

## PR 31F — Relationship observation and Evidence drill-down [DONE]

Connect graph topology to ATI's evidence-backed semantics. From a selected
Relationship (``GraphEdge.relationship_id``), the analyst inspects the
Investigation-scoped Relationship, browses one bounded page of immutable
`RelationshipObservation` records supporting it, selects an exact
observation (`RelationshipObservation.id`), and navigates from that
observation to the exact Evidence/EvidenceObservation provenance
(`observation.evidence_id`) already maintained by ATI.

Reuse existing Evidence APIs and presentation capabilities rather than
inventing a parallel evidence representation. The graph answers not only
"what is connected?" but also "why does ATI believe this relationship
exists, when was it observed, and what evidence supports it?" without
adding backend or API changes.

PR 31F is the first complete investigation-grade graph-exploration
milestone.

## PR 31G — Graph filtering and investigation context

Add controls needed to work with larger graphs: Entity type, Relationship type,
datasource/provenance where supported, and observation-time filters.

Define and expose investigation context explicitly. ATI's canonical Entities,
Relationships, Evidence, and observations are global, while an Investigation
records a particular investigative trajectory/admission context. The graph UI
must not imply that every globally known relationship displayed around an
investigation was discovered by that investigation.

Provide clear semantics for investigation-scoped versus broader known-graph
views without duplicating or weakening the global evidence model.

## PR 31H — Bounded multi-hop traversal

Add server-side depth-limited neighborhood traversal using PostgreSQL recursive
CTEs over the canonical Relationship topology. Support a small, explicit
maximum depth, cycle prevention, deterministic result semantics, and hard
resource/result limits.

Benchmark representative ATI graph sizes and access patterns. Multi-hop
traversal is an exploration convenience, not permission for unbounded
whole-graph queries. Preserve one-hop incremental expansion as the normal
interactive path.

## PR 31I — Bounded path finding

Allow an analyst to select two Entities and ask ATI to find bounded connection
paths between them. Implement path discovery with recursive CTEs, explicit
cycle avoidance, maximum depth, maximum returned paths, deterministic ordering,
and resource limits.

Return paths in the same canonical graph DTO vocabulary used elsewhere so the
UI can highlight or isolate connections without creating another graph model.
This PR intentionally stops short of general graph analytics, community
detection, centrality, or arbitrary pattern-query infrastructure.

## PR 31J — Temporal graph exploration

Use `RelationshipObservation` to make the graph temporally explorable. Allow
the analyst to constrain displayed relationships by observation interval and
inspect how observed topology changes over time while preserving ATI's
distinction between `observed_at` and `retrieved_at`.

Integrate with the planned Temporal Relationship View rather than creating
competing temporal semantics. Do not infer unsupported relationship start/end
lifetimes from observation gaps: the UI describes what ATI observed, not an
unproven continuous existence interval.

## PR 31K — Graph-driven investigation actions

Connect graph exploration to ATI's existing agentic research machinery. From a
selected Entity, allow an analyst to initiate an investigation/research action
using the existing Coordinator, ResearchRequest/ProviderWork planning, and
datasource architecture.

Do not introduce a separate Maltego-style "Transform" subsystem. Graph actions
are another entry point into ATI's existing investigation capabilities.
New Evidence, Entities, Relationships, and observations produced by the action
flow through the normal authoritative persistence path and can then be
reflected back into the graph.

This closes the series by making the graph both an evidence-exploration surface
and an analyst-controlled entry point into ATI's agentic investigation loop.

## Milestones

```text
PR 31A–31C
Graph infrastructure
        │
        ▼
PR 31D–31F
Maltego-like evidence-backed exploration
        │
        ▼
PR 31G–31K
Investigation-grade graph analysis and actions
```

## Architectural boundaries to preserve

- PostgreSQL relational persistence remains authoritative for ATI v0.5.
- `Entity` and `Relationship` define graph topology; a
  `RelationshipObservation` is provenance/temporal evidence, not a duplicate
  rendered edge.
- Apache AGE, Neo4j, Cypher, and other graph-database dependencies are outside
  the PR 31 series.
- Graph DTOs and APIs remain independent of the selected frontend graph
  library.
- Multi-hop and path queries are bounded, cycle-safe, resource-limited, and
  implemented behind ATI's repository/stored-function boundaries.
- Graph views never weaken ATI's evidence/provenance model or conflate global
  knowledge with Investigation-specific provenance.
- Temporal views preserve `observed_at` versus `retrieved_at` and never
  manufacture unsupported relationship-ended semantics.
- Graph-triggered acquisition reuses existing Coordinator/provider/research
  abstractions rather than establishing a second orchestration system.

## Non-goals for the PR 31 series

The PR 31 series does not migrate ATI to a graph database, introduce a second
authoritative graph representation, implement unrestricted graph-query
languages, provide general-purpose graph analytics, infer relationship
lifetimes from observation gaps, or duplicate ATI's existing Evidence,
datasource, Coordinator, or Research Agent architecture.

A graph database can be reconsidered later if concrete measured requirements
such as large-scale arbitrary pattern matching, community detection, centrality
analysis, or path workloads prove materially awkward or inefficient with the
relational model.

## PR 31F-2 — Investigation failure diagnostics [DONE]

Follow-on to the PR 31F Evidence drill-down and the PR 31F-1 human-readable
presentation work. Delivers safe analyst-facing diagnostics for failed
investigations.

Final scope:

- adds a bounded (4096 char) nullable `error_message` to the append-only
  investigation Timeline domain, migration `0034` (+ SQL API `v0029`),
  repository/query mappings, the public Timeline DTO, and the generated
  frontend schema — on failure-bearing event shapes only
  (`PROVIDER_WORK_FAILED`, mixed partial `PROVIDER_WORK_COMPLETED` with a
  retained `error_code`, and `INVESTIGATION_STOPPED` with
  `reason_code == fatal_error`);
- centralizes ATI-owned root-cause traversal
  (`app/error_messages.py`): explicit `__cause__` first, applicable
  unsuppressed `__context__`, `from None` suppression, cycle/depth
  defense;
- centralizes deterministic secret/control-character redaction and
  truncation (before persistence), with independent unit tests;
- threads the sanitizer through the existing orchestration composition so
  every graph fatal catch keeps its stable `error_code` while persisting
  the sanitized root-cause diagnostic through the existing
  `FatalStopService`;
- exposes the stable fatal code and sanitized message on the final
  `INVESTIGATION_STOPPED` Timeline event and renders it as plain text in
  the existing Timeline event-detail drawer;
- preserves invariants: Timeline append-only/order/cursor/isolation
  unchanged; persistence failures and cancellation propagate as before;
  no tracebacks, raw provider payloads, prompts, hidden reasoning, or
  unsanitized secrets are persisted; environment variables remain the
  ultimate configuration override.

Provider work failures intentionally remain code-only (the provider
boundary retains no safe free-form message); `error_message` for provider
failure events therefore stays `NULL` and provider-wide redesign is out of
scope. The standard fake-world investigation completes successfully, so no
real-browser fatal E2E was manufactured; the fatal path is proven by the
deterministic integration vertical slice and component tests.

## PR 31F-4 — Appearance preferences and multi-theme analyst workbench [DONE]

A deliberately bounded browser-local appearance preference evolves ATI's
single MUI theme into a centralized semantic multi-theme system. Initial
appearances: Light (default), Dark, Wargames, Control Room.

Final scope:

- a finite typed frontend model (`AppearancePreference`: exactly
  `light` / `dark` / `wargames` / `control-room`; Light canonical default;
  runtime validation; stable ATI storage key `ati.appearance`);
- a safe localStorage adapter reading during provider initialization
  (no first-render flash) and falling back to Light on absent/unknown/
  corrupt/throwing storage; writes touch only the ATI appearance key and
  never call `clear()`;
- a centralized theme factory/registry (`frontend/src/app/theme.ts`) that
  prebuilds the four stable themes once, with a typed semantic-token
  contract (`theme.ati`) carried through MUI module augmentation
  (`surface/text/accent/border/selection/status/graph/map/focus`);
- one `AppearanceProvider` feeding the existing single MUI `ThemeProvider`
  + `CssBaseline` (`AppProviders`), preserving one stable QueryClient;
- a Preferences gear beside the authenticated user controls opening a
  modal MUI Dialog: four human-readable choices, live preview, Save
  persisting locally, Cancel/Escape restoring the committed appearance,
  focus trapped and restored by the Dialog itself;
- React Flow graph integration via the same semantic tokens: ATI-owned
  canvas/node/edge/selection/controls styling only — topology, positions,
  expansions, selection, provenance and requests are untouched, and
  switching appearance never causes a graph refetch;
- Leaflet integration theming only ATI-owned container/chrome/overlay
  surfaces; `TILE_URL`, OSM attribution, coordinates and markers are
  unchanged;
- focus-visible and status surfaces consume semantic tokens in every
  theme (keyboard focus and non-color status semantics retained);
- all Preferences/theme strings go through i18next (`shell` namespace);
- docs: `ARCHITECTURE.md` frontend presentation note, `TESTING.md`
  Playwright worker/resource-control guidance, this roadmap entry;
- Playwright remains `workers: 1` with controlled `npx playwright test
  --workers=1` local runs.

Presentation only: no backend preference model, no database migration, no
API/OpenAPI change, no authorization/Investigation/Tenant change, and
environment-variable configuration precedence is untouched.

**PR 31F-3 status.** The previously discussed Timeline performance
hardening is not an active prerequisite for 31F-4: the observed Firefox
slowdown during manual testing was traced to excessive concurrent Firefox
instances saturating the host CPU, not an established ATI Timeline defect.
Reopen performance work only after a controlled single-browser/one-worker
reproduction shows ATI-specific excessive resource use.

## PR 31F-5 — Investigation workspace UX correctness and human-readable analyst presentation [DONE]

Corrective work on fresh main after 31F-4 (no PR 31G scope). Final scope:

- **Browser lifecycle (A).** The shared DetailDrawer and PivotWorkspace
  close controls use deterministic deferred focus (never browser
  `autoFocus` inside the mount commit) and every close path drops active
  focus before the URL navigation unmounts the control; the shared
  PivotMenu keeps its non-modal Portal and focus-safe navigation. No
  forced reload, browser branch, arbitrary delay, or MUI modal chain was
  introduced, and Playwright stays `workers: 1`.
- **Nested Evidence detail (B).** X, Escape and backdrop each close only
  the nested drawer inside the PivotWorkspace (topmost-only Escape:
  `stopPropagation` on the drawer and the action menu), never the
  workspace; filters/cursors/breadcrumbs and post-close table interaction
  are preserved, with the URL-backed pivot step `selected` removed by
  serialization.
- **Overview vs Report (C).** The Overview is a concise dashboard in the
  exact section order (lifecycle, analytical outcome, executive summary,
  at-a-glance loaded-array counts, first 3 findings, first 3 next steps,
  navigation/action row) and never renders the full `ReportContent`; the
  full Report stays complete on its route.
- **Entity presentation (D).** Shared no-fetch `EntityReference`
  (value primary + translated type adjacent + optional technical ID);
  the Evidence Subject cell, the Relationship source/target cells and
  detail, and the Relationship CSV show value/type before UUIDs without a
  frontend N+1 (the Relationship read projection now joins endpoint
  Entities through the bounded query/API).
- **Support presentation (E).** One bounded Investigation-scoped batch
  resolver
  (`POST /api/v1/investigations/{id}/support-presentations/resolve`,
  set-oriented SQL, exact observation identity, cross-Investigation
  fail-closed, per-kind request cap, projections only) feeds semantic
  Finding support lines on the Overview and the full Report; IDs stay
  secondary and actions stay exact.
- **Date/time labels (F).** All native `datetime-local` fields use the
  supported MUI shrink slot (`slotProps={{ inputLabel: { shrink: true } }}`);
  no CSS offsets, filter/interval semantics unchanged.

Threading: URL remains authoritative for filters/cursor/selection/pivot
stack; no second drawer/pivot store; no reload/delay/browser branch; no
LLM labels or Overview; no migration; no orchestration/provider change;
no new analytical artifact; no weakening of QA gates.

**Acceptance criteria.** Delivered only after backend `--qa`
(unit + integration), frontend unit + lint, OpenAPI drift check, and the
Firefox + Chromium overlay journeys (zz-pivots, zz-analyst-tables)
pass with one Playwright worker.

## PR 31F-6 — Conservative in-flow resource list/detail + Pivot workbench

PR 31F-5 hardened the shared `DetailDrawer`, but manual Firefox
verification on fresh main still reproduced the browser
freeze/inability-to-close defect, and the failure was not
Evidence-specific. PR 31F-6 replaced the overlay resource-detail drawers
(and the interim side-Inspector) with a conservative in-flow **resource
list/detail** model, and (amendment 5) replaced the fixed PivotWorkspace
overlay with an ordinary in-flow **URL-backed Pivot workbench** — a
presentation change only. Existing URL/Pivot selection remains
authoritative; exact detail reads and Pivot domain semantics are
unchanged.

Final scope:

- **List/detail (A4).** Ordinary AnalystTable resources use ALTERNATIVE
  full-width in-flow views: `View` renders the exact scoped detail as
  the main content (`ResourceDetailView`: semantic Back +
  human-readable heading), and Back restores the bounded list context
  (filters/order/cursor untouched). `selected=<uuid>` remains the sole
  selection authority; no side Inspector, Portal, modal/drawer/backdrop,
  focus trap, body masking, or second selection state exists.
- **Pivot workbench (A5).** When the bounded `pivot` URL stack is
  non-empty the route owner renders the in-flow Pivot workbench as the
  PRIMARY content (never together with the normal Investigation
  workbench): breadcrumbs + semantic Close + the active step's resource
  list OR detail. No durable `pivotOpen` state; the Pivot model, stack,
  `MAX_PIVOT_STEPS`, URL serialization, capability registry, push/
  truncate/close, breadcrumbs, Back/Forward and no-op suppression are
  unchanged. The already-proven next-macrotask navigation boundaries are
  preserved.
- **Migration (C).** Evidence, Relationships, Relationship Observations,
  Research, History, Timeline, Relationship Evolution, GEOINT and the
  Geolocation Map's exact Evidence all use the shared list/detail model;
  resource steps inside the Pivot workbench use the same model.
  `ResourceInspector`, `ResourceInspectorLayout`, `DetailDrawer`,
  `GeointDetailDrawer` and the fixed-overlay PivotWorkspace are retired.
- **Regressions (D).** Raw-pointer acceptance journeys run first-attempt
  with `--retries=0` in Chromium AND Firefox (`zz-pointer-acceptance`,
  `zz-pivot-acceptance`, `zz-list-detail` plus the scoped
  `inspector-firefox` Playwright project): geometry-proved raw
  interactions, >= 5 same-page cycles per engine, no synthetic click,
  no reload, no retry dependence. Playwright stays `workers: 1`.

Threading: selection stays in `table.selection/openSelection/
closeSelection` and the Pivot state port; no second selected-resource
state, no new routing/query parameter; PivotWorkspace navigation
architecture (stack/URL/capabilities) unchanged; no
backend/schema/persistence/graph change.

**Status.** Implemented on `dev/new-ui-layout`; the A5 former-wedge
checkpoint and the A4/A5 raw-pointer acceptance journeys pass first
attempt (retries=0) in Chromium and Firefox, static/component gates pass
(671/671), and the full broader-suite E2E classification is recorded in
`out/PR31F6_A6_IMPLEMENTATION_REPORT.md` (amendment 6): the reported
E20/E22/E23 items were corrected as stale-contract (C3) with deterministic
coverage, the E24-E27 map/geolocation assertion bug from the A4-era
spec migration was fixed (C1), the GEOINT-seeding and appearance-preview
failures were classified C2 (pre-existing; PR31F-6 has zero
backend/DB/theme diffs) with follow-ups, and the intermittent raw-input
misses remain the documented C5 environment class (never a deterministic
product failure; the critical raw-pointer authority passes in both
engines). [DONE]
manual Firefox verification matrix in `docs/TESTING.md`.
