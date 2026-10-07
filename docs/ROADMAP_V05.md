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
| **31G** | Filtering and investigation context | Manage larger graphs without confusing global knowledge with investigation provenance [DONE] |
| **31H** | Bounded multi-hop traversal | Depth-limited recursive exploration using PostgreSQL recursive CTEs |
| **31I** | Path finding | Bounded connection discovery between analyst-selected entities [DONE] |
| **31J** | Temporal graph exploration | Explore topology through RelationshipObservation time semantics |
| **31K** | Graph-driven investigation actions | Launch ATI research/investigation actions directly from graph entities |
| **31F-1** | UI correctness and human-readable analyst presentation | Analyst-facing i18n labels before raw codes on Timeline/relationship surfaces [DONE] |
| **31F-2** | Investigation failure diagnostics | Bounded, sanitized root-cause `error_message` on failure Timeline events, fatal-stop propagation, safe detail presentation [DONE] |
| **31F-4** | Appearance preferences and multi-theme analyst workbench | Browser-local Light/Dark/Wargames/Control Room appearances over centralized semantic MUI tokens; presentation only [DONE] |
| **31F-5** | Investigation workspace UX correctness and human-readable analyst presentation | Shared detail/pivot lifecycle focus hygiene, topmost-only nested Escape, Overview/Report separation, human-readable Entity and support references, bounded support presentation resolver, date/time label shrink, Firefox + Chromium overlay journeys [DONE] |
| **31F-6** | Conservative in-flow analyst resource list/detail + in-flow URL-backed Pivot workbench | Ordinary AnalystTable resources use list/detail alternative views; the Pivot workbench is ordinary in-flow content with inline Pivot actions and cross-browser physical-pointer coverage (acceptance-qualified, see PR report) [DONE] |
| **31F-7** | Non-overlay More navigation and reliable appearance preview | The investigation Workspace More control becomes an ordinary in-flow secondary-navigation disclosure (no Portal/menu overlay class); the generic appearance live-preview lifecycle is proven for every supported appearance (preview-before-Save, Cancel restore, Save/reload persistence, route/graph untouched) [DONE] |

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

## PR 31G — Graph filtering and investigation context [DONE]

Add controls needed to work with larger graphs: Entity type, Relationship type,
datasource/provenance where supported, and observation-time filters.

Define and expose investigation context explicitly. ATI's canonical Entities,
Relationships, Evidence, and observations are global, while an Investigation
records a particular investigative trajectory/admission context. The graph UI
must not imply that every globally known relationship displayed around an
investigation was discovered by that investigation.

Provide clear semantics for investigation-scoped versus broader known-graph
views without duplicating or weakening the global evidence model.

Delivered (PR 31G):

- Two explicit graph scopes: ``investigation`` (default; a Relationship is
  visible only when a supporting RelationshipObservation's exact
  EvidenceObservation is admitted to the Investigation) and ``known``
  (globally known live one-hop Relationships around an Investigation-visible
  focal Entity). Omitted scope preserves current-main behavior.
- Known scope never becomes arbitrary global Entity lookup: the focal Entity
  must still be admitted to the Investigation through an exact
  EvidenceObservation.
- Per-edge backend-computed ``investigation_observation_count`` (set-wise
  conditional aggregate; never a row-multiplying admission join) so globally
  known topology is never presented as Investigation-discovered topology.
- Bounded server-side filters applied before aggregation/bounding: connected
  (counterparty) Entity type, canonical Relationship type,
  ``RelationshipObservation.source`` exact match, and half-open
  ``observed_at`` interval (never ``retrieved_at``).
- Identical scope/filter context for root reads and every explicit one-hop
  expansion; a scope/filter change aborts stale expansion and resets
  accumulated graph state.
- URL-backed graph context (``graph_scope`` / ``graph_entity_type`` /
  ``graph_relationship_type`` / ``graph_source`` / ``graph_observed_from`` /
  ``graph_observed_to``) reconstructing refresh and Back/Forward, with an
  explicit draft/Apply/Clear pattern.
- No graph database, multi-hop traversal, path finding, relationship-lifetime
  inference, provider/Coordinator/Research execution, or graph mutation.
  PR31H owns multi-hop, PR31I path finding, PR31J temporal exploration.

## PR 31H — Bounded multi-hop traversal

Add server-side depth-limited neighborhood traversal using PostgreSQL recursive
CTEs over the canonical Relationship topology. Support a small, explicit
maximum depth, cycle prevention, deterministic result semantics, and hard
resource/result limits.

Delivered:

- `GraphTraversalQuery` (the exact PR 31G graph context plus an explicit
  1..3 hop depth) and `GraphQueryService.traverse()` returning the existing
  `GraphResult` vocabulary;
- the entire traversal is implemented inside the versioned stored function
  `ati.traverse_graph` (migration `0035_graph_traversal`): focal visibility,
  PR 31G eligible-observation/scope/source/time/type filters before
  recursion, direction and connected Entity type at every frontier,
  Entity-path cycle prevention (self-loops returned once, never recursing),
  minimum-hop-depth derivation, canonical deduplication, set-wise support
  aggregation, endpoint Entity projection, deterministic
  `(minimum_hop_depth, id)` ordering, and bounded distinct Relationship
  results with truthful `truncated`. `PostgresGraphQueryService.traverse()`
  is an invocation/mapping boundary only — no traversal SQL lives in
  Python;
- depth-1 traversal is proven equivalent to the one-hop neighborhood under
  the same context; cycle/diamond/self-loop/scope/filter/deletion/
  truncation/determinism vertical slices pass against real PostgreSQL;
  representative `EXPLAIN (ANALYZE, BUFFERS)` evidence shows the existing PR
  31B adjacency/admission index families serve the recursive plan (no new
  index migration is introduced);
- a dedicated GET `.../entities/{entity_id}/traversal` endpoint reuses the
  existing `GraphNeighborhoodResponse` wire vocabulary (default depth 2;
  `/neighborhood` stays one-hop and backward-compatible; OpenAPI + generated
  TypeScript synchronized);
- URL-backed `graph_depth` committed state (absent/invalid = depth 1,
  depth 1 serializes as absent), a bounded depth selector in the graph
  draft with no request before Apply, TanStack Query ownership with distinct
  traversal/neighborhood keys (no cross-depth cache or race), traversal
  root + explicit one-hop expansion with reset on committed depth change,
  existing `RelationshipGraph` with deterministic minimum-distance rings,
  and a Chromium+Firefox directed journey + 20-cycle same-page stress;
- multi-hop is an exploration convenience: one-hop incremental expansion
  remains the normal interactive path, and path finding remains PR 31I. [DONE]

Benchmark representative ATI graph sizes and access patterns. Multi-hop
traversal is an exploration convenience, not permission for unbounded
whole-graph queries. Preserve one-hop incremental expansion as the normal
interactive path.

## PR 31I — Bounded path finding [DONE]

Allow an analyst to select two Entities and ask ATI to find bounded connection
paths between them. Implement path discovery with recursive CTEs, explicit
cycle avoidance, maximum depth, maximum returned paths, deterministic ordering,
and resource limits. [DONE]

Return paths in the same canonical graph DTO vocabulary used elsewhere so the
UI can highlight or isolate connections without creating another graph model.
This PR intentionally stops short of general graph analytics, community
detection, centrality, or arbitrary pattern-query infrastructure.

Delivered (PR 31I): one versioned ``ati.find_graph_paths`` stored function
with endpoint Investigation visibility, PR 31G scope/filter semantics,
Entity-path cycle-safe recursive simple-path search, entity-sequence
deduplication, deterministic shortest-first ordering with a canonical path
signature, a ``max_paths + 1`` truthful truncation probe and canonical graph
closure; an explicit metadata row distinguishes endpoint-invalid (`None` /
scoped 404) from visible-but-unconnected (200 with empty `paths` and the two
visible endpoint nodes); bounded depth 1..6 (default 4) and path count 1..25
(default 10); source==target returns exactly one zero-hop path; paths reuse
``GraphNode`` / ``GraphEdge`` plus reference-only ordered paths. The legacy
direct-SQLAlchemy one-hop ``neighborhood`` read was consolidated onto
``ati.traverse_graph(..., max_depth = 1)`` with real-PostgreSQL parity
coverage, so every graph read now lives behind versioned stored functions.
The analyst-facing path mode (two canonical Entity selections from the graph,
explicit Find, deterministic path selector and highlight, no-connection and
truncation states, ordinary-graph restoration) was added to the routed Graph
workbench. No graph database, persisted path model, path caching,
graph-query language, graph analytics, temporal playback, or graph-driven
action is pulled into PR 31I.

## PR 31J — Temporal graph exploration [DONE]

> **Superseded by PR 38-8.** The frame model described below is historical.
> Current temporal graph exploration uses one direct observed-time range
> (required start/end dates with optional times normalizing to local
> midnight); it has no frame count, frame index, or Previous/Next
> navigation. The graph `observed_from`/`observed_to` half-open contract is
> unchanged. See `docs/TESTING.md` and
> `frontend/e2e/zz-38-8-temporal-range.spec.ts`.

Delivers bounded temporal exploration of the existing entity-centric Graph
workspace using `RelationshipObservation.observed_at` only.

Final scope:

- adds a pure frontend temporal frame model + URL codec
  (`frontend/src/relationship-graph/graph-temporal.ts`): committed tuple
  (`graph_temporal`, `graph_time_start`, `graph_time_end`, `graph_time_frames`
  `4|8|12|24` default 8, `graph_time_frame`), deterministic exact-epoch-ms
  partitioning into half-open `[from, to)` frames, Previous/Next clamped
  navigation, fail-closed malformed-value parsing, and effective
  observed-bound derivation; the URL is the sole committed temporal authority
  (refresh and Back/Forward reconstruct the same frame);
- integrates the tuple into `RelationshipEvolutionWorkspace`: one effective
  `GraphContext` derives the active frame's bounds and is passed consistently
  to the existing neighborhood/traversal/expansion/path hooks, so the active
  frame constrains root topology, multi-hop traversal, explicit expansion and
  path finding through the existing graph `observed_from`/`observed_to`
  contract — no backend endpoint, DTO, stored function, migration, or
  index change; frame identity participates in graph-context/key/reset
  semantics so a frame transition deterministically resets stale expansion
  and path state;
- adds the presentation-only `GraphTemporalControls` (draft range/frame
  count, validated atomic Apply starting at frame 1, Disable, Previous/Next,
  observational frame-status banner, observation-specific empty-frame
  wording) and localizes every new string in the `relationshipEvolution`
  resource;
- preserves invariants: temporal mode is frontend framing only, never
  lifetime/start/end inference, never wall-clock, never a second durable
  temporal store; temporal-off behavior matches PR 31G/31H/31I exactly;
  unrelated URL parameters survive Apply/Prev/Next/Disable.

Acceptance (all executed through `scripts/e2e.sh`, workers=1, retries=0):
Chromium and Firefox directed journeys + 20-cycle temporal stress
(`zz-31j-temporal-graph.spec.ts`) green in both engines; existing
31F8/31G/31H/31I graph regression journeys re-run green in both engines;
full frontend quality gates (Vitest 757 tests, tsc, eslint) green.

## PR 31K — Graph-driven investigation actions [DONE]

Closes the PR 31 graph series by making a selected canonical graph Entity an
analyst-controlled entry point into ATI's **existing** durable Investigation
loop. No Maltego-style Transform subsystem, graph-specific provider,
graph-specific persistence, or second orchestration engine was introduced;
the graph remains an exploration/selection surface only.

Final scope:

- adds a bounded graph-action model (`frontend/src/relationship-graph/graph-actions.ts`):
  the action target is always a canonical persisted Entity ID (authoritative),
  with exact canonical type/value as presentation metadata only; a neutral
  prefilled objective (`Investigate <type> <value>`) and objective/value
  validation reuse the exact create-Investigation bounds;
- adds the in-flow, non-modal `GraphActionPanel` (`frontend/src/relationship-graph/GraphActionPanel.tsx`):
  human-readable Entity type/value, canonical ID, editable objective,
  Start investigation / Cancel controls, pending state and typed failures;
  it reuses the existing `useCreateInvestigation` mutation + `apiRequest`/CSRF/
  `Idempotency-Key` semantics and the exact create-attempt uncertainty policy,
  so an accepted action navigates through the existing Investigation workflow
  and the durable worker/Coordinator execute all investigation work;
- integrates transient selected-Entity state into `RelationshipEvolutionWorkspace`:
  with path mode off, clicking a rendered node selects that canonical Entity
  for the action panel; entering path mode or any committed graph-context/
  temporal-frame transition deterministically clears the selection (PR 31I
  path-mode click precedence and PR 31J temporal framing are unchanged);
  selection is browser-local workbench state — never URL-backed, never
  persisted, never a global store;
- the graph never calls providers or the ResearchAgent directly, never mutates
  graph state optimistically, and never bolts the action onto the generic
  PivotMenu: the action routes the selected Entity through the existing
  `POST /api/v1/investigations` application command (reused exactly, no
  backend changes), so results use normal authoritative persistence/provenance
  and the new Investigation's graph reflects them through ordinary queries;
- localizes every new string in the `relationshipEvolution` resource and covers
  the boundary with deterministic unit/component tests (21 new Vitest tests:
  model, panel idempotency/pending/error semantics, workspace selection
  precedence/clearing, no optimistic data, no URL corruption).

Acceptance (all executed through `scripts/e2e.sh`, workers=1, retries=0):
Chromium and Firefox directed journeys + path-mode precedence + temporal
compatibility + duplicate-submission + 20-cycle action-selection stability
(`zz-31k-graph-actions.spec.ts`) green in both engines; existing
31F8/31G/31H/31I/31J graph regression journeys re-run green in both engines;
full frontend quality gates (Vitest 778 tests, tsc, eslint, api:check) green.

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

## PR 31F-7 — Non-overlay More navigation and reliable appearance preview [DONE]

Corrective UI follow-up owning the two remaining user-visible defects
raised during the PR 31F-6 closure (A6 follow-ups #1 and #3). Final
scope:

- **More (A).** The Investigation workspace `More` interaction was the
  last fixed-Portal MUI `Menu` in the analyst navigation path (A6 wedge
  record: idling with the Portal menu open stalled the browser main
  thread in Chromium AND Firefox). It is replaced by a conservative
  in-flow secondary-navigation disclosure: a plain trigger with
  `aria-expanded`/`aria-controls` expands an ordinary `nav` region in
  the workspace layout. No MUI Menu/Popover/Modal, no Portal, no
  backdrop/focus trap/body lock, no document-global dismissal listener,
  no ARIA `menu/menuitem` roles, and transient local open state only.
  The History destination (the only entry) is preserved verbatim as a
  semantic react-router link with exactly one navigation per activation;
  an explicit Close collapses the region. Keyboard behavior is native
  (Tab reaches trigger and entries, Enter/Space toggles, no trap).
- **Appearance (B).** The E30-A6 "Wargames preview does not apply after
  Save/reload/reopen" failure was diagnosed as an E2E assertion
  artifact: the MUI Preferences dialog is a genuine modal and correctly
  marks the rest of the page `aria-hidden` while open, so the old
  `getByRole("banner")` poll matched nothing during the in-dialog
  preview step. The product state flow (single provider over the stable
  prebuilt theme registry, committed + transient preview) was verified
  correct in real browsers for all four appearances; no appearance
  algorithm changed and no appearance-specific workaround exists. The
  E2E probes now resolve the rendered header surface through the AppBar
  element as DOM, and the appearance E2E covers every supported
  appearance on the same generic path: preview before Save, Cancel
  restores the committed appearance, Save persists across reload, reopen
  selects the committed value, and theme-only changes never alter the
  route or refetch graph topology.

**Status.** Implemented on `fix/pr31f-7` over the accepted PR 31F-6
baseline. The PR 31F-7 critical acceptance
(`frontend/e2e/zz-pr31f7-critical.spec.ts`) passes first attempt
(`--retries=0`, `workers=1`) in Chromium AND Firefox: five same-page raw
More -> History cycles per engine with heartbeat/geometry proofs and no
Portal/modal/body-lock, plus the four-appearance lifecycle journey per
engine. E20/E21 and `zz-list-detail` reach History through the in-flow
disclosure; the comprehensive graph/route/no-refetch appearance slice
passes in Chromium. Component suite, typecheck, ESLint and Vite build are
green; the full E2E classification is recorded in
`out/PR31F7_IMPLEMENTATION_REPORT.md`. GEOINT seeding and backend/DB work
remain outside this PR. [DONE]

## PR 31F-8 — Route-Oriented Investigation Resource Navigation

Corrective work on fresh main after PR 31F-7 (no PR 31G scope).

The generic URL-encoded `PivotWorkspace` resource host is replaced by
ordinary Investigation-scoped React Router navigation: every Pivot
capability resolves to one explicit routed content surface, the
Investigation shell stays mounted around a single active `<Outlet>`
resource, and the live nested list/detail/Pivot lifecycle implicated in
the deterministic Chromium/Firefox detached-DOM and native-pointer class
is removed from production navigation.

Final scope:

- **One exhaustive mapper (A).** `frontend/src/pivots/pivot-route.ts`
  (`pivotTargetToRoute`) translates every allowlisted `PivotResource`
  target to its canonical route with validated query filters; the map is
  exhaustive (a new resource without a case fails compilation), canonical
  IDs own path identity (labels are presentation only), and malformed
  targets fail closed without any navigation (R01..R14 unit matrix).
- **Capability activation is semantic navigation (B).** `PivotMenu`
  renders route-known actions as react-router links (direct action or the
  in-flow action bar); local/context commands remain buttons that never
  touch the URL. No encoded pivot stack mutation, depth accounting, or
  deferred-commit workaround remains.
- **Route-owned detail (C).** Exact scoped detail surfaces are dedicated
  routes: `/evidence/:evidenceId`, `/relationships/:relationshipId`,
  `/relationships/observations/:observationId` and
  `/geoint/observations/:observationId`, each reusing the existing
  query hooks and detail bodies with a semantic Back link that carries
  the reconstructible list filter/cursor query. GEOINT surfaces mount as
  explicit routes (`/geoint/entities/:entityId`,
  `/geoint/locations/:locationId/entities`,
  `/geoint/locations/:locationId/observations`); route-dependent
  breadcrumbs replace the Pivot-stack breadcrumbs/Close.
- **GEOINT detail lifecycle (D).** `EntityGeointView`, `LocationViews`
  and `GeointPage` retire the local `evidenceId`/`table.selection` ->
  `ResourceDetailView` replacement: "View Evidence" is a semantic link to
  the exact Evidence route and observation rows navigate to the exact
  GEOINT Observation route; browser Back reconstructs Entity
  GEOINT/Location surfaces from route/query state (N09/N15..N18). The
  Location containment controller becomes two ordinary toggle buttons
  flowing through the shared filter controller (the former MUI
  ToggleButtonGroup roving-focus internals reproduced a deterministic
  main-thread freeze on the real stack under pointer AND keyboard
  activation; the plain buttons preserve the semantic query change and
  cursor reset exactly, N19/N20).
- **Investigation shell cutover (E).** `InvestigationWorkspace` is
  route-only: persistent header + navigation + one `<Outlet>` surface.
  Legacy `?pivot=` URLs have one deterministic policy: a valid stack
  redirects once (replace) to its canonical route through the same
  mapper, removing the parameter; malformed state is removed in place
  (N03/N04). No second navigation architecture exists.
- **Obsolete hosting retired (F).** `PivotWorkspace`, `PivotStepHost`,
  `pivot-port.ts`, `PivotBreadcrumbs`, the Pivot-stack mutation/projection
  helpers, and the now-unused `GeointDetailContent` local detail surface
  are removed; the validated legacy parser/serializer remains for the
  deterministic legacy policy.
- **Browser acceptance (G).** `zz-geoint.spec.ts` runs the canonical
  routed G1..G6 journeys with normal locator clicks (no dispatch/force/
  coordinate/sleep), `zz-31f8-stress.spec.ts` repeats the routed GEOINT
  journey at least 20 consecutive cycles per engine in one page process
  (Chromium + Firefox, workers=1, retries=0), and the pivot trajectory
  specs (`zz-pivots`, `zz-pivot-acceptance`, `zz-list-detail`,
  `zz-geolocation-workflow`, `zz-relationship-evolution`) are converted to
  routed navigation. G4 explicitly returns to `/investigations` before
  creating Investigation B (no product control added).

Threading: URL path/query remains the sole reconstructible analyst state;
no second router/global store/generic navigation stack; capability
registration and resource semantics unchanged; no overlay; no graph
redesign; no backend/API/DB/migration/seeder/provider/Coordinator
change; no PR31G scope.

**Status.** Implemented on `fix/pr31f-8` over the accepted PR 31F-7
baseline. Frontend component suite (690/690), typecheck, ESLint and Vite
build are green; the exhaustive mapper matrix and routed navigation
component coverage are recorded in
`out/PR31F8_IMPLEMENTATION_REPORT.md`. The
real-stack browser gate (routed G1..G6 plus >= 20-cycle Chromium +
Firefox stress, workers=1/retries=0) passes through `scripts/e2e.sh`
(see docs/TESTING.md "PR 31F-8 routed GEOINT browser gate"), and the
converted pivot trajectory specs (zz-pivots, zz-pivot-acceptance,
zz-list-detail, zz-geolocation-workflow, zz-relationship-evolution,
zz-pointer-acceptance, zz-pr31f7-critical) pass in the directed
real-stack runs. [DONE]
