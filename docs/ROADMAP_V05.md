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
| **31E** | Interactive graph expansion | Analyst-driven incremental expansion of already-known graph relationships |
| **31F** | Evidence drill-down | Relationship -> observation -> evidence navigation from the graph |
| **31G** | Filtering and investigation context | Manage larger graphs without confusing global knowledge with investigation provenance |
| **31H** | Bounded multi-hop traversal | Depth-limited recursive exploration using PostgreSQL recursive CTEs |
| **31I** | Path finding | Bounded connection discovery between analyst-selected entities |
| **31J** | Temporal graph exploration | Explore topology through RelationshipObservation time semantics |
| **31K** | Graph-driven investigation actions | Launch ATI research/investigation actions directly from graph entities |

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

## PR 31E — Interactive graph expansion

Turn the visualization into an exploration tool. Allow an analyst to expand a
selected Entity by all, incoming, outgoing, or selected relationship types.
Each expansion requests an incremental one-hop neighborhood and merges the
returned nodes and edges into the current client-side graph without duplicating
canonical identities.

Expansion means "show more of ATI's already-known graph"; it does not perform
provider acquisition or start a new investigation. Preserve deterministic
merge/selection behavior and place reasonable client/server limits around
expansion size.

## PR 31F — Relationship observation and Evidence drill-down

Connect graph topology to ATI's evidence-backed semantics. From a selected
Relationship, allow the analyst to inspect the ordered
`RelationshipObservation` records supporting it and navigate from each
observation to the exact Evidence/EvidenceObservation provenance already
maintained by ATI.

Reuse existing Evidence APIs and presentation capabilities where practical
rather than inventing a parallel evidence representation. The graph should
answer not only "what is connected?" but also "why does ATI believe this
relationship exists, when was it observed, and what evidence supports it?"

PR 31F is the first complete investigation-grade graph-exploration milestone.

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
