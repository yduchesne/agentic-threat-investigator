# Agentic Threat Investigator — Testing and Engineering Quality

## Table of contents

- [Purpose](#purpose)
- [Quality contract](#quality-contract)
- [Python project management](#python-project-management)
- [Formatting](#formatting)
- [Imports](#imports)
- [Linting](#linting)
- [Static typing](#static-typing)
- [Pytest test categories](#pytest-test-categories)
- [Unit tests](#unit-tests)
- [Provider contract tests](#provider-contract-tests)
- [Provider validation matrices](#provider-validation-matrices)
- [Synthetic HTTP provider integration tests](#synthetic-http-provider-integration-tests)
- [Typical provider issues to watch for](#typical-provider-issues-to-watch-for)
- [Database integration tests](#database-integration-tests)
- [TAXII interoperability testing strategy](#taxii-interoperability-testing-strategy)
- [Redpanda / Kafka integration tests (PR 28G)](#redpanda--kafka-integration-tests-pr-28g)
- [Distributed Evidence ingestion closure (PR 28H)](#distributed-evidence-ingestion-closure-pr-28h)
- [Migration tests](#migration-tests)
- [Test isolation](#test-isolation)
- [Synthetic fixtures](#synthetic-fixtures)
- [Fake implementations](#fake-implementations)
- [Structured agent output and deterministic formatter tests](#structured-agent-output-and-deterministic-formatter-tests)
- [Scenario factory](#scenario-factory)
- [Coverage](#coverage)
- [Pre-commit](#pre-commit)
- [Canonical quality command](#canonical-quality-command)
- [No quality-gate bypass](#no-quality-gate-bypass)
- [CI quality gate](#ci-quality-gate)
- [Frontend quality](#frontend-quality)
- [Server-rendered web presentation tests (V07-01)](#server-rendered-web-presentation-tests-v07-01)
- [PR 35-1 UI correctness testing](#pr-35-1-ui-correctness-testing)
- [PR 35-2 GEOINT UI consolidation testing](#pr-35-2-geoint-ui-consolidation-testing)
- [PR 35-8 focal-Entity exploration testing](#pr-35-8-focal-entity-exploration-testing)
- [PR 26 GEOINT testing strategy](#pr-26-geoint-testing-strategy)
- [Definition of done](#definition-of-done)
- [Configuration tests](#configuration-tests)
- [Batch persistence and history tests](#batch-persistence-and-history-tests)

## Purpose

This document defines ATI's conventional software testing and source-quality requirements.

Behavioral evaluation of agents, LLM outputs, RAG quality, investigation trajectories, and release evaluation gates is specified separately in `EVALUATION.md`.

## Quality contract

ATI treats automated quality gates as mandatory engineering requirements.

Python tooling:

- `uv` — environment, dependency, lockfile, and command management.
- Ruff — formatting, import ordering, linting.
- Mypy — static type checking.
- Pytest — tests.
- pytest-cov — coverage.
- pre-commit — fast local checks.

The authoritative dependency files are:

- `pyproject.toml`
- `uv.lock`

`uv.lock` is committed.

## Python project management

`uv` owns:

- Python dependency management;
- virtual environment management;
- dependency locking;
- development command execution.

Typical commands:

```bash
uv sync --locked
uv run ruff format .
uv run ruff check .
uv run mypy ...
uv run pytest
```

Do not maintain parallel hand-edited `requirements.txt` dependency definitions unless an external integration explicitly requires an exported format.

## Formatting

Ruff formatter is authoritative for Python formatting.

Development:

```bash
uv run ruff format src tests
```

CI:

```bash
uv run ruff format --check src tests
```

No competing Python formatter is introduced.

## Imports

Ruff's `I` rules own import ordering; the first-party package is declared in
`[tool.ruff.lint.isort]`.

Commands:

```bash
uv run ruff check src tests --select I
uv run ruff check src tests --select I --fix
```

## Linting

Ruff is the Python linter. Enabled rule families are explicit in
`pyproject.toml` ([`tool.ruff.lint.select`]); enabled violations are binary
pass/fail — one violation fails the gate.

Project-wide exceptions belong in repository configuration when architecturally justified.

Local suppressions are exceptional and must use an explicit code:

```python
# noqa: <CODE>
```

Only narrowly scoped `# noqa` directives are allowed; bare `# noqa` and
blanket file/global suppressions are prohibited unless independently
justified and approved. Every non-obvious suppression should keep a short
justification. Ruff's `RUF100` gate reports any unused suppression.

## Static typing

Mypy runs in strict mode for ATI-owned production code and all integration-test code. The integration target is checked explicitly, including every module under `tests/integration/`:

```bash
uv run mypy src tests/integration
```

Conceptually:

```toml
[tool.mypy]
strict = true
```

Third-party typing gaps may receive narrowly scoped exceptions.

Do not globally weaken type checking because one dependency lacks complete typing.

Architectural boundaries should avoid casual propagation of `Any`.

Test infrastructure such as fake providers, scenario builders, repositories, `FakeLlmClient`, and fixture factories should also be strongly typed.

## Pytest test categories

Pytest owns automated Python testing.

Tests are organized into:

- unit tests;
- integration tests;
- provider contract tests;
- database/migration tests;
- deterministic scenario-support tests.

Suggested markers:

```python
@pytest.mark.unit
@pytest.mark.integration
@pytest.mark.provider_contract
```

Agent/LLM behavioral evaluation may use additional markers but its contracts and scoring belong in `EVALUATION.md`.

## Unit tests

Unit tests should be fast, deterministic, and isolated from network/database
dependencies unless the tested unit specifically requires them.

### Graph read-contract unit tests (PR 31A)

``tests/unit/app/query/test_graph.py`` validates the PR 31A application
graph contract without any database:

- **identity closure**: entity IDs unique, relationship IDs unique, every
  edge source/target endpoint present in the nodes, self-relationships
  require exactly one node;
- **uniqueness and boundedness**: distinct canonical identities, positive
  ``observation_count``, explicit positive query ``limit``;
- **temporal validation**: UTC-aware ``first_observed_at`` /
  ``last_observed_at`` summaries (naive timestamps fail), well-ordered
  summary pair, null summaries accepted;
- **query model**: Investigation scope, focal entity, ``EITHER`` default
  direction, optional relationship-type filter;
- **service semantics**: a tiny concrete test double satisfies
  ``GraphQueryService``; an isolated focal-node result is distinct from
  ``None`` (missing/not-visible focal entity);
- no PostgreSQL vertical slice existed before PR 31B; PR 31B adds it below.

### PostgreSQL graph vertical slice (PR 31B)

``tests/integration/test_query_graph.py`` exercises the real schema and the
production query service (``PostgresGraphQueryService`` through
``PostgresQueryServices.graph``) with the shared synthetic seeding helpers
(no fake graph database, no fake query service):

- **Investigation isolation**: missing focal Entity, focal visible in one
  Investigation but not another, soft-deleted focal, visible isolated focal
  Entity returning a one-node graph;
- **direction and topology**: SOURCE / TARGET / EITHER relative to the
  focal Entity, self-relationships, repeated counterparties, relationship
  type filtering, soft-deleted Relationships and soft-deleted endpoint
  Entities;
- **aggregation**: repeated admitted observations collapse to one canonical
  edge, cross-Investigation summary isolation, first/last observed ignoring
  nulls, all-null observed-at summaries, one EvidenceObservation shared by
  two Investigations counting once in each, and edges whose observations
  are never admitted to the requested Investigation;
- **bounds and determinism**: exact-limit and ``limit + 1`` truncation
  behavior, oversized limits rejected by ``QueryLimits`` before SQL, node
  ordering (focal first, then Entity ID), and edge ordering (Relationship
  ID);
- **projection**: display name/canonical fields, canonical
  ``RelationshipType`` mapping, and endpoint closure.

PR 31B also adds query-plan/index eligibility tests to
``tests/integration/test_query_indexes.py`` (G31B-X01..X04 / P31B-01..02):
the source neighborhood uses ``relationship_adjacency_idx``, the target
neighborhood uses ``relationship_target_adjacency_idx``, the focal
visibility probe uses ``evidence_observation_entity_entity_idx`` and the
InvestigationEvidence admission indexes, and the edge admission join uses
an ``investigation_evidence`` index. These assert only index eligibility
under ``SET LOCAL enable_seqscan = off``, never costs, plan tree shapes, or
wall-clock latencies.

No PR 31B test requires live internet, API keys, or any external service;
the vertical slice runs entirely against the isolated PostgreSQL integration
fixtures.

### Graph scope and filter vertical slice (PR 31G)

``tests/integration/test_query_graph_filters.py`` seeds a deterministic
two-Investigation world (focal DOMAIN, IP/ASN counterparties, an incoming
ASN edge, a DOMAIN self-loop and a null-``observed_at`` CNAME edge, with
observations admitted to I1, some only to I2, at distinct sources/times)
and validates the PR 31G two-scope/filter semantics against the real schema:

- **scope**: Investigation scope shows only I1-supported edges; Known scope
  broadens to globally supported live Relationships while keeping the
  Investigation-visible focal (a focal admitted only to I2 maps to ``None``
  in I1 Known, never arbitrary global Entity lookup);
- **support counts**: known-only edges have ``investigation_observation_count == 0``
  while ``observation_count`` stays truthful; mixed edges report both
  counts; Investigation scope leaves the two equal;
- **source and time**: exact ``RelationshipObservation.source`` match,
  half-open ``observed_at`` bounds (lower inclusive, upper exclusive), and
  null ``observed_at`` failing an active time bound but contributing
  otherwise;
- **connected Entity type**: counterpary-relative semantics with SOURCE /
  TARGET / EITHER, and self-loop inclusion/exclusion by focal type;
- **combined semantics and bounds**: Relationship type intersection,
  combined-filter intersection, focal-only filtered results, soft-deleted
  Relationship/endpoint exclusion in both scopes, truthful ``limit + 1``
  truncation after filtering, Relationship-ID ordering, duplicate
  observations remaining one edge, and endpoint closure with filters.

### Graph context/filter unit tests (PR 31G)

Frontend ``frontend/src/relationship-graph/graph-context-url.test.ts``
covers the URL codec (absent scope \=\> Investigation, Known/filter
reconstruction, malformed canonicalization, Clear, refresh/Back-Forward
round-trip, unrelated-parameter preservation, minimal canonical URL);
``graph-queries.test.tsx`` covers the request/key/filter mapping and scope
change issuing a new request; ``use-graph-expansion.test.tsx`` covers
context inheritance and scope/filter-change abort/reset; and
``relationship-graph.test.tsx`` covers the Investigation/Known edge
context cues and exact server support counts.

### Bounded multi-hop traversal tests (PR 31H)

``tests/unit/app/query/test_graph.py`` (H-U01..H-U14) validates the
``GraphTraversalQuery`` contract (depth 1..3 accepted, 0/4 rejected,
Investigation default scope, source/time validation identical to the one-hop
neighborhood, GraphResult identity/closure rules, and the service double
implementing both `neighborhood` and `traverse` with isolated-focal vs
`None` semantics).

``tests/unit/app/query/test_graph_traversal_boundary.py`` (H-SF03/H-SF04/
H-SF09) pins the mandatory stored-function boundary: the adapter issues
one `ati.traverse_graph` call with the exact validated parameters, maps
only returned rows, and a source-review assertion fails if any traversal
SELECT / recursive CTE / join / filter / aggregation / endpoint SQL is ever
introduced into the Python adapter.

``tests/integration/test_query_graph_traversal.py`` (H-I01..H-I28) runs the
real migration-installed stored function through the production service:

- **depth boundaries**: A→B→C→D→E returns exactly the depth-1/2/3 edge
  boundaries and depth-4 topology is never traversed;
- **direction at every frontier**: SOURCE / TARGET / EITHER applied to each
  frontier Entity;
- **cycle/self-loop safety**: A→B→C→A terminates with canonical dedup and a
  self-loop appears once without recursive growth;
- **diamond/min-depth**: D once, E reachable, cross-branch repeated edges
  keep one edge with one summary (never count multiplication);
- **scope/filters before recursion**: cross-Investigation support hidden in
  Investigation scope, Known global support traversable with truthful
  investigation counts, Known-invisible root returns `None`, and
  source/intervals/Relationship type/connected Entity type filters block
  deeper reach;
- **deletion/null semantics**: soft-deleted Relationships/endpoints are
  absent, null `observed_at` matches one-hop semantics;
- **equivalence/determinism**: depth-1 traversal topology and summaries
  equal the one-hop neighborhood, ordering is deterministic
  `(minimum_hop_depth, relationship_id)` / `(entity depth, entity_id)`;
- **bounds/truncation**: exact-limit returns `truncated=false`, `limit + 1`
  returns limit with `truncated=true`, endpoint closure is retained, an
  isolated visible focal is focal-only, and a missing/deleted focal is
  `None`.

``tests/integration/test_query_indexes.py`` (H-P01..H-P08) records
PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` evidence against the exact
function-body query (extracted from the versioned SQL artifact for plan
inspection only — never a second Python implementation): the source/target
chain traversals stay served by the PR 31B adjacency index family,
branching/high-degree/cycle-rich depth-2/3 recursion terminates with bounded
work, Investigation scope uses the exact-admission index family, Known scope
keeps one canonical row per Relationship, and filters plan as
eligible-selection predicates.

``tests/integration/test_migration.py`` (H-SF01/H-SF02) asserts migration
`0035_graph_traversal` installs `ati.traverse_graph` at head and that a
downgrade to `0034_timeline_error_message` drops only the traversal function
(re-upgrade restores it).

`tests/unit/api/test_graph_routes.py` (H-A01..H-A12) covers the traversal
route: default depth 2 + Investigation + either, explicit depths 1/3
forwarded, depth 0/4 as stable 400, every PR 31G filter forwarded exactly,
oversized limit through the existing `QueryLimits` bound, scoped 404,
isolated-focal 200, truthful truncation, exact summaries, the pinned
OpenAPI operation `get_graph_entity_traversal`, and the one-hop
`/neighborhood` contract remaining unchanged.

Frontend: `graph-context-url.test.ts` (H-F01..H-F05) proves absent/invalid
depth canonicalizes to 1, depth 2/3 reconstruct, depth 1 serializes as
absent (2/3 canonical), and the context key/equality and
`graphDepthActive()` include depth without redefining
`graphContextActive()`; `graph-queries.test.tsx` (H-F12/G31H-D01) proves
the traversal request maps `max_depth` + every filter exactly and that the
traversal and neighborhood TanStack keys are distinct and depth-aware;
`use-graph-expansion.test.tsx` (H-F19/H-F20) proves expansion inherits the
full committed context at depth 2 and that a root depth change discards
stale prior-depth expansion state; `relationship-graph-layout.test.ts`
(H-L01..H-L05) proves the layered distance-ring layout (ring 1 identical to
the one-hop radial layout, hop rings, diamond minimum distances,
self-loops never stepping, determinism) and `relationship-graph.test.tsx`
keeps the one-hop presentation contract green.

### Bounded path-finding tests (PR 31I)

``tests/unit/app/query/test_graph_path.py`` (P-U01..P-U20) validates the
path contract: server-owned depth (1..6) and path-count (1..25) bounds with
oversized values rejected, the inherited PR 31G blank-source / half-open
interval rules, `GraphPath` structural rules (zero-hop legality, arity, no
repeated Entity/Relationship in a simple path) and `GraphPathResult`
closure (unique canonical nodes/edges, every edge endpoint present, path
references present, adjacency of the relationship references).

``tests/unit/app/query/test_graph_traversal_boundary.py`` (P-SF03..P-SF10)
pins the path stored-function boundary: one `ati.find_graph_paths` call
with every parameter bound exactly, canonical model mapping, the
`endpoints_visible` metadata distinguishing `None` from an empty result,
unknown-row-kind and mis-anchored-path invariant failures, plus the
one-hop consolidation (P-N17): `neighborhood()` invokes the shared
`_invoke_traverse_graph(..., max_depth=1)` helper and the whole adapter
module passes a source-review assertion that no graph SELECT / recursive
CTE / JOIN / aggregation / ORM graph-row SQL exists anywhere inside it.

``tests/integration/test_query_graph_paths.py`` (P-I01..P-I38 + the plan's
vertical slice) runs the real migration-installed stored function through
the production service against deterministic topology fixtures (sparse
chain, branching tree, diamond, cycles, dense bounded neighborhoods,
multiple equal-length paths, Known-only support, filtered topology):

- **basic topology**: one-edge and two-edge chains, path longer than
  `max_depth` yields no path, source==target yields exactly one zero-hop
  path, and two visible but unconnected endpoints yield empty paths with
  both endpoints projected;
- **endpoint visibility and scope**: Investigation-invisible source or
  target (including a soft-deleted or Known-global-only target) maps to
  `None`; Known-only intermediate topology is found only in Known scope;
  Investigation scope never traverses global-only support;
- **filters**: exact source removal, inclusive `observed_from`, exclusive
  `observed_to`, null `observed_at` excluded under a time filter,
  `retrieved_at` never substituted, Relationship type and counterparty
  Entity type blocking at every hop, SOURCE/TARGET/EITHER direction at
  every frontier;
- **cycles**: simple cycles never repeat an Entity, self-loops never grow
  recursion;
- **ordering/truncation**: shorter paths first, equal-length canonical
  signature ordering, `max_paths + 1` truthful truncation (more than the
  bound vs exactly the bound), repeated invocation returns identical
  paths/order;
- **deduplication/summaries**: one canonical edge/node per selected path
  topology, observation-based support counts (never path counts), Known
  scope Investigation-support counts, soft-deleted Relationship/intermediate
  Entity exclusion;
- **closure**: only selected-path topology is returned (explored-only
  entities never leak) and a no-path result still projects both visible
  endpoints; the depth-6 chain fixture completes bounded work.

The plan's canonical vertical slice seeds the full stack — A→B→D, A→C→D,
B→C, C→A cycle, one Known-only support edge, one filtered-out source and a
boundary-time observation — and asserts endpoint visibility, the two
deterministic equal-length paths sorted first (with canonical longer
simple paths after), canonical deduplication, support summaries, scope and
filter behavior, cycle safety and public DTO identity preservation.

``tests/integration/test_query_graph_one_hop_parity.py`` (P-N01..P-N16) is
the acceptance gate for the legacy-SQL removal: for every representative
graph context (both scopes, source/time filters, half-open interval,
Relationship/Entity type, self-loops, mixed support, isolated/invisible
focal, truncating limit, repeated calls) ``neighborhood(query)`` matches
``traverse(equivalent query, max_depth=1)`` exactly on nodes, edge
ordering, per-edge summaries, `truncated`, focal-only results and the
`None` visibility outcome.

``tests/integration/test_query_indexes.py`` (P-P01..P-P03) records
PostgreSQL `EXPLAIN (ANALYZE, BUFFERS)` evidence against the exact path
function-body query (extracted from the versioned v0031 SQL artifact for
plan inspection only): a source chain path plan stays served by the
relationship-access index family, the dense bounded lattice fixture at the
depth-6 ceiling terminates with bounded work under the combinatorial-work
gate, and both-endpoint visibility uses the exact-admission and entity
association index families. No new index is introduced.

``tests/integration/test_migration.py`` (P-SF01/P-SF02) asserts migration
`0036_graph_path_finding` installs `ati.find_graph_paths` at head and that
a downgrade to `0035_graph_traversal` drops only the path function
(`ati.traverse_graph` and the authoritative graph tables/data remain
untouched; re-upgrade restores it).

`tests/unit/api/test_graph_routes.py` (P-A01..P-A12) covers the path route:
defaults (depth 4, max paths 10), explicit in-window bounds accepted,
depth 7 / max paths 26 as stable 400 `invalid_request`, Investigation-
invisible source/target as the scoped 404, no-path 200 with empty paths,
source==target 200 with the zero-hop path, Known scope and every PR 31G
filter forwarded exactly, blank source / reversed interval as 400, the path
response reusing the canonical node/edge DTO vocabulary (no SQL row kinds
or PostgreSQL arrays) and the pinned OpenAPI operation
`get_graph_paths`.

Frontend: `graph-paths-queries` are covered in
`frontend/src/relationship-graph/graph-path.test.tsx` (P-F01..P-F05,
P-F09..P-F13, P-F15, P-F17): the API boundary sends exactly the
`/graph/paths` parameters with both endpoints + committed context + path
bounds (never `graph_depth`); the path TanStack key is distinct and
contains endpoints/context/bounds; the hook issues no request while
disabled and exactly one on Find; the toolbar's Find is disabled until both
endpoints are selected and Exit restores the ordinary state flag; the
result panel renders the no-connection state, the truthfully-truncated
warning and the deterministic *All / Path N (M hop(s))* selector; the
renderer emphasizes highlighted-path relationships and dims the rest; and
a 404 path failure surfaces a typed `ApiError`.

Browser acceptance: `frontend/e2e/zz-31i-path-finding.spec.ts` runs in
Chromium and Firefox (workers=1, retries=0) with the directed journey
(authenticate → deterministic F02 Investigation → routed Graph workbench →
enter path mode → select source → select target → prove no request before
Find → one bounded Find → path graph rendered → individual path selection
with no refetch → exit → ordinary graph restored → one-hop expansion →
committed context change → second Find in the new context → stale
prior-context result cannot reappear → heartbeat → clean product console)
plus the 20-cycle same-page path stress (ordinary graph → path mode → two
selections → Find → exit → expansion → re-enter → clear) proving no
request storm, no stale-result contamination, no frozen UI and no route
remount.

### Real-browser multi-hop acceptance (PR 31H)

`frontend/e2e/zz-31h-multihop.spec.ts` runs the depth journey in Chromium
**and** Firefox at `workers=1` / `retries=0`: completed fake-world
Investigation → Graph route at depth 1 → draft depth 2 with no request
before Apply → Apply (one committed `graph_depth=2` transition) → edge
selection + existing provenance → explicit one-hop node expansion on a
traversal root → Apply Known scope (traversal inherits full context) →
Clear (canonical depth-1 state) → Back reconstructs depth 2 / Forward
depth 1 → depth 3 → refresh reconstructs the committed depth. A 20-cycle
same-page stress (depth 1 → draft/apply 2 → interact/select/expand →
draft/apply 3 → interact → Clear → Back → Forward → heartbeat) proves no
route/Graph remount, no detached-DOM/native-pointer wedge, no duplicate
request storm, no stale cross-depth result, and no accumulating product
console errors. The PR 31G lifecycle gate remains green.

### Real-browser temporal graph acceptance (PR 38-8)

`frontend/e2e/zz-38-8-temporal-range.spec.ts` runs the direct-range
temporal graph journey in Chromium **and** Firefox at `workers=1` /
`retries=0` through `scripts/e2e.sh` (the authoritative E2E/stability
harness; a direct `npx playwright test` is not acceptance evidence):
completed fake-world Investigation → Graph route → enable temporal
exploration (neutral draft shows a blank start and an end DATE defaulting to
the browser-local current calendar date with a blank end time) → Apply a
date-only range normalizing both boundaries to local `00:00:00` → Apply a
range with an explicit non-midnight time preserved exactly → the exact
committed range changes the displayed topology → invalid drafts (missing
start, equal, reversed) are rejected without silent repair or a committed
request → refresh reconstructs the committed range → browser Back/Forward
reconstruct the prior committed ranges → Disable removes temporal-owned
parameters and restores ordinary graph behavior. An empty range renders
observation-specific wording ("No matching relationship observations were
recorded in this time range.") and can never present the prior range's
topology as its own; a committed range change resets stale expansion/path
state through the same graph-context identity. Temporal semantics are
frontend framing over the existing graph `observed_from`/`observed_to`
contract only: PR 38-8 has no backend endpoint, DTO, stored function,
migration, or index, and never infers a Relationship lifetime/start/end from
observation gaps. The range is half-open `[observed_from, observed_to)`; the
upper bound is exclusive. There is no frame count, frame index,
partitioning, or Previous/Next navigation.

A PR-38-8-specific **20-cycle same-page temporal stress**
(`ATI_38_8_STRESS_CYCLES=20`) re-enables temporal exploration each cycle,
applies a provably empty range → applies a non-empty range → verifies the
topology → Disable, and asserts the controls stay actionable, the URL stays
canonical, no stale topology is presented, no reload/recovery is needed, and
no product console error accumulates. The browser E2E stack uses
`ATI_LLM_DRIVER=deterministic` (the offline production-compatible driver);
Python `FakeLlmClient` is never injected into the browser stack.

### Real-browser graph-driven investigation action acceptance (PR 31K)

`frontend/e2e/zz-31k-graph-actions.spec.ts` runs the graph-action journey in
Chromium **and** Firefox at `workers=1` / `retries=0` through
`scripts/e2e.sh` (the authoritative E2E/stability harness; a direct
`npx playwright test` is not acceptance evidence). The real stack exercises
built frontend → real FastAPI → real auth/CSRF/idempotency → the existing
`POST /api/v1/investigations` durable Investigation command → real
PostgreSQL job → real durable worker → real Coordinator → deterministic
fake-world provider boundary → `ATI_LLM_DRIVER=deterministic` → real
persistence. Python `FakeLlmClient` is never the browser E2E LLM boundary.

- **Directed journey (K-E2E01):** completed deterministic fake-world
  Investigation → routed Graph workbench → select a canonical graph Entity
  with path mode off → in-flow action panel shows the canonical Entity
  (type/value and exact canonical Entity ID derived from the graph API
  response) → Start investigation issues exactly one accepted (202) durable
  command whose request DTO carries the EXACT canonical type/value of the
  selected Entity (no label parsing, no free-form IOC) → navigation through
  the existing Investigation workflow → the new Investigation reaches a
  terminal status (durable worker) → persisted outputs are queryable through
  normal resource/graph surfaces → heartbeat + clean product console.
- **Path-mode precedence (K-E2E02):** PR 31I endpoint clicks inside path
  mode never open the action panel and never POST; exiting path mode restores
  action selection. **Temporal compatibility (K-E2E03):** PR 38-8 temporal
  mode is active, the action target is the canonical Entity (never temporal
  metadata), and a committed direct range that removes the node clears the
  stale selection so it cannot be submitted. **Duplicate submission
  (K-E2E04):**
  one semantic attempt → exactly one accepted durable command on the real
  stack.
- **Stability:** a 20-cycle same-page action-selection stress
  (`ATI_31K_STRESS_CYCLES=20`, 20 cycles by default) repeatedly selects
  different visible nodes, opens/closes the action panel, and enters/exits
  path mode around the selection WITHOUT submitting durable work, then
  performs one real durable action at the end; it proves no duplicate
  requests, no detached node/pointer failure, no route remount loop, and no
  accumulating console errors.

Graph regression journeys for the interaction classes PR 31K touches
(`zz-31f8-stress` PR 31F-8, `zz-31g-graph-context` PR 31G, `zz-31h-multihop`
PR 31H, `zz-31i-path-finding` PR 31I, `zz-38-8-temporal-range` PR 38-8) are
re-run green in both engines as PR 31K regression evidence.

### Graph API route/DTO tests (PR 31C)

PR 31C test coverage spans three layers over the existing PR 31A/31B graph
read contract:

- **fake-service route contract tests** (`tests/unit/api/test_graph_routes.py`,
  G31C-R01..R17): pure HTTP tests with `FakeQueryBundle` +
  `FakeGraphService`. They assert the exact public projection (canonical
  IDs, observation summaries, no cursor/page/raw/UI fields), that exactly
  one `GraphNeighborhoodQuery` is built from the path/query parameters
  (direction defaults to `either`, omitted `limit` uses the configured
  `query_default_page_size`), scoped 404 semantics (service `None` maps to
  `graph_entity_not_found`; a visible isolated focal is 200), 422 on
  malformed UUIDs/enums, 400 `invalid_request` on an oversized limit, and
  401/403 authentication behavior;
- **DTO/mapper tests** (`tests/unit/api/test_graph_dto.py`, G31C-D01..D07):
  the public response DTOs are frozen `extra="forbid"` allowlists, mapping
  preserves service ordering/truncation and never substitutes null
  observation times;
- **real HTTP -> PostgreSQL vertical slice**
  (`tests/integration/test_api_graph.py`, G31C-I01..I10): real FastAPI,
  real authentication, request-scoped `PostgresQueryServices`, the
  PostgreSQL graph query, and the existing seed helpers (no fake
  GraphQueryService). It covers visible focal + admitted edge, SOURCE /
  TARGET direction, `RelationshipType` filtering, cross-Investigation
  scoped 404, isolated focal 200, observation aggregation summaries,
  Relationship detail handoff by graph `relationship_id`, the same ID
  filtering the Observation list, and `truncated=true` with no cursor.

OpenAPI remains pinned to `tests/fixtures/openapi_v1.json`; the PR 31C
addition (operation `get_graph_entity_neighborhood`, graph tag, cookie
security, and the public graph response DTOs only) is intentional and
reviewed through `tests/unit/api/test_openapi.py`.

### Deterministic telemetry unit tests (PR 29A)

Telemetry tests are deterministic and fully offline; they never contact
Prometheus, Jaeger, Loki, Grafana, LangSmith Cloud, Langfuse Cloud, an OTel
Collector, or any self-hosted backend, and they never require Docker/Podman.
They use OpenTelemetry's in-memory exports/reads:

- span assertions use `InMemorySpanExporter` (name, parent/child, attributes,
  status, exception events);
- metric assertions use `InMemoryMetricReader` (name, unit, value, attributes);
- the decorator seam is injected by monkeypatching ATI's own
  `telemetry.decorators` helper functions, never process-global OTel providers
  (which OTel's public API only allows setting once).

PR 29A adds **no telemetry integration-test requirement**; that is deliberate
and matches the approved roadmap. There is no dedicated telemetry
integration-testing phase.

PR 29A-1 keeps that policy and adds deterministic unit coverage of the
PostgreSQL/Kafka/Evidence instrumentation:

- a structural repository-coverage test walks every concrete PostgreSQL
  repository/resolver class and asserts each public I/O method carries
  `@postgres_repository_operation` telemetry, pinned against a committed
  reviewed inventory (no brittle source-text parsing);
- UoW telemetry tests drive the real `PostgresUnitOfWork` with a fake
  SQLAlchemy-like session (composite registration neutralized) and assert
  commit/rollback/failure/cancelled outcomes, explicit commit/rollback
  timing, and nested repository spans;
- Kafka publish/poll/commit telemetry tests use the same broker boundary
  doubles as the PR 28G adapter matrix;
- Evidence-flow telemetry tests use the spy consumer/persistence doubles.

The telemetry helper seams (
`telemetry.decorators.get_tracer`/`get_histogram`/`get_counter` and the
corresponding module-level bindings in `database.py`, the Kafka adapters, and
the Evidence consumer) are injected through the shared `tests/unit/conftest.py`
fixtures; no test relies on process-global OTel providers.

PR 29B keeps the same deterministic, offline policy and adds unit coverage
for every remaining stable boundary:

- **DS1..DS7** (datasource): acquisition success span/duration, typed stage
  failure counts, cancellation propagation, conversion item counts (N and
  zero), conversion exception preserving the lifecycle, and no duplicate
  Kafka publication counters on the producer path;
- **H1..H7** (provider HTTP): first-attempt success, retry-then-success,
  exhausted retries, cancellation, and the absence of URLs/paths/bodies
  from attributes;
- **PW1..PW5** (provider work): one logical work span regardless of internal
  HTTP attempts, mixed-result outcome semantics, bounded failure counts,
  and cancellation;
- **EP1..EP4** (Evidence persistence): the `ati.evidence.persist` span,
  persist > UoW > repository nesting, rollback/exception preservation, and
  no double-counted outcome counters;
- **G1..G5** (GEO): resolved/unresolvable/failed counts, empty-claim no
  invented work, and cancellation;
- **I1..I4** (investigation): one execution span/counter, no-op terminals
  count nothing, bounded failures, and no Investigation-ID labels;
- **A1..A5** (agents): Research Agent normal/empty/one-repair model-attempt
  counts, Evidence Analyst and Report Writer using the common observed
  client;
- **A6..A13** (LLM): one span + one observation per actual attempt, typed
  `LlmError` and cancellation preservation, no prompt/output capture, no
  fabricated token metrics, backend fail-open, and NoOp export absence;
- **P1..P6** (Kafka W3C): producer traceparent injection, consumer parent
  extraction making downstream work a child, malformed-header safety,
  unrelated-header preservation, byte-identical payload/key, and no-outer-
  span publish correctness.

PR 29B-1 keeps the same deterministic, offline policy for the inbound
FastAPI/ASGI HTTP boundary and adds the API-T01..API-T18 unit matrix in
`tests/unit/api/test_telemetry.py` using in-memory OTel providers and the
previously delivered in-memory span/metric readers — no Collector,
Prometheus, Jaeger, Loki, Grafana, Docker/Podman, or live services:

- **API-T01/API-T15/API-T16**: one standard HTTP server span per registered
  route (including `/health/live` and `/health/ready`) and bounded identity
  for unknown unmatched paths (no route label is manufactured from an
  arbitrary incoming path);
- **API-T02/API-T03/API-T05/API-T06/API-T07**: method × registered
  route-template distinction (GET vs DELETE on the same template), dynamic
  UUID paths mapped to the registered template, and `2xx`/`4xx`/`5xx`
  standard response-status telemetry with unchanged response behavior;
- **API-T08/API-T09**: a valid incoming W3C `traceparent` resumes the
  upstream trace and a malformed one fails safely;
- **API-T10**: an ATI span started inside a route is a descendant of the
  HTTP server span (same trace ID and server parent) with no context
  plumbing into handler signatures;
- **API-T04/API-T11/API-T12/API-T13**: query, request-body, response-body,
  authorization, cookie, CSRF, and Idempotency-Key sentinels
  (`DO_NOT_CAPTURE_*_29B1`) are absent from every recorded span
  attribute/event and metric attribute;
- **API-T14/API-T17/API-T18**: disabled telemetry installs no HTTP pipeline
  and leaves API behavior identical, repeated instrumentation never
  duplicates spans/metrics, and the request-ID middleware contract is
  unchanged through the instrumented middleware stack.

The tests pin `OTEL_SEMCONV_STABILITY_OPT_IN` to an empty value so the
resolved official instrumentation deterministically emits its default
semantic-convention names in any developer environment.

PR 29B-2 keeps the same deterministic, offline policy for the API telemetry
lifecycle and adds the API-L01..API-L07 unit matrix in
`tests/unit/api/test_telemetry_lifecycle.py`, using the real `create_app`
lifespan over an `ApiComposition` double plus a plain seam-level harness with
in-memory OTel providers — no database, Kafka/Redpanda, Collector,
Prometheus, Jaeger, Loki, Grafana, Docker/Podman, or live services:

- **API-L01/API-L07**: on normal shutdown `ApiComposition.dispose()` runs
  before the telemetry-shutdown callback, which runs exactly once per
  application lifecycle;
- **API-L02**: when API disposal raises, telemetry shutdown is still
  attempted and the original disposal exception remains authoritative;
- **API-L04**: when application startup fails before serving, the
  `finally`-equivalent seam cleanup still runs and the original startup
  exception propagates;
- **API-L03**: disabled telemetry (no providers, no HTTP instrumentation)
  completes the same production-style sequence safely through the real
  `configure_telemetry`/`shutdown_telemetry`;
- **API-L05**: a request executes and its PR 29B-1 HTTP server span records
  before any shutdown, proving providers are never shut down prematurely;
- **API-L06**: a failing provider shutdown stays fail-open inside
  `shutdown_telemetry()` (logged, contained) and never replaces application
  semantics.

API-L08 (exactly one direct `opentelemetry-instrumentation-fastapi`
declaration) is enforced by dependency review and the repository build
(`uv lock`), consistent with the no-brittle-text-test policy.

### Deterministic OTLP composer tests and config validation (PR 29C)

PR 29C keeps the same deterministic, offline policy. The exporter
composition matrix (INF-C01..C09) lives in
`tests/unit/telemetry/test_setup.py` and drives the real
`configure_telemetry`/`shutdown_telemetry` with in-memory recording
exporters monkeypatched into the composition seams — no network, no
Collector/backends:

- **INF-C01/C02**: disabled (or enabled-without-endpoint) telemetry composes
  no exporter/logger pipeline and stays offline;
- **INF-C03**: enabled with an explicit endpoint composes all three
  OTLP/HTTP pipelines exactly once;
- **INF-C04/C05**: repeated identical setup is idempotent (no duplicate
  pipeline or logging handler); conflicting setup raises ``RuntimeError``;
- **INF-C06/C07**: shutdown shuts all configured signal providers, detaches
  the additive OTel logging handler, and is fail-open;
- **INF-C08/C09**: an exported log outside any span carries no fabricated
  identity; inside a span it carries the standard OTel trace/span ids;
- the endpoint contract is pinned (the exporter appends `/v1/traces`,
  `/v1/metrics`, `/v1/logs` to the standard `OTEL_EXPORTER_OTLP_ENDPOINT`).

The worker/GEO process wiring matrix (INF-C10..C14) lives in
`tests/unit/infrastructure/test_cli_telemetry.py` and proves, with fake
engines and no database, that disabled observability stays unchanged and
that engines are disposed before `shutdown_telemetry` on both normal and
failure paths, without replacing original error semantics.

PR 29C adds deterministic **configuration validation** (not
end-to-end telemetry integration tests):

- **INF-C19**: the pinned Collector accepts `infra/observability/otel-collector/config.yaml`
  via the image's non-network `validate --config` path;
- **INF-C20**: `promtool check config` (pinned `prom/prometheus:v3.14.0`)
  succeeds on `infra/observability/prometheus/prometheus.yml`;
- **INF-C21**: the Grafana datasource YAML parses and Datasource UIDs are
  unique/stable (`ati-prometheus`, `ati-jaeger`, `ati-loki`);
- **LOKI-C1..C7** (PR 29C-1): PyYAML-level static invariants on
  `infra/observability/loki/config.yaml` — global retention exactly `336h`,
  structured metadata enabled, the obsolete `storage_retention_days` key
  absent, Compactor retention enabled, filesystem delete-request store, and
  the retention-compatible TSDB/v13/24h/filesystem topology;
- **INF-C16/C17/C18**: `compose.yaml` alone and with
  `compose.observability.yaml` both validate.

The no-live-integration-test policy is unchanged: there is **no** PR 29E
and PR 29C does not add a test that boots the stack and waits for spans/logs
inside a Collector/Jaeger/Loki. The developer smoke procedure documented in
`docs/OBSERVABILITY.md` is a manual developer flow, not CI correctness.

The PR 29C-1 testing boundary for Loki configurations is three distinct
levels; unit tests deliberately cover only the first:

```text
PyYAML unit tests (LOKI-C1..C7)
  -> ATI-owned static retention/topology invariants

pinned Loki -verify-config=true (grafana/loki:3.7.8)
  -> Loki configuration/schema compatibility

full telemetry/backend integration
  -> intentionally not part of PR 29
```

PyYAML parsing never proves Loki accepts a configuration; the pinned
`-verify-config=true` command is the documented developer/reviewer check
(`docs/OBSERVABILITY.md`) and ordinary unit CI must not require a container
runtime.

### Deterministic Grafana dashboard tests (PR 29D / PR 29D-1)

PR 29D added `tests/unit/observability/test_grafana_dashboards.py`, a static
(offline, deterministic) validation of the dashboards-as-code contract. PR 29D-1
corrected the tests to validate Grafana 13.2.2's *actual* runtime fields: the
Prometheus helpers parse the executable `expr` targets (never the ATI-invented
`query` surrogate) and the navigation helpers parse Grafana's dashboard
`links` model (never `externalLink` pseudo-panels). The file parses
`infra/observability/grafana/provisioning/dashboards/dashboards.yaml`, the
provisioned datasources, `compose.observability.yaml` (mount contract), and
every dashboard JSON under `infra/observability/grafana/dashboards/`, and
asserts the frozen matrices:

- **GRAF-C01**: the file provider parses and points at the mounted canonical
  directory (`/etc/grafana/dashboards`), and Compose mounts the provisioning
  tree and the canonical dashboard directory read-only;
- **GRAF-C02..C05**: exactly nine dashboard files, all valid JSON, with the
  exact nine UIDs (unique) and the agreed titles;
- **GRAF-C06..C08**: Prometheus panels use `ati-prometheus`, Loki panels use
  `ati-loki` with classic LogQL brace expressions, and trace usage stays
  within the stable `ati-jaeger` contract (datasource provisioned; the Jaeger
  UI is reached through a supported dashboard `link`, not a pseudo-panel);
- **GRAF-C09..C11**: overview links to all eight details, every detail links
  back to the overview, and the agreed drill-down hierarchy exists
  (Investigations -> Agents & LLM, Datasource & Ingestion -> Kafka / Redpanda
  and -> Persistence / Repository, Persistence / Repository -> PostgreSQL);
- **GRAF-C12/C13**: no IDs/IP/domain/URL/request/execution identifiers or IP
  literals anywhere in the dashboard surface, and API identity is method x
  registered route template only (no concrete-path filter values);
- **GRAF-C14..C18**: panels reference only the stable datasource UIDs, tags
  include `ati`/`observability`, sane last-1h/10s defaults, plain-JSON-only
  canonical tree (no dashboard-generation framework), and no embedded
  credentials;
- **query ownership** (executable target expressions are parsed, not
  descriptions searched): API uses route-template HTTP telemetry; Kafka lag
  joins derive from `redpanda_kafka_max_offset` minus
  `redpanda_kafka_consumer_group_committed_offset` and never from `ati_kafka`
  counters; PostgreSQL uses postgres-exporter series; Persistence uses ATI
  repository/UoW series; Datasource & Ingestion contains the Evidence-flow
  series; GEO contains GEO outcome series; Agents & LLM contains
  agent/LLM/provider series; Investigations & Reports contains
  investigation/report series; counters are consumed with
  `rate()`/`increase()`/grouped `sum`; `histogram_quantile` uses `_bucket`
  series with `by (le, ...)` grouping; application and infrastructure
  dashboards remain separated;
- **GRAF-F01..F18** (PR 29D-1 runtime-contract matrix):
  - **GRAF-F01/F02**: every intended Prometheus target has non-empty,
    executable `expr` and no target uses the custom `query` surrogate field;
  - **GRAF-F03**: the frozen PR 29D PromQL multiset is preserved exactly
    (the expressions were moved into `expr` without text changes);
  - **GRAF-F04/F05**: navigation is parsed from Grafana's verified dashboard
    `links` contract (`type: "link"`, `url`, `keepTime`, `targetBlank`, ...)
    and no `type == "externalLink"` pseudo-panel remains;
  - **GRAF-F06..F10**: overview links to all eight details; every detail
    links back; the drill-down hierarchy exists; destinations use stable
    `/d/<uid>` relative URLs (only the allowlisted local Jaeger UI is an
    absolute link); `keepTime` preserves the time range on dashboard links;
  - **GRAF-F11**: the three stable datasource UIDs are unchanged; panels use
    only `ati-prometheus`/`ati-loki` and the `ati-jaeger` datasource stays
    provisioned for trace exploration;
  - **GRAF-F12**: per-dashboard query-ownership markers (API
    route-template HTTP, Redpanda-authoritative lag, postgres-exporter,
    ATI repository/UoW, Evidence flow, GEO, agent/LLM/provider/embedding,
    investigation/report);
  - **GRAF-F13**: privacy/cardinality rules preserved in every executable
    expression;
  - **GRAF-F14**: Loki targets use the verified contract (`expr` LogQL with
    a bounded `service_name` label set, `queryType: "range"`, `ati-loki`);
  - **GRAF-F15**: Jaeger uses a supported dashboard link for the developer
    UI entry point plus the provisioned `ati-jaeger` datasource — no
    proxy/plugin/backend;
  - **GRAF-F16**: exactly nine dashboards with the exact UID/title mapping;
  - **GRAF-F17**: provisioning YAML and the read-only canonical mount are
    unchanged;
  - **GRAF-F18**: no new ATI application telemetry series is referenced
    (scope guard: every `ati_*` series used belongs to the frozen PR 29D
    instrument set).

These tests never require a live stack. PromQL/Loki/panel runtime health is
verified by the manual developer smoke procedure in
`docs/OBSERVABILITY.md` (`Grafana dashboards (PR 29D)` section; PR 29D-1
re-validates it against pinned Grafana 13.2.2) — the
no-telemetry-integration-test rule is unchanged *for the PR 29 dashboard/
config-validations layer*; PR 34 (below) is now the one authoritative
telemetry-delivery integration gate.

### End-to-end OpenTelemetry delivery integration tests (PR 34)

PR 34 closes the delivery gap with one authoritative, isolated, real-stack
gate proving that ATI telemetry traverses the deployed observability stack
in a single real execution:

```text
ati-telemetry-test (production composition)
  -> OTLP/HTTP
  -> OpenTelemetry Collector (otel/opentelemetry-collector-contrib:0.161.0)
  -> Prometheus (prom/prometheus:v3.14.0) / Jaeger (jaegertracing/jaeger:2.21.0)
     / Loki (grafana/loki:3.7.8)
  -> Grafana (grafana/grafana:13.2.2) provisioning/health
```

Authoritative command (feature acceptance):

```bash
./scripts/observability-integration.sh [--keep-on-failure] [--timeout N]
```

The harness starts an isolated five-service Compose
topology (`compose.observability.test.yaml`, reusing the exact
source-controlled `infra/observability/` configs and pinned images), waits
for bounded topology readiness (`TOPOLOGY_READY`), builds the repository ATI
image, runs the real one-shot generator attached to the isolated network
(producing the unique run UUID and receiving only
`ATI_OBSERVABILITY_ENABLED=true` + the standard
`OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318`), bounded-polls
per-backend convergence (Prometheus / Jaeger / Loki) plus Grafana
verification until `READY_FOR_ASSERTIONS`, runs the authoritative
`-m observability` pytest gate, records bounded run-state
(`artifacts/observability-integration/<run-id>/run-state.json`), and tears
down only harness-owned resources.

Generator boundary: `ati-telemetry-test --run-id <uuid>` uses ATI's
production composition (`configure_telemetry(service=ati-telemetry-test)`
-> emit -> `shutdown_telemetry()`); it knows **only the Collector** and
refuses emission when observability is disabled, when the standard endpoint
is absent, or when signal-specific OTLP endpoint/header overrides are set
(even empty — the pinned OTel exporters resolve signal-specific variables
in preference to the standard endpoint). Diagnostic names
(`ati.telemetry.test.*`, `telemetry_test_signal`) stay strictly separate
from the frozen production vocabulary.


Assertion matrix (T34-I01..I15): Collector/health check, generator exit 0,
Prometheus counter exactly 1 / duration count 1 sum 0.125s on the run's
series, Jaeger root/child spans with exact names/run attribute and child
parent = root, Loki structured log with exact event/run ID, Loki trace ID
== Jaeger trace ID (cross-signal), the three exact Grafana datasource UIDs
(`ati-prometheus`/`ati-jaeger`/`ati-loki`) healthy/queryable through the
proxy (never container health), `ati-telemetry-test` service attribution,
and ordering: assertions run only after `READY_FOR_ASSERTIONS`.

Failure classification uses the section-20 taxonomy (TOPOLOGY_START,
COLLECTOR_READY, PROMETHEUS_READY, JAEGER_READY, LOKI_READY, GRAFANA_READY,
GENERATOR, OTLP_EXPORT, PROMETHEUS_CONVERGENCE, JAEGER_CONVERGENCE,
LOKI_CONVERGENCE, GRAFANA_PROVISIONING, CROSS_SIGNAL_CORRELATION,
TEARDOWN) with bounded diagnostics into the artifact directory.

Resource prerequisites: Podman + podman-compose, `uv`, ~2-4 GB free image
disk, and the first run builds the ATI image (subsequent runs reuse layer
cache). The stack is **not** part of `./build.sh --intg`: ordinary
integration stays lightweight and never requires observability services.

Unit coverage of the harness logic (no containers/network):
`tests/unit/observability/test_pr34_harness_logic.py` proves the convergence
gate ordering (T34-I14), the failure taxonomy (T34-F01..F10),
run-scoped matching (stale other runs can never satisfy), bounded
malformed-response classification, and secret-safe summaries;
`tests/unit/telemetry/test_diagnostic.py` and
`tests/unit/infrastructure/test_telemetry_test_cli.py` cover the generator
contract (T34-G01..G15).

Priority unit-test areas include:

- entity canonicalization;
- pivot-policy helpers;
- budget accounting;
- coordinator policy (PR 21): deterministic candidate ordering from
  traversal, same-or-better-depth suppression, root work at entity-budget
  capacity, exact depth/entity/provider/replan boundaries, stop-reason
  precedence, and replan-only-with-new-work semantics;
- coordinator scenario loading (PR 21, updated by PR 21D): a strict
  13-scenario corpus under `evals/scenarios/coordinator/` that fails closed
  on malformed JSON, duplicate IDs, unsupported versions, blank fixture
  names, unknown fields, duplicate labels, and — since PR 21D — a missing
  `allowed_pivots` oracle, duplicate allowed pivot identities, blank or
  negative pivot entries, required pivots not represented in `allowed_pivots`,
  and forbidden pivots appearing in `allowed_pivots`;
- coordinator trajectory evaluation (PR 21, updated by PR 21D): every
  failure code, bounded `[0.0, 1.0]` metrics, depth-aware provider-work
  matching, transition bounds, deterministic failure ordering, and the
  independent per-scenario pivot oracle — pivot authorization
  (`PIVOT_ENQUEUED`) and `PIVOT_EXECUTED` are each validated against
  `allowed_pivots` (entity + exact depth), execution additionally requires a
  preceding matching enqueue, an illegal enqueue fails even when never
  executed, and policy-invalid rates count unique pivot identities;
- PR 21B/21D admission and corpus semantics: the entity budget is evaluated
  only above exact capacity (`entity_count > max_entities`); an
  exact-capacity pivot onto an already-admitted entity remains legal. Every
  repository-owned scenario executes through the real Coordinator graph from
  its deterministic checkpoint and evaluates cleanly (zero
  invented/policy-invalid pivots, zero budget violations, full termination)
  in `tests/unit/app/orchestration/test_coordinator_trajectories.py`, and
  the canonical PostgreSQL trajectory evaluates through the loaded oracle in
  `tests/integration/test_coordinator_trajectory.py`;
- relationship extraction;
- deterministic source extraction (PR 18B) including per-source
  malformed-fact rejection and deterministic deduplication;
- source normalization;
- content hashing;
- authorization decisions;
- soft-delete semantics;
- DTO/domain validation;
- retry classification;
- report/assessment structural validation;
- structured agent-result validation and serialization;
- deterministic report/presentation formatting;
- deterministic orchestration mechanics (PR 19A, updated by PR 19C): typed
  work-item validation, FIFO queue selection, duplicate suppression, outcome
  bookkeeping, provider-call counter accounting, and JSON state round-trip.
  Queue-exhaustion termination is legacy PR 19A mechanics exercised only
  through the explicitly named `build_legacy_investigation_graph` test
  helper; it does not describe the production graph, which is
  Coordinator-driven (coordinator -> execute provider work -> authorize
  pivot -> request analysis -> stop). Queue exhaustion no longer terminates
  production investigation execution directly: it returns control to the
  Coordinator, which selects the next bounded decision or a specific
  stop reason. Graph mechanics are tested against `TaskDispatcher`;
- local dispatch (PR 19C): `LocalTaskDispatcher` delegates the exact selected
  item exactly once, preserves the exact outcome, propagates exceptions and
  cancellation unchanged, and performs no state, persistence, or timeline
  mutation;
- deterministic provider execution (PR 19B): target/provider resolution,
  applicability validation, empty-success and error-only outcomes,
  cancellation propagation, extraction-before-persistence sequencing,
  per-Evidence PR 18C invocation, outcome ID bookkeeping (evidence,
  relationship, discovered entity merges; one provider-call increment per
  work item), and timeline event ordering/failure semantics, via fakes in
  `tests/unit/app/orchestration/test_provider_executor.py` (shared
  deterministic fakes/builders in `tests/support/provider_executor_fixtures.py`);
- provider-output provenance and partial-failure regressions (PR 19B
  fixes): binding validation of the returned provider, owning
  investigation, and persisted target (type, exact canonical value,
  subject identifier; malformed/noncanonical subjects provably reach zero
  extraction and zero persistence; a two-Evidence tuple with one invalid
  item proves full preflight), retention of all committed
  Evidence/Entity/Relationship IDs when a later Evidence fails extraction
  or persistence (including through state bookkeeping and when the failure
  timeline event itself cannot append), canonical first-seen aggregate ID
  lists across outcomes and completion events, and bounded secret-free
  logging of caught provider/persistence/timeline exceptions (adversarial
  injected exception text never appears in any log message or record and
  every record has `exc_info is None`), via
  `tests/unit/app/orchestration/test_provider_executor_regressions.py`;
- timeline event-shape and error-code contract (PR 19B): table-driven
  domain tests for every valid event type and each invalid field
  combination, including blank, padded, uppercase, punctuation, and
  65-character error codes, via
  `tests/unit/domain/test_investigation_timeline.py`, plus a database
  integration assertion that an invalid code is rejected even when model
  validation is bypassed;
- migration lifecycle and schema contract (PR 19B): migration 0013
  downgrades to 0012 and re-upgrades to head, proving the timeline table
  and owned sequence absence at 0012 and clean reinstall with checks,
  index, and sequence ownership; the schema contract asserts the
  error-code CHECK and that no ATI routine mutates timeline events, via
  `tests/integration/test_migration.py`;
- UnitOfWork lifecycle (PR 19B): a closed UoW exposes no stale timeline
  repository and re-enters with a fresh repository, including the
  rollback path, via `tests/integration/test_investigation_timeline_repository.py`;
- production composition (PR 19B, updated by PR 19C):
  `build_provider_investigation_graph` assembles `ProviderWorkExecutor`, wraps
  it in `LocalTaskDispatcher`, and injects that dispatcher into the compiled
  graph without global state. The compiled graph is invoked asynchronously in
  the vertical slice, via `tests/unit/app/orchestration/test_composition.py`
  and the pipeline test;
- application-level runner (PR 21C): `LocalInvestigationRunner` loads the
  authoritative persisted Investigation through a short UnitOfWork, closes it
  before graph execution, treats terminal investigations as idempotent
  no-ops, creates a fresh bound analysis executor and graph per invocation
  (cross-investigation isolation, conflicting bindings fail before provider
  or graph work), passes the exact persisted state into the graph, fails
  closed on non-terminal graph output and on graph/durable mismatches,
  returns the authoritative durable reload, propagates cancellation
  unchanged, and rejects non-positive recursion limits — via
  `tests/unit/app/orchestration/test_runner.py` with fakes only, plus the
  canonical PostgreSQL trajectory, terminal-idempotency, isolation,
  missing-ID, and graph-owned analysis-failure cases in
  `tests/integration/test_coordinator_trajectory.py`;
- graph context binding (PR 19B): a provider-backed compiled graph is bound
  to one investigation ID; invoking it with a state for another
  investigation raises `InvestigationGraphContextMismatchError` during
  `initialize` before queue selection, target lookup, timeline emission,
  provider I/O, extraction, or persistence. The binding path is
  `graph -> LocalTaskDispatcher -> bound ProviderWorkExecutor`: automatic
  investigation binding is preserved through the dispatcher, direct public
  composition cannot bypass isolation, an explicit conflicting ID fails at
  construction with `InvestigationGraphBindingConflictError`, and a wrong
  invocation state fails before dispatch or I/O. Generic graphs without an
  expected ID and ordinary unbound dispatchers remain supported. Unit coverage
  (all five binding
  cases, the direct-builder bypass, and the construction conflict) lives in
  `tests/unit/app/orchestration/test_graph.py`, `test_composition.py`, and
  `test_provider_executor.py`; two PostgreSQL regressions in
  `tests/integration/test_provider_execution_pipeline.py` (factory path and
  direct generic-builder path) prove durable absence (no Evidence, timeline
  event, Relationship, RelationshipObservation, or state mutation for either
  investigation) using exploding transports.

### Datasource vocabulary and definition contracts (PR 27A)

`tests/unit/domain/test_datasource.py` and
`tests/unit/config/test_datasource_settings.py` pin the typed datasource
vocabulary deterministically and offline (stable matrix IDs D27A-01..D27A-13):

- exact durable semantic-format URNs
  (`urn:ati:datasource:semanticformat:stix21` and
  `urn:ati:datasource:semanticformat:threatfox`);
- every existing durable `SourceId` serialized value remains exact;
- one immutable `DatasourceDefinition` requires all five dimensions with
  exact independent values for the ThreatFox (HTTPS + JSON + ThreatFox
  semantics) and MITRE ATT&CK (FILE + JSON + STIX 2.1 semantics)
  representative definitions;
- datasource-instance ID validation rejects blank, whitespace-only, padded,
  malformed, and over-bound values;
- unknown protocol, serialization, and semantic-format values fail closed;
- duplicate datasource IDs are rejected in any `Settings`/profile collection
  while two datasource instances sharing one `SourceId` remain legal;
- no-inference tests prove provider, protocol, and serialization never select
  semantics (JSON definitions carry distinct semantic formats; unusual
  provider/protocol combinations construct unchanged).

These tests never touch the network or the database.

### Datasource execution logging (PR 27B)

`tests/unit/domain/test_datasource_log.py`, `tests/unit/app/test_datasource_execution_recorder.py`
and `tests/integration/test_datasource_log.py` pin the PR 27B acquisition
lifecycle deterministically and offline/against real PostgreSQL (stable
matrix IDs D27B-U01..U13, D27B-P01..P15, D27B-V01/V02, D27B-C01, D27B-S01):

- fresh per-execution UUIDs; identity stability across every event of one
  execution (same `execution_id`, same `datasource_id`);
- immutable `DatasourceLogEvent` model: aware timestamps normalize to UTC,
  naive timestamps fail closed, zero/positive stage-local counts accepted and
  negative counts rejected, bounded canonical error codes (blank/
  whitespace/over-bound/malformed rejected) bound to `FAILED` only, and
  `extra="forbid"` rejecting any payload/exception/credential/metadata field;
- recorder lifecycles: success (STARTED + selected stages + COMPLETED),
  failure (STARTED + FAILED with a safe code), deterministic sleep-free
  cancellation (`CancelledError` propagates after a best-effort CANCELLED
  append; the durable log holds STARTED + CANCELLED and no
  FAILED/COMPLETED), terminal exclusivity, stage-after-terminal and
  duplicate-STARTED local rejection, and legal omitted stages
  (STARTED -> COMPLETED);
- real-PostgreSQL lifecycle/concurrency matrices: append/persist correlation,
  STARTED-first and STARTED-unique enforcement, datasource identity
  stability, terminal exclusivity, post-terminal rejection, concurrent
  terminal and initial-STARTED races yielding exactly one durable row,
  independent concurrent executions, database-owned count/error-code
  constraint backstops (direct SQL bypassing the Python model), and
  append-only repository shape (no update/delete method);
- migration round trip (D27B-P15): upgrade creates exactly the PR 27B
  objects and no `datasource_execution` table; downgrade removes only PR 27B
  objects while pre-existing authoritative rows (source records,
  investigations) survive unchanged;
- PR 28F-2 extension (F2-L12..L15 and V28F2-06): `PUBLISHED` is a
  non-terminal stage (accepted-message `item_count`, no `error_code`),
  rejected before STARTED and after a terminal outcome both locally and by
  the real stored function; SQL API v0028 (migration 0033) opens exactly
  the one additional non-terminal stage with a round-trip-tested
  downgrade restoring the seven-value v0025 vocabulary;
- the canonical vertical slice (D27B-V01/V02): the real
  `DatasourceExecutionRecorder` -> append port -> PostgreSQL repository ->
  stored function path over real PostgreSQL with simulated local work
  between short committed transactions, asserting exact ordering, counts
  only where supplied, no payload columns, no credentials/raw exception
  text, and no execution table;
- schema-level proof (D27B-S01) that the durable log columns are exactly
  the bounded operational set, so source bodies, Evidence bodies,
  credentials, and tracebacks cannot be persisted by the event schema.

### Datasource acquisition-to-semantic boundary (PR 27C)

PR 27C tests are deterministic, offline, and use real production parsing/
HTTP paths; only the external Internet endpoint is faked via in-process
`httpx.MockTransport`:

- cross-cutting contracts (`tests/unit/app/test_datasource_semantics.py`,
  D27C-U01..U08): exact context identity derived from one
  `DatasourceDefinition`, timezone-aware UTC retrieval timestamps (naive
  rejected), credential-free and bounded source references (credential-
  bearing, blank, non-HTTP, hostless, and over-bound references rejected),
  success/empty-semantics vs failure result invariants, bounded
  error-code grammar, and nonnegative retry delays;
- ThreatFox semantics (`tests/unit/infrastructure/datasources/test_threatfox_semantics.py`,
  D27C-T01..T20): no-result/empty-data empty successes, typed records in
  source order, identical-duplicate retention and conflicting-duplicate
  whole-response failure, unrelated-IOC rejection, malformed
  timestamp/URL/domain failures, body-encoded `ratelimited` as an
  operational acquisition failure, canonical `ip:port`/bracketed IPv6:port
  matching, ambiguous unbracketed IPv6+port rejection, UTC timestamps,
  parse determinism, and proof that the semantic module has no
  Evidence/provider import dependency;
- ThreatFox acquisition path (`tests/unit/infrastructure/datasources/test_threatfox_datasource.py`,
  D27C-X01..X09): full success (STARTED -> ACQUIRED -> DECODED ->
  COMPLETED), HTTP/serialization/semantic failures with typed stage-aware
  bounded codes and no intermediate stages, no-result DECODED item_count=0,
  deterministic cancellation (CANCELLED recorded, `CancelledError`
  propagates, never FAILED), distinct per-execution IDs, no UoW held across
  HTTP or semantic parsing (short committed transactions per append), no
  CONVERTED event, fail-closed dimension validation before I/O, and
  header-only Auth-Key with zero context/log leakage;
- STIX semantics (`tests/unit/infrastructure/datasources/test_stix21_semantics.py`,
  D27C-S01..S12 + M33A-01..30): typed bundle/object parsing in source
  order, fail-closed envelope and object-identity validation, preserved
  `x_mitre_*` extension fields and unknown valid types, deep snapshot
  isolation from caller mutation, the serialization boundary (raw bytes
  must be decoded before the semantic parser), direct single-object
  validation through the reusable `parse_stix21_object()` seam
  (Bundle-rejected, bounded errors that never echo source values,
  deterministic re-parse equality), Bundle-adapter delegation with
  member-index error context (proved both by parity against the direct
  seam and by source inspection), and module isolation from Evidence/
  provider/HTTP/persistence/TAXII imports. MITRE ATT&CK compatibility is
  pinned at the existing boundary by
  `tests/unit/infrastructure/test_mitre_attack_source.py` and the
  repository integration suites, all with ATI-authored synthetic STIX and
  no live external source;
- the canonical real-stack vertical slice
  (`tests/integration/test_datasource_semantic_acquisition.py`): a
  deterministic local HTTP fixture -> real `ProviderHttpClient` -> real
  `ThreatFoxDatasource` -> real semantic parser -> real
  `DatasourceExecutionRecorder` -> real `PostgresUnitOfWork` -> real
  `ati.append_datasource_log_event` stored function -> real
  `ati.datasource_log`, asserting one execution ID, the exact
  STARTED/ACQUIRED/DECODED/COMPLETED and failure/cancellation lifecycles,
  exact bounded byte/item counts, no Evidence/SourceRecord/Investigation
  rows, and no raw body or credential in the durable log.

### MISP native semantic parsing (PR 32A)

PR 32A adds the native MISP semantic boundary
(`tests/unit/infrastructure/datasources/test_misp_semantics.py`, M32A-01..50,
with ATI-authored synthetic fixtures in `tests/support/misp_fixtures.py`):

- a decoded `{"Event": {...}}` envelope validates to immutable
  `MispAttributeRecord` / `MispObjectRecord` records: Event-level
  Attributes first, then Objects, each in source order, with nested Object
  Attributes/ObjectReferences preserved and never duplicated top level;
- strict scalars are verified against the current MISP core format: Unix
  timestamps must be decimal JSON strings -> UTC, `first_seen`/`last_seen`
  must be timezone-aware ISO-8601 (`first_seen <= last_seen`), semantic
  booleans must be real booleans, and modeled strings are bounded without
  truncation;
- UUID is upstream identity: identical duplicates are kept once, conflicting
  duplicates and any malformed modeled member fail the whole Event with a
  bounded, non-retryable `SEMANTIC_VALIDATION` error and zero records;
- `deleted`, Attribute/Object distribution (including `5` = inherit Event),
  sharing-group state, and unknown valid MISP Attribute types are preserved
  without interpretation; binary `data` and unmodeled members never leak;
- caller-mutation isolation, repeated-parse equality, module isolation from
  Evidence/provider/HTTP/persistence imports, and no source-content logging
  are asserted directly.

No live MISP/network and no database are involved; REST acquisition is
outside 32A (PR 32C), and `MispToEvidenceConverter` is PR 32B. See
`docs/DATASOURCE_ARCHITECTURE.md`.

### Native MISP-to-Evidence conversion (PR 32B)

PR 32B adds the pure MISP semantic-record -> `ConvertedEvidence` layer
(`tests/unit/infrastructure/datasources/test_misp_evidence.py`, M32B-01..57
and M32B-V01..V05, with 32B fixture additions in
`tests/support/misp_fixtures.py`). Everything is synthetic, static, and
offline:

- registration/contract (M32B-01..06): the converter owns exactly
  `SemanticFormatId.MISP`; the real `build_misp_conversion_registry()`
  lookup selects it by semantic format only; wrong source type, wrong
  semantic-format context, and wrong `SourceId` each raise the bounded
  `ConversionError`; repeated conversion is structurally equal;
  `convert_semantic_source_objects` selection is keyed only by semantic
  format (a MISP-SourceId/THREATFOX-format context fails on the format
  lookup);
- identity/provenance (M32B-07..16): `source_record_id` is the exact
  Attribute UUID string; Evidence ID equals the deterministic
  `evidence_id_for_source_record(SemanticFormatId.MISP, SourceId.MISP,
  str(attribute.uuid))`; value changes keep the same ID, different UUIDs
  yield different IDs, Event UUID and retrieval-time changes never move
  the ID; `source_reference`/`retrieved_at` come from the semantic
  context, `observed_at` is the exact Attribute timestamp, and
  `raw_payload` is `None`;
- IOC profile (M32B-17..24): `domain`/`hostname` -> one canonical DOMAIN
  IOC, `ip-src`/`ip-dst` -> one canonical IP_ADDRESS IOC with IPv4 and
  compressed IPv6 coverage, and existing strict `validate_dns_name`/
  `canonicalize_ip_address` behavior (mixed-case/trailing-dot and IDNA
  domains, expanded IPv6) — the supported set is pinned to exactly the
  five approved types;
- compound (M32B-25..32 + 57): `domain|ip` is one Evidence with two
  ordered canonical IOC facts through both the direct converter and the
  real generic flattening seam; missing/extra/invalid components raise
  `ConversionError`; identity is the bare Attribute UUID with no
  component suffix;
- unsupported/state preservation (M32B-33..45): sha256/url/arbitrary
  types, `MispObjectRecord`, and Objects nesting supported Attributes all
  return zero Evidence; `to_ids=false` and `deleted=true` Attributes still
  convert with state preserved; distribution `5` is preserved not
  resolved; distribution `4` + sharing group, Event distribution,
  ordered Event/Attribute tags, comments/object relation, and published
  metadata are preserved exactly;
- fact/determinism/generic seam (M32B-46..55): exact UTC `Z` timestamp
  format, canonical UUID strings, original source value retained
  separately from canonical `iocs`, immutable output, no verdict/risk/
  attribution synthesis, no local MISP numeric IDs or binary `data`;
  supported+unsupported+supported passes emit two outputs in source
  order, all-unsupported passes succeed empty, and one malformed
  supported record fails the whole pass with no partial API;
- parser-to-converter vertical slices (M32B-V01..V05): a synthetic ATI
  MISP Event through the **real** `parse_misp_event`, then the **real**
  registry and `convert_semantic_source_objects` — multiple supported
  Event Attributes emit in source order, `domain|ip` stays one
  Evidence/two IOC facts, unsupported types are skipped, deleted
  supported Attributes emit with `deleted=true`, and Object-only Events
  convert to successful empty output.

PR 32A MISP semantic suites (including Object distribution `5`), the
ThreatFox and generic converter/registry suites, and Evidence identity
tests remain green; no generic conversion contract is weakened for MISP.

### STIX 2.1 IOC Evidence conversion and pattern whitelist (PR 33B)

PR 33B adds the pure STIX 2.1 semantic-object -> `ConvertedEvidence` layer
over the reusable PR 33A seam. Two new offline suites:

- `tests/unit/infrastructure/datasources/test_stix21_pattern.py`
  (adapter matrix, 53 cases): the three-way whitelist-adapter verdict
  (SUPPORTED with ordered left-to-right decoded leaves /
  VALID_BUT_UNSUPPORTED with zero leaves / MALFORMED with the fixed safe
  `indicator_pattern_syntax` error kind), the exact approved
  equality-only leaf set, string-literal escape decoding, approved
  `AND`/`OR`/parenthesis composition order, duplicate-leaf preservation,
  whole-tree whitelisting (MATCHES/LIKE/ISSUBSET/ISSUPERSET/
  inequalities/sets/`!=`/`NOT`-prefixed operators, file/URL paths,
  indexes/wildcards/extension paths, non-string literals, `FOLLOWEDBY`,
  `WITHIN`, `REPEATS`), malformed syntax, and module isolation (no
  regex/string-splitting grammar, no network/clock/random imports, and
  the maintained `stix2patterns` parser is the only grammar boundary);
- `tests/unit/infrastructure/datasources/test_stix21_evidence.py`
  (M33B-01..78 + M33B-V01..V06, with ATI-authored synthetic fixtures in
  `tests/support/stix21_fixtures.py`):
  - registration/contract (M33B-01..04): the converter owns exactly
    `SemanticFormatId.STIX_21`; wrong Python source type and wrong
    semantic-format context raise bounded `ConversionError`; **no** fixed
    `SourceId` guard — a non-MITRE source identity with STIX format is
    accepted;
  - identity/provenance (M33B-05..10): repeated conversion yields the
    same UUID; a later `modified` never changes identity; the same STIX
    `id` under a different ATI source namespace yields a different UUID;
    `source_record_id` is the exact STIX `id`; retrieval-time-only
    changes never move the identity; no Investigation/subject identity
    in output;
  - direct SCOs (M33B-11..20): `domain-name` -> one canonical DOMAIN
    IOC; mixed-case/root-dot and IDNA domains canonicalize through
    `validate_dns_name`; malformed domains are `ConversionError`; IPv4
    canonicalizes, malformed IPv4 fails, an `ipv4-addr` carrying IPv6
    fails closed, IPv6 canonicalizes to its compressed form, and an
    `ipv6-addr` carrying IPv4 fails closed (IP family enforced);
  - unsupported objects (M33B-21..25): malware/relationship/sighting/
    attack-pattern/custom types each return zero Evidence;
  - indicator profile (M33B-26..48 + 72): single domain/IPv4/IPv6
    equality, approved OR/AND and nested parentheses preserve
    deterministic left-to-right order, duplicate leaves preserved, a
    malformed pattern raises `ConversionError`, MATCHES/LIKE/subset/
    superset/inequality/file/URL/mixed/FOLLOWEDBY/qualifiers/indexed/
    wildcard/extension/non-string-literal patterns return `()`, wrong
    `pattern_type` returns `()`, missing/non-string/blank pattern while
    `pattern_type=stix` fails closed, an admitted path with a malformed
    IOC value fails closed, the original pattern is preserved exactly,
    and a multi-leaf Indicator is still exactly **one**
    `ConvertedEvidence`;
  - facts/provenance (M33B-49..66): exact common and Indicator fact key
    sets, id/type/spec_version preserved, created/modified and
    valid_from/valid_until normalized to UTC `Z`, marking refs and
    granular markings preserved-not-dereferenced/not-enforced,
    confidence preserved as a source fact only, label/indicator_types
    order preserved, external references preserved, SCO `defanged`
    pinned, `observed_at is None`, `retrieved_at`/`source_url` exact
    context values, `raw_payload is None`, deeply immutable output, no
    verdict/risk/relationship synthesis, and bounded errors that never
    echo IOC/pattern/source content;
  - registry/generic seam/isolation (M33B-67..78): registry lookup by
    semantic format only, deterministic independent registry factories,
    supported-object source order through the real
    `convert_semantic_source_objects`, all-unsupported empty success,
    malformed-after-valid aborts with no partial result, multi-leaf
    Indicator as one Evidence, converter module isolation from HTTP/DB/
    broker/orchestration imports, PR 33A semantic-module
    Evidence-independence, no regex/string-splitting grammar, pattern
    adapter with no network/clock/random behavior, the bounded
    `stix2-patterns>=2.1.2,<3` dependency pinned in `pyproject.toml` +
    `uv.lock`, and MITRE batch-source isolation;
  - parser-to-converter vertical slices (M33B-V01..V06): synthetic
    decoded STIX objects through the **real** `parse_stix21_object()`
    (PR 33A), the **real** pattern-adapter parser, the **real**
    registry, and the **real** `convert_semantic_source_objects` —
    three direct SCOs in order, one supported Indicator stays one
    Evidence with ordered IOCs, mixed objects yield exactly three
    outputs in supported source order, a valid unsupported Indicator
    converts to zero, a malformed Indicator raises with no partial
    result, and version continuity keeps the same Evidence identity
    across changed material facts.

All fixtures are ATI-authored synthetic STIX (RFC 5737 / RFC 2606 / RFC
3849 documentation-safe values and fixed synthetic IDs); the **real**
pattern parser boundary is exercised (never faked except by the isolated
adapter tests, and no test contacts TAXII, MITRE, OASIS, or the
Internet). The mandatory acceptance topology runs the STIX semantic
(M33A) and evidence (M33B) suites together with
`tests/unit/app/test_evidence_conversion.py` (generic conversion),
`tests/unit/infrastructure/test_mitre_attack_source.py` (MITRE
compatibility), and the MISP Evidence (M32B) regression suite.

### Source-neutral CTI Entity expansion, extraction, and persistence (PR 33C)

PR 33C adds exactly five source-neutral CTI Entity types and their strict
machine-identity contracts (unit, offline, synthetic):

- `tests/unit/domain/test_canonicalization.py` (M33C-D01..D25): exact
  STIX machine IDs pass through unchanged for all five types; wrong
  prefixes, missing `--`, malformed/non-canonical UUIDs, surrounding
  whitespace, mutated prefixes, human names, and blank values fail
  closed; idempotency; same-name/different-ID identities stay distinct;
  every new enum has a registered canonicalizer; existing MALWARE /
  VULNERABILITY / ATT&CK / IOC contracts are regression-pinned; exact
  wire-value serialization;
- `tests/unit/infrastructure/datasources/test_stix21_evidence.py`
  (M33C-S01..S35 + M33C-V01): one Evidence per supported CTI SDO with
  exact Evidence/`source_record_id` identity, the exact `cti_entity`
  block (`type` wire value / exact machine value / verbatim
  `display_name`), same-name/different-ID non-merging, wrong-prefix and
  malformed IDs as bounded `ConversionError`, missing/non-string/
  blank/over-512-char names as bounded failure, errors that never echo
  source content, common STIX metadata preserved as in 33B, `iocs: []`
  and `indicator: null` for CTI SDOs, `cti_entity: null` for PR 33B
  IOC/Indicator Evidence, unsupported objects (relationship, sighting,
  attack-pattern, malware, vulnerability, custom) still returning `()`,
  the single-STIX-converter registry invariant, and converter isolation
  from persistence/graph imports;
- `tests/unit/app/extraction/test_stix_extraction.py` + message-context
  additions (M33C-X01..X34): one `ExtractedEntity` (exact type/value/
  display name) and zero relationships per CTI fact; malformed blocks,
  unknown CTI wire types, non-canonical/wrong-prefix values, and invalid
  display names fail closed with `MALFORMED_FACTS`; errors never echo
  source values; PR 33B direct domain/IP durable facts reconstruct;
  multi-leaf Indicators associate all canonical Entities in deterministic
  order with first-seen deduplication of duplicate leaves; no Indicator
  pattern reparsing; no `RelationshipAssertion` from CTI facts; no
  reference/alias/marking-derived entities or edges; durable message
  reconstruction derives the STIX invocation from the `cti_entity` fact
  or the first `iocs` entry (source-fact-derived, never fabricated);
- `tests/unit/app/test_investigation_submission.py` and
  `tests/unit/domain/test_investigation.py`: `INVESTIGATION_SEED_TYPES`
  is an explicit allowlist of the nine established seed types; the five
  CTI types are rejected at the application boundary as seeds (never
  provider/orchestration work) while established seed types keep their
  behavior; `pivot_class` coverage pins the established nine (unlisted
  types deterministically produce no provider/research work).

The PostgreSQL vertical slices (`tests/integration/test_stix_evidence_pipeline.py`, M33C-V01..V07) run every layer through its production
implementation over real PostgreSQL and the real durable-log seam
(`parse_stix21_object` -> real converter -> real PR 28C message codec ->
real message reconstruction -> real STIX extraction -> real
`EvidencePersistenceConsumer`/`EvidenceBatchPersistenceService`):

- M33C-V01: one `threat-actor` object closes the full pipeline — one
  Evidence, one EvidenceObservation, one THREAT_ACTOR Entity with the
  exact STIX ID canonical value and exact `name` display name, one
  `EvidenceObservationEntity` association, zero Relationships and zero
  RelationshipObservations;
- M33C-V02: one object of each of the five types persists five distinct
  typed Entities with exact values/names and zero graph edges;
- M33C-V03: same-name threat actors with different STIX IDs persist two
  Entities (mandatory anti-false-merge acceptance);
- M33C-V04: two material versions (same STIX ID + source namespace,
  changed `modified`/`name`) keep the same Evidence ID, append a second
  EvidenceObservation, keep one canonical Entity whose display metadata
  follows existing upsert semantics, associate both observations, and
  create zero relationships;
- M33C-V05: the same STIX ID under two ATI source namespaces produces two
  Evidence identities but one canonical (type, machine value) Entity,
  each observation associates to it, and no inferred equivalence
  Relationship is created;
- M33C-V06: a supported multi-leaf Indicator persists one Evidence, one
  observation, and all represented DOMAIN/IP Entities, with zero
  relationships;
- M33C-V07: generic graph/API projection — test-only relationship
  observations created through the authoritative persistence APIs let
  two new Entity types appear as graph nodes and pass through the
  generic `entity_type` filter with exact value/display name retention;
  STIX extraction itself never produces edges.

The API/frontend matrix (M33C-U01..U15) is covered by the regenerated
OpenAPI snapshot (`tests/unit/api/test_openapi.py`), the generated
`frontend/src/api/schema.generated.ts` (regenerated via `npm run
api:generate`; `api:check` verifies currency), the exhaustive
`ENTITY_TYPE_LABEL_KEYS` registry and the English `relationshipEvolution`
i18n labels for all five values, `GRAPH_ENTITY_TYPES` filter acceptance,
graph/render tests, and the untouched `ENTITY_TYPE_OPTIONS` Investigation
seed form. No CTI-specific endpoint, icon, or broad UI redesign is
introduced; type differentiation remains textual.

### Source-asserted relationships and STIX Sightings (PR 33D)

PR 33D adds the four source-neutral RelationshipType URNs (`USES`,
`TARGETS`, `ATTRIBUTED_TO`, `CONTROLS`), the stable `source_assertion`
normalized-fact key, and the bounded STIX 2.1 Relationship/Sighting
conversion+extraction+persistence profile over the existing global Evidence
path. Matrices are deterministic, offline where possible, and real-PG/real
Redpanda in the slices:

- `tests/unit/domain/test_relationship_types.py` (M33D-D01..D07): the
  four URNs are exact, all pre-existing URNs are byte-unchanged, the URNs
  are free-text for the generic persistence path (no migration), and the
  OpenAPI + frontend registries (`labels.ts`, `relationships.json`
  i18n) represent all four;
- `tests/unit/infrastructure/datasources/test_stix21_assertion_evidence.py`
  (M33D-R01..R38 + M33D-S01..S25): the exact §5.3 Relationship matrix
  (13 admitted pairs -> exactly one Evidence each with pinned normalized
  assertion facts), exact Evidence identity from the STIX Relationship ID
  + source namespace, `observed_at=None`, context retrieval provenance,
  normalized `start_time`/`stop_time` with ordering enforcement,
  same-edge/different-ID and different-namespace identity separation,
  admitted-prefix malformed UUID as bounded `ConversionError`, the
  no-echo error rule, `indicates`/`related-to`/malware/domain/attack-
  pattern/vulnerability endpoints and out-of-profile endpoint pairs as
  zero Evidence, blank/non-string `relationship_type` as bounded failure,
  the exact Sighting profile (one Evidence per CTI `sighting_of_ref`,
  pinned shape, normalized first/last, positive count, boolean summary,
  bounded ordered reference lists with the 256 maximum and malformed-
  member rejection, out-of-order rejection, malware/indicator/domain/IP
  sightings as zero), no synthetic Sighting edge, the converter's
  profile table and reference-list bound pinned to the extraction-side
  table/seam, and converter isolation from persistence/graph imports;
- `tests/unit/app/extraction/test_stix_assertion_extraction.py`
  (M33D-X01..X16): one Relationship assertion extracts exactly the two
  canonical endpoint Entities (first-seen source order) and one approved
  RelationshipAssertion in source-asserted direction; a Sighting extracts
  exactly the sighted Entity and zero assertions; `where_sighted_refs` /
  `observed_data_refs` create no Entity or edge; self-edges, tampered
  STIX/ATI mapping pairs, inconsistent endpoint types, unknown kinds,
  contradictory profiles (assertion + `cti_entity` or nonempty `iocs`),
  and missing/mismatched bodies fail closed with `MALFORMED_FACTS`
  without echoing content; the legacy IOC/CTI-SDO paths and the pure-
  no-I/O module guarantee stay intact;
- `tests/unit/app/extraction/test_stix_assertion_message_context.py`
  (M33D-M01..M13): a Relationship derives its transient invocation Entity
  from the durable **source endpoint**, a Sighting from `sighting_of`;
  assertion + `cti_entity`, assertion + nonempty `iocs`, unknown kinds,
  missing/mismatched relationship/sighting bodies, and tampered endpoint
  canonicality fail closed with `MalformedMessageExtractionError` without
  echoing content; the old IOC and CTI-SDO paths are unchanged.

The PostgreSQL vertical slices
(`tests/integration/test_stix_assertion_pipeline.py`, M33D-V01..V10) run
the same real all-production slice as M33C-V01..V07 over real PostgreSQL:

- M33D-V01: threat actor USES tool — one Evidence, one
  EvidenceObservation, two canonical Entities with two `
  EvidenceObservationEntity` associations, one `USES` Relationship A->B,
  one RelationshipObservation whose `evidence_observation_id` equals the
  exact persisted observation ID, `observed_at` null, `retrieved_at` from
  the context, `source` the ATI source namespace;
- M33D-V02: one supported assertion of each of the four relationship types
  persists the four exact URNs with asserted directions;
- M33D-V03: the same semantic edge asserted by two different STIX
  Relationship IDs yields two Evidence identities, two observations, one
  stable Relationship, and two RelationshipObservations with distinct
  per-Evidence provenance;
- M33D-V04: the same Relationship ID with same edge but later material
  `modified`/`start_time`/`stop_time` appends a second observation and a
  second RelationshipObservation reusing the one Relationship;
- M33D-V05: the same Relationship ID changing its semantic edge
  (A USES tool B -> A USES infrastructure C) keeps one Evidence identity,
  appends a new observation, and preserves the old Relationship without
  deletion or end inference;
- M33D-V06: a Sighting with full first/last/count/summary/reference facts
  persists one Evidence + observation + one sighted Entity association
  and zero Relationship/RelationshipObservation rows;
- M33D-V07: a later Sighting material version appends a second observation
  and associates the same canonical Entity, still with zero graph edges;
- M33D-V08: a mixed batch of supported Relationship / unsupported
  `indicates` / supported Sighting / malware Sighting converts exactly
  two messages and persists only the supported structure;
- M33D-V09: the same Relationship ID + edge under two ATI source
  namespaces yields two Evidence identities and two
  RelationshipObservations sharing the one canonical Relationship;
- M33D-V10: a batch containing a valid supported Relationship message and
  a tampered assertion message fails atomically in consumer preflight
  with zero PostgreSQL rows (no partial write, no receipt).

The distributed durable-ingestion acceptance
(`tests/integration/kafka/test_stix_assertion_distributed_ingestion.py`,
M33D-K01..K03) reuses the existing real Redpanda + PostgreSQL harness:

- M33D-K01: a Relationship published through `EvidencePublisher` -> real
  Redpanda -> `EvidencePersistenceConsumer` -> real PostgreSQL persists
  the full V01 result (evidence, observation, both endpoint Entities,
  one Relationship, one RelationshipObservation with exact observation
  provenance);
- M33D-K02: a Sighting persists evidence + observation + sighted Entity
  association with zero relationship rows, and `first_seen`/`last_seen`
  never become an ATI observation time;
- M33D-K03: a tampered assertion fails consumer preflight before any
  PostgreSQL write and the Kafka position stays uncommitted — a
  same-group reader still sees the message for redelivery.

### Native MISP REST acquisition (PR 32C)

PR 32C adds bounded native MISP Event acquisition tests
(`tests/unit/infrastructure/datasources/test_misp_acquisition.py`, M32C-01..60
+ M32C-V01..V05, config matrix M32C-C01..C10 in
`tests/unit/config/test_misp_settings.py`, with PR 32C fixture additions in
`tests/support/misp_fixtures.py`). Everything fakes only the external HTTPS
boundary (in-process `httpx.MockTransport`) and runs the real
`ProviderHttpClient`, the real `MispDatasource`, the real REST-envelope
adapter, and the real PR 32A `parse_misp_event`; no test contacts a live
MISP server and no test reads the wall clock or sleeps for timing:

- configuration/construction (M32C-01..10): HTTPS base URL joins the
  canonical `https://misp.example.test/events/restSearch` endpoint; HTTP/
  credentialed/query/fragment URLs fail; blank resolved keys fail;
  composition resolves the `SecretsResolver` reference into the exact
  `Authorization` value and a missing key raises `SecretNotFoundError`
  before any I/O; defaults are pinned; invalid page/window bounds fail;
  environment values beat profile values;
- definition guards (M32C-11..15): MISP/HTTPS/JSON/MISP is accepted and
  every wrong dimension fails before any request;
- request/security (M32C-16..22): `POST` to the exact `restSearch`
  endpoint with the key only in `Authorization`, JSON `Accept`/`Content-`
  `Type`, exact `{"page": N, "limit": L}` bodies, a credential-free
  `SemanticSourceContext`, and no key/body leakage into errors, events, or
  context;
- envelope/parser reuse (M32C-23..31): one Event equals the direct
  `parse_misp_event` output; multiple Events preserve order; empty pages
  are successful empty; invalid roots, missing/`non-list` `response`
  members, non-object Events, and malformed Event semantics fail with the
  bounded `SEMANTIC_VALIDATION` error and zero objects; supported +
  unsupported Attribute types and Event Objects are all transported;
- pagination (M32C-32..42): short-first-page one request; full-then-short
  two requests; empty-page stop; all-full pages stop at exactly
  `max_pages` with no `max_pages+1` probe; deterministic cross-page order;
  later-page HTTP/envelope/Event failures leak zero objects; request
  bodies carry pages `1..N` with a constant limit; `ACQUIRED` carries the
  exact successful-page byte sum; raw page payloads are never retained;
- HTTP mapping (M32C-43..50): timeout, 429/Retry-After, 401/403/404,
  exhausted 5xx, malformed JSON/media, and oversized responses map to the
  bounded typed `DatasourceStageError` outcomes with exact retryability,
  never by matching free-form message text;
- cancellation/determinism (M32C-51..60): cancellation during a request or
  limiter wait propagates (`CancelledError`, recorder CANCELLED in the
  runner), cancelling before page 2 yields no successful result, identical
  inputs yield structurally equal results, acquisition returns only typed
  MISP semantic records and performs no persistence beyond lifecycle
  appends, the real parser is exercised end to end, no second concurrency
  wrapper is stacked, and at most one page request is ever in flight;
- acquisition vertical slices (M32C-V01..V05): ATI-authored REST fixtures
  -> controlled external HTTP boundary -> real `ProviderHttpClient` -> real
  `MispDatasource` -> real REST adapter -> real `parse_misp_event` ->
  `SemanticAcquisitionResult`, covering one-page acquisition with exact
  request/context/record assertions, two-page deterministic flattening,
  later-page failure atomicity, semantic-failure atomicity, and the
  max-window bound without extra probing;
- config matrix (M32C-C01..C10): exact PR 32C defaults, environment
  precedence for the base URL and the secret reference (never the key
  value itself), legal/illegal page bounds, concurrency and request-rate
  bounds, safe malformed-URL rejection, and the guarantee that an unset
  MISP URL keeps ordinary fake/local startup legal before PR 32D without
  composing any MISP datasource or requiring the MISP key.

### MISP collection runtime and Evidence closure (PR 32D)

PR 32D closes the MISP collection runtime through the source-neutral
producer and the existing distributed Evidence pipeline. Deterministic
unit/offline matrices:

- collection producer (`tests/unit/app/test_collection_datasource_evidence_producer.py`,
  P01..P16): one converted object -> `CONVERTED(1)`/one publish/
  `PUBLISHED(1)`/`COMPLETED`; multiple objects keep deterministic
  sequence/order; zero conversion -> `publish(())`/`PUBLISHED(0)`/
  `COMPLETED`; typed acquisition failure -> exact bounded `FAILED` code
  with no publish; acquisition exception -> `unexpected_error` re-raised;
  conversion failure -> `conversion_failed` (no publish); message
  construction failure -> `message_construction_failed`; publisher failure
  -> `publication_failed` without `COMPLETED`; cancellation in acquisition
  and publication -> `CANCELLED` and propagate; lifecycle append failure
  after publish -> no republish; execution-ID propagation to recorder and
  messages; flattening order unchanged; lifecycle-UoW-only with no
  Evidence persistence and no transaction open across HTTP; unchanged
  entity-producer regression; and the explicit no-Entity/no-`supports`
  collection contract (the real `MispDatasource` satisfies the protocol
  structurally).
- MISP durable-message extraction (`tests/unit/app/extraction/test_misp_message_context.py`,
  X01..X18): canonical DOMAIN invocation; hostname-produced facts are
  DOMAIN; IPv4/IPv6 -> IP_ADDRESS; domain+IP preserves both Entities with
  zero relationships; missing/empty/non-array/non-object/unknown-type/
  malformed/noncanonical/duplicate `facts.iocs` fail closed; MISP format
  with a wrong source and MISP source with a wrong format fail closed;
  and the ThreatFox reconstruction/extraction path regression is
  unchanged. Dispatch is by the exact `(semantic_format, source)` pair
  only.
- composition (`tests/unit/infrastructure/providers/test_misp_collection_composition.py`,
  C01..C10): blank URL -> no producer without a key requirement; URL +
  exact MISP definition -> composed; URL + missing definition -> fail
  before acquisition; ambiguous (multiple MISP) definitions -> fail
  closed; wrong protocol/serialization/semantic format/source -> fail; the
  real MISP conversion registry is selected by `SemanticFormatId.MISP`
  only; and `ProviderComposition.provider_registry()` has no MISP entry.

Real-stack vertical slices (only external MISP HTTPS is faked, in-process
`httpx.MockTransport`):

- V01..V05 (`tests/integration/test_misp_evidence_pipeline.py`, real
  PostgreSQL + `InMemoryEvidenceLog`): MISP fixture -> real
  `ProviderHttpClient` -> real `MispDatasource` -> real `parse_misp_event`
  -> real `MispToEvidenceConverter` -> real collection producer -> real
  `EvidenceMessage` -> real consumer -> real `EvidenceBatchPersistenceService`
  -> real PostgreSQL. V01 asserts the exact
  `STARTED, ACQUIRED, DECODED, CONVERTED(1), PUBLISHED(1), COMPLETED`
  lifecycle, one global Evidence with the exact Attribute UUID identity,
  one Observation with exact `observed_at`/`retrieved_at`/credential-free
  provenance, normalized facts with `raw_payload IS NULL`, canonical DOMAIN
  association, zero relationships, and zero `InvestigationEvidence`; V02 is
  canonical IPv6; V03 is `domain|ip` with two Entity associations and zero
  relationships; V04 is a supported + unsupported + Object mix that
  persists only the supported Event-level Evidence; V05 is an
  unsupported/Object-only input yielding `CONVERTED(0)`, `PUBLISHED(0)`,
  `COMPLETED` and no Evidence.
- K01..K06 (`tests/integration/kafka/test_misp_distributed_ingestion.py`,
  mandatory feature acceptance with real Redpanda + real PostgreSQL,
  reusing the PR 28G/28H topology): K01 complete domain pipeline with
  broker processing and committed Evidence/Observation/Entity; K02
  multi-message distinct Attribute-UUID identities (no cross-partition
  order claims); K03 replay/idempotency through the
  PostgreSQL-commit/Kafka-commit-failure seam (no duplicate Evidence,
  Observation, Entity association, or receipt; final poll empty); K04
  unchanged material state in a new execution (new receipt, UNCHANGED, no
  new Observation); K05 a material change under the global state contract
  (same Evidence, next Observation version, PostgreSQL-owned diff, exact
  authoritative observation references); K06 pre-commit persistence failure
  with broker uncommitted until the retry's PostgreSQL commit succeeds.

### TAXII 2.1 acquisition and runtime integration (PR 33E)

Deterministic unit/offline matrices (only the external TAXII 2.1 HTTPS
boundary is faked, via in-process `httpx.MockTransport` that speaks the
real wire contract):

- protocol/envelope (`tests/unit/infrastructure/datasources/test_taxii21.py`,
  T33E-P01..P18): empty envelope is valid empty semantics; one/multiple
  objects preserve order exactly; `more=true` requires a nonblank opaque
  `next`; malformed roots/non-array `objects` fail closed; non-object and
  malformed STIX members fail the whole acquisition semantically; a valid
  unsupported STIX object is accepted (converter yields zero later); a
  Bundle member is rejected by the direct object boundary (never
  fake-wrapped); opaque punctuation-bearing `next` round-trips verbatim;
  `application/taxii+json;version=2.1` is accepted and incompatible
  content types are bounded serialization failures; date-added headers
  canonicalize and malformed values fail closed; server error bodies never
  leak into outcomes.
- acquisition/pagination (`test_taxii21.py`, T33E-A01..A20): no
  checkpoint -> no `added_after`; configured initial cursor sent; durable
  checkpoint wins; 2-3 page runs pass the exact `next` tokens in strict
  order; `max_pages` reached with `more=true` is a successful bounded
  window with no extra request; empty first page is successful empty;
  401/403/404/429/timeout map to bounded codes; a malformed later page or
  later-page STIX member yields zero semantic objects overall; cancellation
  propagates unchanged; pages are strictly sequential (single in-flight
  request, no second limiter); the bearer token travels only in the
  `Authorization` header; public collections send no header; the
  source reference is credential-free with no incremental cursor state.
- checkpoint semantics (`tests/unit/app/test_taxii_checkpoint_commit.py`,
  T33E-C01..C20): the durable checkpoint advances only after a successful
  publish; HTTP/STIX/conversion/publication/PUBLISHED-append failures leave
  it unchanged; checkpoint-DB failure after publish fails the call and
  permits replay; COMPLETED-append failure keeps the (already advanced)
  checkpoint without republishing; older candidates are rejected and equal
  candidates are idempotent no-ops; stale expectations conflict without
  overwrite; `next` is never a durable checkpoint value; STIX `modified`
  and ATI `retrieved_at` never drive the cursor; cancellation before the
  commit leaves the checkpoint unchanged.
- settings (`tests/unit/config/test_taxii_settings.py`) and composition
  (`tests/unit/infrastructure/providers/test_taxii_collection_composition.py`,
  T33E-R01..R15): blank URL -> no producer/token; URL + exact definition
  composes; missing/ambiguous definitions fail closed; the MITRE ATT&CK
  FILE STIX definition can never be selected; HTTPS/FILE instead of
  TAXII_21, non-JSON, and non-STIX dimensions fail closed; OpenCTI is pure
  provenance and another explicit source works generically; a missing
  bearer secret fails at composition before HTTP; the converter registry is
  selected only by STIX_21; TAXII/OpenCTI is absent from the Investigation
  provider registry.
- checkpoint DB matrix (`tests/integration/test_datasource_checkpoint.py`,
  T33E-DB01..DB10, real PostgreSQL): absent read is `None`; first advance
  creates version 1; equal advance is an idempotent no-op; a later advance
  bumps the version; an earlier TAXII date-added candidate is rejected by
  the kind adapter (never a generic lexical rule); a stale
  compare-and-advance conflicts without overwrite; datasource and kind
  isolation; oversized values are rejected; the schema exposes exactly the
  bounded operational columns.

Real-stack vertical slices (`tests/integration/test_taxii_evidence_pipeline.py`,
V01..V14, real PostgreSQL + `InMemoryEvidenceLog`): IOC ingestion, the five
CTI SDO types, Relationship ingestion with exact observation provenance,
Sighting stays Evidence + entity association with zero edges,
mixed supported/unsupported (unsupported = zero Evidence), cross-page
request/message order, the incremental second execution using the durable
checkpoint, publisher failure without advancement, checkpoint-commit
failure after broker publication (no rollback, no republish, replay
legal), replay idempotency with stable deterministic identity, bounded
max-pages windows advancing only through admitted pages, malformed later
page atomicity (zero Evidence, unchanged checkpoint), source-namespace
separation (same STIX ID in OpenCTI and another source: separate Evidence,
shared Entity), and unresolved-reference safety (no placeholder
Entity/edge).

## OpenCTI interoperability harness (PR 33E section 10)

The **separate, explicit OpenCTI interoperability gate** is NOT part of
ordinary `./build.sh --intg` (normal integration stays deterministic and
OpenCTI-free). Entry point:

```bash
./scripts/opencti-integration.sh
# optional flags: --keep-on-failure --incremental --timeout <seconds>
```

Topology (pinned images only): `opencti/platform:6.9.29` +
`opencti/worker:6.9.29` + `opencti/connector-import-file-stix:6.9.29`
+ `redis:8.10.1` + `docker.elastic.co/elasticsearch/elasticsearch:8.19.21`
+ `rabbitmq:4.3-management` + `nginx:1.27.5` (TLS terminator for the
credential-free HTTPS production client) + `chrislusf/seaweedfs:4.48`
(S3-compatible object store; MinIO archived its open-source server and
revoked public container pulls, so the harness substitutes SeaweedFS's
S3 gateway, path-style addressing like OpenCTI's `forcePathStyle`) +
ATI PostgreSQL + ATI Redpanda.
The harness owns its Compose project, random host ports, synthetic random
credentials, and an ATI-authored deterministic STIX fake world
(`tests/interop/opencti/fixtures/opencti_fake_world.py`), whose fixed IDs
and the expected-state manifest are consumed by both the readiness barrier
and the assertion suite.

Flow: start isolated topology -> wait infrastructure health -> bootstrap
OpenCTI (admin user, TAXII collection, restricted consumer bearer token
via the standard GraphQL surface) -> seed fixtures (bundle stored through
6.9's `uploadImport` and dispatched with `askJobImport(bypassValidation:
true)` to the `INTERNAL_IMPORT_FILE` connector; the one-call
`uploadAndAskJobImport` mutation hardcodes `forceValidation: true` and
routes into the validation workbench so it never materializes bundles,
verified against the pinned platform source) -> wait real TAXII feed
convergence -> resolve the seed -> OpenCTI canonical identity mapping from
OpenCTI materialization state (`x_opencti_stix_ids` -> `standard_id`) and
verify every canonical identity (including relationship endpoints and the
Sighting references) against the real TAXII collection -> run the
production `Taxii21Datasource`/producer over real Redpanda -> wait the
PostgreSQL-backed ingestion-completion barrier
(`tests/interop/opencti/status.py --wait`, exit 0 only for
`READY_FOR_ASSERTIONS`; never fixed sleeps) -> only then run the interop
assertion suite (`pytest tests/interop -m interop`) -> collect evidence ->
teardown. `--incremental` additionally seeds v2 objects and proves the
second acquisition uses the durable checkpoint. `--keep-on-failure` retains
the topology; `status.py --diagnose` collects a bounded diagnostic bundle
under `artifacts/opencti-interop/<run-id>/` (gitignored) that classifies
the failure stage/root cause without ever printing credentials or raw
payloads.

### Seed -> canonical identity mapping (PR 33E-1 Option C)

Real OpenCTI 6.9 regenerates deterministic `standard_id`s (UUIDv5) and
never preserves external STIX IDs in its TAXII export; the fixture seed IDs
are kept only in the platform's durable materialization state
(`x_opencti_stix_ids`). The harness therefore:

1. establishes the seed -> canonical mapping from OpenCTI materialization
   state (Elasticsearch `x_opencti_stix_ids.keyword`, published on a
   per-run randomized host port for the identity resolver only), never by
   accepting arbitrary TAXII output;
2. independently verifies every mapped canonical identity appears in the
   real TAXII collection, that the four legal Relationship instances'
   `source_ref`/`target_ref` and the Sighting's `sighting_of_ref` /
   `where_sighted_refs` are all rewritten to canonical identities, and that
   REJECTED_BY_OPENCTI_PROFILE objects stayed out of both ES and the feed;
3. builds the canonical manifests (`manifest-v1-canonical.json`,
   `manifest-v2-canonical.json`) that drive the readiness barrier and the
   assertion suite, so ATI `source_record_id` and CTI Entity canonical
   identities are exactly the identities ATI received through TAXII.

The fixture partitions every seeded object into - present in the manifest -
`MATERIALIZABLE_AND_ATI_SUPPORTED`, `MATERIALIZABLE_BUT_ATI_UNSUPPORTED`,
and `REJECTED_BY_OPENCTI_PROFILE`. Rejected objects (real OpenCTI 6.9's
relationship-schema matrix rejects `targets` toward Infrastructure and
`controls` from Intrusion-Set for the supported CTI types; the unresolved-
reference relationship fails with `MISSING_REFERENCE_ERROR`) are **never**
counted as ATI unsupported-object coverage; the Sighting carries the STIX
2.1-required `where_sighted_refs` (a deterministic Identity, which is
itself ATI-unsupported and must produce zero semantics beyond the Sighting
handling). Ground truth was verified empirically on a live pinned stack:
all 16 materializable objects materialize and export with canonical IDs and
canonical refs; the three rejected relationships are absent from ES and the
feed.

Seed-availability machinery: the seeder waits for the ATI worker to bind
its RabbitMQ push queue (worker-mailbox gate) so the connector's bundle
publish is never dropped by a not-yet-bound exchange route, and the import
job must be dispatched with `forceValidation: false`/`bypassValidation:
true` (PR 33E-1 import-path fix).

OpenCTI 6.9 API deltas the harness accommodates (verified against the
pinned image): the platform health endpoint requires the configured
`?health_access_key=` query parameter; the TAXII 2.1 server is rooted at
`/taxii2/root/` (not `/taxii2/`); `APP__ADMIN__TOKEN` must be a strict
UUIDv4; bundle ingestion uses the supported two-step surface - `uploadImport`
(file only) followed by `askJobImport(bypassValidation: true,
forceValidation: false)` - because the legacy `importBundle` mutation and
`authTokenAdd` are gone (replaced by `userEdit { tokenRenew { api_token } }`)
and the one-call `uploadAndAskJobImport` hardcodes `forceValidation: true`
(workbench detour, no materialization); the worker reads
`OPENCTI_URL`/`OPENCTI_TOKEN` (+ the import connector process must run as
its own service); the seeder waits for the worker's RabbitMQ push-queue
consumer before seeding (worker-mailbox gate); fixture STIX IDs must be
RFC 4122 UUIDv4 (the platform validates every incoming id with
`uuidValidate`); OpenCTI regenerates canonical `standard_id`s on export
(seed -> canonical mapping, see above); its relationship-schema matrix
rejects `targets`/`controls` for the supported CTI type pairs and the
STIX Sighting requires `where_sighted_refs` (all verified in the pinned
source and live). The readiness barrier and assertion suite consume the
canonical manifests and the recorded `identity_map`/`feed_verification`;
OpenCTI-rejected objects are tracked as REJECTED_BY_OPENCTI_PROFILE and
ever asserted as nothing but absent.

Orchestration-state machine unit tests O01..O14
(`tests/unit/infrastructure/test_opencti_interop_status.py`) prove the
gate ordering with fabricated probes: seed-accepted-but-feed-not-visible
waits; feed-visible-producer-running waits; producer-COMPLETED-consumer-
incomplete waits; broker-drained-but-rows-absent never READY; all-durable-
state-present is READY; FAILED/CANCELLED datasource and consumer failures
are terminal; hard timeouts diagnose non-zero; unrelated traffic is
ignored; unsupported fixtures converge per manifest; checkpoint
expectations gate readiness; status reruns recover the same durable stage.

MITRE regressions unchanged: STIX-parser reuse in the batch source keeps
`SourceRecord` identities, canonical payloads, content hashes, and
checkpoints identical across the unit source tests, the ATT&CK ingestion
suite, and the real-format vertical slice.

### Semantic-format-driven Evidence conversion (PR 27D)

PR 27D tests are deterministic and offline; only the external Internet
endpoint is faked via in-process `httpx.MockTransport`:

- generic conversion contracts (`tests/unit/app/test_evidence_conversion.py`,
  D27D-C01..C10): immutable `EvidenceConversionContext` with exact
  Investigation/subject/semantic-context preservation, legal zero/one/
  multiple Evidence cardinality, deterministic flattening of multiple
  source objects (source-object order then converter-return order),
  structural repeatability of identical conversions, and deterministic
  local `ConversionError` failure;
- converter registry (`tests/unit/app/test_evidence_conversion.py`,
  D27D-R01..R10): lookup keyed only by `SemanticFormatId`; duplicate
  registration fails construction; unknown formats raise the typed
  `UnknownSemanticFormatError`; changed SourceId/protocol/serialization/
  datasource ID never select; misleading object shapes never fall back;
  and a wrong object for the selected converter fails closed;
- ThreatFox converter (`tests/unit/infrastructure/datasources/test_threatfox_evidence.py`,
  D27D-T01..T20): one validated `ThreatFoxRecord` -> one immutable
  `THREAT_INTELLIGENCE` Evidence with exact Investigation/subject/source
  URN/retrieved_at/observed_at/credential-free reference provenance,
  shared legacy-format match facts (identical to the legacy provider),
  source-confidence-as-source-fact, preserved tags/reference/nulls,
  `raw_payload=None`, `source_record_id` = exact upstream record ID,
  immutability, no credentials, no analytical inference, structural
  repeatability, and fail-closed wrong-format/wrong-object handling;
- legacy compatibility (D27D-L01..L08): the existing ThreatFox provider
  suites (`tests/unit/infrastructure/providers/test_threatfox*.py` and the
  extraction regression suite) remain green and assert the unchanged
  grouped-evidence shape, no-result/malformed/rate-limit/unsupported
  behaviors, and unchanged downstream extraction;
- conversion lifecycle (`tests/unit/infrastructure/datasources/test_threatfox_evidence.py`,
  D27D-E01..E06): typed `DatasourceStage.CONVERSION`, runner lifecycles
  over an in-memory UnitOfWork — success with `CONVERTED(item_count=N)`,
  valid no-result `CONVERTED(0)` then COMPLETED, converter violation
  `FAILED(conversion_failed)` with no CONVERTED/COMPLETED and no exception
  text, bounded durable error code, one execution ID, short committed
  transactions with no UoW held across HTTP/parsing/conversion, and
  cancellation (CANCELLED recorded, `CancelledError` propagates);
- the canonical real-PostgreSQL conversion-lifecycle slice
  (`tests/integration/test_datasource_evidence_conversion.py`, D27D-I01..I06):
  deterministic local ThreatFox HTTP fixture -> real `ProviderHttpClient`
  -> real `ThreatFoxDatasource` -> real semantic parser -> real
  `SemanticSourceContext` -> real `ToEvidenceConverterRegistry` -> real
  `ThreatFoxToEvidenceConverter` -> in-memory Evidence -> real
  `DatasourceExecutionRecorder` -> real `PostgresUnitOfWork` -> real
  stored function -> real `ati.datasource_log` (only the external Internet
  endpoint is faked): one-record success (exact provenance,
  STARTED/ACQUIRED/DECODED/CONVERTED(1)/COMPLETED, one execution ID, no
  Evidence persisted), valid no-result (`CONVERTED(0)`), two records ->
  two Evidence in source order, conversion failure (bounded
  `conversion_failed`, no CONVERTED/COMPLETED, no exception text),
  cancellation (CANCELLED, propagates), and minimization (Auth-Key, raw
  body, credential-bearing URL, and exception text absent from durable
  logs and Evidence).

### Runtime datasource migration (PR 27E)

PR 27E tests are deterministic and offline; only the external ThreatFox
endpoint is faked via in-process `httpx.MockTransport`:

- datasource-backed provider matrix (`tests/unit/app/test_datasource_provider.py`,
  D27E-A01..A10, E01..E10, T01..T10, L01..L06, U01..U07): the real
  `ThreatFoxDatasource`/`ProviderHttpClient`/converter/recorder over an
  in-memory UnitOfWork fake and the real `ProviderWorkExecutor` with fake
  reader/persistence/timeline seams — provider identity, legacy-identical
  `supports()`, no-I/O for unsupported/malformed inputs, exact
  Investigation/subject binding and signalled `DatasourceDefinition`,
  semantic-format-only converter selection (a registry owning an
  unrelated format fails closed), empty-result success, typed error
  mapping (timeout/429/auth/forbidden/malformed JSON/semantic invalid),
  bounded `conversion_failed`, message-independent classification,
  secret-bearing exceptions never persisted, cancellation stays CANCELLED
  and propagates, per-record Evidence provenance (exact
  `source_record_id`, per-record `observed_at`/facts, `raw_payload=None`,
  no synthesized inference), full/3-Evidence/no-result/conversion-failure/
  persistence-failure/cancellation lifecycles, and deterministic UoW
  probes (no UoW across target read/HTTP/conversion/extraction; one
  distinct persistence call per Evidence in provider order; lifecycle
  events never multiplied per Evidence; binding failure fails the
  lifecycle with `provider_binding_failed` and writes nothing);
- real-PostgreSQL vertical slices (`tests/integration/test_datasource_provider_runtime.py`,
  D27E-P01..P09): persisted Investigation + Entity -> real
  `ProviderWorkExecutor` -> migrated datasource-backed ThreatFox provider
  -> real extractor -> real `ProviderObservationPersistenceService` ->
  real `PostgresUnitOfWork`/stored functions — one-record (exact
  provenance, graph/audit rows, one STARTED + one terminal lifecycle),
  two records (per-record Evidence IDs and RelationshipObservation rows,
  one CONVERTED(count=2), one COMPLETED), no-result (CONVERTED(0),
  COMPLETED, nothing persisted), cross-Investigation and subject binding
  fail-closed (no observation written, FAILED with
  `provider_binding_failed`), later-item persistence failure (E1 committed,
  E2 rolled back, FAILED with `persistence_failed`, outcome retains E1),
  extraction failure (nothing persisted for the failed item), acquisition
  cancellation (CANCELLED, propagates, no Evidence), and lifecycle DB
  invariants (one STARTED, one terminal, stable execution/datasource
  identity, append-after-terminal rejected by the stored function);
- batch transaction regression (`tests/integration/test_batch_source_transaction_regression.py`,
  D27E-B01..B10): one batch commits records + checkpoint atomically; two
  batches commit one UoW per batch; batch-2 failure leaves batch-1 durable
  and batch-2 fully rolled back; restart resumes from the last committed
  checkpoint; a completed artifact short-circuits; a conflicting batch
  rolls back data + checkpoint; and ingestion writes zero
  `ati.datasource_log` rows. MITRE identity/hash/normalization/checkpoint
  stability is pinned by the existing MITRE suites (D27E-B09/B10).

### Evidence message wire contract (PR 28C)

PR 28C tests are deterministic, offline, and involve no database, network,
broker, or UnitOfWork. `tests/unit/app/test_evidence_message.py` pins the
E28C matrix:

- identity (E28C-I01..I10): deterministic UUIDv5 `message_id` over
  execution + flattened sequence + Evidence identity, deterministic
  `observation_candidate_id` derived from the message identity,
  tuple-reactive identity changes, retrieval-time independence, no broker
  metadata dependence, Evidence identity free of schema representation,
  and negative-sequence rejection;
- builder/binding (E28C-B01..B16): exact V1 mapping from
  `ConvertedEvidence` + `SemanticSourceContext` + execution ID + sequence,
  fail-closed Evidence/candidate/source cross-binding, empty record
  identity and empty source URL rejection, naive timestamp rejection,
  nullable `observed_at`/`raw_payload`, empty facts, deterministic
  flattened 0..N-1 sequences, and boolean `schema_version` rejection;
- round trips (E28C-R01..R06): message -> bytes -> message and
  `ConvertedEvidence` -> message -> `ConvertedEvidence` equality, exact
  nested JSON, UTF-8 Unicode, microsecond precision, and non-UTC aware
  timestamp canonicalization;
- canonical encoding (E28C-S01..S09): byte-identical repeated encoding,
  facts/raw-payload insertion-order independence, canonical lowercase
  UUID strings, stable enum URNs, pinned JSON nulls, and NaN/Infinity/
  arbitrary-object rejection;
- PR 28F-1 canonical oracle: golden V1 bytes pin the stdlib `json` codec
  (F1-E01..E10) — the encoder probe proved `orjson` cannot reproduce the
  canonical float scientific notation (`1.2e-07` vs `1.2e-7`) or parse
  beyond-64-bit integers exactly, so the EvidenceMessage codec is
  deliberately retained on Python's standard library in both directions;
- strict decode (E28C-D01..D18): malformed JSON/UTF-8 -> decode error,
  missing/non-integer/zero/bool/string/float/version-2 schema handling
  (unsupported-version vs validation error), extra-field rejection,
  malformed UUID/timestamp rejection, identity-mismatch rejection,
  facts-array/raw-payload-scalar rejection, missing-provenance rejection,
  non-standard JSON constants rejected as malformed, non-string
  `datasource_id` rejection, and bounded error text that never echoes the
  raw payload;
- contract boundary (E28C-P01..P08): no Investigation/subject/graph/
  broker/generic-metadata state, reconstructed candidate carries no
  Observation version/diff, and material-state equality under retrieval-
  time-only change;
- ThreatFox vertical slices (E28C-V01..V03): production
  `ThreatFoxToEvidenceConverter` -> builder -> canonical encode -> strict
  decode -> reconstruction with the canonical synthetic AsyncRAT fixture
  (stable Evidence identity, exact source record, bounded provenance,
  no DB/network); deterministic slot replay; and a later unchanged
  acquisition keeping Evidence identity with distinct message/candidate
  identities and equal `EvidenceMaterialState` (no DB behavior is tested
  here — that stays PR 28E).

### Distributed-log contracts and in-memory log (PR 28D)

PR 28D tests are deterministic, offline, and involve no database, network,
broker, sleep, random failure, or UnitOfWork. `tests/unit/app/
test_evidence_log.py` drives the real PR 28C `EvidenceMessage` builder and
pins the E28D matrix plus the D28D vertical slices:

- contract/value (E28D-C01..08): negative positions rejected, immutable
  comparable positions, blank and oversized consumer identities rejected,
  records carrying exact PR 28C messages, immutable batch tuples, in-memory
  handles conforming to the `EvidencePublisher`/`EvidenceConsumer` ABCs,
  and no Kafka/topic/partition/offset/group fields anywhere;
- publication (E28D-P01..P09): first position 0, contiguous ordered
  multi-message runs, position continuation, empty publish as a documented
  no-op, fail-next-publish as a typed error with no append or gap, retry
  from the original next position, the same message published twice
  creating two records (the log never deduplicates), concurrent publishes
  keeping unique contiguous positions with per-call order, and
  non-`EvidenceMessage` element rejection;
- poll/redelivery (E28D-R01..R13): empty poll, bounded prefixes, larger
  bounds, poll never advancing the cursor, repeat-before-commit returning
  the identical batch, zero/negative bounds rejected without mutation,
  exact commit advance, poll-after-commit, final commit, append after
  catch-up, handle recreation after commit resuming the cursor, and
  handle recreation after an uncommitted poll redelivering the batch;
- commit validation (E28D-K01..K11): empty-batch no-op, foreign-consumer
  rejection, skipped positions rejected, strict stale/repeat policy
  (an exact already-committed batch is rejected with the documented
  error), non-contiguous and reversed batches rejected, a forged record at
  a valid position rejected, a contiguous position beyond the log
  rejected, cursor unchanged after every failed validation, and the
  prefix-commit policy (committing a strict prefix of a larger poll is a
  valid whole-batch commit that advances exactly past the batch's final
  record; the remaining record stays redeliverable with no partial-ack
  state);
- consumer independence (E28D-G01..G05): shared initial prefix, A's
  commit never moving B's cursor and vice versa, two handles with the
  same identity sharing one cursor, and different identities keeping
  independent cursors;
- failure injection (E28D-F01..F09): one-shot `fail_next_publish` raising
  `EvidencePublishError` with no append/no gap and a clean retry,
  `fail_next_poll` raising `EvidencePollError` with the cursor unchanged,
  `fail_next_commit` raising `EvidenceCommitError` with the cursor
  unchanged so the next poll redelivers the identical batch, retry after
  each fault, consumer-targeted faults leaving other consumers unaffected,
  and cancellation propagating unchanged with the log state still valid;
- vertical slices (D28D-V01..V05): deterministic ordered
  publish/poll/commit with exact message values and positions; the
  crash/redelivery model (an uncommitted poll redelivers to a recreated
  handle); commit-failure redelivery (the seam PR 28E depends on);
  independent consumers; and PR 28C message/evidence/candidate identity
  surviving transport with the log position never appearing inside the
  message or its canonical wire.

No PostgreSQL integration test is required for PR 28D: the slice is pure
application state with no database boundary, and consumer-side PostgreSQL
processing is owned by PR 28E.

### Bounded Evidence persistence consumer (PR 28E)

PR 28E tests span three layers and pin the E28E-C/X/P, I28E, and V28E
matrices:

- deterministic unit tests (`tests/unit/app/test_evidence_consumer.py`,
  `tests/unit/app/test_evidence_batch_persistence_service.py`,
  `tests/unit/app/extraction/test_message_context.py`,
  `tests/unit/infrastructure/test_evidence_batch_repositories.py`) cover
  consumer sequencing (empty poll, bounded poll bound, one batch = one
  persistence call, DB-before-log-commit ordering, DB failure without
  consumer commit, commit failure after DB success, cancellation without
  false acknowledgement), the persistence service size/transaction
  contract, message-context reconstruction (exact ConvertedEvidence, IP/
  domain invocation contexts, malformed/unsupported fail-closed, reused
  ThreatFox extractor, no subject/log-position wire fields), and the
  adapter's deterministic JSONB serialization;
- real-PostgreSQL injection tests (`tests/integration/
  test_evidence_batch_consumer.py`) cover the I28E matrix: first batch
  with exact derived state, receipt-based exact replay, CREATED candidate
  identity, UNCHANGED candidate unused (a later same-state NEW message), a
  material update appending the authoritative observation (Option A),
  atomic batch rollback (metadata conflict), deterministic same-Evidence
  ordering in one batch, duplicate messages in one batch, soft-deleted
  Entity/Relationship conflicts, no generic Evidence history, no
  Investigation admission, exact RelationshipObservation provenance, the
  SQL-side size bound, and the required distinct-message recurrence test
  (`[M1:A, M2:B, M3:A]` — the second A is APPENDED, never resolved as a
  receipt replay);
- the required same-Evidence multi-state replay test
  (`tests/integration/test_evidence_batch_replay.py`) proves the canonical
  at-least-once boundary with the real log and real PostgreSQL: persist
  `[A,B,C]`, PostgreSQL commit succeeds, consumer commit fails, the
  identical batch is redelivered, and exactly three observations remain
  with no duplicate derived graph state (receipts are keyed by message
  identity and return the previously established authoritative results
  without invoking the Evidence transition);
- the V28E vertical slices drive the real `InMemoryEvidenceLog` through
  the real consumer/service/repository against the migrated database:
  success, DB failure before log commit (cursor unchanged, redelivery),
  material change across runs, and bounded multi-record processing in
  bounded prefixes.

### Datasource Evidence producer (PR 28F-2)

PR 28F-2 tests close the producer side of the v0.2 Global Evidence
pipeline with deterministic, offline producer vertical slices — no live
Internet, broker, or consumer is involved:

```text
real ThreatFox-format HTTP fixture (httpx.MockTransport)
 -> production ProviderHttpClient / orjson decode
 -> production ThreatFox semantic parser
 -> production ThreatFoxToEvidenceConverter
 -> production EvidenceMessage builder (evidence_message_from_converted)
 -> EvidencePublisher (InMemoryEvidenceLog.publisher())
```

- the unit matrix (`tests/unit/app/test_datasource_evidence_producer.py`)
  pins F2-M01..M10 (message construction over flattened output: one/
  multi-object order, multi-item converter return order, mixed 0/1/N
  contiguous flat sequence, zero output, PR 28C deterministic identity,
  exact recorder execution ID, exact semantic provenance, builder
  failure with no publish, and identical injected execution ID + fixture
  yielding identical messages), F2-L01..L11 (producer lifecycle through
  the real ThreatFox HTTP stack: normal, zero, typed acquisition failure,
  decode/semantic failure, conversion failure, message-construction
  failure, publisher failure, acquisition and publication cancellation,
  publish-success/PUBLISHED-append failure without republish, and
  PUBLISHED-success/COMPLETED-append failure without republish),
  F2-P01..P07 (exactly one ordered publish call, ordered input, empty
  no-op publish, no retry, no direct-persistence fallback, PUBLISHED
  count equals message count, `EvidencePublisher` ABC-only dependency),
  and F2-S01..S06 (reference corpus excluded, no observation-persistence
  dependency, no Investigation/broker fields in messages, no
  consumer/PostgreSQL wait, and the PR 28F-1 stdlib JSON codec
  unchanged). F2-L12..L15 (`PUBLISHED` non-terminal, post-terminal
  rejection, pre-STARTED rejection, no `error_code`) live at the
  recorder/domain level (`tests/unit/app/test_datasource_execution_recorder.py`,
  `tests/unit/domain/test_datasource_log.py`);
- the real-PostgreSQL vertical slices
  (`tests/integration/test_datasource_evidence_producer.py`) run the
  full production stack over the migrated database and pin V28F2-01..07:
  ThreatFox success with the exact `STARTED, ACQUIRED, DECODED,
  CONVERTED, PUBLISHED, COMPLETED` lifecycle under one execution ID,
  multi-record order (semantic order == converted order == message
  sequence == log position order), valid zero result recording
  `PUBLISHED(0)`, publisher failure via
  `InMemoryEvidenceLog.fail_next_publish()` (`FAILED(publication_failed)`,
  no direct fallback), deterministic cancellation at the publisher
  boundary (`CANCELLED` + propagation), real-PostgreSQL `PUBLISHED`
  lifecycle acceptance plus atomic post-terminal rejection (SQL API
  v0028, migration 0033), and producer/consumer separation (the producer
  reaches `COMPLETED` without any `EvidencePersistenceConsumer` running,
  no receipt/Evidence rows created).

### Deterministic vertical-slice provider execution (PR 19B)

`tests/integration/test_provider_execution_pipeline.py` proves the real
pipeline against the isolated migrated PostgreSQL database and the
in-process synthetic HTTP boundary (real `httpx.AsyncClient` over
`ASGITransport` into an ATI-authored FastAPI stub upstream guarded by a
host allowlist; no public internet):

```text
persisted DOMAIN root
  -> queued GOOGLE_PUBLIC_DNS work
  -> LangGraph
  -> LocalTaskDispatcher
  -> ProviderWorkExecutor
  -> real GooglePublicDnsProvider over the synthetic upstream
  -> normalized DNS Evidence
  -> PR 18B deterministic extraction
  -> PR 18C atomic persistence
  -> ProviderExecutionOutcome + persisted timeline events
```

The slice runs through the public `build_provider_investigation_graph`
factory along the `ProviderWorkExecutor -> LocalTaskDispatcher -> compiled
graph` composition path and invokes the graph asynchronously; it asserts the
persisted Evidence row, the discovered IP entity, the stable relationship
and its immutable observation, the outcome/state ID bookkeeping
(`provider_calls_used == 1`), the durable Investigation's
`root_entity_ids == [root.id]` (the fixture persists the actual root Entity
UUID), the started/evidence-persisted/completed timeline sequence, and that
discovered entities are never automatically enqueued. The provider's
internal HTTP parsing is not mocked. Timeline repository integration tests
cover append, chronological read, exact foreign-key SQLSTATE 23503 with
rollback and closed-UoW assertions, rollback, append-only semantics, and
the database error-code rejection.

## Provider contract tests

Every provider implementation should cover at least:

- positive response;
- valid empty/negative response;
- malformed response, including malformed nested provider structures;
- timeout;
- rate limit;
- authentication failure;
- unsupported indicator;
- normalization behavior;
- cancellation paths that propagate ``asyncio.CancelledError`` unchanged and
  release limiter permits and client resources.

Ordinary CI uses ATI-authored synthetic provider-shaped fixtures.

Optional live-provider contract tests validate external assumptions but do not gate normal deterministic CI.

## Provider validation matrices

Every live or local provider must maintain a traceable validation matrix in
its authoritative source documentation and tests. Green aggregate coverage is
not a substitute for this matrix. For each supported request/object/record
type, document and test:

| Dimension | Required coverage |
|---|---|
| Applicability | every `EntityType`, including unsupported and invalid values with proof of no I/O |
| Schema | required/optional fields, missing fields, wrong container types, strict scalar types, and unknown-field policy |
| Ordinary semantics | at least one positive normalization case with canonical facts and provenance |
| Valid miss | protocol-defined empty/negative behavior, distinct from benign assessment and provider failure |
| Canonicalization | case, whitespace, IDNA, address/range normalization, terminal delimiters, and idempotent canonical output |
| Special protocol forms | every standards-valid sentinel, root/null value, optional representation, escape form, or boundary ATI claims to support |
| Malformed nearest neighbors | values immediately outside each valid bound, incomplete escapes/tokens, wrong family/type, and contradictory identities |
| Cross-field invariants | range ordering/containment, class/identity matching, dependent fields, and timestamp requirements |
| Collection invariants | duplicates, ambiguity, entry ordering, owner/target attribution, chains/cycles, and mixed sentinel/ordinary entries |
| Error totality | malformed provider data returns a safe typed error and never an incidental parser/index/decoder/arithmetic exception |
| Eligibility | normalized values explicitly classified as discoverable entities, non-discoverable facts, or sentinels |
| Side effects | no persistence, assessment, relationship inference, pivoting, link traversal, or secret disclosure |

Tests should pair each standards-valid special case with malformed nearest
neighbors. For example, null MX requires positive `0 .` coverage plus nonzero
root preference, mixed null/ordinary MX, and duplicate-null rejection. A valid
boundary test should assert the boundary itself, not merely an interior value.

When transport documentation does not define field semantics, tests must use
the applicable protocol standard rather than extrapolating from one provider
fixture. If ATI has no approved representation for a standards-valid form,
stop and update the authoritative source contract before implementation.

Validation-order tests must prove original input is checked before lossy
canonicalization. Construction-boundary tests must instantiate reusable
policies/caches directly as well as through application settings. Injected
clocks, random/jitter functions, sleeps, and factories require valid-boundary,
invalid-return, and raised-exception tests; programming errors and cancellation
must propagate unchanged.

## Synthetic HTTP provider integration tests

Live provider integration tests (`tests/integration/test_live_provider_http_integration.py`) exercise production provider adapters through a real in-process HTTP boundary without public internet access:

- Every request traverses a real `httpx.AsyncClient` over `httpx.ASGITransport` into an ATI-authored FastAPI stub application. Virtual upstreams (Google DNS, IANA bootstrap, authoritative RDAP services, ThreatFox, URLhaus) are dispatched by request host and path inside genuine ASGI routes; tests assert on request state recorded by the routes, proving requests reached the ASGI application rather than a direct mock callback.
- A narrow `HostAllowlistASGITransport` wrapper enforces an explicit allowlist of permitted hosts and fails closed with a `RuntimeError` before the ASGI application handles any unapproved request. The wrapper never synthesizes provider responses.
- Stateful upstream behavior (a 503 followed by success, and persistent 429 responses) is implemented inside the ASGI routes so retry behavior traverses the application boundary; exact attempt counts are asserted from route-recorded requests.
- Routes assert exact method, `User-Agent`, and `Accept` headers, the DNS route asserts the absence of EDNS client-subnet parameters, the ThreatFox route asserts the exact POST search body, `Auth-Key` header, and JSON content type, and the URLhaus routes assert the exact `application/x-www-form-urlencoded` form body (`url=` / `host=` field), `Auth-Key` header, and JSON content type — all while proving the credential never appears in the URL or body. All payloads are synthetic, local, and credential-free.
- Fast, deterministic execution is guaranteed by injecting non-blocking sleep callables, fixed clocks, and deterministic zero-offset jitter.
- Multi-host discovery flows (IANA bootstrap to authoritative RDAP services) are tested with distinct virtual upstream hosts, including longest-prefix and narrowest-range authority selection and proof that wrong-authority hosts are never contacted.
- Non-persistence isolation guarantees are verified directly against PostgreSQL: provider invocation alone must leave `ati.evidence` row counts unchanged.

### Bounded concurrent Google Public DNS RR lookups (PR L-1)

`GooglePublicDnsProvider` domain investigations schedule the post-A RR
queries concurrently (`tests/unit/infrastructure/providers/test_google_dns_concurrency.py`):

- the initial A query remains sequential and is the authoritative
  clean-NXDOMAIN gate — a clean first-A NXDOMAIN still performs exactly one
  request before any other RR query is scheduled;
- after a continuing A outcome, AAAA/CNAME/MX/NS/TXT/SOA run concurrently
  through the provider's real `ProviderHttpClient`, whose configured
  `BoundedLimiter` stays the **sole** admission authority for HTTP
  concurrency and request rate (no additional semaphore, limiter, or
  concurrency setting);
- evidence and typed-error aggregation remains deterministic in canonical
  `_DOMAIN_RR_TYPES` order regardless of task completion order;
- `asyncio.TaskGroup` provides structured cancellation: parent cancellation
  settles/cancels every outstanding child and propagates `CancelledError`
  without orphan DNS requests, and an unexpected child exception fails the
  whole operation (a lone child failure is re-raised as its original
  exception, never converted to a `ProviderError`/partial success);
- PTR/IP investigations and retry/429/timeout semantics are unchanged.

These scheduling tests prove overlap, limiter bounding, completion ordering,
and cancellation with `asyncio.Event` barriers and counters at the synthetic
in-process HTTP transport boundary — never with wall-clock timing or live
Google DNS.

## Typical provider issues to watch for

The following checklist captures recurring failure modes in live-provider implementations and tests. It is intentionally non-exhaustive: implementers and reviewers must still apply provider specifications, ATI contracts, security requirements, and change-specific reasoning. Relevant items should be considered while designing and implementing code changes, the implementation should account for them, and corresponding tests should exercise them. Apply an item only when supported by the change's actual behavior, contract, or risk; do not invent speculative requirements or imaginative edge cases without a concrete basis.

- **Untrusted response validation:** Strict field types are necessary but not sufficient. Test missing, coerced, malformed, contradictory, and semantically inconsistent values, including nested structures, relationships between fields, and collection/RR-set invariants. Every malformed-provider path must be total: it returns a safe typed error rather than leaking an incidental parser, index, decoder, arithmetic, or model exception.
- **URL safety and canonical identity:** Validate URLs on the actual request path, not only in an unused helper. Require the approved scheme, reject userinfo, queries or fragments where prohibited, malformed hosts and ports, and unsafe path replacement. Canonicalize equivalent host spellings, IDNA forms, terminal dots, IPv6 literals, and default ports before authority comparison.
- **Selection and path construction:** Exercise multiple candidate services, invalid candidates followed by valid ones, ambiguity, longest-prefix/range boundaries, source-order rules, and exact percent-encoded resource paths. Never allow an entity value to replace the selected authority.
- **HTTP response handling:** Bound both declared and streamed response sizes before JSON decoding. Test missing or incorrect content types, malformed JSON, malformed content encodings, redirects, timeout and transport failures, permanent HTTP errors, rate limiting, and exhausted transient retries.
- **Provider JSON format (PR 28F-1):** accepted JSON bodies are parsed with `orjson` directly on bounded bytes. The F1-J01..J15 matrix pins valid-object/nested/array/Unicode/finite-numeric shape preservation; malformed syntax, invalid UTF-8, empty bodies, and the non-standard `NaN`/`Infinity`/`-Infinity` constants all fail closed as a non-retryable `INVALID_RESPONSE` + `SERIALIZATION` + fixed `"malformed JSON"` outcome with no decoder/payload leakage; oversize bodies, wrong content types, malformed content encodings, and retryable statuses keep their existing outcomes; V28F1-01/02 run real-format ThreatFox bytes through the production client into semantic records and prove non-standard provider JSON never reaches `DECODED`. `orjson` parses integers beyond the signed-64/unsigned-64 range as `float` (stdlib returned exact `int`); no supported provider contract emits such integers, and tests verify realistic int64-range values keep exact `int` Python shapes.
- **Safe typed errors:** Provider failures should map to stable typed codes with generic messages. Error values and logs must not expose response bodies, credentials, headers, exception URLs, query values, or other untrusted provider content.
- **Retry and limiter behavior:** Verify exact attempt counts, backoff numbering, jitter bounds, 429 `Retry-After` ordering and caps, first-request behavior, concurrency limits, and rate spacing. Test cancellation while waiting for a semaphore, rate slot, transport, retry delay, and streamed body; cancellation must propagate without leaking permits, resources, or stale future reservations.
- **Validation at construction boundaries:** Enforce invariants in directly constructible infrastructure policies and caches as well as in application `Settings`. Tests and future composition code may bypass the normal settings bootstrap.
- **Canonical evidence and provenance:** Normalize names, addresses, ranges, statuses, timestamps, handles, and fallback identifiers into stable forms. Distinguish protocol-valid values from entity-eligible values; root/null/sentinel facts must never become entities or pivots unless explicitly authorized. Assert source URNs, subjects, investigation IDs, exact credential-free source URLs, UTC timestamps, observation-time policy, immutable facts, and raw-payload policy.
- **Optional external fields:** Do not require fields that the external specification makes optional. When optional values are present, validate them strictly and define whether malformed individual entries invalidate the response or are omitted. Include absent, valid-present, wrong-type, malformed-entry, and mixed-valid/malformed tests. Keep that policy consistent in code, tests, and documentation.
- **Protocol presentation and special forms:** Transport schemas do not replace protocol semantics. Exercise standards-valid sentinels, roots/nulls, escaped presentation syntax, empty represented values, and malformed nearest neighbors. Define normalization and entity-discovery eligibility before implementation.
- **Resource ownership and cleanup:** Distinguish owned from caller-supplied clients. Test normal close, partial-construction rollback, one-close failure, and cancellation during cleanup. A component must close only resources it owns.
- **Deterministic, realistic tests:** Use fixed clocks and UUIDs, injected sleep/jitter, ATI-authored payloads, exact request and attempt assertions, and fail-closed host allowlists. Provider integration tests should cross the intended HTTP boundary rather than repeat a unit-test parser or transport callback.
- **Negative side effects and scope:** Assert that retrieval-only providers do not persist data, infer relationships, assess maliciousness, follow arbitrary links, or perform unplanned recursive lookups.
- **Quality-gate limitations:** Green typing, lint, coverage, and test commands do not prove behavioral completeness. Add adversarial contract cases for branches and invariants that aggregate coverage can miss; do not weaken gates or use broad suppressions to hide defects.
- **Documentation and completion state:** Keep accepted media types, normalization shapes, retry behavior, optional-field policy, and test topology synchronized with implemented behavior. Mark work complete only after the final code and documentation pass all required gates.

## API contract and OpenAPI tests (PR 23C)

The `/api/v1` HTTP adaptation layer is tested at three levels:

- **unit/route contract tests** (`tests/unit/api/**`) exercise pure HTTP
  contracts with injected application fakes (no database, no LLM, no
  providers): DTO validation (`extra="forbid"`), pure allowlist mappers,
  stable error envelopes (including FastAPI validation overridden to the
  ATI envelope and request-ID echo/replacement), auth route behavior,
  canonical idempotency fingerprints, filter/cursor mapping per collection,
  durable-pointer routes, deterministic Markdown, and cross-Investigation
  404s;
- **OpenAPI snapshot** (`tests/unit/api/test_openapi.py`) pins the
  normalized schema to `tests/fixtures/openapi_v1.json`, verifies explicit
  operation IDs, public DTOs only, error responses, and the accurate
  cookie-session security scheme (regeneration command is documented in the
  test module);
- **real-PostgreSQL API integration tests** (`tests/integration/test_api_*`)
  exercise the production FastAPI application and the PR 23A/23B services
  end to end: login/session round trip with only the token digest persisted;
  the atomic create-Investigation transaction (Investigation + durable job +
  audit + idempotency record); idempotent replay/race/mismatch; collection
  routes with cursors surviving HTTP; raw Evidence payload exclusion;
  durable Assessment/Report pointer correctness (never `MAX(version)`);
  history redaction/allowlist; deterministic Markdown; and the canonical
  async vertical slice proving `POST -> durable job -> worker claim ->
  InvestigationRunner -> terminal Investigation -> HTTP GET` through
  production persistence/orchestration seams with synthetic providers and
  `FakeLlmClient`.

These tests require no live Internet or API keys.

## Database integration tests

Integration tests use real PostgreSQL + pgvector from the supported database family.

They validate:

- Alembic migration from an empty database;
- versioned PostgreSQL stored functions;
- repository behavior;
- UnitOfWork transaction semantics;
- batch upserts;
- inserted/updated/unchanged classification;
- soft deletion;
- immutable observation behavior;
- relationship-history semantics;
- authentication/session persistence;
- audit persistence;
- RAG document/chunk/vector persistence;
- investigation resource and immutable evidence persistence (versions,
  history, lifecycle, soft deletion, and transaction atomicity);
- PR 18A concurrency invariants: locked-row lifecycle revalidation with a
  controlled two-session transition race, typed duplicate-identity errors
  under concurrent inserts, and evidence insertion blocked across a
  concurrent parent soft deletion;
- PR 18C atomic graph persistence: the canonical DNS/ThreatFox scenarios
  (domain RESOLVES_TO IP, IP ASSOCIATED_WITH malware) with exact Entity,
  Evidence, Relationship, RelationshipObservation, and history counts;
  repeated observations under new Evidence IDs reusing stable identities;
  same-Evidence-ID replay conflicting with unchanged counts; empty
  extraction persisting Evidence only; fact-only/URLhaus evidence creating
  no invented edges; typed preflight errors leaving zero rows; injected
  mid-transaction failures leaving no partial state; two concurrent writers
  converging on one canonical Entity/Relationship with both observations;
  fail-closed soft-deleted Entity/Relationship rediscovery; graph
  reconstruction from durable rows without re-extraction; and no spurious
  version bumps for unchanged re-observation;
- PR 18C graph-integrity hardening: a controlled two-transaction Entity
  soft-deletion race proving the locked write rejects the deleted identity
  with full observation rollback and one remaining canonical row; the
  canonical-create recovery path rejecting a raced row that was soft-deleted
  before recovery; database-enforced (not only preflight) soft-deleted
  Entity writes; Relationship soft deletion allocating a sequence version
  and exactly one immutable DELETE history row with diff and actor
  preservation, plus stale/missing/repeat rejections with zero extra
  mutation or history; the named non-cascading
  `relationship_observation_evidence_fk` rejecting dangling Evidence
  references with no residual observation or history rows; and migration
  0012 contract checks covering the FK, the `ati.soft_delete_relationship`
  signature, and an isolated downgrade/re-upgrade cycle.
- PR 20A versioned Assessment persistence: direct and graph support
  round-trips (Evidence with zero relationships; one evidence feeding
  several observations; repeated observations of one edge; ordered
  Findings/supports/string collections), cross-Investigation and
  provenance-mismatch rejections (including uncited analyzed Evidence,
  wrong-Investigation observations, and substitute observations of the
  same Relationship), database-enforced Finding/support structural
  rejection (no support, unknown/gapped/duplicate ordinals, invalid
  discriminator), deleted Relationship/endpoint-Entity ineligibility,
  empty-evidence INCONCLUSIVE round-trip and no-evidence
  SUSPICIOUS/BENIGN/MALICIOUS rejection, version 1 then version 2 with
  version 1 unchanged and distinct later versions, the Investigation
  assessment pointer only changing after durable success, stale
  expected-version conflict with no partial Assessment, failed-append
  rollback of parent/history/audit/pointer, locked-row concurrency races
  (Assessment creation serialized against Relationship and Entity soft
  deletion), the approved deletion policy (current-Assessment deletion
  rejected, superseded deletion with DELETE history and transactional
  ASSESSMENT_DELETE audit, stale-version delete rollback), and migration
  0014 checks covering the normalized schema, the empty-table guard
  (nonempty legacy rows block the upgrade and survive), and an isolated
  downgrade/re-upgrade cycle. Two additional deterministic concurrency
  tests observe PostgreSQL lock state (`pg_stat_activity`/`pg_locks` with
  bounded timeouts, never fixed sleeps) to prove that concurrent pointer
  assignment and Assessment deletion serialize on the owning Investigation
  row lock in both orders: pointer-wins (deletion rejected with the
  current-reference conflict, no DELETE history/audit) and deletion-wins
  (pointer assignment to the deleted A rejected, exactly one DELETE
  history and audit row). Input bounds are tested at three layers: unit
  tests proving each bounded candidate collection is rejected before any
  UnitOfWork entry plus exactly-at-limit acceptance, repository unit tests
  with a recording session proving oversized inputs never execute SQL, and
  a PostgreSQL test bypassing Python bounds to prove the database
  defensive hard ceiling (10,000) rejects plus-one inputs before any
  staging or mutation.

Do not replace critical PostgreSQL integration coverage with SQLite.

## Redpanda / Kafka integration tests (PR 28G)

The PR 28G real-broker tests (`tests/integration/kafka/`) prove the
Kafka-compatible Evidence adapters against a real Redpanda broker using
real `aiokafka` clients. They cover canonical EvidenceMessage round trip,
same-Evidence partition affinity, multi-Evidence/multi-partition behavior,
manual offset commit and group restart, no-commit redelivery, independent
consumer groups, corrupt/key-mismatched payloads failing closed, producer
metadata, empty publication, clean shutdown, and PR 28E application
compatibility through a deterministic persistence double.

Prerequisites and running:

- `podman`/`podman-compose` (the same toolchain as the PostgreSQL
  integration suite).
- `./integration-test.sh` provisions an isolated Redpanda broker (via
  `compose.yaml`) alongside the isolated PostgreSQL database, waits for the
  Kafka API to become ready, and exposes it to the test process as
  `ATI_EVIDENCE_KAFKA_BOOTSTRAP`. The Evidence topic is created explicitly
  with **3 partitions** so the multi-stream (partition) abstraction is
  actually exercised; each test uses an isolated topic/group identity so no
  state bleeds across runs or prior runs.
- The broker tests require no Internet and no Schema Registry; Redpanda is
  Kafka-compatible test/development infrastructure only, never a Python
  runtime dependency.
- Unit matrix (`tests/unit/infrastructure/kafka/`) covers the adapter
  boundaries with deterministic `aiokafka` doubles (E28G-P publisher,
  E28G-R consumer poll, E28G-K commit) and runs offline without any broker.

Responsibility split: unit tests pin the adapter contracts and failure
mapping; real-broker tests pin partition/offset/group/redelivery/restart
semantics. Note that `tests/integration/kafka/conftest.py` provisions a
fresh empty 3-partition Evidence topic per test (never shared between
tests), with per-test consumer groups; the suite's assertions on exact
batch sizes depend on that isolation.

## Distributed Evidence ingestion closure (PR 28H)

The PR 28H module `tests/integration/kafka/test_distributed_evidence_ingestion.py`
(H28H-01..21) proves the complete production-shaped vertical slice against
real Redpanda and real PostgreSQL, faking only the external Internet
endpoint (`httpx.MockTransport` serving deterministic ThreatFox-format
fixture bytes):

- temporal semantics: fresh A, later A-equivalent (`UNCHANGED`, never
exact replay), A->B, A->B->C, A->B->A recurrence (a distinct message
appends v3), and one atomic multi-Evidence batch;
- replay/idempotency: exact-message replay is a receipt no-op; same
semantic state with a new datasource execution is a new receipt with
unchanged EO history;
- failure/recovery: failure before PostgreSQL commit (no partial state,
no Kafka commit, same-group redelivery, one retry), PostgreSQL-commit-
then-Kafka-commit-absent recovery, poll-then-stop redelivery, atomic
multi-record rollback, committed-restart with no redelivery;
- producer lifecycle: `COMPLETED` without a consumer, `publication_failed`
failure, post-terminal lifecycle append rejection;
- provenance: exact `EvidenceObservationEntity` and
`RelationshipObservation` references per committed observation;
- Investigation reproducibility: explicit observation-exact admission
(two Investigations sharing one EO, one Investigation admitting v1+v2,
and a later global EO never silently mutating prior admissions).

Failure seams are narrow test wrappers only (a commit-failing consumer and
a fail-before-commit persistence boundary); there are no production chaos
APIs, no Kafka transactions, no retry topics/DLQ, no Schema Registry, no
live Internet, and no ThreatFox clone/download. The real PostgreSQL
integration lane, fresh per-test topics and groups, and the no-internet
rule keep the module deterministic and isolated.

## TAXII interoperability testing strategy

ATI distinguishes protocol correctness, third-party interoperability, and live-data robustness when validating TAXII 2.1 ingestion. These layers are complementary; no single layer replaces the others.

### 1. Protocol-level tests — planned

Use a deterministic TAXII 2.1 test server or fixtures controlled by ATI to exercise the TAXII client/adapter cheaply and precisely. These tests should cover API-root and collection discovery, authentication behavior where applicable, object retrieval, pagination, incremental acquisition (including `added_after` semantics), error handling, malformed/unsupported input, and conversion through the STIX 2.1 semantic boundary.

These tests use deterministic data and exact assertions and are suitable for ordinary automated integration testing. They do not by themselves establish interoperability with an independent CTI product.

### 2. OpenCTI deterministic interoperability — PR 33 foundation

PR 33 is establishing the prerequisite OpenCTI integration environment using a real OpenCTI deployment loaded with ATI's deterministic Fake World data. Once TAXII ingestion is implemented, this environment is the canonical deterministic third-party interoperability path:

```text
ATI deterministic/Fake World STIX data
        -> real OpenCTI
        -> OpenCTI TAXII 2.1 endpoint
        -> ATI TAXII ingestion
        -> STIX 2.1 conversion
        -> ATI canonical persistence
```

The purpose is to prove interoperability against another product's real TAXII/STIX implementation while retaining exact, reproducible expected outcomes. Tests should exercise the production OpenCTI application and its real TAXII endpoint; they must not replace OpenCTI or TAXII with ATI-owned fakes at this boundary.

PR 33 provides the OpenCTI + Fake World prerequisite; the TAXII round trip itself remains planned until the TAXII implementation lands.

### 3. OpenCTI live-data interoperability — planned

A separate live integration path will load OpenCTI with a real-world CTI dataset (not ATI Fake World data), expose that data through OpenCTI's real TAXII 2.1 endpoint, and ingest it into ATI.

"Live" here means **real third-party implementation plus real-world CTI data**. The OpenCTI instance may be locally/self-hosted; the TAXII endpoint does not need to be a public Internet service for this to constitute live interoperability testing.

Because the upstream dataset can change, live-data tests should assert stable invariants rather than brittle exact object counts or identities. At minimum, validate that:

- API-root/collection discovery and authentication succeed as configured;
- pagination and incremental retrieval complete correctly;
- returned STIX objects are syntactically/semantically handled according to ATI's supported-object contract;
- supported objects convert and persist through the production STIX 2.1 conversion path;
- supported relationships preserve endpoint/provenance semantics;
- datasource provenance identifies the actual OpenCTI/TAXII acquisition path;
- unsupported or malformed objects fail or skip only according to the documented fail-closed policy, with bounded/sanitized diagnostics;
- repeated/incremental acquisition preserves ATI's idempotency and history contracts.

Live-data interoperability is a robustness/interoperability test, not a deterministic Fake World correctness oracle. It should not become a mandatory ordinary-CI dependency on changing external data.

### Layering and acceptance intent

The intended testing stack is therefore:

| Layer | TAXII implementation | Data | Assertion style | Status |
| --- | --- | --- | --- | --- |
| Protocol | ATI-controlled deterministic server/fixtures | Deterministic | Exact protocol/conversion assertions | Planned |
| Deterministic interoperability | Real OpenCTI TAXII 2.1 | ATI Fake World | Exact end-to-end assertions | OpenCTI prerequisite in PR 33; TAXII path planned |
| Live interoperability | Real OpenCTI TAXII 2.1 | Real-world CTI dataset | Stable invariants + robustness diagnostics | Planned |

The deterministic OpenCTI path is the reproducible interoperability gate. The live-data path supplements it by exposing ATI to real-world STIX diversity and changing CTI content; it must not replace the deterministic gate.

## Migration tests

At minimum, CI verifies:

```text
empty database
 -> alembic upgrade head
 -> expected schema/functions/extensions
```

As the repository matures, migration regression tests should also exercise supported upgrade paths from representative prior schema versions.

Versioned SQL stored-function files must be tested against the real database.

## Test isolation

Tests must never use normal developer persistent data.

Use:

- unique test database names;
- unique Compose project name;
- isolated host/container storage;
- explicit environment guards.

Example:

```text
COMPOSE_PROJECT_NAME=ati-test-<unique>
```

Host ports for isolated containers are selected above the default Linux
ephemeral-port range (`net.ipv4.ip_local_port_range`, 32768-60999 on
GitHub-hosted runners): under rootless Podman every mapped host port is bound
by a user-space forwarder, so a port inside the ephemeral range can be
silently occupied by an outbound connection. `integration-test.sh` and
`scripts/e2e.sh` pick available ports from disjoint high ranges, probe them
by binding all interfaces exactly like the forwarder (no `SO_REUSEADDR`), and
retry container starts with a fresh port when the forwarder reports a bind
conflict.

Test startup should fail safely if configuration appears to reference a normal development database/data directory.

## Synthetic fixtures

CI fixtures are ATI-authored and deterministic.

Do not depend on live public DNS, provider APIs, changing ATT&CK web content, live model responses, or wall-clock-dependent external data for ordinary PR correctness tests.

Provider-shaped fixture data should avoid copying third-party payloads wholesale when redistribution terms are uncertain.

## Fake implementations

The test suite should provide deterministic implementations such as:

- `FakeEvidenceProvider`;
- `FakeTaskDispatcher` (PR 19C): a deterministic dispatcher used by graph
  tests so orchestration mechanics do not depend on executor behavior;
- `FakeWorkExecutor` (PR 19A, in `tests/support/orchestration_fixtures.py`):
  a deterministic in-memory `WorkExecutor` driven by an explicit
  `ProviderWorkItem -> ProviderExecutionOutcome` mapping with no network,
  database, or LLM I/O, retained for dispatcher and executor tests;
- `FakeLlmClient`;
- fake embedding model;
- fixed retriever;
- deterministic clock where needed;
- scenario factory/builders.

Fakes should implement the same ABC contracts as production components.

## Fake operating mode versus test mode (PR 23D)

Fake **operating mode** is a runtime concept, not a test mode:

- `ATI_OPERATING_MODE=fake` changes only which intelligence-source implementations are composed at bootstrap;
- automated tests are deterministic regardless of operating mode and inject `FakeLlmClient` at the model boundary;
- CI never requires live network access or a live LLM;
- runtime `fake` mode at a real deployment still uses the configured real `LlmClient` when an LLM-bearing path executes.

PR 23D adds the following deterministic, offline coverage:

- **configuration tests** (`tests/unit/config/test_operating_mode.py`): safe production default, exact `fake`/`production` values, fail-closed validation, profile orthogonality;
- **catalog/fixture tests** (`tests/unit/infrastructure/test_fake_runtime.py`): strict schema validation (duplicate scenario IDs, duplicate root indicators, unknown providers, malformed timestamps, path escapes), deterministic shared-world lookups, fake provider contract behavior, no-network invariants, and composition branches (fake only fakes, production only real);
- **runtime metadata tests** (`tests/unit/api/test_runtime.py`): `GET /api/v1/runtime` reports the mode only, requires authentication, and never exposes configuration or secrets;
- **fake batch bootstrap tests** (`tests/integration/test_fake_batch_bootstrap.py`): first ingestion through the production `MitreAttackBatchSource`, idempotent re-run, malformed-fixture fail-closed, production-mode refusal;
- **canonical fake-mode vertical slice** (`tests/integration/test_fake_canonical_vertical_slice.py`): HTTP `POST /investigations` → durable job → `InvestigationJobWorker` → `LocalInvestigationRunner` → fake intelligence providers → `FakeLlmClient` → real PostgreSQL → HTTP reads (Investigation, Evidence, Relationships, RelationshipObservations, Research, Assessment, Timeline, runtime mode);
- **relationship evolution** (`tests/integration/test_fake_relationship_evolution.py`): repeated observations of a stable relationship at distinct source-semantic times and a later new counterparty, with `observed_at` preserved separately from `retrieved_at`;
- **research-required** (`tests/integration/test_fake_research_required.py`): the coordinator research lifecycle persists a contextual `ResearchResult` that remains distinct from Evidence.

The fake world and scenario fixtures are repository-owned under `src/agentic_threat_investigator/infrastructure/fake_runtime/data/v1/` and are versioned and strictly validated; runtime randomness is forbidden and fixture-internal relevance classifications are never exposed to the analytical pipeline as privileged truth.

## Structured agent output and deterministic formatter tests

All programmatic agent outputs are validated Pydantic models. Conventional
tests and behavioral evaluations together enforce this boundary.

`TESTING.md` owns deterministic schema, serialization, formatter, and
application-boundary tests. `EVALUATION.md` owns model/agent behavioral
quality and trajectory scoring.

### Structured-output contract tests

For every agent output model, deterministic tests must cover:

- valid representative output;
- missing required fields;
- unexpected fields where `extra="forbid"` applies;
- wrong scalar/container types;
- invalid enum/URN values;
- invalid referenced-ID shapes;
- empty versus absent semantics;
- field-level bounds;
- cross-field invariants implemented outside Pydantic;
- stable JSON-compatible serialization.

An invalid LLM result must never partially update investigation state or
persistence.

### Reference validation tests

Where an agent result references ATI resources, tests must prove that
deterministic application validation rejects:

- nonexistent entity IDs;
- nonexistent Evidence IDs;
- nonexistent retrieved-chunk IDs;
- references outside the current investigation where prohibited;
- duplicate or contradictory references where prohibited;
- Coordinator pivots that are not root/evidence-discovered entities;
- references that violate pivot policy or budgets.

### FakeLlmClient

`FakeLlmClient` returns typed Pydantic results corresponding to the requested
response model.

Tests must not rely on parsing free-form fake model prose to simulate a
structured-output operation.

The fake should also support deterministic invalid-output/failure cases needed
to test bounded repair and `INVALID_STRUCTURED_OUTPUT` handling.

Deterministic PR 20B coverage requirements:

- one successful call increments the Investigation LLM budget by exactly one;
- an invalid first attempt plus a successful repair increments by two and the
  second User Prompt carries the bounded schema-repair instruction;
- prompt construction occurs BEFORE reservation: an initial-prompt
  construction failure consumes zero budget, makes zero model calls, and
  touches no persistence/audit state; a repair-prompt construction failure
  keeps the prior real attempt counted (one reservation, one call) without
  reserving the nonexistent repair call;
- a non-retryable ``INVALID_STRUCTURED_OUTPUT`` error is NOT retried (one
  call, one reservation, no Assessment, strict propagation);
- attempt counts are hard-limited to ``1..2`` even on direct constructor
  use;
- an input-loading failure and the no-evidence short circuit never consume
  budget (no model call happens at all);
- a cancellation during the model boundary propagates unchanged AND the
  actually-attempted invocation stays durably reserved;
- an attempted call that then times out/provides garbage persists no
  Assessment and moves no Investigation pointer;
- an exhausted attempt budget (or LLM budget) fails with no partial
  persistence;
- invalid support references (unknown/cross-Investigation Evidence or
  RelationshipObservation, substitute observation, soft-deleted graph
  resource) are rejected by the PR 20A validator with no pointer update and
  the durable LLM count reflects every actual invocation.

The loader bounds are fail-closed: direct construction enforces the same
hard ceilings as ``Settings`` (evidence 1..500, observations 1..1000, input
bytes 1000..1000000, normalized-facts bytes 1000..1000000); the aggregate
normalized-facts size is independently byte-bounded (UTF-8, never counting
Python characters and never inspecting raw payloads); and a 1001st
observation at a 1000 bound raises ``EvidenceAnalystInputBoundsError``
before any model call via the sentinel probe, never a silent clamp.

### Evidence Analyst vertical slice (PR 20B)

Integration tests run the complete application path against isolated
real PostgreSQL with `FakeLlmClient` standing in for the model:

```text
persist Investigation + Evidence (+ Relationship/Observation)
 -> EvidenceAnalystInputLoader (raw_payload excluded from model prompts)
 -> EvidenceAnalyst + LlmAccountingService
 -> FakeLlmClient (asserts the shared real-UnitOfWork transaction counter
    is zero while the model boundary runs; records prompts)
 -> Assessment validation/persistence
 -> durable Assessment + Investigation pointer + budget counters
```

The transaction coverage instruments the actual ``PostgresUnitOfWork``
instances composed into the analyst stack (loader, LLM accounting,
Assessment persistence) with a shared enter/exit tracker; the fake LLM
asserts the active count is exactly zero and the event order proves the read
loader exited before accounting started, the reservation UnitOfWork exited
before the model call, and Assessment persistence begins only after a typed
decision exists.

Coverage includes evidence-only, graph-backed, mixed-support, explicitly
contradicting, and no-evidence INCONCLUSIVE styles; invalid/cross-Investigation
citations; substitute-observation and deleted-graph rejection; structured-
output and persistence failures leaving no pointer; appended later analysis
versions with the earlier Assessment unchanged; and durable LLM accounting.
The observation listing read added for analyst input is covered separately
against real PostgreSQL (scope, determinism, exclusion, paging).

### Canonical real-format Threat Research/RAG path (PR 22A)

The canonical PR 22A vertical slice (`tests/integration/test_mitre_real_format_vertical.py`)
exercises the complete production corpus pipeline against isolated real
PostgreSQL:

```text
deterministic local STIX 2.1 fixture
 -> production FileSystemObjectStore + MitreAttackBatchSource (real parser)
 -> SourceRecord persistence (checkpoint/idempotency)
 -> MitreAttackDocumentBuilder (real builder)
 -> DocumentIndexingService (real chunking/indexing)
 -> PostgreSQL Document/DocumentChunk persistence (citation identities)
 -> PgVectorResearchRetriever (real cosine retrieval)
```

The embedding representation is the only external/non-deterministic boundary
and is replaced with deterministic offline embeddings; nothing else is faked.
The fixture rule for PR 22A and later research work:

> Automated tests may replace network acquisition and external embedding
> service calls, but must exercise the production source parser, document
> builder, persistence/indexing, and pgvector retrieval path being tested.

The fixture (`tests/fixtures/mitre_attack/enterprise_attack_small.json`) is
ATI-authored synthetic STIX 2.1 content that conforms exactly to the
production `MitreAttackBatchSource` input contract; it is a deterministic
real-format fixture, not a separate fake data source, and is never presented
as real threat intelligence. The slice proves ingestion, document
construction provenance, chunk persistence with stable `citation_id` values,
deterministic retrieval provenance, same-model idempotency, and embedding
identity migration (chunks replaced, citations stable, identity-filtered
retrieval). Durable research provenance is proven separately in
`tests/integration/test_research_result_repository.py` (immutable
ResearchResult round trip, reference rejection, rollback, no-Evidence
creation, and snapshot survival across active chunk replacement).

### Structured Research Agent (PR 22B)

Unit strategy (`tests/unit/domain/test_research_agent.py`,
`tests/unit/app/research_agent/`):

- immutable request/output contract boundaries (blank query, bounded
  `max_results` 1..100, filter deduplication, blank filters, claim
  citation presence/uniqueness, extra-field rejection);
- deterministic prompt construction and prompt-injection tests: hostile
  chunk instructions stay inside the untrusted-data section, the system
  prompt still forbids acting on them, no tool surface exists, and
  `chunk_id` is never rendered as the model citation token;
- deterministic prompt tests for PR 22B-2 provenance/score semantics:
  exact and empty `source_url` field rendering (null URL never renders Python
  `None`), URL provenance/no-browsing/no-unsupplied-inference guardrails,
  `similarity_score` defined as retrieval relevance/ranking only (not
  credibility, factual correctness, evidentiary strength, maliciousness, or
  claim/Assessment confidence), and the prohibition on using similarity to
  choose a winner between contradictory sources;
- application execution tests drive the real `ResearchResultPersistenceService`
  and real `LlmAccountingService` against in-memory seams with a scripted
  `FakeLlmClient` and a scripted retrieval fake: relevant-context
  persistence, unsupported-citation fail-closed behavior, no-context and
  irrelevant-context empty results, contradictory separately-cited claims,
  reuse/ordering of citation snapshots, retry/repair accounting (at most one
  repair, retry only retryable `INVALID_STRUCTURED_OUTPUT`, no retry on
  timeout/config/provider failure), cancellation propagation, constructor
  attempt bounds, prompt-build and retrieval failures consuming no budget,
  and append-only repeat executions.

Canonical PostgreSQL vertical slice (`tests/integration/test_research_agent.py`):

```text
deterministic local STIX 2.1 fixture
 -> production MitreAttackBatchSource / MitreAttackDocumentBuilder
 -> DocumentIndexingService + deterministic embeddings
 -> real PostgreSQL persistence + PgVectorResearchRetriever
 -> ResearchAgent (production composition incl. LlmAccountingService)
 -> FakeLlmClient          (model boundary only)
 -> ResearchResultPersistenceService + real ResearchResultRepository
```

The slice covers relevant context persistence with real pgvector retrieval and
copied citation provenance, unsupported-citation rejection with no partial
state, no-retrieval and irrelevant-context empty results, contradictory
context represented as separately cited claims (via a second real-format
STIX fixture), persistence reference validation/rollback, and structured-
output repair with exactly two accounted LLM calls. `FakeLlmClient` is the
only fake external model boundary; tests never require live Internet or a
live LLM.

### Coordinator research execution trajectories (PR 22C)

The canonical PR 22C slice (`tests/integration/test_research_trajectory.py`)
runs the full production research lifecycle against isolated real PostgreSQL:

```text
domain -> DNS (real provider over synthetic HTTP) -> discovered IP
 -> ThreatFox (scripted provider) -> RESEARCHABLE malware
 -> real CoordinatorPolicy + production LangGraph + LocalInvestigationRunner
 -> MARK_RESEARCH_REQUIRED -> RESEARCH_REQUESTED
 -> real Research Agent (real pgvector retriever, real result persistence)
 -> FakeLlmClient (model boundary only)
 -> COMPLETED / EXHAUSTED -> normal Coordinator stop
```

The canonical slice never fakes the research architecture: the real
production Coordinator, graph, runner, real-format MITRE ATT&CK STIX
fixture, parser/document builder, `DocumentIndexingService`, real
PostgreSQL/pgvector, real `PgVectorResearchRetriever`, real Research Agent,
and real ResearchResult persistence all participate, with `FakeLlmClient`
used only at the external LLM boundary. Provider execution uses the existing
deterministic production-compatible seam to create the RESEARCHABLE entity.

Covered trajectories:

- I01 — complete trajectory: marker consumed, `RESEARCH_REQUESTED` fired,
  one authoritative result with valid citation provenance, result linked
  once, execution COMPLETED, no Evidence/Assessment created by research, no
  direct research->pivot transition;
- I02 — no-context result is completed research (zero claims/citations, zero
  LLM calls, result linked once);
- I03 — unchanged-context rerun is idempotent (zero additional calls,
  results, or `RESEARCH_REQUESTED` events);
- I04 — crash-window reconciliation: a persisted matching result with
  REQUESTED state is adopted with zero LLM calls and no duplicate rows;
- I05 — LLM-accounting/version interaction: research reservations advance
  the Investigation version and completion reloads the authoritative
  version without overwriting accounting;
- I06 — bounded recoverable retry: exactly two `RESEARCH_REQUESTED` events,
  attempts == 2, one result, no third attempt;
- I07 — exhaustion after two recoverable failures: EXHAUSTED, no result
  link, no retry on subsequent invocation;
- I08 — research cannot authorize a pivot: completion returns to
  Coordinator and the SUFFICIENT disposition stops without any post-research
  pivot.

The transition allowlist slice (`tests/integration/test_research_execution_transition.py`)
proves `REQUEST_RESEARCH`/`RECORD_RESEARCH_OUTCOME` accept only approved
field changes, reject provider/pivot/evidence/assessment mutations and
duplicate contexts, reject stale expected versions, require authoritative
result linkage (investigation/subject/query), never link an exhausted
context, and preserve LLM-accounting version increments. `FakeLlmClient` is
the only fake external model boundary; tests never require live Internet or
a live LLM.

### PR 30A common evaluation foundation tests

PR 30A adds one backend-neutral evaluation contract under
`src/agentic_threat_investigator/evaluation/common/` and freezes it with
fully offline, deterministic tests in `tests/unit/evaluation/common/` plus
dataset tests in `tests/unit/evaluation/test_datasets.py`:

```text
common models (EVAL-A01..A12):
  COMPLETED+PASS and COMPLETED+FAIL valid; ERROR+no-verdict valid;
  ERROR+PASS/FAIL and COMPLETED+null rejected; no numeric score field;
  nonblank explanations; stable evaluator IDs; PASS/FAIL/ERROR
  aggregation rules identical to the frozen contract; timestamps absent;
  JSON-safe diagnostics that never alter aggregation

scenario-quality validation (EVAL-S01..S15):
  fully described case loads; missing/blank title, description, purpose,
  operational_relevance, and regression_risk rejected; empty, blank, or
  duplicate-normalized expected-behavior statements rejected; duplicate
  case IDs rejected; invalid dataset versions and unknown targets
  rejected; target/version mismatches rejected; invalid/duplicate
  architecture refs rejected; unknown fields fail closed; target-specific
  fixture/expectation validation still executes; strict duplicate-key JSON
  loading; deterministic target inference

runner (EVAL-R01..R10):
  all-PASS -> dataset PASS; evaluator FAIL -> FAIL; evaluator exception
  -> ERROR never FAIL; target exception -> case ERROR; cancellation
  propagates; independent cases continue after an ERROR; deterministic
  case and evaluator ordering; no backend/network dependency; diagnostics
  cannot affect aggregation; malformed datasets refuse to start

reporting (EVAL-P01..P06):
  correct PASS/FAIL/ERROR summaries; failing case/evaluator/explanation
  identified; ERROR visually distinct from FAIL; machine output
  round-trips with sorted keys; no aggregate numeric score; human report
  never exposes diagnostics or secrets

datasets:
  every registered target loads with deterministic counts/ordering;
  research-agent concatenates retrieval then synthesis; unregistered and
  version-mismatched datasets refuse; mixed-version and mixed-target
  directories reject; `ati-eval validate` CLI exit codes offline
```

PR 30A requires no LangSmith, no real LLM, and no network access anywhere
in the unit suite; future judge scenarios (PR 30B/30C) stay offline behind
deterministic fakes. The optional credentialed evaluation workflow (real
model runs uploading to LangSmith) begins in PR 30B only.

### PR 30B LangSmith adapter tests

PR 30B adds the LangSmith evaluation adapter under
`src/agentic_threat_investigator/evaluation/backends/langsmith/` with a
fully deterministic, network-free, credential-free unit matrix in
`tests/unit/evaluation/langsmith/` (fake-boundary tests only) and static
workflow tests. All ordinary tests inject the in-memory
`FakeLangSmithClient` (or the duck-typed `FakeSdkClient` for the real SDK
wrapper); no test acquires `LANGSMITH_API_KEY` or reaches the network, and
no test merely skips without a key and calls that coverage.

```text
mapping (LS-M01..M10):
  deterministic dataset names; stable case identity inputs;
  required/forbidden behavior projection; sorted tag/architecture
  metadata; identical canonical projection for identical inputs; digest
  changes on any semantic change; ordering-only changes keep the digest;
  no secret/raw runtime fields projected; projection schema version
  emitted; malformed metadata rejected before any remote call

sync (LS-S01..S16):
  absent dataset -> create + examples; existing empty dataset -> create;
  exact mirror -> no writes; only missing examples created; same
  identity/digest -> unchanged; digest mismatch -> fail without overwrite;
  remote extra ATI identity -> fail without delete; duplicate remote
  identity -> fail; dataset identity mismatch -> fail; unsupported
  projection schema -> fail; malformed local -> no remote mutation;
  create/list/create-examples API errors surfaced; repeated identical sync
  performs zero writes; cancellation propagates

verify (LS-V01..V08):
  exact mirror success; missing dataset/example/extra example/digest
  mismatch/duplicate identity/malformed metadata all fail closed;
  verification performs no writes

result mapping (LS-R01..R10):
  PASS/FAIL/ERROR map to categorical pass/fail/error (never numeric);
  bounded explanations preserved; ERROR explanations sanitized;
  diagnostics never published by default; case/run aggregates categorical
  only; stable evaluator feedback keys/order; no score/weight/percentage

client boundary (LS-C01..C06):
  SDK dataset/example objects convert to bounded DTOs; foreign metadata
  filtered to the ati.* namespace; SDK exceptions become bounded backend
  errors; credential-like/control-character text bounded out of messages;
  cancellation propagates; no SDK object escapes the adapter boundary

CLI (LS-CLI01..CLI09):
  valid sync/verify succeed through the fake; invalid datasets fail
  before any client call; missing credentials bounded nonzero failure
  with no environment dump; drift exits nonzero; pre-existing validate
  unchanged; run command deferred to PR 30C; no secret in output

workflow static tests (LS-W01..W13):
  evaluation.yml exists; workflow_dispatch only (no push/PR/schedule);
  contents: read; LANGSMITH_API_KEY only (PR 30B has no model-provider
  secret); Python 3.14; uv sync --locked; local validation before the
  remote operation; invokes ati-eval langsmith; ci.yml stays
  uncredentialed (GITHUB_TOKEN only)
```

PR 30B changes no production agent/persistence behavior, requires no
living LangSmith service for mandatory CI, and adds no dependency beyond
the already-locked `langsmith>=0.3.45,<0.12` bound inspected against the
installed 0.11.x SDK. A real LangSmith smoke is manual only, through the
optional `workflow_dispatch` workflow or operator execution.

### PR 30C real Evidence Analyst target tests

PR 30C adds the first real target execution layer
(`tests/unit/evaluation/analyst/`, `tests/unit/evaluation/langsmith/`,
`tests/integration/`) with the same deterministic discipline: mandatory
CI stays offline/uncredentialed (FakeLlmClient at the model boundary,
FakeLangSmithClient at the remote boundary, real PostgreSQL only in the
`integration`-marked vertical slice).

```text
target executor (EA-T01..T12):
  exact identity lookup; unknown case/version mismatch/duplicate identity
  fail closed; target mismatch refuses before any model call;
  materialization then exactly one analyst call; persisted Assessment +
  resolution returned; LLM/persistence failures are runner ERROR;
  cancellation propagates; two cases never cross-contaminate;
  deterministic same-case rerun; target has no LangSmith dependency

evaluator adapter (EA-E01..E10):
  existing evaluator PASS/FAIL map to COMPLETED/PASS and COMPLETED/FAIL;
  deterministic nonblank explanation; JSON-safe descriptive diagnostics;
  partial coverage never decides a verdict; no numeric correctness;
  identity mismatch is runner ERROR; cancellation propagates; forbidden
  support and missing required contradiction FAIL

run service (EA-R01..R14):
  all cases projected to the runner; non-analyst dataset rejected;
  pass/fail/error aggregation preserved; no LangSmith dependency;
  cancellation propagates; exactly one materializer + analyst call per
  case; one case rerun stays deterministic

LangSmith experiment (EA-LS01..LS15):
  exact mirror allows the experiment; one case -> one remote case
  association; PASS/FAIL/ERROR map to pass/fail/error; missing remote
  dataset/digest drift refuse before any model work (verify-first);
  feedback acceptance confirms; feedback/confirmation failures fail
  closed; no score/threshold; diagnostics not uploaded; metadata bounded
  and secret-free; cancellation propagates; no duplicate model execution
  (evaluate()/aevaluate() never invoked)

CLI run (EA-R06..R12):
  local run constructs no LangSmith client; PASS exits 0; FAIL exits 1;
  ERROR exits 2; missing model credential bounded exit 2; deterministic
  driver rejected; publication failure is exit 2; FAIL stays exit 1 after
  successful publication; non-analyst dataset rejected

workflow static tests (EA-W01..W18):
  workflow_dispatch only; contents read; operations verify/sync/run;
  Python 3.14; uv sync --locked; validate before run; LangSmith verify
  before the model run; PostgreSQL and migrations configured for run;
  LANGSMITH_API_KEY used; the model-provider secret is wired only for run;
  verify/sync need no model execution; ordinary CI uncredentialed; no
  push/PR/schedule; no write permission; secrets never echoed/literalized

PostgreSQL vertical slice (integration):
  real scenarios -> real materializer -> real loader -> real
  EvidenceAnalyst -> FakeLlmClient -> real AssessmentPersistenceService
  -> persisted Assessment -> real evaluator through the PR 30 adapter ->
  common EvaluationRunner; direct-evidence PASS, contradiction PASS,
  nonconforming output FAIL (still persists), LLM failure ERROR (nothing
  persists, one bounded attempt); rerun reuses the fixture and evaluates
  the current invocation
```

PR 30C changes no existing V1 scenario semantics, no production
Evidence Analyst behavior, and no common evaluation contract; adds no DB
migration; and keeps every mandatory test free of live LLM/LangSmith
dependencies.

### PR 30D Coordinator + Research Agent target tests

PR 30D adds the second and third real target layers with the same
deterministic discipline: real PostgreSQL/pgvector in the
`integration`-marked vertical slices, FakeLlmClient at every model
boundary, FakeLangSmithClient at the remote boundary, and offline/
uncredentialed ordinary CI. Coordinator research-lifecycle slices boot the
repository-owned ATT&CK fixture corpus through the production
ingestion/indexing services (deterministic hashing embeddings).

```text
Coordinator target (C-T01..T14):
  exact identity lookup; unknown case/version mismatch/duplicate identity
  fail closed; materialize + one production investigation execution;
  durable terminal state + structured actions (no log parsing); version
  transition span; provider/analysis failure is runner ERROR; cancellation
  propagates; repeated cases use fresh run-scoped identities; no LangSmith
  dependency

Coordinator evaluator (C-E01..E10):
  existing evaluator PASS/FAIL map to COMPLETED/PASS|FAIL; deterministic
  bounded explanation; metrics diagnostics only (no threshold verdict);
  evaluator exception is runner ERROR; cancellation propagates;
  policy-invalid pivot, duplicate research request, and wrong stop reason
  all FAIL through the real existing evaluator

Research dispatch (R-T01..T16):
  retrieval/synthesis exact identities; cross-family duplicate rejected;
  retrieval branch zero LLM; synthesis branch one real agent execution;
  exact supplied chunks from the actual invocation (no probe); resolution
  over the exact supplied sequence; empty retrieval persists empty with
  zero LLM; LLM failure ERROR; unsupported citation ERROR; persistence
  failure ERROR; before/after snapshots; cancellation propagates; no
  LangSmith dependency

Research evaluator (R-E01..E14):
  retrieval/synthesis PASS/FAIL mapping with per-kind evaluator ids;
  JSON-safe metrics diagnostics only; no numeric correctness;
  required/forbidden citation FAIL; Evidence/RelationshipObservation/
  Assessment promotion hard-gate FAIL; evaluator exception ERROR;
  cancellation propagates

CLI run (D-R01..R15):
  coordinator/v1 and research-agent/v1 dispatch to their benchmark seams;
  Evidence Analyst unchanged; unsupported target rejected; pass/fail/error
  exits 0/1/2; local run constructs no LangSmith client; verify-first;
  drift/missing mirror refuse before target work; publication failure exit
  2; FAIL stays exit 1 after successful publication; missing credential
  bounded; cancellation propagates

LangSmith targets (D-LS01..LS10):
  exact mirrors allow coordinator/research/analyst runs; drift refuses
  before target; one ATI execution per case; categorical values unchanged;
  no raw research content in metadata; no numeric score; verify/sync stay
  model-free

workflow static tests (W19/W20 + the PR 30B/30C set):
  dataset input quoted as data; Evidence Analyst remains supported;
  dataset-agnostic run step; PostgreSQL + migrations; research corpus
  bootstrap inside the benchmark seams; LANGSMITH_API_KEY always and
  ATI_OPENAI_API_KEY only for run; workflow_dispatch only; contents read

PostgreSQL vertical slices (integration):
  Coordinator: productive-pivot PASS (domain-discovers-ip), immediate-stop
  PASS (sufficient-evidence-stop), justified-replan PASS
  (one-justified-replan), research lifecycle PASS (requested -> completed,
  one request), exhausted research bounded (no duplicate), deliberately
  nonconforming trajectory FAIL, materialization dependency ERROR, full
  corpus smoke (every case PASS/FAIL/ERROR, never crashes)
  Research: retrieval PASS with zero LLM calls, forbidden record FAIL,
  synthesis relevant + contradictory PASS with non-promotion,
  expected-empty retrieval zero-model-call PASS, unsupported citation
  ERROR, scenario-wrong claim FAIL
```

Known honest state for V1 Coordinator: several `coordinator/v1` scenarios
carry allowed-pivot oracles and budgets authored against an older
Coordinator topology (pre-PR-28B), so their trajectories no longer
reproduce under the current production graph; the run service reports them
deterministically as FAIL (or ERROR for the ORGANIZATION materialization
limitation in `non-pivotable-discovery`). No scenario expectation was
weakened, no production policy changed, and no V1 case is silently skipped.

PR 30D changes no existing V1 scenario semantics, no production
Coordinator/Research behavior, and no common evaluation contract; adds no
DB migration; and keeps every mandatory test free of live LLM/LangSmith
dependencies.

### PR 30E Report Writer target tests

PR 30E adds the Report Writer real-target layer with the same deterministic
discipline: real PostgreSQL in the `integration`-marked vertical slice,
FakeLlmClient exactly at the model boundary, FakeLangSmithClient at the
remote boundary, and offline/uncredentialed ordinary CI. The canonical
fixture/materializer code moved out of `tests.support` into
`agentic_threat_investigator.evaluation.report_writer.fixtures|scenarios`;
`tests/support/report_writer_fixtures.py|scenarios.py` are thin test-only
re-exports and production evaluation code never imports `tests.support`.

```text
fixture/materializer (RPT-F01..F09):
  known fixture exact; unknown fixture fails closed; same execution
  identity deterministic; different execution identities isolate
  execution-owned Investigation/Assessment/EvidenceObservation/Research
  identities while canonical Entity/Relationship identities stay global;
  Assessment/Research persistence confirmed (integration); canonical
  Entity reuse without destructive reset (integration); evaluation package
  has no tests.support import

target executor (RPT-T01..T14):
  exact identity lookup; unknown/version mismatch/duplicate fail closed;
  normal scenario runs the production writer exactly once; success returns
  the persisted report; exact current-execution model-attempt count;
  declared no-report failures become evaluation inputs (PASS), unexpected
  exceptions are runner ERROR; allowlisted typed failures map to stable
  codes (report_provenance_error / invalid_structured_output /
  stale_report_input) without message parsing; cancellation propagates;
  repeated runs use isolated execution identities; no LangSmith dependency

evaluator adapter (RPT-E01..E13):
  existing evaluator PASS/FAIL map to COMPLETED/PASS|FAIL; bounded stable
  failure-code explanations (never report prose); diagnostics-only metrics
  with no threshold verdict; verdict mismatch, missing finding, forbidden
  research claim, and phrase-envelope violation FAIL; expected no-report
  with correct code PASS, wrong code FAIL; evaluator exception is runner
  ERROR; cancellation propagates

run service (RPT-R01..R13):
  report-writer/v1 requires the Report Writer target; wrong/empty datasets
  rejected before model work; cases projected to the common runner;
  cancellation propagates; no LangSmith dependency

CLI run (RPT-R01..R13):
  report-writer/v1 dispatches to the Report Writer benchmark seam; prior
  three targets unchanged; unsupported target rejected; PASS/FAIL/ERROR
  exits 0/1/2; local run constructs no LangSmith client; verify-first;
  drift refuses before target; publication failure exit 2; FAIL stays exit
  1 after successful publication; missing model credential bounded exit 2;
  the Report Writer benchmark never bootstraps the research corpus;
  cancellation propagates

LangSmith targets (RPT-LS01..LS10):
  exact report-writer mirror allows the run; drift refuses before model;
  categorical PASS/FAIL/ERROR publication reused; one ATI execution per
  case; no raw report/prompt/model content in metadata; confirmation
  mismatch fails closed

workflow static tests (RPT-W01..W04):
  report-writer/v1 accepted by the dataset-agnostic run step; stale
  Evidence-Analyst-only run description corrected; no research-corpus
  bootstrap step in the workflow; prior targets remain supported

PostgreSQL vertical slice
(`tests/integration/test_evaluation_report_writer_runner.py`):
  real scenarios -> strict loader -> repository-owned fixture -> real
  materializer (run-scoped execution identity) -> PostgreSQL -> real
  Assessment/Research persistence -> ReportWriterInputLoader -> real
  ReportWriter -> FakeLlmClient -> real provenance validator -> real report
  persistence -> actual persisted report/no-report -> existing
  ReportWriterEvaluator -> PR 30 adapter -> common EvaluationRunner; S01..S05
  PASS with the pointer advanced to the persisted report; S06 unsupported
  reference rejected by the real provenance boundary (no report/history/
  pointer); S07 real structured-output repair exhaustion (two bounded
  attempts); S08 real stale-Assessment race (Assessment B current, no
  report); runtime-valid-but-scenario-wrong output FAIL (report still
  persists: FAIL is distinct from ERROR); unexpected model failure ERROR;
  cancellation propagates; canonical Entity reuse and no destructive reset
```

PR 30E changes no existing V1 scenario semantics, no production Report
Writer/Assessment/Research behavior, and no common evaluation contract;
adds no DB migration; and keeps every mandatory test free of live
LLM/LangSmith dependencies.

### PR 30F End-to-end Investigation target tests

PR 30F adds the end-to-end Investigation real-target layer: one case is one
complete deterministic investigation world executed through the production
Coordinator graph/policy, providers/extractors/persistence, Evidence
Analyst, Research Agent where authorized, and production Report Writer after
the terminal state. The same deterministic discipline applies: real
PostgreSQL + pgvector, FakeLlmClient exactly at the model boundary,
FakeLangSmithClient at the remote boundary, and offline/uncredentialed
ordinary CI.

```text
models (L01..L09):
  valid V1 scenario loads; unknown fields rejected; wrong target rejected
  at dataset level; mixed/wrong version rejected; duplicate cases rejected;
  invalid semantic labels rejected; negative envelopes rejected;
  investigation/v1 registered; deterministic file order

fixtures (F01..F08):
  known fixture resolves its exact world; unknown fixture fails closed;
  scenario-owned worlds validated through the strict catalog
  extraction-contract loader; provider registries expose exactly the
  enabled world-truth providers (never policy)

materialization (F03..F10, integration):
  same execution identity deterministic planned state; new execution
  identity isolates Investigation worlds; initial state is a
  production-valid RUNNING Investigation with only the root Entity
  (providers discover everything else); providers state truth only;
  root persists through the normal repository seam; deterministic
  Research corpus via production ingestion/indexing; no live dependency
  for non-Research worlds; reruns require no destructive cleanup

target executor (T01..T16):
  exact identity lookup; production runner invoked once per case;
  terminal durable state required; final current Assessment loaded from
  persistence; production Report Writer after terminal state consuming
  the actual final Assessment; captured structured trajectory; exact
  provider/LLM counts; unexpected runner failure ERROR; report failure
  ERROR; cancellation propagates; repeated runs isolated; no LangSmith;
  no component-target chaining (the end-to-end target never invokes the
  analyst/coordinator/research/report-writer evaluation targets)

evaluator (E01..):
  every outcome/trajectory/provenance/efficiency predicate tested
  independently; all true -> PASS; one semantic violation -> FAIL;
  evaluator exception -> ERROR via the common runner; values within an
  envelope PASS regardless of numeric variation; cancellation propagates

run service (INV-R01..R06):
  investigation/v1 requires the Investigation target; wrong/empty
  datasets rejected before model work; cases projected to the common
  runner; cancellation propagates; bounded output payload; no LangSmith

CLI run (INV-R01..R04/INV-LS08):
  investigation/v1 dispatches to the end-to-end benchmark seam; prior
  four targets unchanged; unsupported target rejected; PASS/FAIL/ERROR
  exits 0/1/2; local run constructs no LangSmith client; drift refuses
  before target; missing model credential bounded exit 2; the end-to-end
  benchmark bootstraps the deterministic research corpus; publication
  metadata carries no raw prompt/model/Evidence/Research/report content

LangSmith targets (INV-LS01..LS03, unit):
  exact investigation mirror allows the run; drift refuses before model;
  the real investigation corpus syncs and verifies through the generic
  dataset path; the scenario semantic digest is stable and
  content-sensitive

workflow static tests (INV-W01..W03):
  investigation/v1 accepted by the dataset-agnostic run step; run
  operation description lists investigation/v1; prior component targets
  remain supported

PostgreSQL vertical slice
(`tests/integration/test_evaluation_investigation_runner.py`):
  real scenario JSON -> strict loader -> repository-owned world -> real
  PostgreSQL/pgvector -> persisted RUNNING Investigation -> production
  LocalInvestigationRunner -> production Coordinator -> production
  provider/extraction/persistence -> production Evidence Analyst ->
  production Research Agent where authorized -> FakeLlmClient only at
  the model boundary -> terminal durable Investigation -> final current
  Assessment -> production ReportWriter -> persisted report -> durable
  Evidence/Relationship/Research/timeline snapshot -> InvestigationEvaluator
  -> common EvaluationRunner; I01..I06 canonical worlds PASS (malicious
  multi-source, benign, inconclusive, conflicting, research-required,
  cycle/duplicate) with zero forbidden duplicates where authored;
  I07 structurally valid but scenario-wrong model output is
  COMPLETED/FAIL (FAIL distinct from ERROR); I08 unexpected model error
  is ERROR; I09 report-stage error is case ERROR; I10 cancellation
  propagates; I11 rerun isolation (distinct Investigation worlds, no
  destructive cleanup); full-corpus smoke never crashes
```

PR 30F changes no existing V1 scenario semantics, no production
Coordinator/provider/Evidence Analyst/Research Agent/Report Writer
behavior, and no common evaluation contract; adds no DB migration; and
keeps every mandatory test free of live LLM/LangSmith dependencies.

### Threat Research evaluation baseline (PR 22D)

PR 22D adds a separate **behavioral evaluation layer** over the unchanged
PR 22A-C runtime: the runtime tests above prove *what the production path
does*; the PR 22D evaluators prove *whether the persisted artifacts satisfy
repository-owned scenario expectations*. The two layers are deliberately
distinct and both remain fully offline.

Evaluator unit matrix (`tests/unit/evaluation/research/`,
`tests/unit/evaluation/test_coordinator_research_evaluator.py`):

```text
retrieval metrics: Recall@k, Precision@k, MRR, expected-source rank,
  duplicate identities, empty denominators, explicit gap, filter leaks,
  forbidden records, deterministic failure ordering (22D-U01..U12)
strict retrieval/synthesis loaders: malformed JSON, duplicate JSON keys,
  duplicate (id, version) identities, duplicate expectation labels,
  invalid scenario ids, extra-field rejection (22D-U13..U15)
synthesis envelope: citation closure, supplied-set membership,
  required/forbidden citations, empty-result semantics, claim matching,
  contradiction pairs, deterministic failure ordering, denominator-safe
  metrics (22D-U16..U29)
epistemic snapshots: unchanged Evidence/RelationshipObservation/Assessment
  passes; any promotion is a stable failure; a ResearchResult alone is not
  promotion (22D-U30..U34)
coordinator research lifecycle: required/forbidden requests, bounded
  budgets, legitimate retry vs. post-completion duplicate, exhaustion,
  termination, backward compatibility of pre-research scenarios
  (22D-U35..U42)
```

Real-format retrieval evaluation slice
(`tests/integration/test_research_retrieval_evaluation.py`, 22D-I01):

```text
local MITRE ATT&CK STIX 2.1 fixture
 -> production MitreAttackBatchSource / MitreAttackDocumentBuilder
 -> DocumentIndexingService + deterministic embeddings
 -> real PostgreSQL / pgvector
 -> PgVectorResearchRetriever
 -> ordered RetrievedChunk values
 -> ResearchRetrievalEvaluator
```

Repository-owned scenarios under `evals/scenarios/research/retrieval/`
declare stable ATT&CK identities expected/forbidden at bounded ranks, filter
contexts, and an explicit retrieval-gap case. A deliberately failing
scenario (`real-mitre-forbidden-technique`) proves a structurally successful
retrieval can fail the baseline.

Synthesis evaluation slice
(`tests/integration/test_research_evaluation.py`, 22D-I02..I06):

```text
real-format fixture
 -> production parser/builder/indexing/retrieval
 -> ResearchAgent + FakeLlmClient (model boundary only)
 -> real ResearchResult persistence
 -> repository-read-back result -> ResearchSynthesisEvaluator
 -> epistemic snapshots before/after the isolated research interval
```

The slice covers RAG-S01 relevant context, S02 no-retrieval empty result,
S03 retrieved-but-irrelevant empty result, S04 contradictory separately
cited claims, S05 unsupported-citation safe failure (execution envelope, no
fabricated result), and S06 hostile corpus text. A runtime-valid but
scenario-wrong persisted result (supplied-but-wrong citation) is proven to
fail the behavioral evaluation (22D-I03). The canonical synthesis/trajectory
career observes the exact supplied citation set with a recording wrapper
around the production retriever; nothing is re-ranked or substituted.

Bounded research retrieval is total and deterministic: production pgvector
retrieval orders by vector distance first and the stable unique chunk
identity second, so chunks with equal distance have a well-defined order and
top-N membership cannot vary across otherwise identical executions. A test
that claims a citation was supplied to a model execution must derive it from
the exact retrieval of that execution (a `FakeLlmClient` response factory
over the chunks recorded by the `RecordingResearchRetriever`), never from an
independent probe retrieval; only the genuinely unsupplied-citation failure
path (rag-S05) intentionally probes a wider set. Intentional equal-distance
regression coverage (`tests/integration/test_research_retrieval_determinism.py`,
RDET-01..05) pins distinct-distance ranking, equal-distance stable ordering,
ties crossing the `LIMIT` boundary, repeated-retrieval identity, and
filtered-set determinism through the production path.

Coordinator trajectory evaluation slices
(`tests/integration/test_research_trajectory_evaluation.py`, 22D-I07/I08)
run the full production research lifecycle (real CoordinatorPolicy, real
LangGraph, real runner, real corpus/research agent) and evaluate the durable
timeline/state with the extended `CoordinatorTrajectoryEvaluator` against
the repository scenarios C-R01 (research requested), C-R02 (completed
unchanged context not re-requested on rerun), C-R03 (bounded exhaustion, no
further request), and C-R04 (no direct research->pivot authority).

### Evidence Analyst evaluation vertical slices (PR 20C)

`tests/integration/test_evidence_analyst_evaluation.py` runs the repository-
owned analyst scenarios end to end against isolated real PostgreSQL with
`FakeLlmClient`:

```text
AnalystScenario JSON -> AnalystScenarioMaterializer (UnitOfWork seam)
 -> existing EvidenceAnalystInputLoader
 -> existing EvidenceAnalyst + LlmAccountingService
 -> FakeLlmClient (canonical decision built from the scenario expectations)
 -> existing PR 20A validation/persistence
 -> persisted Assessment read back through the repository
 -> EvidenceAnalystEvaluator
```

Documented properties of the PR 20C slice:

- **Evaluator consumes persisted Assessments only.** Inputs are scenario,
  resolution, and the repository-read-back Assessment; no raw LLM response,
  pre-persistence decision, prompt, or provider response object is ever
  evaluated (see `EVALUATION.md`).
- **Deterministic fixtures win over a second model.** Scenario truth -
  allowed verdict/confidence envelopes, required/forbidden support,
  contradiction pairs, canonical limitation/question/next-step phrases -
  drives both the scripted fake decision and the evaluator, so they can
  never drift.
- **Semantic labels resolve to exact UUIDs.** Expectation labels point into
  the fixture; materialization returns `AnalystScenarioResolution`. The
  evaluator fails closed on unknown labels. Corpus identity is the exact
  `(id, version)` pair: distinct versions of one stable id may coexist.
- **Fail-closed authoring validation.** Duplicate entries inside any
  expectation label/phrase collection and duplicate JSON object keys at any
  nesting depth are rejected before set conversion; every fixture label and
  support reference must be a stable bounded lowercase semantic label
  (`^[a-z0-9][a-z0-9._-]*$`, ≤ 64 characters); invalid UTF-8 scenario
  bytes surface as `AnalystScenarioLoadError`, never a raw decoding error.
- **Repository-confirmed persisted IDs only.** `AnalystScenarioMaterializer`
  fails closed when a repository returns `id=None` instead of substituting
  a planned UUID, and records the repository-returned identity (including
  canonical redirects) everywhere dependent rows reference it.
- **Truthful support metrics.** `required_support_satisfied` reflects the
  best single shape-matching, clean candidate's required-label coverage;
  support split across Findings never counts twice, missing-label messages
  name labels absent from that one candidate, and disallowed Finding
  confidence does not erase otherwise present support. Tie-breaking controls
  support metrics and diagnostics only; any fully supported candidate may
  satisfy the confidence requirement.
- **Behavioral failure is not persistence failure.** Negative slices prove a
  structurally valid (PR 20A-accepted) Assessment that is behaviorally wrong
  still persists exactly one durable row while the evaluator rejects it with
  the stable bounded codes (for example MALICIOUS-on-geolocation-only,
  missing required limitation, one-sided contradiction).
- **No live LLM in CI.** Normal PR tests require no external model key, no
  internet, no provider credential, and no LangSmith service.

Unit coverage (`tests/unit/evaluation/analyst/`) exercises every bounded
failure code with passing and failing cases, deterministic failure ordering,
metrics derived from the same comparisons (including partial-support
coverage and confidence-not-erasing-support), scenario/DTO validation
exhaustively (duplicate labels, duplicate JSON keys, invalid semantic
labels, unknown fixture references, blank/naive fields, empty envelopes,
extra-field rejection), scenario loader fail-closed behavior (malformed
JSON, invalid UTF-8, duplicate top-level and nested object keys,
duplicate `(id, version)` identities, deterministic discovery order),
committed-corpus integrity, and deterministic materializer identity
derivation against an in-memory `UnitOfWork` (including fail-closed
`id=None` repositories and repository-confirmed redirects).

### Serialization tests

For persisted/API-visible structured agent results, test:

```text
Pydantic model
 -> JSON-compatible serialization
 -> persistence/API mapping
```

as applicable.

Tests must verify preservation of:

- stable IDs;
- enum/URN values;
- verdict/confidence;
- typed Finding provenance (Evidence and RelationshipObservation references);
- research/chunk citations;
- list ordering where semantically relevant;
- optional/empty semantics.

Do not use human-readable rendered text as the source for reconstructing
the structured result.

### Deterministic formatter tests

Every human-readable formatter must be tested without an LLM.

Given a fixed structured result and fixed formatter configuration,
repeated calls must produce identical output bytes unless the formatter
contract explicitly defines a non-semantic presentation variation.

Formatter tests must prove that rendering:

- preserves verdict/confidence;
- preserves findings;
- preserves Evidence references;
- preserves research citations;
- preserves limitations;
- preserves recommended next steps;
- introduces no unsupported claim;
- does not omit material structured content required by the target
  format;
- does not mutate the source Pydantic object;
- performs no provider/retriever/LLM call.

Use golden/snapshot fixtures only when repository policy permits them
and when the fixture is reviewed as a deterministic presentation
artifact. Semantic assertions must still cover critical fields so that
an indiscriminate snapshot update cannot hide a semantic regression.

### Report Writer versus formatter tests

Keep these responsibilities separate:

**Report Writer structural tests (PR 23B)**

- strict domain contracts: blank titles/statements rejected, unsupported
  narrative statements rejected, duplicate source references rejected,
  forbidden model-authored verdict/confidence/persistence metadata rejected
  via `extra="forbid"`;
- input materialization: no current Assessment fails typed before any LLM
  call, missing provenance fails closed, input collections and serialized
  bytes are independently bounded, raw Evidence payloads never enter the
  context, ordering and prompt bytes are deterministic;
- deterministic provenance validation: unknown finding/research references,
  cross-Investigation references, snapshot drift, caveat changes, and
  source-set drift all fail before persistence;
- LLM execution: one reservation per actual invocation, at most one
  schema-repair invocation, cancellation propagates, no free-form fallback;
- report persistence: DB-assigned versions, one CREATE history row, atomic
  append + pointer update, stale-Assessment rejection, superseded-only soft
  deletion, current-report delete rejection;
- report query: `version DESC, id ASC` keyset pagination, current report via
  the durable `report_id` pointer, index eligibility via EXPLAIN.

**Report Writer behavioral evaluation**

- grounded synthesis;
- correct Evidence/research references;
- no unsupported material claims;
- Assessment verdict/confidence preserved;
- useful structured report content.

Behavioral evaluation is repository-owned and deterministic (scenario JSON
under `evals/scenarios/report_writer/`, stable failure codes, no
LLM-as-judge); it never claims that deterministic reference validation
proves semantic entailment.

**Formatter deterministic tests**

- exact rendering behavior;
- escaping;
- ordering;
- headings/labels;
- citation presentation;
- format-specific syntax;
- semantic preservation.

A formatter failure is a deterministic software defect, not an LLM
evaluation failure.

**Canonical offline vertical slice**

The primary “PR 23B actually works” proof is a real-PostgreSQL slice that
runs the production input loader, prompt builder, Report Writer service,
provenance validation, report persistence, and Markdown formatter with
`FakeLlmClient` ONLY at the model boundary, asserting the exact persisted
report is returned, verdict/confidence equal the Assessment, provenance
references resolve, and Markdown is deterministic. No live Internet or live
LLM participates.

### No free-form fallback

Tests must prove that ATI does not silently accept free-form text when a
structured response model is required.

If structured parsing/validation fails after the bounded repair policy,
the operation returns the typed LLM failure. ATI must not:

- persist the raw text as the authoritative result;
- regex/heuristically extract a verdict or action;
- execute a pivot inferred from prose;
- generate a final report directly from the unvalidated text.

### Deterministic report equivalence

For a fixed `InvestigationReport` version, formatter tests should verify
that all supported renderers represent the same material semantics even
though their syntax differs.

For example:

```text
InvestigationReport JSON
       |             |
       v             v
   Markdown         HTML
       \             /
        same verdict
        same findings
        same citations
        same limitations
        same next steps
```

## Scenario factory

A reusable `ThreatScenarioFactory` should construct deterministic integration/evaluation fixtures.

Representative scenarios include:

1. benign;
2. clearly malicious;
3. inconclusive;
4. conflicting evidence;
5. domain-to-malicious-IP pivot;
6. two IOCs sharing infrastructure;
7. malware with RAG context;
8. monitor with no material change;
9. monitor with meaningful change;
10. historical evolution.

Canonical fixture:

`malicious_domain_with_ip_and_malware_pivot`

Behavioral expectations and scoring for these scenarios live in `EVALUATION.md`.

## Coverage

Use pytest-cov to report test coverage in CI.

Do not invent a repository-wide percentage before meaningful implementation exists.

Critical deterministic logic should receive especially strong coverage:

- canonicalization;
- pivot-policy enforcement;
- budget accounting;
- relationship extraction;
- deterministic source extraction;
- source normalization;
- persistence invariants;
- assessment validation;
- authorization;
- soft deletion;
- job claiming;
- monitoring diff logic.

Coverage is a diagnostic and quality gate, not a substitute for meaningful tests.

## Pre-commit

Pre-commit provides fast developer feedback for inexpensive deterministic checks such as:

- trailing whitespace;
- end-of-file normalization;
- Ruff check (with safe fixes) and Ruff format;
- selected fast checks.

Do not require slow database integration or real-model evaluation for every local commit.

CI remains authoritative.

## Canonical quality command

The repository exposes one documented command, for example:

```bash
make quality
```

It should run the required source-quality/test checks in a stable order, conceptually:

```text
Ruff format --check
Ruff check
Mypy
Pytest deterministic suites
```

A separate command may run full integration tests when containerized dependencies are required.

As implementation matures, `make quality` may orchestrate both fast and required integration stages in CI.

## No quality-gate bypass

A coding agent or developer must not make a failing gate pass by:

- weakening global configuration;
- lowering a coverage requirement without justification;
- adding broad `type: ignore`;
- adding broad Ruff/`noqa` suppression;
- skipping failing tests;
- deleting assertions;
- disabling migration checks;
- replacing real PostgreSQL integration tests with weaker substitutes;

unless the change is independently justified and reviewed.

## CI quality gate

Every PR should eventually run approximately:

```text
uv sync --locked
      |
Ruff format --check
Ruff check
Mypy
      |
unit tests
provider fixture contract tests
      |
PostgreSQL/pgvector integration environment
Alembic migration from empty database
database/integration tests
      |
deterministic agent evaluation hard gates
      |
license/SPDX checks
```

See `EVALUATION.md` for the behavioral-evaluation portion.

## Frontend quality

The React/TypeScript frontend must have equivalent automated engineering discipline:

- formatting;
- linting;
- strict TypeScript;
- unit/component tests;
- relevant integration tests.

The v0.1 frontend toolchain (PR 24A):

- **Vitest + jsdom** for unit/component tests, with global setup in
  `frontend/src/test/setup.ts`;
- **Testing Library + user-event** for interaction, and jest-dom matchers;
- **MSW** centralizes deterministic HTTP behavior: `src/test/server.ts`
  owns the server lifecycle and `src/test/handlers.ts` owns the
  `/auth/me`, `/auth/login`, `/auth/logout`, `/runtime` and PR 24B
  Investigation handlers (list, create, detail, current Assessment,
  current Report, Report Markdown) with deterministic lifecycle
  transitions (`pending -> running -> completed`, `pending -> failed`,
  `running -> partial`) modeled on the public HTTP contract only — never
  on worker internals. Every test builds an isolated QueryClient (no
  shared Query cache); unhandled requests fail loudly;
- **OpenAPI-derived types**: `npm run api:generate` regenerates
  `frontend/src/api/schema.generated.ts` from the committed snapshot
  `tests/fixtures/openapi_v1.json`; `npm run api:check` fails when the
  committed types are stale. CI never fetches a live development server's
  OpenAPI document;
- **Playwright** runs the real-browser production-path slice against real
  FastAPI/PostgreSQL — see *Browser E2E* below.

What is mocked versus real:

| Layer | Unit/component tests | Playwright E2E |
|---|---|---|
| HTTP | MSW handlers | real FastAPI via Nginx `/api` proxy |
| Auth/session | jsdom cookie jar + real CSRF contract code | real HttpOnly session + CSRF cookies |
| Database | none | real throwaway PostgreSQL 18 |
| LLM | none (unit tests inject `FakeLlmClient`/the deterministic client directly) | `ATI_LLM_DRIVER=deterministic` offline scripted boundary; never a live LLM |

TanStack Query itself is never mocked and the API client is never replaced
with per-component fakes.

### Selector and test-identity rule

Tests must not use localized display strings as stable widget identity
unless localization, wording, or accessible naming is the behavior under
test. Prefer, in order:

- a stable `data-ati-id` for a semantic surface (for example
  `relationship.focal-entity` for the focal-Entity indicator);
- a stable `data-testid` derived from the action key (for example
  `graph-explore-entity`);
- canonical route/query state (URL path + search parameters);
- a semantic ARIA role scoped inside a stable container;
- a canonical graph node identity (`rf__node-n:<uuid>`).

An accessibility test may separately assert the localized accessible name;
the same test must not also treat that English string as the only widget
selector. This keeps tests stable across copy/localization changes and
prevents a translation edit from silently rewiring an interaction test.

### Server-rendered web presentation tests (V07-01)

The `web/` HTML presentation adapter is tested at four layers; none of them
substitutes for another.

- **View-model / Jinja rendering unit tests** (`tests/unit/web/`): typed web
  view models, Jinja autoescape (malicious user text is escaped), the
  centralized full-page-versus-HTMX-fragment convention, HTML error
  presentation, and the form-compatible CSRF helper. These are fast and
  database-free.
- **Web route contract unit tests** (`tests/unit/web/`): web login/logout
  cookie semantics, HTML 404/403/503 presentation, API errors remaining JSON,
  and the exact approved-origin CSRF behavior. They use the same
  presentation-neutral fakes as the API route tests.
- **FastAPI + Jinja + PostgreSQL integration tests**
  (`tests/integration/test_api_web.py`, marker `integration`): the real
  application stack — real `AuthenticationService`, real session
  persistence, real DB — proves login/shell/fragment/logout, exact-origin
  rejection, and that a web login authenticates the same session the JSON
  API uses.
- **Real-stack browser acceptance** (`scripts/e2e-web.sh`, durable suite in
  `web-e2e/`): Playwright against the real stack. Critical acceptance runs
  with `workers=1`, `retries=0`, and covers Chromium and Firefox.

HTMX fragments are tested server-side (same view model, bounded fragment,
no duplicate full document) so that browser tests are reserved for genuine
browser semantics (HTMX swap, refresh/session persistence, logout
navigation).

#### Dual E2E harness lifecycle (V07-01..V07-07)

During the migration the repository has two real-stack browser harnesses:

```text
V07-1..V07-6:
  scripts/e2e.sh      -> React regression harness (existing frontend/)
  scripts/e2e-web.sh  -> new server-rendered web acceptance harness

V07-7 (cutover):
  React removed
  the proven web harness becomes canonical scripts/e2e.sh
```

`scripts/e2e-web.sh` follows the same isolation principles as
`scripts/e2e.sh` (unique Compose project, throwaway PostgreSQL volume,
generated bootstrap credentials, random high host ports, fake operating
mode, scoped cleanup) and additionally proves the two exact browser origins
run concurrently against one backend. Its Playwright suite is owned by
`web-e2e/` (not `frontend/`) so it survives the eventual React deletion.
React E2E (`scripts/e2e.sh`) is regression evidence only and cannot
substitute for web acceptance, and vice versa.

The V07-1 acceptance matrix is:

| E2E | Browser | Required |
|---|---|---:|
| New web login → shell → HTMX → refresh → logout | Chromium | **Yes** |
| Same new-web journey | Firefox | **Yes** |
| Targeted legacy React auth/origin compatibility | Chromium | **Yes** |
| Targeted legacy React auth/origin compatibility | Firefox | No |
| Full legacy `scripts/e2e.sh` suite | — | **No** |

The two new-web rows are covered by `./scripts/e2e-web.sh` (which runs both
projects). The targeted legacy React row is covered by
`./scripts/e2e.sh auth.spec.ts --project=chromium --workers=1 --retries=0`,
which exercises React login, session restore after reload, CSRF-protected
logout, and SPA navigation through Nginx against the same real stack.

### Browser E2E (PR 24A)

`scripts/e2e.sh` builds the full production-path topology in isolation:
throwaway PostgreSQL → migrations → fake-data bootstrap → FastAPI (fake
mode, generated bootstrap admin) → static frontend + Nginx `/api` proxy →
Playwright Chromium. Isolation follows `integration-test.sh` principles:
unique Compose project, unmistakable test database/user, random host
ports, a throwaway named volume, and generated test-only credentials.
Cleanup only touches resources the harness created; no live LLM is used
and no normal developer data is touched.

#### Mandatory real-stack E2E execution procedure for coding agents

Browser E2E, critical-browser acceptance, and browser stability/lifecycle
tests **MUST execute against the repository-managed real E2E stack**. A
coding agent MUST NOT report one of these tests as executed or passing
unless that stack was successfully created, started, and made ready.

The authoritative stack-lifecycle entry point is:

```bash
./scripts/e2e.sh [Playwright arguments...]
```

The harness performs the complete lifecycle in one invocation:

```text
throwaway PostgreSQL
  -> migrations
  -> deterministic fake-data bootstrap
  -> FastAPI
  -> durable worker
  -> Nginx / built frontend
  -> Playwright
  -> isolated-stack cleanup
```

It waits for the frontend/API boundary and fake-data bootstrap before
starting Playwright, imports the canonical reference geography, exports the
test-only credentials and URLs required by the browser suite, and removes
only the isolated resources that it created.

For a PR-specific or stability test, pass the Playwright selector and
options through the harness rather than invoking Playwright directly. The
harness ultimately runs `npm run test:e2e -- "$@"`, so use Playwright CLI
arguments exactly as you would after `npx playwright test`. For example:

```bash
./scripts/e2e.sh zz-31f8-stress.spec.ts --project=chromium --workers=1 --retries=0
./scripts/e2e.sh zz-31f8-stress.spec.ts --project=inspector-firefox --workers=1 --retries=0
```

If a PR-specific browser test needs an environment variable such as a
stability-cycle override, set it on the harness invocation itself so the
value is inherited by Playwright, for example:

```bash
ATI_31F8_STRESS_CYCLES=50 ./scripts/e2e.sh zz-31f8-stress.spec.ts --project=chromium --workers=1 --retries=0
```

Commands shown elsewhere in this document in the form:

```bash
cd frontend && npx playwright test ...
```

describe Playwright test selection/execution against an **already
established compatible E2E environment**. They do not replace the
repository stack-lifecycle requirement. For normal coding-agent execution,
use `scripts/e2e.sh` and pass the equivalent Playwright arguments through
it.

Before claiming PR-level browser acceptance, a coding agent MUST:

1. invoke the repository E2E harness so that the isolated real stack is
   actually started;
2. verify that harness startup/readiness and deterministic bootstrap
   complete successfully;
3. execute the requested Playwright E2E/stability specs through that
   harness;
4. preserve `workers=1` and `retries=0` wherever the relevant acceptance
   contract requires them;
5. report stack startup/readiness separately from the Playwright result,
   including the browser project and requested stability-cycle count.

If the stack cannot be started or does not become ready, the corresponding
E2E/stability acceptance criterion is **NOT TESTED**, not PASS. The agent
must report the startup/readiness failure explicitly. It MUST NOT substitute
Vitest/component tests, mocked browser tests, source inspection, or a bare
Playwright invocation against no compatible running stack for the missing
real-stack acceptance.

If a PR plan requires multiple browser engines, completing the harness run
for one engine does not satisfy the other. Run the required Chromium and
Firefox projects independently through the harness unless the invoked
Playwright selection explicitly covers both.

### Playwright resource control (PR 31F-4)

Real-stack browser tests boot the whole production-path topology (PostgreSQL
→ migrations → fake bootstrap → FastAPI → durable worker → Nginx → built
frontend) and are therefore resource-intensive:

1. Each Playwright **worker** is a separate browser process (plus its helper
   processes) against that full stack — one worker per test-file slot.
2. Raising `frontend/playwright.config.ts` `workers` above `1` runs several
   full stacks concurrently; on a typical development machine this can
   saturate the CPU and produce misleading slowdown/flake symptoms that look
   like ATI defects but are pure resource contention.
3. The repository default is deliberately `workers: 1` (see the config file)
   and must stay bounded.
4. Developers should not raise the worker count casually; any future CI
   increase must be measured and deliberate, backed by benchmark evidence.
5. Controlled local runs use the explicit bounded invocation:

   ```bash
   cd frontend && npx playwright test --workers=1
   ```

6. Suspected ATI performance problems must first be reproduced under a
   single browser worker/session; only a controlled single-worker
   reproduction establishes an ATI-specific defect.
7. Playwright worker count is distinct from Firefox internal
   process/thread counts and from ATI runtime performance. A slow Firefox
   session on a busy machine is not by itself evidence of an ATI Timeline
   issue — reproduce with one worker (and a clean machine) before
   considering ATI performance work.
8. No OS-level CPU affinity/throttling is used anywhere in the repository.

### Real-browser list/detail regression coverage (PR 31F-6)

PR 31F-6 replaced the overlay resource-detail drawers (and the interim
side Inspectors) with a conservative list/detail workspace: the exact
selected detail is the main in-flow workspace content, `Back to
<resource>` restores the bounded list, and Pivot actions stay inline in
the detail. The regressions prove that lifecycle in a real browser,
never with visibility alone:

- The workspace is proven with interaction on BOTH sides of the
  lifecycle: `View` replaces the bounded list with the full-width
  detail, and Back restores the list with its committed
  filters/order/cursor intact. The list and detail are ALTERNATIVE
  views — the table is never rendered under/beside the detail (no
  interactive side panel exists). Assertions also pin the semantics:
  the detail is ordinary in-flow content with a human-readable heading
  (never a dialog with `aria-modal`, never `position: fixed`, no
  backdrop/Portal/body lock).
- Repeated same-page cycles are mandatory: at least **five**
  View/detail/Back cycles in the same page/browser process (no
  reloads) for each critical surface — Evidence, Timeline, History,
  and the routed Evidence surface reached through cross-resource
  exploration (Relationships: three). After
  every Back an action on the list must prove the browser is still
  alive; asserting that the Back button received a click is
  insufficient. The lifecycle regression lives in
  `frontend/e2e/zz-list-detail.spec.ts`. PR 31F-8: cross-resource
  exploration no longer hosts resources in a PivotWorkbench; the
  second `zz-list-detail` journey reaches the Evidence surface through
  the routed relationships -> evidence navigation.
- The raw-pointer evidence slice is the acceptance authority:
  `frontend/e2e/zz-pointer-acceptance.spec.ts` drives the complete
  Evidence journey (Investigation -> list -> RAW View -> full-width
  detail -> RAW inline Pivot trigger -> RAW Cancel -> RAW Back ->
  list returns -> RAW another ordinary list control) five times in ONE
  page/browser process. Every critical raw interaction is
  geometry-proved first (connected, visible, width > 0, height > 0 —
  PR 31F-6 §17), every operation is bounded by a short wedge guard,
  and the journey must pass on the FIRST attempt (``--retries=0``).
- The exact motivating freeze class is automated and sandboxed: the
  final uncontaminated control (native bubble-phase no-op Close) still
  produced a 0x0 next-Pivot-target in both engines (record:
  `out/PR31F6_A4_CONTROL_EXPERIMENT.md`), which authorized the
  list/detail migration. Amendment 5 then replaced the fixed
  PivotWorkspace overlay with an ordinary in-flow workbench; the former
  in-overlay raw View wedge is regression-guarded by
  `frontend/e2e/zz-pivot-acceptance.spec.ts`,
  which proves the same raw `View` press completes cleanly first attempt
  in both engines (healthy geometry, five same-process cycles per
  engine, `--retries=0`, synthetic clicks are not acceptance evidence).
  The raw-pointer geometry assertions guard every critical transition.
- **Firefox is a merge requirement.** The list/detail lifecycle and the
  raw-pointer acceptance journey must run in both Chromium and Firefox
  with the repository `workers: 1` because both engines reproduce the
  motivating freeze class. Playwright runs them in Chromium (default
  project) and in the scoped `inspector-firefox` project; run them
  with:

  ```bash
  cd frontend && npx playwright test zz-pointer-acceptance.spec.ts zz-list-detail.spec.ts zz-pivot-acceptance.spec.ts --project=chromium --workers=1 --retries=0
  cd frontend && npx playwright test zz-pointer-acceptance.spec.ts zz-list-detail.spec.ts zz-pivot-acceptance.spec.ts --project=inspector-firefox --workers=1 --retries=0
  ```

- Closing clears the existing selection only: filters/cursors/back stack
  survive, and deep-linked `selected=<uuid>` opens the detail directly.
  `frontend/src/analyst-table/list-detail.test.tsx` covers the
  A4-LD matrix (alternative views, human-readable heading, semantic
  Back, URL/browser-history restoration, exact scoped read, no
  simultaneous list/detail fetch, one durable selected identity,
  inline Pivot/Cancel, keyboard-operable Back, no Portal/modal/body
  masking).
- Resource detail is ordinary layout content: no Escape listener, no
  deferred focus, no backdrop click — do not reintroduce overlay
  machinery for resource detail.
- Real-browser pointer dispatch on this stack can hang
  Playwright/Chromium's composite ``locator.click`` mid-gesture
  (``performing click action``) regardless of application code — the
  identical hang reproduces with the pre-31F-6 production app on the
  real stack (A/B-verified in the PR 31F-6 record). The raw-pointer
  helpers therefore drive interaction through ``page.mouse``
  (move/down/up) over geometry-proved targets with a bounded wedge
  guard, and the multi-surface lifecycle spec uses the same physical-
  pointer path. Do not treat ``locator.click`` hangs on this stack as
  list/detail regressions without the A/B control against the base
  app.

### PR 31F-8 routed GEOINT browser gate

PR 31F-8 replaces the generic URL-encoded `PivotWorkspace` resource host
with ordinary Investigation-scoped React Router navigation; the browser
acceptance proves the routed architecture natively, without the former
workarounds:

- **Routed GEOINT journey (`frontend/e2e/zz-geoint.spec.ts`, G1..G6).**
  `Geographic context` -> Location Explore (semantic link) -> the routed
  `/geoint/locations/:locationId/entities` surface -> Entity Explore ->
  `/geoint/entities/:entityId` -> `View Evidence` (semantic link) -> the
  exact `/evidence/:evidenceId` route -> browser Back reconstructs
  Entity GEOINT, then the Location surface. G3 additionally proves
  containment toggling writes `include_contained=true` and that refresh
  restores the contained surface (URL-owned state). G4 explicitly
  returns to `/investigations` before creating Investigation B (the
  second Investigation is always created from the list page — no
  product control was added).
- **No workaround class.** The canonical acceptance uses NORMAL locator
  clicks or raw pointer input only: no `dispatchEvent`, no `force: true`,
  no coordinate `clickForce`, no arbitrary sleeps, no JS DOM click
  bypasses, no retry dependence.
- **Native-pointer stability gate
  (`frontend/e2e/zz-31f8-stress.spec.ts`).** The routed journey repeats
  at least **20 consecutive cycles per engine in ONE page process**
  (Geographic context -> Location Entities -> Entity GEOINT -> Evidence
  -> Back -> Back -> Forward -> Forward -> semantic parent/back). Each
  cycle proves the target is visible, the native click completes, the
  canonical URL contains no `pivot=` and no `pivot-workbench`, content
  renders, Back/Forward restore the expected routes, the returned
  resource stays interactive, the browser stays responsive (heartbeat),
  and no product console error accumulates. Run with `workers=1` and
  `retries=0` in Chromium (default project) and Firefox (`inspector-
  firefox` project):

  ```bash
  cd frontend && npx playwright test zz-geoint.spec.ts zz-31f8-stress.spec.ts --project=chromium --workers=1 --retries=0
  cd frontend && npx playwright test zz-geoint.spec.ts zz-31f8-stress.spec.ts --project=inspector-firefox --workers=1 --retries=0
  ```

  `ATI_31F8_STRESS_CYCLES` may raise the cycle count (e.g. 50) without
  changing the assertion contract; the default 20 is never silently
  reduced.
- **Routed navigation architecture (`frontend/e2e/zz-pivots.spec.ts`,
  `zz-pivot-acceptance.spec.ts`, `zz-list-detail.spec.ts`,
  `zz-geolocation-workflow.spec.ts`, `zz-relationship-evolution.spec.ts`).**
  Report provenance opens the exact Evidence route; capabilities resolve
  through the exhaustive typed mapper; Back/Forward/refresh reconstruct
  from URL state; the Investigation shell stays mounted. The
  `zz-pointer-acceptance.spec.ts` raw list/detail Evidence journey is
  unchanged (ordinary list/detail selection remains URL-backed query
  state), and the point-to-history acceptance in `zz-analyst-tables`
  retains its established History convention.

### Secondary navigation and appearance lifecycle (PR 31F-7)

PR 31F-7 closes the two remaining known analyst-facing UI-correctness
follow-ups raised during the PR 31F-6 closure and proves them with
real-browser critical acceptance.

**More is an ordinary in-flow disclosure, not a Portal menu.** The
Investigation workspace `More` control was the last fixed-Portal MUI
`Menu` in the analyst navigation path (the A6 wedge record: idling with
that Portal menu open stalled the browser main thread in Chromium AND
Firefox). It is now a conservative in-flow secondary-navigation
disclosure: a plain `Button` (`aria-expanded`/`aria-controls`) expands an
ordinary `nav` region rendered in the workspace layout — no MUI
Menu/Popover/Modal, no Portal, no backdrop/focus trap/body lock, no
document-global dismissal listener, and no ARIA `menu/menuitem` roles.
Open state is transient local React state only (never URL/global/server
state). The History destination (the menu's only entry) is preserved
verbatim as a semantic react-router link committing exactly one
navigation; an explicit Close collapses the region. Keyboard behavior is
native (Tab reaches the trigger and the region entries, Enter/Space
toggles the trigger, Tab leaves the region — no trap). The old
U34..U37 anchored-menu component tests were replaced by the PR 31F-7
matrix M01..M12 in `frontend/src/investigations/InvestigationWorkspace.test.tsx`
(collapsed initial state, in-flow expansion, close/toggle, preserved
destination, single navigation, Tab/Enter/Space, no menu/Portal/modal
contract, no body masking, Pivot context keeps More hidden).

**Appearance live-preview is deterministic for every supported
appearance.** PR 31F-7 documented the actual root cause of the E30-A6
"Wargames preview never applies after Save/reload/reopen" failure: it was
an E2E assertion artifact, not an appearance-engine defect. The MUI
Preferences dialog is a genuine modal and correctly marks the rest of
the page `aria-hidden` while it is open (the a11y-correct MUI Modal
behavior), so the old `getByRole("banner")` poll resolved to nothing
during the in-dialog preview step. The product state flow — one
AppearanceProvider owning committed + transient preview state over the
single stable prebuilt theme registry — was verified correct in a real
browser for all four appearances; PR 31F-7 changes no appearance
algorithm. The E2E probes now resolve the rendered header surface
through the AppBar element as DOM (CSS locator, unaffected by the modal
accessibility mask; the assertion contract is a rendered surface/token,
never just the radio value), and the spec covers every supported
appearance (Light/Dark/Wargames/Control Room) on the SAME generic path:
select -> live render before Save; Cancel restores the committed
appearance; Save persists across reload; reopen selects the committed
value; no theme-only change alters the route or refetches the graph
topology. No appearance-specific branch or workaround exists.

**Critical real-stack acceptance.** `frontend/e2e/zz-pr31f7-critical.spec.ts`
drives both journeys with physical-pointer-equivalent input
(`mouse.move`/`down`/`up`) over geometry-proved targets, `--workers=1`,
`--retries=0`, no recovery reload and no arbitrary sleeps:

```bash
cd frontend && npx playwright test zz-pr31f7-critical.spec.ts --project=chromium --workers=1 --retries=0
cd frontend && npx playwright test zz-pr31f7-critical.spec.ts --project=inspector-firefox --workers=1 --retries=0
```

- **More journey:** five same-page cycles per engine — RAW open -> region
  visible + page responsive (bounded heartbeat) + no `role=menu`/
  modal/body-lock anywhere -> RAW toggle close -> RAW reopen -> RAW
  History -> one navigation, History renders -> normal browser Back
  restores the workspace -> another raw ordinary control proves the page
  stayed live.
- **Appearance journey (per engine):** preview Dark (rendered surface
  BEFORE Save) -> Save -> reload -> Dark committed -> reopen -> preview
  Wargames before Save -> Cancel -> Dark restored -> reopen -> preview
  Control Room -> Save -> route unchanged -> reload -> Control Room
  committed -> reopen -> preview Light -> Cancel -> Control Room restored.
- `frontend/e2e/zz-list-detail.spec.ts` (both engines) and
  `frontend/e2e/zz-analyst-tables.spec.ts` reach the History route through
  the new in-flow disclosure; `frontend/e2e/zz-appearance.spec.ts` keeps
  the comprehensive graph/route/no-refetch appearance slice in Chromium.

### Frontend wedge-testing methodology

When testing for frontend wedges (browser main-thread lockups), the
goal is to detect a stall in **seconds**, never to sit waiting on
JavaScript events for minutes. Follow this procedure for every wedge
hunt — new E2E regression, manual reproduction, or bisection:

1. **Instrument progress up front.** Every step of the probe must emit a
   progress marker with an elapsed-time stamp (for example
   ``[+1240ms] step name``); no step is ever silent. Before the probe
   starts, install the debugging sinks that will be needed later:
   ``page.on("pageerror")``, ``page.on("console")`` for errors, and a
   captured ``lastUrl`` that is refreshed after every navigation. Every
   assertion runs against the real rendered DOM.
2. **Bound every operation with a short timeout.** A wedge is a stalled
   main thread, not a slow action. Give every JavaScript-backed
   operation (``page.evaluate``, pointer events, dispatches) a bounded
   per-operation timeout of a few seconds (for example 5000 ms), and
   use a heartbeat probe — ``page.evaluate("1+1", undefined,
   { timeout: 3000 })`` — after each interaction to classify the page
   as alive or wedged. Detecting a wedge must never require waiting
   minutes on JS events.
3. **Fail fast and switch to troubleshooting.** The moment the heartbeat
   times out or any bounded operation exceeds its cap, stop the probe
   immediately, dump the triage context (last step marker, last URL,
   captured errors, heartbeat result), and switch to diagnosis —
   browser trace/console, crash dumps, and a minimal repro. Do not
   let the harness keep spinning while the browser is unresponsive.
4. **A/B against the base app before blaming code.** This stack's
   overlay/pointer machinery can wedge independent of any application
   change: build a byte-identical base app (``git archive HEAD
   frontend`` -> ``npm ci`` -> ``npm run build``) and run the same
   probe against a swapped-in base ``dist`` before attributing a wedge
   to a change. If base reproduces it, the wedge is pre-existing; do
   not treat ``locator.click``/raw-pointer stalls as regressions
   without this control.
5. **Distinguish the input path before diagnosing the app.** On the
   real stack, DOM-dispatched clicks (``dispatchEvent("click")``) drive
   the same React handlers as pointer input but do not reproduce
   pointer-path freezes. A wedge on raw pointer events with clean
   dispatch behavior points at the browser's pointer/overlay machinery
   (fixed modal/backdrop/portal scroll and hit-test bookkeeping), not
   at the application's click handlers. The former PivotWorkspace
   fixed-overlay freeze site was removed in PR 31F-6 amendment 5
   (in-flow workbench; raw-pointer acceptance in
   `zz-pivot-acceptance.spec.ts`); no fixed overlay remains in the
   resource/pivot analyst path.

- **Navigation commits defer past the native pointer event.** A
  synchronous router commit (`setSearchParams`) with the live TanStack
  Query re-rendering inside a native click hard-freezes the browser main
  thread (both engines; minimal in-harness reproduction in the PR
  record: the same table/query/selection click freezes when the commit
  is synchronous and is clean when it is deferred one macrotask). The
  resource-table selection commit therefore schedules the URL transition
  after the originating event completes. PR 31F-8 extends the same
  boundary to EVERY controller state transition that accompanies a URL
  commit (the local back stack) — a synchronous `setBackStack` during a
  pointer event re-rendered the routed GEOINT Location containment
  surface and deterministically stalled Chromium/Firefox (reproduced
  with pointer AND keyboard activation; fixed by deferring the state
  update with the commit). Do not regress these commits back to
  synchronous without the raw-pointer control. Cross-resource navigation
  is plain React Router route navigation (semantic links), which owns
  its own commit; the encoded Pivot-stack push/close/truncate commits
  were retired with the host.
- **Same-URL activations are inert.** Re-activating the CURRENT routed
  surface (the active Investigation tab, a breadcrumb root already
  active, or a Pivot action whose canonical destination equals the
  current URL) is a no-op in the routed architecture: no same-URL
  router navigation is issued (a deterministic main-thread stall
  reproduced on the real stack with pointer AND keyboard activation).
  The active tab renders as an inert tab; PivotMenu suppresses actions
  whose destination equals the current route (the older Pivot-stack
  no-op doctrine); the GEOINT breadcrumb root is inert on the context
  route.
- The former fixed-overlay freeze (the second, engine-level pointer-hit
  class documented in the PR 31F-6 record) is addressed architecturally:
  the former overlay/Pivot hosting is replaced by ordinary in-flow
  content and routed resource surfaces, and the native-pointer
  acceptance journey (`zz-31f8-stress.spec.ts`) proves the routed GEOINT
  transitions first-attempt in both engines. Synchronous router commits
  inside native pointer events remain prohibited for the resource-table
  deferred commit; treat any NEW freeze as its own touching-path bisect
  and never reintroduce side-pane/overlay detail or a generic hosted
  workbench.

### Manual Firefox verification (PR 31F-6 merge requirement)

Because the motivating defect was a real-browser freeze, E2E alone is
insufficient: before merging PR 31F-6, manually verify the list/detail
workspace against a real local stack in Firefox and record, per
surface: Firefox version, ATI commit, surface, cycle count and result.
Minimum cycles:

| Surface | Cycles |
| ------- | ------ |
| Evidence (normal route) | 5 |
| Routed exploration Evidence (cross-resource journey) | 5 |
| Timeline | 5 |
| History | 5 |
| Relationships | 3 |
| Relationship Observations | 3 |
| Research | 3 |
| GEOINT | 3 |

Each cycle is open detail -> verify -> Back -> verify the list is
restored -> interact with the primary surface. Confirm visually that no
resource-detail backdrop/side-pane exists at any point.

### Investigation workflow tests (PR 24B)

Component tests (`frontend/src/investigations/`) cover the full matrix:

- list: default bounded page, exact status filter enum, opaque cursor
  Previous/Next via a browser-local cursor stack, no count/page-number
  fiction, empty/error/retry states, and no fabricated subject labels;
- create: localized requiredness and the exact backend bounds exposed in
  OpenAPI (objective ≤ 4000, indicator value ≤ 2048, at least one typed
  indicator), exact `EntityType` submission, cryptographic in-memory
  `Idempotency-Key` generation, commit-uncertain retry reusing the same
  key for transport failures and transient HTTP 5xx outcomes (API 500/
  502/503 envelopes and malformed 5xx bodies, PR 24F F-B02..F-B05),
  new key for changed semantic content after an uncertain attempt
  (including after a 503, F-B11), definitive 4xx validation/conflict/
  auth-permission settling the attempt (F-B06/F-B07/F-B08), pre-transport
  CSRF never treated as uncertain (F-B09), explicit
  `409 idempotency_conflict`, `202` immediate workspace navigation, list
  invalidation, and CSRF preservation;
- polling: pending/running refetch on the bounded 2s interval,
  completed/partial/failed stop refetching, no interval-in-background,
  AbortSignal propagation and cancellation on unmount, transient poll
  failure retaining the last successful state;
- current-resource queries are pointer-gated (`/assessments/current`,
  `/reports/current` only) — never version-list `MAX(version)` — with one
  bounded detail reconciliation for pointer/read-race 404s;
- Overview: Report-based presentation when present, Assessment fallback
  otherwise, partial/failed terminal states, no invented progress, escaped
  analytical text (no raw HTML), Research visibly distinct from Evidence,
  and visible support references;
- full Report route with persisted metadata and the optional deterministic
  Markdown view as plain text;
- workspace placeholders (Evidence/Relationships/Research/Timeline) issue
  no collection queries; detail 404 renders a scoped not-found surface.

### Browser E2E (PR 24B)

`scripts/e2e.sh` now includes the real durable Investigation worker in the
isolated topology (isolated PostgreSQL → migrations → fake-data bootstrap →
FastAPI → worker → static frontend + Nginx → Playwright Chromium). The
worker runs the production Coordinator/runner/persistence with the
deterministic offline LLM boundary (`ATI_LLM_DRIVER=deterministic`),
including the worker-owned PENDING -> RUNNING lifecycle transition and the
post-run Report writing, so the browser slice exercises the complete
workflow with no live LLM or live network: login → create the documented F02 fake-world Investigation → 202 →
immediate workspace → bounded detail polling → terminal lifecycle → current
Assessment → current Report → Overview, verifying `Idempotency-Key`,
`FAKE DATA`, verdict/confidence, executive summary, findings and support
references, and that the list shows exactly one logical Investigation.

Covered paths (frontend/e2e):

- E01 login → authenticated shell → runtime `FAKE DATA` indicator;
- E02 reload restores the server-side session;
- E03 real CSRF-protected logout revokes the session;
- E04 direct SPA navigation through Nginx resolves via React Router;
- E10 create → 202 → workspace → poll → terminal Assessment/Report
  Overview (real stack, fake world, deterministic LLM boundary);
- E11 the created Investigation appears exactly once in the real list.

### Analyst resource tables and drill-down (PR 24C)

Component tests (`frontend/src/analyst-table/`, `frontend/src/{evidence,
relationships,research,timeline,history}/`) cover the full PR 24C matrix
over central MSW handlers for every list/detail route:

- shared table mechanics: semantic header rows, loading/empty/error/retry
  states, keyboard-operable row `View` actions, no sort affordances,
  Next enabled only with a `next_cursor`, opaque cursor bytes passed
  unchanged, Previous over the browser-local back stack, filter-change
  cursor/back-stack reset, URL-cursor deep links, invalid-cursor first-page
  recovery, stale-data retention on transient failure, and the running-
  Investigation freshness notice with Refresh;
- filter codecs: unknown/invalid enum/UUID values normalize to absence
  (never sent), empty values are omitted, local datetime inputs convert to
  UTC ISO with half-open semantics preserved, and `selected` never alters
  list query identity;
- CSV: RFC 4180 quoting of commas/quotes/CR/LF, spreadsheet
  formula-injection neutralization, objective-free filenames, and export
  scoped to the loaded page only (no recursive cursor fetching);
- Evidence: subject/type/source and distinct observed/retrieved rendering,
  exact type/source/entity/time filters, authoritative scoped detail,
  safe HTTP(S)-only source links, escaped markup, and empty-does-not-mean-
  benign;
- Relationships/Observations: source/type/target with analyst labels,
  exact filters, Investigation-scoped detail, bounded relationship-scoped
  observation previews (never generic History), first-class observations
  route, observed/retrieved range independence, and no ended/removed
  inference;
- Research: metadata/counts, exact filters, inspectable claim-to-citation
  closure, visible separation from Evidence, escaped external text, no
  browser source fetching, and retrieval scores never labeled as
  credibility/confidence;
- Timeline: canonical order preserved, exact event/date filters, label
  mapping with safe unknown fallback, and no Relationship Evolution
  wording;
- History: allowlisted object types only (the exact backend public
  allowlist), exact operation/date filters, escaped state/diff rendering,
  exact-version detail (including scoped 404), bounded object-version
  browsing, and RelationshipObservation never fetched through generic
  History; the generic History list skips non-allowlisted audit rows (such
  as the immutable ``evidence`` rows appended by the stored functions)
  instead of failing with a 500, while explicit requests for
  non-allowlisted types fail closed with ``400 invalid_request``
  (api/routes/history.py + tests/unit/api/test_history_routes.py).

### Browser E2E (PR 24C)

`scripts/e2e.sh` exercises the built frontend + real FastAPI + real
PostgreSQL + the durable worker over the PR 23D fake world with the
deterministic offline LLM boundary. PR 24C coverage (frontend/e2e):

- E20 completed-Investigation browsing: bounded Evidence table with a real
  exact filter (evidence type DNS) surviving URL round-trip reload, the
  authoritative scoped list/detail Evidence detail with distinct Observed at /
  Retrieved
  at, Relationship analyst-label rows with detail and a bounded
  relationship-scoped observation preview, first-class
  `/relationships/observations`, Research context (visible separation),
  Timeline with an exact event filter, secondary History with
  exact-version state/diff detail, a browser-proven current-page CSV
  download with the safe filename shape;
- E21 plain browsing after completion opens no pivot modal: pivot triggers
  exist on typed values but the modal appears only after an explicit
  pivot action;
- the PR 24C browser suite runs after the PR 24A/24B specs
  (`frontend/e2e/zz-analyst-tables.spec.ts`) and performs a single login
  (the E2E harness sets the test-only `ATI_CONFIG_PROFILE=local` on the
  API so the throwaway stack's in-process login rate limit (100/60s
  instead of the production 5/60s) never makes the authenticated
  multi-spec suite timing-dependent; production deployments keep the
  default limit), then captures a Playwright storageState
  (`test-results/analyst-session.json`) that the PR 24D suite reuses
  without an additional login.

PR 31F-1 adds the following real-browser regression coverage
(`frontend/e2e/zz-relationship-evolution.spec.ts`):

- **Timeline/relations drawer close**: opening an event/observation detail
  from the analyst table and closing it through `✕`, Escape and the
  backdrop each removes `selected`, preserves the active filters and page,
  and reopening works — the URL-backed drawer never reloads and never
  re-fetches the list;
- **graph edges are visibly rendered in Chromium**: for the canonical
  fake-world multi-node neighborhood, every `.react-flow__edge` SVG path
  connects its exact source/target node (count matches the loaded edge
  list), the translated Relationship label and direction arrow are
  visible, and selecting an edge resolves its exact canonical
  Relationship with provenance preserved. jsdom alone is insufficient
  (React Flow needs a real layout engine), so the check lives in the
  real-browser suite;
- **Firefox datetime controls**: the native `datetime-local` filter labels
  stay visually separate (shrunk) both empty and populated, and the native
  controls remain usable; the same assertion covers Chromium;
- **no-N+1 Evolution invariant**: the Evolution workspace issues exactly
  the bounded observation page for its endpoint metadata — the request
  list shows no per-row Entity/Relationship lookups and no fallback
  topology requests.

### Failure-diagnostic coverage (PR 31F-2)

PR 31F-2 is verified through deterministic unit, migration/repository,
API, and production-path vertical-slice coverage; it never requires live
Internet, a live provider, or a live LLM.

- **Root-cause traversal** (`tests/unit/app/test_error_messages.py`):
  explicit `__cause__` wins, implicit unsuppressed `__context__` is
  followed, `raise ... from None` never reveals the suppressed context,
  both cause-and-context follows the explicit branch, cycles and excessive
  depth terminate deterministically, and an empty root message falls back
  to a safe type-based text.
- **Sanitizer**: configured known secret values (conspicuous synthetic
  sentinels only, never real credentials) are redacted; Bearer/JWT/
  `password=`-style assignment/AWS access-key/PEM private-key/
  `user:password@` credential-URL shapes are redacted; terminal/control
  characters are normalized; Unicode and multiline text survive; SQL- and
  HTML-looking ordinary text is preserved as text; redaction happens
  before truncation and the final value never exceeds the persisted
  maximum (4096).
- **Domain/action contract** (`tests/unit/domain/test_investigation_timeline.py`,
  `tests/unit/app/orchestration/test_fatal_diagnostics.py`):
  `error_message` is accepted only on the failure-bearing shapes
  (PROVIDER_WORK_FAILED, mixed PROVIDER_WORK_COMPLETED, fatal
  INVESTIGATION_STOPPED), over-limit and blank values are rejected or
  normalized, a fatal stop exposes the exact stable code plus sanitized
  message, and non-fatal stops carry neither field.
- **Graph fatal boundaries**: a caught nested exception keeps its stable
  `error_code` while the sanitized root-cause message replaces the generic
  text; persistence failures still propagate (never fatalized);
  `asyncio.CancelledError` still propagates untouched.
- **Migration/repository/query** (real PostgreSQL): the nullable bounded
  column/constraint installs and downgrades cleanly, existing rows keep
  `NULL`, Unicode/multiline messages round-trip exactly, the database
  bound rejects over-limit direct inserts, and the bounded Timeline query
  returns the message without changing ordering or cursor semantics.
- **Production fatal vertical slice**
  (`tests/integration/test_fatal_diagnostics.py`): a controlled nested
  exception at the (faked) analysis boundary flows through the real
  coordinator graph, the real `FatalStopService`, and real Timeline
  persistence into a `fatal_error` INVESTIGATION_STOPPED event carrying
  the stable code and sanitized message; the secret sentinel never
  appears in the persisted row, the Investigation state, or the API
  response.
- **UI** (`frontend/src/timeline/TimelinePage.test.tsx`): the persisted
  diagnostic renders in the detail as plain pre-wrap text with
  wrap-anywhere, a bounded height with vertical scrolling, a localized
  unavailable marker for `null`, no HTML parsing of markup-like values,
  and the PR 31F-1 translated-label + raw-code presentation intact.

PR 31F-2 does not add a real-browser E2E for the fatal diagnostic: the
standard E2E fake world terminates successfully, and manufacturing a fatal
outcome would require changing fake-world data (prohibited). The real-FastAPI/
real-PostgreSQL fatal path is instead covered by the deterministic
integration vertical slice above, and the analyst-visible presentation by
component tests.

### Cross-resource pivots and provenance navigation (PR 24D)

> **PR 31F-8 corrective (delivered behavior).** Cross-resource
> navigation no longer uses the URL-encoded Pivot stack or the
> PivotWorkspace host; the bullets below document the historical PR 24D
> contract. Current production behavior: route-known resource actions are
> semantic react-router links produced by the exhaustive
> `pivotTargetToRoute` mapper (`frontend/src/pivots/pivot-route.ts`), and
> provenance navigation opens the exact Investigation-scoped routes (see
> "PR 31F-8 routed GEOINT browser gate" above and
> `frontend/src/pivots/provenance.test.tsx`). The validated legacy
> `pivot` URL serializer/parser remains only for the deterministic
> one-time legacy policy in `InvestigationWorkspace`.

Separate generated-schema-projected pivot steps from router-backed page
components so the pivot modal and the normal routes reuse the exact PR 24C
resource query/filter/table/detail machinery (`frontend/src/pivots/`,
`frontend/src/analyst-table/resource-page.ts`):

- serializer/parser (`pivot-url.test.ts`): versioned base64url JSON
  envelope in the reserved `pivot` search parameter; query-identity
  stability, unicode labels, headers-only URL length stays within the
  4096-byte bound, malformed/truncated/foreign-version/base64url-off-json
  payloads fail closed, unknown resources filter to presence, max depth 5;
- capability registry (`pivot-capabilities.test.ts`): at least one legal
  action per typed value (Evidence subject/type/source, Relationship
  source/target, observation relationship + exact Evidence) and the
  RelationshipObservation support reference opening the exact scoped
  observation selection;
- navigation/URL projection (`pivot-port.test.ts` regressions inside
  `PivotWorkspace.test.tsx`): step filters arrive pre-applied at the
  table, pillars (evidence type/source) stay anchored to the Investigation;
- modal behavior (`PivotWorkspace.test.tsx`): one Material UI Dialog
  hosting the extracted route-independent workspaces, breadcrumbs with
  clickable truncation, depth cap at five with a visible notice, browser
  history push (Back/Forward restore prior pivot states and the base URL
  search parameters), malformed-cycle deep links degrade to the first
  legal step, 404/network failure shows the in-modal error/retry state,
  network retry, drawing exact Evidence inside the modal, and Close
  preserving base filters;
- provenance (`provenance.test.tsx`): the Report/Overview support list
  pivots exact Evidence by persisted id, Research context/claim
  references pivot exact Research, and RelationshipObservation support
  pivots the exact Investigation-scoped observation (F-P03/F-P04 via the
  scoped GET — the list page deliberately serves a different row, so the
  exact id must drive the request; F-P08 free Report text never enters
  the URL; F-P09 bounded breadcrumb label). A scoped observation 404
  keeps the pivot workspace open with an honest not-found and no
  fallback/substitute (F-P05/F-P06); observation detail pivots to exact
  Evidence by `evidence_id` (F-P07); Close restores the base Overview
  (F-P10). Report/Research free text never enters the URL;
- real-stack E22 (`frontend/e2e/zz-pivots.spec.ts`): overall completing
  F02 Investigation, Evidence support → exact Evidence workspace →
  subject pivot Relationships (the typed direction with the real edge
  set — the fake world's domain is only ever a Relationship SOURCE and
  its malware only ever a TARGET, and report-support evidence ordering
  is run-variable, so the test drives the direction from the evidence
  subject type) → open Relationship → RelationshipObservations →
  observation Evidence → Evidence; breadcrumb path mirrors the
  sequence; browser Back/Forward traverse pivot states; breadcrumb
  truncation restores the Relationships step; reload restores the
  active workbench; Close restores the underlying Overview route;
  `FAKE DATA` and a clean browser console throughout. The observation
  Evidence action is a single-entry inline PivotMenu button (accessible
  name "Evidence" with visible text "Open evidence") and is selected by
  EXACT name — substring "Evidence" would hit the breadcrumb's "Return
  to Evidence" truncation buttons (A6 classification: C3 stale-selector
  trap). Interactions use the raw pointer path (`page.mouse`) because
  the Playwright/Chromium composite locator hit-test can hang the
  browser main thread while a full-viewport fixed layer is open
  (DIAG-verified). Two controls use the documented dispatch convention
  where the raw press deterministically misses on the real stack
  (A6 E22-diag: the single-entry PivotMenu inside the async-loaded
  detail preview): that does not weaken A4/A5 raw-pointer authority,
  which lives in `zz-pointer-acceptance` / `zz-pivot-acceptance`.
  The same raw events can intermittently wedge the Chromium pointer
  dispatch on this stack (environment-specific; the identical
  interaction passes on retry and passed whole-suite runs), so CI
  retries E22 once before failing;
- real-stack E22-B (`frontend/e2e/zz-pivots.spec.ts`, PR 24F): benign/
  dead-end pivot path against the deterministic F01 fake-world
  Investigation — a legal typed pivot (Evidence subject -> Research for
  this entity) opens the target modal with the exact server filter
  visible, shows the honest filtered-empty research state (no invented
  relationship, no automatic fallback, no entity equivalence),
  preserves the breadcrumb context, closes safely to the base Evidence
  route with `FAKE DATA` visible and a clean browser console;
- exact observation query/API coverage (PR 24F): backend contract tests
  F-O01..F-O06 (same-Investigation item, missing/cross-Investigation
  `None`, joined relationship semantics, distinct observed/retrieved),
  real-PostgreSQL identity + Investigation-scope matrix
  (`tests/integration/test_query_relationship_observations.py`),
  API tests F-A01..F-A06 (200 projection, unknown/cross-Investigation
  scoped 404 without existence leaks, malformed UUID stable 422
  envelope, unauthenticated 401, same public fields as the list DTO),
  the regenerated OpenAPI snapshot, and frontend exact-detail coverage
  (F-P04 plus the observations-workspace selection test);
- the PR 24 series is closed: PR 24F performs the final source-and-test
  compliance sweep of PR 24A–24E and reconciles the authoritative
  documentation; no PR 24A–24E requirement remains unrecorded as
  compliant and no material architectural debt blocks PR 25.

### Investigation geolocation read projection and API (PR 25A)

PR 25A delivers the backend/query/API foundation for the v0.1 Investigation
Map: a bounded, Investigation-scoped, read-only projection over already-
persisted immutable `GEOLOCATION` Evidence joined to its canonical IP
entity. Coverage (G-Q01..G-Q10, G-M01..G-M12, G-P01..G-P16, G-A01..G-A10,
plus the vertical slices):

- **read-model invariants** (`tests/unit/app/query/test_geolocation_query.py`):
  fully mappable item; coordinate-less context accepted; partial
  coordinate pair rejected; latitude [-90,90]/longitude [-180,180] bounds;
  precision restricted to the existing persisted vocabulary; provider
  required and non-blank; canonical IP value carried; timezone-aware
  timestamps; frozen/extra-forbid behavior;
- **pure persisted-facts mapping** (`tests/unit/app/query/test_geolocation_query.py`):
  all approved facts map; unknown extra facts ignored (never leaked);
  missing optional city/region/country accepted; missing required
  provider/precision rejected; non-numeric, boolean, NaN/infinity, and
  partial-pair coordinates rejected; out-of-vocabulary precision and
  country-code representations rejected; only the approved fields can ever
  appear on the item;
- **real-PostgreSQL query matrix** (`tests/integration/test_query_geolocation.py`,
  G-P01..G-P16): core projection/bounded-read cases G-P01..G-P13 — empty
  Investigation; one IP; multiple IPs with deterministic ordering;
  latest-per-entity; deterministic id tie-breaker; generic Evidence types
  (REPUTATION/NETWORK/DNS) excluded; non-IP GEOLOCATION defensively
  excluded; cross-Investigation isolation with a shared Entity; coordinate-
  less context retained; truncation at `max_items + 1` with deterministic
  prefix; exactly-at-bound not truncated; historical volume stays one
  item per entity; and the G-P13 bounded-single-read verification — and
  defensive cases G-P14..G-P16: malformed persisted facts and partial
  coordinate pairs fail closed with `GeolocationFactsError`
  (G-P14/G-P15), and an unknown Investigation yields the established empty
  collection (G-P16). G-P13 verifies the single-read criterion
  structurally: the service issues exactly one SELECT over the
  latest-per-entity ranked subquery with a `max_items + 1` LIMIT, never
  per-item Evidence gets or Python-side grouping of historical rows. PR
  25D explicitly inspected the repository for reusable SQL
  statement-counting infrastructure (SQLAlchemy event listeners, query
  counters, statement recorders); the only SQLAlchemy event listeners
  present register batch composite types (the E2E geolocation seeder) or
  track UnitOfWork lifecycle phases (the analyst pipeline transaction
  tracker) — neither counts SQL statements. No generic instrumentation
  framework was created; structural verification is retained and
  documented at the test and in the PR 25D closure note below;
- **index eligibility** (`tests/integration/test_query_indexes.py`,
  test_p13): the latest-per-entity projection drives through the existing
  investigation-prefixed evidence listing indexes; no new index/migration
  is required at v0.1 (plan 28)
- **API contract** (`tests/unit/api/test_geolocation.py`): unauthenticated
  401; ANALYST and ADMIN 200; exact allowlisted response DTO; no
  facts/raw payload/source record id/artifact path leakage; empty
  collection 200; truncation transport; malformed persisted projection
  maps to a safe 500 internal error without leaking values; OpenAPI
  declares path, GET, operation id `list_investigation_geolocations`,
  cookie-session security, and the dedicated response schemas (a lower-
  privilege authenticated role does not exist in the v0.1 UserRole
  vocabulary, so the 403 branch remains covered at the shared
  `require_analyst` dependency);
- **real PostgreSQL + FastAPI vertical slices**
  (`tests/integration/test_api_geolocation.py`): persisted Entity +
  `GEOLOCATION` Evidence -> PostgreSQL query service -> QueryServiceBundle
  -> FastAPI route -> public JSON DTO (raw-payload-bearing non-geolocation
  Evidence never enters the projection), and the same path proving strict
  cross-Investigation HTTP isolation;
- regenerated OpenAPI fixture (`tests/fixtures/openapi_v1.json`) and
  frontend generated API types (`frontend/src/api/schema.generated.ts`,
  verified with `npm run api:check`).

### Investigation Map / Leaflet visualization (PR 25B)

PR 25B is the frontend Map feature over the PR 25A bounded projection
(`frontend/src/geolocation/`). The rendering boundary mock
(`frontend/src/test/react-leaflet-mock.tsx`) replaces the react-leaflet
surface with inert labeled elements so component tests assert Leaflet
semantics (one marker per mappable item, popup content, tile attribution,
and the deterministic viewport commands) without a layout engine or live
tile requests; TanStack Query and the centralized API client are never
mocked. Coverage:

- **pure map view model** (`geolocation-map-model.test.ts`, B-M01..B-M10):
  empty collection; valid paired coordinates; null/null context retained;
  mixed partition; server order preserved inside groups; truncation
  propagated exactly; partial pairs, NaN/infinity and out-of-range
  coordinates never plotted (inclusive boundary values are); input
  transport objects never mutated;
- **location labels** (`geolocation-labels.test.ts`, B-L01..B-L05):
  city/region/country join; region+country without punctuation artifacts;
  country only; no-label yields the explicit unavailable signal; external
  strings remain escaped text;
- **viewport policy** (`geolocation-viewport.test.ts`, B-V01..B-V07): zero
  points -> no fit command; one point -> exact center at the conservative
  fixed zoom 8; two/many points -> bounds over every mappable returned
  coordinate; multi-point max zoom cap; coordinate-less and malformed
  defensive items ignored for bounds;
- **API/key/query seam** (`geolocation-queries.test.tsx`, B-Q01..B-Q08):
  exact PR 25A path with no query string/cursor/limit; centralized
  `apiGet`; caller AbortSignal cancellation reaches the fetch; query key
  contains the Investigation ID (distinct per Investigation); one bounded
  fetch with no polling; errors remain typed `ApiError`;
- **route page states** (`InvestigationMapPage.test.tsx`, B-U01..B-U17;
  PR 35-2): the consolidated primary navigation (Overview | Evidence |
  Graph | GEOINT | Research | Timeline) selects GEOINT on
  `/geoint/map`, and the active MAP sub-tab is inert while TABLE remains a
  semantic link; translated loading
  state; API failure + Retry with no fallback; honest empty state with no
  invented marker; one/multiple mappable items reach the map and the
  non-map list; unlocated-only state; mixed state with explicit counts;
  truncated warning (server bound never bypassed); persistent visible
  approximation disclaimer; exact precision enum -> translated neutral
  labels; known provider friendly label and unknown provider escaped
  text; observed/retrieved timestamps stay distinct; the exact Evidence
  drawer opens from the row action; the page is built from the
  geolocation endpoint and never from Evidence pagination; hostile
  external values cannot inject markup; the global `FAKE DATA` marker
  remains visible;
- **Leaflet wrapper** (`InvestigationMap.test.tsx`, B-F01..B-F08): one
  Marker per mappable item and none for unlocated items; popup carries
  the exact item and Evidence action; TileLayer carries the centralized
  OSM attribution/URL (no secret-bearing URL); no fabricated precision
  circle; no clustering plugin/component; unmount leaves no
  application-owned timers/listeners; single-point `setView` and
  multi-point `fitBounds` wiring matches the pure viewport policy;
- **provenance** (`InvestigationMapPage.test.tsx`, B-P01..B-P06): marker
  popup and non-map row both drive the exact PR 25A `evidence_id` (no
  lookup by IP, no Evidence list scan, Investigation-scoped request, and
  Close returning to the intact Map view) through the shared
  DetailDrawer/EvidenceDetail PR 24C surface;
- **accessibility** (`InvestigationMapPage.test.tsx`, B-A11Y01..B-A11Y08):
  translated GEOINT heading; visible disclaimer; labeled keyboard-reachable
  non-map table; native Evidence buttons; no hover-only information;
  unlocated items inspectable without the map; labeled map region; tile
  attribution present.

Real-stack browser coverage **E24** (`frontend/e2e/zz-geolocation.spec.ts`)
runs the principal Map workflow over the full production-path stack (built
frontend + Nginx + real FastAPI + real PostgreSQL + the durable worker
over the fake world, real PR 25A endpoint, no geolocation interception,
no correctness dependency on live tile delivery). The E24 data
prerequisite is closed by the PR 25C deterministic real-stack seeding
seam: after the browser completes the exact Investigation, the spec
invokes `scripts/e2e-seed-geolocation.sh <investigation-id>
single_mappable` (the harness-only seeder persists a normal canonical IP
Entity + `GEOLOCATION` Evidence row through the normal repositories into
the throwaway E2E database), then asserts the disclaimer, the exact
seeded IP in the non-map representation, a real Leaflet marker, and the
exact persisted geolocation Evidence provenance in the drawer (subject
IP + `Geolocation` type + `urn:ati:source:dbip_city_lite` source),
followed by a safe return, `FAKE DATA`, and a clean browser console.
Seed failure is test failure; there is no data-path skip.

### Map analyst workflow and E2E seeding (PR 25C)

Deterministic E2E seeding and the Map-origin typed pivot workflow:

- **seeder unit contracts** (`tests/unit/infrastructure/test_e2e_geolocation_seed.py`,
  C-S01..C-S13): unknown scenarios rejected; malformed/nil Investigation
  IDs rejected; missing/soft-deleted Investigation refused; the explicit
  E2E guard (`ATI_OPERATING_MODE=fake` **and** `ATI_E2E_SEEDING_ENABLED`)
  required with the CLI exiting nonzero without it; valid single mappable
  construction; distinct multi-IOC identities; same-coordinate identities
  remain distinct; null/null coordinate fixture valid; deterministic
  timestamps/values on repeat derivation; repeated invocation bounded and
  idempotent against an in-memory seam; no raw payload/secret-bearing
  values; and a structural review that the seeder owns no raw SQL (only
  `investigations.get_by_id` / `entities.upsert` / `evidence.insert` on
  the real `PostgresUnitOfWork` seam);
- **seeder real-PostgreSQL proof** (`tests/integration/test_e2e_geolocation_seed.py`,
  SG01..SG07): a normal Investigation is created and seeded, then read
  through `PostgresInvestigationGeolocationQueryService` with exact
  seeded Entity/Evidence identity, mappable/unlocated/same-coordinate
  records, deterministic ordering, idempotent repeat, and strict
  cross-Investigation isolation; an authenticated FastAPI check proves
  the real `/geolocations` endpoint returns the seeded projection without
  leaking facts/raw payloads;
- **map-origin entity action contracts**
  (`frontend/src/geolocation/GeolocationEntityActions.test.tsx`, C-P01..C-P12):
  the single `map_entity` source kind; exact Evidence subject filter;
  exact Relationship source and target filters (never merged); exact
  Research subject filter; IP display label (never coordinates); View
  Evidence remains the exact `evidence_id`; marker popup and non-map row
  expose equivalent Explore actions; coordinate-less items stay
  actionable; same-coordinate items keep distinct Entity IDs; no client
  Relationship OR merge; no unsupported resource/scoped selection; a
  rendering test proves Explore navigates the canonical filtered Evidence
  route (PR 31F-8 routed activation);
- **pivot model/URL validation** (`pivot-url.test.ts`, `pivot-capabilities.test.ts`,
  C-V01..C-V08): `map_entity` accepted and URL round-trips; unknown
  source kinds (`map_marker`, `map_row`) rejected; max pivot depth (5),
  label bound (128), UUID filter validation, no-op suppression, and
  close/back behavior unchanged;
- **real-stack browser matrix** (`frontend/e2e/zz-geolocation-workflow.spec.ts`,
  E25..E28): E25 seeds `multi_ioc` and explores each IP independently
  through typed pivots (Evidence with breadcrumb IP identity and
  server-filtered target; a legal Relationships-source target resolving
  to an honest empty/dead-end state; exact Evidence drill-down and
  disclaimer after return); E26 seeds two identical-coordinate IPs and
  proves both remain distinct inspectable rows with their own View
  Evidence/Explore actions and no co-location/cluster claim; E27 seeds a
  coordinate-less item and proves the row is fully actionable (exact
  Evidence, legal Explore action, honest empty Research target, safe
  close/back) with no marker; E28 uses an unseeded fake-world
  Investigation to prove the honest empty Map and strict isolation from
  every other Investigation's seeded rows.

Related real-stack instability is separately recorded: E22/E22-B
(`zz-pivots.spec.ts`) and occasional E23 (`zz-relationship-evolution.spec.ts`)
interactions hit the documented Chromium/MUI main-thread wedge under the
existing retry-1 configuration (reproduced on the pre-PR base commit;
E22/E22-B consistently, E23 intermittently) and are outside PR 25C scope
per the PR 24F stability notes and `docs/INVESTIGATION_STABILITY.md`.
The PR 25C E24-E28 geolocation suite passes deterministically.

### PR 25D — PR 25-series compliance closure [DONE]

PR 25D is the final closure PR for the PR 25 geolocation-map series; it
added no geolocation, Map, API, persistence, pivot, provider, spatial, or
GEOINT functionality. Delivered:

- **Fresh source-level audit of PR 25A-C** against actual source/tests
  (not implementation summaries) with a COMPLIANT/PARTIAL/MISSING/
  OUT-OF-SCOPE classification of every material requirement; no material
  PR 25 production defect was found;
- **G-P matrix normalization:** the three duplicate `gp12` identifiers
  became the distinct G-P14 (malformed persisted facts fail closed), G-P15
  (partial coordinate pair fails closed), and G-P16 (nonexistent
  Investigation empty); G-P12 remains the historical-volume test and
  G-P13 the bounded-single-read test; the test module and this document
  reflect G-P01..G-P16 with G-P01..G-P13 as the core projection/
  bounded-read cases and G-P14..G-P16 as the defensive cases;
- **G-M matrix normalization:** the duplicate `gm10` identifiers became
  the distinct G-M11 (invalid precision vocabulary) and G-M12 (invalid
  country code); the test module and this document reflect G-M01..G-M12;
- **Seeder unit matrix normalization:** the duplicate `cs04` identifier
  became the distinct C-S13 (CLI exits nonzero when the guard is not
  satisfied); the test module and this document reflect C-S01..C-S13;
- **G-P13 disposition:** existing test support for SQL statement counting
  was explicitly inspected (see above); no reusable lightweight mechanism
  exists, so structural verification is retained and documented at the
  test, and no generic instrumentation framework was added;
- **B/C/SG/E traceability audit:** B-M/B-L/B-V/B-Q/B-U/B-F/B-P/B-A11Y,
  C-P/C-V, SG01..SG07, and E24-E28 carry no duplicate or misleading
  identifiers (the E22/E22-B Chromium/MUI wedge remains separately
  classified per `docs/INVESTIGATION_STABILITY.md`);
- **E24-E28 rerun** on the canonical full stack with all four real-stack
  browser specs passing through the real PR 25A read path;
- **No production/API/schema/persistence change:** the PR 25A endpoint,
  operation ID, DTO, paired coordinates, provider/precision/timestamps,
  `{items,truncated}` shape and authentication, PR 25B Map route/Leaflet
  behavior, 30s stale time, viewport policy and disclaimer, PR 25C typed
  pivot behavior, and the deterministic seeder implementation are
  unchanged.

PR 25A-D are closed; no known PR 25 functional residual remains, and PR 26
remains the next v0.1 feature phase.

### Relationship Evolution and graph (PR 24E)

Backend test coverage for the entity-centric observation query:

- **query contracts** (`tests/unit/app/query/test_query_contracts.py`):
  `direction`/`counterparty_entity_id` without `entity_id` fail closed;
  a bare `entity_id` has the documented `either` behavior; fingerprints
  include entity/direction/type/counterparty (entity-only and
  explicit-`either` share one cursor context; different entities,
  directions, types and counterparts never share one);
- **route contracts** (`tests/unit/api/test_relationship_evolution_routes.py`):
  valid entity UUIDs, direction/counterparty/type filters map exactly to
  the query DTO; malformed UUIDs, unknown direction values and unknown
  relationship types fail with the stable 422 envelope; `direction` and
  `counterparty_entity_id` without `entity_id` fail with 400
  `invalid_request`; the public observation DTO exposes the joined
  relationship fields without leaking operational columns; the one-hop
  Relationships `entity_id` filter maps to the DTO;
- **real PostgreSQL integration**
  (`tests/integration/test_query_relationship_evolution.py`): the PR 24E
  E-B01..E-B16 matrix over a synthetic world (focal A, counterparties
  B/C, reverse edge, unrelated D->E, multiple providers, distinct
  observed/retrieved times, a null-observed row, another Investigation
  re-observing the same edge): entity/direction/counterparty/type/provider/
  observed-range intersection, wrong-Investigation isolation, no
  self-relationship duplication, canonical `retrieved_at DESC, id ASC`
  ordering, bounded one-row cursor pagination, and cursor/filter mismatch
  (across focal entity, direction, type, and collection kind) failing
  closed;
- **plan eligibility** (`tests/integration/test_query_indexes.py` P12):
  the entity-joined observation query shape uses the existing
  `relationship_observation_investigation_retrieved_idx` — no structural
  migration was required, so none was added;
- the OpenAPI snapshot fixture is regenerated after the contract change
  (governed by `tests/unit/api/test_openapi.py`).

Frontend coverage (`frontend/src/relationship-evolution/`,
`frontend/src/relationship-graph/`):

- pure derived model (`relationship-evolution-model.test.ts`, E-D01..E-D09):
  outbound/inbound/self lanes, null-observed rows in the explicit
  unavailable group, stable ID tie-breaks, retrieved-time independence,
  repeated observations as distinct points, type-separated lanes, and
  page-scoped annotations that never claim global first-observed;
- Evolution workspace (`relationship-evolution.test.tsx`, E-U01..E-U18 via
  central MSW handlers): no request without an entity, bounded
  entity/direction page, direction/type/counterparty/provider/observed-range
  filters reaching exact server params with cursor reset, points rendered
  from `observed_at` with `retrieved_at` as distinct tooltip metadata,
  explicit null-observed state, bounded-page notice + Next/Previous,
  activation opening the observation detail with Evidence provenance,
  honest no-results wording, running-Investigation notice, error Retry
  preserving context, keyboard-accessible points, and the tabular
  alternative;
- graph (`relationship-graph-model.test.ts` + `relationship-graph.test.tsx` +
  `graph-queries.test.tsx`, PR 24E E-G01..E-G11 then PR 31D G31D-M01..M12,
  G31D-Q01..Q10, G31D-U01..U20): the model is a faithful one-hop projection
  of the canonical `GraphNeighborhoodResponse` (focal/counterparty roles by
  request ID, exact server Entity metadata and edge observation summaries,
  self-loop one-node/one-edge, distinct multi-edge pairs, preserved server
  ordering and truncation, null times staying null, deterministic radial
  layout keyed by identity set); the API/query seam requests exactly the
  PR 31C neighborhood path with only `direction`/`relationship_type`/
  `limit`, never sends cursors or Evolution-only filters, propagates
  AbortSignal, keys off semantic inputs, disables without a focal Entity,
  and surfaces typed `ApiError` values without Relationships fallback; the
  workspace tests assert the graph endpoint (not the Relationships list)
  carries direction/type and omits `observed_from`-style filters, node
  selection exposes canonical ID/type/value/display name, loading/error/
  Retry, truncated notice from the API flag, isolated-focal success,
  pane-click deselection, and the controlled node-change path
  (jsdom cannot run React Flow pointer drags, so the draggable wiring and
  SELECT-change round-trip are unit-tested and the real browser drag is the
  E2E drag smoke); the jsdom test environment stubs `ResizeObserver` for
  `@xyflow/react` (documented in `src/test/setup.ts`); no pixel/layout
  snapshots and no exact canvas-coordinate assertions are made;
- PR 31D frontend tests use deterministic MSW graph fixtures/builders
  (`graphNeighborhoodHandler` recording path/direction/type/limit) and the
  existing `renderAtPath`/user-event/jest-dom harness; `schema.generated.ts`
  is regenerated from the committed OpenAPI snapshot and `npm run api:check`
  stays green;
- real-stack E23 (`frontend/e2e/zz-relationship-evolution.spec.ts`):
  completed F03 fake-world Investigation (`logistics-corp.test`),
  Relationships -> source entity -> Relationship Evolution, temporal
  points driven by `observed_at` with distinct `retrieved_at` tooltips,
  `Earliest shown on this page`, observation activation -> exact
  observation detail, observation -> Evidence exact navigation through
  the PR 24D pivot workspace, switch to Graph -> canonical graph endpoint
  (observed requests prove `/graph/entities/…/neighborhood`, never a
  Relationships or observations page), entity semantics (server
  value/type cue), canvas edge label + edge selection showing the
  observation summary (count/first/last observed), node selection showing
  canonical Entity identity, pan/zoom/fit controls, a node drag smoke that
  proves the moved position without any additional graph request (read-only), ->
  accessible relationship list -> exact Relationship table context, route
  refresh preserving Evolution filters/entity, browser Back/Forward
  preserving focal entity identity, `FAKE DATA` visible, clean console;
- PR 24E/31D add no speculative second graph/visualization dependency and
  no new fake-world fixture: the F03 world's repeated observed-at stamps
  drive the browser slice.

#### PR 31F-6 amendment-6 broader-suite classifications (A6)

Every material broader-suite failure raised by the amendment-5 report was
classified before any edit (amendment-6 record `out/PR31F6_A6_IMPLEMENTATION_REPORT.md`):

- **E20 More menu — C3 (test) + C2 (deferred menu defect).** Opening the
  fixed-Portal MUI More menu and idling ~1.5 s wedges the Playwright
  browser main thread in Chromium AND Firefox (A6 diagnostic: dispatched
  open -> heartbeat alive -> first menu probe unresolvable -> heartbeat
  dead; zero application/console errors; the immediate-navigation pattern
  used by the lifecycle spec's History section completes repeatedly). The
  menu itself is untouched by PR 31F-6 and the identical Portal/overlay
  wedge class is A/B-verified against the pre-31F-6 app (the A4 control
  experiment record), so the parent defect is deferred (framework follow-up
  in the A6 record). E20 now opened More and activated its History entry
  back-to-back and asserted the user-visible contract (History reachable,
  single activation, Investigation intact) — Portal existence/geometry is
  not a product contract. PR 31F-7 then REPLACED the Portal menu with the
  ordinary in-flow disclosure (see the PR 31F-7 section below), closing
  the deferred defect class: E20/E21, `zz-list-detail.spec.ts` and
  `zz-pr31f7-critical.spec.ts` now interact with the in-flow region and
  assert the same user-visible contract.
- **E20 History "Diff" — C3 (data-dependent first-row contract).** The
  fake world's newest investigation UPDATE frequently carries an EMPTY
  diff (worker budget/status updates vary per run), so Diff presence on
  the first History row was run-dependent. E20 now deep-links the newest
  event that actually carries a diff (authoritative history API) and
  asserts the same exact-version safe rendering; the deep link exercises
  the list/detail deep-link contract.
- **E22 legacy Pivot — C3 (stale contracts) + C4 (report evidence
  readiness).** (1) The fake world creates NO malware-source edges — the
  report-support evidence is the malware evidence, whose "Relationships
  where source" is legitimately empty forever; the direction is now
  driven by the evidence subject type (domain→source, malware→target),
  preserving the typed-pivot slice over real data. (2) The observation
  Evidence action is a single-entry inline PivotMenu whose accessible name
  is the column aria-label ("Evidence", visible text "Open evidence") and
  is reached by EXACT name; substring "Evidence" hits the breadcrumb's
  "Return to Evidence" truncation buttons and silently rewound the stack
  (diagnosed via the URL-backed stack at each step). (3) The report
  evidence button on the Overview is worker-admitted asynchronously and
  is now waited on explicitly. (4) Two controls inside async-loaded detail
  content use the documented dispatch convention where the raw press
  deterministically misses on this stack (E22-diag; the A4/A5 raw-pointer
  authority is untouched).
- **E23 React Flow drag — C3 (screen≠flow coordinates).** The graph's
  in-flow chrome (the expansion-in-flight Alert above the canvas) shifts
  the canvas on screen without moving nodes, so absolute screen-box
  retention reads a phantom ~56 px Y drift. Retention assertions now
  compare canvas-relative flow coordinates (node box − canvas box);
  drag-moved, topology and request assertions unchanged.
- **Intermittent raw-input misses — C5 (harness/environment).** See the
  wedge-testing methodology above: byte-identical trees alternate pass/
  fail, the failure press varies per run and engine, gestures complete
  (RAW-OK) with a live heartbeat and proved geometry, and the page never
  freezes. Never treat these as application regressions without the
  pre-31F-6 A/B control.
- **`.env`/E2E isolation — bounded harness fix.** podman-compose 1.0.6
  reads the repo `.env` and its values override exported variables, which
  defeated the harness's random host-port isolation on machines whose
  `.env` pins dev ports. `scripts/e2e.sh` now writes a throwaway alternate
  environment file and passes `--env-file` to every compose invocation, so
  the isolated stack needs no manual `.env` move; ATI runtime config
  precedence (environment variables as ultimate override) is unchanged.
- **Component-suite load flake — bounded sync.** Real-route component
  tests under full-suite parallel load exceeded the testing-library
  default 1 s async wait (varying subset per run; every test passes in
  isolation). `src/test/setup.ts` sets `configure({ asyncUtilTimeout:
  10_000 })` — a semantics-keyed poll for real rendered elements, never a
  sleep, assertions unchanged.

#### Incremental graph expansion tests (PR 31E)

PR 31E testing is deterministic and fully offline (MSW + synthetic
fixtures; no live Internet, providers, or LLM):

- **pure merge contract** (`graph-expansion-model.test.ts`, G31E-M01..M15):
  canonical Entity/Relationship identity merge, overlapping responses
  producing exactly one node/edge, newer responses replacing duplicate
  fields (observation counts never summed), self-loop containment, distinct
  source/target/either completion keys, exact-key truncation tracking,
  deterministic order (existing canonical order first, new objects in
  server-return order), preserved root focal, root refresh overlays that
  keep expansions, and no persisted/presentation state;
- **incremental placement** (`relationship-graph-layout.test.ts`, G31E-L01..L08):
  deterministic anchor-ring positions for one/many new Entities, repeat
  calculation identity, empty-set safety, collision avoidance, and never
  repositioning existing nodes;
- **PivotMenu local-action regression matrix** (`PivotMenu.test.tsx`,
  G31E-P01..P14): existing URL pivots unchanged, single/mixed local-action
  rendering, local selection changing no URL/pivot state, navigation pivots
  still pushing exact PivotSteps, local actions surviving `MAX_PIVOT_STEPS`
  and no-op suppression, disabled locals never executing, keyboard Arrow
  navigation skipping disabled items, Escape/outside-pointer close, the
  non-modal Portal/Paper architecture, and no-trigger when no actions
  exist;
- **expansion controller** (`use-graph-expansion.test.tsx`, G31E-Q01..Q16,
  MSW with the existing graph endpoint): exact selected Entity + direction
  mapping, forwarded root Relationship type + `GRAPH_NEIGHBORHOOD_LIMIT`,
  one action -> one request, idempotent completed expansions, overlap
  safety, failure preserving the accumulated graph with exact Retry,
  one-in-flight guarding, root-change abort/stale-result exclusion,
  cancellation as non-failure, truncation state, and no Relationships-list
  fallback;
- **graph component/workspace** (`relationship-graph.test.tsx`, G31E-U01..U25):
  the selected-node menu exposes the three expansion actions with existing
  navigation pivots, expansion requests the canonical selected Entity,
  accumulated nodes/edges render with originals preserved exactly once,
  the accessible list reflects accumulated edges, existing and dragged
  positions survive while only new nodes are placed near the expanded
  anchor, completed expansions are disabled without refetch, in-flight
  actions are disabled, failure keeps the graph with Retry, truncation
  shows a bounded notice, a different root context renders only its own
  topology, local expansion never mutates the pivot URL, and selection
  alone never expands;
- **real-stack E23 extension** (`frontend/e2e/zz-relationship-evolution.spec.ts`):
  select a non-focal Entity -> Pivot menu -> Expand known relationships,
  exactly one bounded graph-neighborhood request for the selected Entity
  (`direction=either`, `limit=25`), no Relationships-list or
  RelationshipObservation traffic, the dragged focal node's position
  preserved across expansion, the completed expansion disabled and never
  refetched, navigation pivots still present, no `pivot=` URL mutation,
  `FAKE DATA` visible, clean console. When the deterministic fake world
  cannot guarantee second-hop growth, the E2E asserts the real request,
  merge safety, and retained topology instead of hard-coding a node-count
  increase (unit/MSW tests own guaranteed-growth cases);
- no pixel-perfect graph assertions anywhere; coordinates are asserted
  only structurally (deterministic placement helpers) or in the real
  browser via bounding-box stability.

#### Graph provenance drill-down tests (PR 31F)

PR 31F testing is deterministic and fully offline (MSW + synthetic
fixtures; no live Internet, providers, or LLM), with the real-stack slice
extending the existing relationship-evolution scenario. The exact identity
chain under test is
`GraphEdge.relationship_id -> Relationship -> bounded RelationshipObservations -> RelationshipObservation.id -> RelationshipObservation.evidence_id -> EvidenceObservation`:

- **provenance component** (`GraphRelationshipProvenance.test.tsx`, G31F-U01..U37):
  the exact Investigation-scoped Relationship request and canonical stable
  fields; bounded loading; scoped 404 and error + Retry repeating the exact
  Relationship request; the observation first page filtered by the exact
  `relationship_id` with the existing bounded page size and opaque cursor
  (Next -> exactly one next-page request, Previous restores the prior page
  through the browser-local back stack, Next disabled without
  `next_cursor`); `observed_at`/`retrieved_at` kept distinct with null
  `observed_at` never replaced by retrieved time; Relationship change
  resetting cursor/back stack/observation/Evidence; observation selection
  by `observation.id` (on-page rows render directly, off-page selections
  resolve through exactly one exact observation GET — never a cursor
  scan); scoped observation 404/error with Retry; existing observation
  provenance pivot actions preserved; zero Evidence requests before the
  explicit action (no fan-out); the explicit `View supporting evidence`
  action requesting exactly `observation.evidence_id`; canonical
  `EvidenceDetail` with distinct timestamps; scoped Evidence 404 and
  Retry; closing Evidence retaining the selected observation; a new
  observation clearing the prior Evidence selection; and only public
  Evidence DTO fields rendering (hostile `raw_payload`/internal fields
  never surface);
- **graph isolation** (G31F-U32..U37, in the same component test file,
  exercised through the accessible edge list because canvas-edge
  selection is not jsdom-renderable): opening the provenance, paginating
  its observations, and opening Evidence issue zero graph-neighborhood
  requests and change no node count or positions; prior expansion state
  (completed expansion menu item stays disabled) and dragged positions
  survive closing the provenance; provenance reads never rebuild graph
  topology (G31F-Q08);
- **real-stack E23 extension** (`frontend/e2e/zz-relationship-evolution.spec.ts`):
  canvas-edge selection -> `Inspect observations` -> the provenance region
  with the exact Relationship detail; exactly one bounded
  RelationshipObservation request filtered by the canonical
  `relationship_id` (limit=25, no cursor, no fan-out, and the request
  identity matches the edge panel's `selected=` link); the
  observed/retrieved distinction visible; observation selection showing
  the exact observation identity with no Evidence traffic yet; the
  explicit View-supporting-evidence action issuing exactly one Evidence
  GET whose UUID path equals the selected observation's `evidence_id`
  (captured dynamically from the DOM); safe canonical Evidence fields
  with no raw-payload surface; return to the graph with the expanded
  topology and the dragged focal position retained (tolerance 2px) and
  zero new topology requests; `FAKE DATA` visible; clean console;
- no hard-coded run-specific UUIDs anywhere: identities are captured
  dynamically from DOM elements and request URLs (run-seeded fake-world
  identities vary between seeds).

## PR 26 GEOINT testing strategy

PR 26 testing must preserve the production-path principle: deterministic tests fake true external/non-deterministic boundaries, not ATI's persistence, canonicalization, PostGIS, resolver state machine, or query contracts.

### PR 26A delivered testing (G26A-D and G26A-P matrices)

PR 26A's non-spatial foundation is covered by:

- **G26A-D01..D14** (`tests/unit/domain/test_geoint.py`): exact
  `LocationType`/`LocationPrecision`/`GeoResolutionStatus` vocabularies;
  country/administrative-area/city type-shape constraints; deterministic
  two-letter country-code normalization without reference data; blank/
  oversized names and codes fail closed; EntityLocation inverted-time
  rejection; naive/offset observation timestamp normalization; mandatory
  exact Entity/Location/Evidence observation IDs; initial pending
  GeoResolution validity; malformed status/error/claim metadata fail
  closed; bounded PostGIS-compatible EWKT text on Location (added by PR 26B);
  `EntityType` unchanged (Location is
  not an Entity); deterministic identity tuple excluding parent.
- **G26A-P01..P34** (`tests/integration/test_geoint_persistence.py`): the
  canonical real-PostgreSQL matrix — Location round-trip, parent/admin
  shape enforcement, canonical-identity reuse without version churn,
  concurrent same-identity upsert yielding one row, incompatible duplicate
  state failing atomically, database-side shape rejection; first observation creating EntityLocation
  atomically, exact provenance storage, GEOLOCATION Evidence requirement,
  Evidence subject mismatch rejection, missing Entity/Location/Evidence
  rejection, duplicate observation rejection without current-state
  mutation, later-observation advancement, older-observation non-rewind,
  equal-timestamp UUID tie-break, earliest first-observed preservation,
  deterministic latest association, zero `domain_object_history` rows for
  observations, rollback atomicity, no public EntityLocation mutation
  path; initial pending GeoResolution creation with exact state, duplicate
  pair idempotency, concurrent duplicate creation yielding one row,
  non-GEOLOCATION and subject-mismatch rejection, missing/invisible
  Entity/Evidence rejection, no second queue table; normal UnitOfWork
  participation, exception rollback, no independent repository commits,
  and authoritative database-assigned versions. (PR 26C supersedes the
  historical "no claim/lease/completion API" assertion: the lifecycle API
  now lives on this same repository and is asserted complete in
  G26A-P29/P42/P43.)

#### PR 26A-2 corrective matrix (G26A2-P01..P05 + corrected G26A-P34)

PR 26A-2 (`tests/integration/test_geoint_persistence.py`, plus the narrow
source-contract guard in `tests/unit/test_geoint_version_contract.py`)
proves `EntityLocation.version` is consistently database-sequence allocated
from `ati.entity_location_version_seq` — never arithmetic `target.version + 1`
— with gaps valid:

- **G26A2-P01** initial version is the exact next value the sequence issues
  (no assumption that the sequence starts at 1);
- **G26A2-P02** the forced-gap provenance regression: deliberately advances
  the sequence with a direct test-only `nextval`, appends a later
  observation, and asserts the persisted version is strictly beyond the
  forced gap — so it cannot be `before + 1`. This is the primary regression
  test and failed on pre-fix main for exactly that reason;
- **G26A2-P03** earliest-time-only mutation (older observation extending
  `first_observed_at`) moves earliest time earlier while leaving
  Location/precision/latest observation/`last_observed_at` untouched and
  receives a new sequence-issued token;
- **G26A2-P04** a true historical no-op (observation inside the current
  window) persists as history while current fields and the persisted version
  stay exactly unchanged — without asserting the sequence itself was not
  consumed;
- **G26A2-P05** a current-state-changing append that is rolled back leaves
  the pre-transaction EntityLocation state/version intact in a new UoW;
- **G26A-P34 (corrected)** no longer asserts `current.version == before + 1`;
  it asserts `current.version > before` (monotonic, non-contiguous). The
  unit guard pins the newest shipped GEOINT SQL API to sequence allocation
  and forbids an arithmetic `target.version + 1` reassignment in the active
  function.
- **Migration tests** (`tests/integration/test_migration.py`) traverse SQL
  API v0022/migration 0026 in both directions: existing EntityLocation
  versions are database-owned historical tokens and are never rewritten.
- **Migration tests** (`tests/integration/test_migration.py`): the 0025
  upgrade installs the four tables, four version sequences, and three
  stored functions; the downgrade removes only the PR 26A objects in
  dependency-safe order while existing Entity/Evidence (including PR 25
  GEOLOCATION Evidence) rows survive untouched. PR 26B supersedes the
  26A-era ``no PostGIS`` assertion: PostGIS is now installed by migration
  0027 and is asserted present at head (and removed on downgrade).

#### PR 26B delivered testing (G26B-D/P/I/R matrices)

PR 26B's deterministic geographic substrate is covered by real PostgreSQL
**+ PostGIS** tests (PostGIS is never mocked):

- **G26B-D01..D14** (`tests/unit/domain/test_geo_reference.py`,
  `tests/unit/app/geoint/test_geo_canonicalization.py`,
  `tests/unit/app/geoint/test_resolution.py`): reference record
  country/admin/city contracts; deterministic UUIDv5 canonical identity
  independent of external source record IDs; identity unchanged by
  geometry changes; claim lat/lon pairing, finite/range validation,
  precision cannot exceed semantic claim support, coordinates never
  upgrade precision; resolution result discriminators/invariants
  (resolved exactly one, ambiguous requires candidates, unresolvable
  carries a reason); deterministic name normalization (NFC/whitespace/
  case-preserving); EWKT canonicalization (SRID 4326 prefix, type rules,
  WGS84 bounds, malformed coordinate rejection); fail-closed hierarchy
  rules.
- **G26B-I01..I12** (`tests/integration/test_geoint_reference_spatial.py`
  plus unit-level ingestion tests in `tests/unit/app/geoint/`):
  parent-before-child country -> admin -> city import; repeated identical
  import is a true no-op; deterministic UUIDv5 ids identical across clean
  databases; a pre-existing PR 26A Location is enriched (same row id, new
  sequence version) rather than duplicated; geometry refresh allocates a
  new version; a repeated refresh is a no-op; incompatible hierarchy and
  malformed source geometry fail closed with no partial state;
  transaction rollback never leaves a partial child hierarchy; aliases
  collapse onto one canonical row; input order never changes canonical
  state; concurrent identical reference upserts converge on one row.
- **G26B-P01..P18** (`tests/integration/test_geoint_reference_spatial.py`
  + migration tests): PostGIS extension availability; pgvector + PostGIS
  coexistence; `ati.location.geometry`/`centroid` are SRID-4326
  `geometry` (never `geography`); country polygon/admin polygon/city
  point persistence round-trips; derived on-surface representative point
  (`ST_PointOnSurface`, documented — never `ST_Centroid`); invalid SRID,
  empty geometry, invalid polygon, city polygon, country/admin point,
  and out-of-WGS84-bounds inputs rejected fail-closed; NULL spatial state
  remains valid; the justified GiST index exists and the concrete
  containment query is proven spatial-index eligible with EXPLAIN;
  pre-26B Location rows migrate with NULL spatial fields; migration
  downgrade restores the pre-26B schema without data loss and without
  CASCADE collateral; pgvector/RAG schema survives upgrade + downgrade.
- **G26B-R01..R18** (`tests/integration/test_geoint_reference_spatial.py`):
  country code resolves the country; country + admin code/name resolves
  the administrative area; country + admin + city resolves the city;
  coordinates never upgrade precision (country-only stays country,
  admin-only stays admin even inside a city); coordinates only
  validate/disambiguate duplicate city names (containment
  disambiguation); unknown country/admin/city are unresolvable outcomes;
  duplicate city names without a discriminator are ambiguous; a semantic
  admin discriminator resolves deterministically; containment is
  boundary-inclusive (`ST_Covers`) and competing boundary coverage is
  ambiguous; coordinate-less semantic claims resolve normally; no
  nearest-city inference; candidate ordering is deterministic; hierarchy
  and spatial containment can disagree without rewriting either;
  resolution performs no mutation and never touches `GeoResolution` (the
  resolver boundary holds in PR 26C: mutations belong to the lifecycle SQL
  API, never the canonical resolver).

### PR 26B-2 delivered testing (G26B2-CLI/SRC/BLD/E2E matrices)

PR 26B-2 (corrective completion) proves the upstream reference-data supply
path: source adapters -> deterministic corpus builder -> installed CLI ->
existing importer -> PostgreSQL/PostGIS.

- **G26B2-CLI01..05** (`tests/unit/infrastructure/test_cli_entrypoints.py`):
  `ati-geography-import` and `ati-geography-build` exist in the installed
  package metadata and resolve to `geography_import_main`/
  `geography_build_main`; both `--help` exits succeed offline with no
  database or network access; the builder refuses mutually exclusive
  output modes fail-closed.
- **G26B2-SRC01..07** (`tests/unit/infrastructure/test_geonames_source.py`):
  the supported GeoNames files parse deterministically (countryInfo.txt,
  admin1CodesASCII.txt, cities-file schema); malformed/non-finite/
out-of-bounds coordinates fail closed; malformed admin/country references
  fail closed; Unicode/diacritics parse and stay NFC-normalizable;
  unsupported record shapes (wrong column counts) can never silently
  become a Location.
- **G26B2-SRC08..12** (`tests/unit/infrastructure/test_natural_earth_source.py`):
  country Polygon and MultiPolygon and admin Polygon parse to canonical
  SRID-4326 EWKT; invalid/non-polygonal/empty/unclosed geometry is
  rejected; country identifiers normalize deterministically (`iso_a2` with
  `iso_a2_eh`/`iso_a2_wb` fallbacks; unusable codes stay `None`).
- **G26B2-BLD01..14** (`tests/unit/infrastructure/test_geography_corpus_builder.py`):
  countries join by stable ISO code; admins join deterministically within
  country; the reviewed `ADMIN1_CODE_EXCEPTIONS` mapping resolves a known
  fixture mismatch; ambiguous admin matches are reported, never guessed;
  unmatched Natural Earth objects cannot create canonical records; a
  GeoNames record without a polygon emits null geometry; parent-before-
  child output ordering; byte-identical output for identical inputs;
  input ordering never changes output; no timestamps/random values;
  output conforms exactly to the PR 26B corpus schema (production parser
  round-trip); city coordinates never become polygons; orphan cities are
  rejected and reported; geometry stays WGS84/SRID-4326; explicit
  `--min-population`/`--countries` filters; invalid options and duplicate
  source codes fail closed.
- **G26B2-E2E** (`tests/integration/test_geography_build_import.py`): real
  PostgreSQL + PostGIS end-to-end proof: real-format fixtures ->
  `ati-geography-build` -> corpus NDJSON -> production corpus parser ->
  `ReferenceIngestionService` -> `ati.location`; United States -> Washington
  -> Seattle is created with deterministic canonical UUIDv5 identities,
  correct parent hierarchy, country MultiPolygon / admin Polygon / city
  point, correct PostGIS SRID (4326) and geometry types, and a second
  import is a true no-op with no version churn. The actual installed
  `ati-geography-import` console script is executed in a subprocess against
  the isolated database (first import creates the corpus atomically, second
  import has no version churn), and a malformed artifact exits non-zero
  committing nothing.

### Domain and persistence

Cover:

- Location type/hierarchy invariants;
- precision preservation/no invented precision;
- immutable EntityLocationObservation;
- explicit historical `entity_id` + `location_id` + Evidence provenance;
- current EntityLocation reconciliation;
- GeoResolution lifecycle/version invariants;
- rollback atomicity and idempotency.

### PostgreSQL/PostGIS

Real-PostgreSQL + PostGIS integration tests cover (PR 26B delivered):

- PostGIS availability through the normal migration path (project-owned
  PostgreSQL 18 image ships both pgvector and PostGIS);
- pgvector + PostGIS coexistence (HNSW/RAG suites stay green);
- spatial Location schema (SRID 4326, type/validity/emptiness/bounds
  rejection, round-trips, NULL spatial state);
- canonical reference ingestion (idempotency, enrichment/version
  semantics, concurrency, rollback atomicity);
- canonical Location claim resolution (exact/code/name matching,
  boundary-inclusive containment disambiguation, explicit
  resolved/ambiguous/unresolvable outcomes);
- hierarchy versus spatial containment;
- justified spatial-index eligibility via EXPLAIN;
- migration upgrade/downgrade with data preservation;
- Investigation isolation remains covered by PR 26D analyst query tests.

### Analyst read/API layer (PR 26D)

- **G26D-Q01..Q10** (`tests/unit/app/query/test_geoint_query.py`): typed
  frozen query contracts carry the mandatory Investigation scope, page
  limits reuse the PR 23A `QueryLimits` bound, the containment flag stays a
  required bounded boolean, Location references expose coordinates only
  (no raw geometry/EWKT/WKB field exists), observation read models retain
  the exact `observation_id`/`evidence_id`, Entity current is explicitly
  Investigation-relative (no global `EntityLocation` state fields), the
  summary is bounded with consistent counts, and malformed persisted rows
  fail the pure persisted-row mappers closed with `GeointReadError`.
  Cursor codec tests pin the PR 26A currentness ordering
  (`COALESCE(observed_at, retrieved_at)` + observation UUID, greater pair
  wins) and the deterministic Location-Entity ordering, and cursor
  fingerprints bind investigation/Entity/Location/containment scope.
- **G26D-A01..A16** (`tests/unit/api/test_geoint.py`): 401
  unauthenticated; shared `require_analyst` 403 gate; typed 200s
  (summary, Entity detail, entity history `PageResponse`, Location-Entity
  and Location-observation typed pages with the `containment_applied`
  flag mapped exactly); 404 `geoint_entity_not_found` /
  `geoint_observation_not_found` for cross-scope detail without resource
  disclosure; stable `invalid_cursor` 400; bounded cursor length 422;
  oversized limits forwarded to the shared bound; PR 25 `/geolocations`
  unchanged; malformed persisted reads surface a safe `internal_error` 500
  with no internals. Six explicit stable operation ids are pinned in the
  OpenAPI snapshot.
- **G26D-P01..P32** (`tests/integration/test_geoint_query.py`): real
  PostgreSQL 18 + PostGIS matrices seeded with two Investigations sharing
  Entities/Locations backed by different Evidence. Scope: observations
  visible only under their Evidence's Investigation, shared Entities see
  only own history, a newer I2 observation never advances I1 current,
  Locations unused in scope are empty collections, cross-scope
  observation detail is not found. Current/history: the exact PR 26A
  ordering and UUID tie-break, `observed_at=NULL` -> `retrieved_at`
  semantics, global-vs-scoped latest divergence. Location/pagination:
  distinct scoped Entities once, every qualifying observation, static-set
  paging with no gaps/duplicates, exact second-page continuation, terminal
  cursor NULL. Containment (US/WA/Seattle, TX/Dallas, CA/BC/Vancouver):
  WA exact vs contained, US contained scope, US excludes Canada,
  boundary-point inclusion via `ST_Covers`, NULL selected geometry
  degrades to exact with `containment_applied=false`, city Point never
  expands, and reads never mutate hierarchy/Relationship rows. Summary:
  zero/empty, exact observation/distinct-Entity counts, precision
  vocabulary counts, deterministic top-group tie-breaks, bounded
  truncation. Plus EXPLAIN-based index-eligibility proof (entity history
  uses the PR 26A entity index; scope joins, Location reverse lookups,
  latest-per-Entity, and containment use the PR 26D read indexes and the
  GiST index, never scanning `entity_location_observation`) and the
  canonical vertical slice: production PR 26C resolution -> real
  `PostgresGeointQueryService` -> real FastAPI -> exact Evidence drill-down
  via the existing Evidence endpoint, cross-scope 404, deterministic
  pagination, and reads mutate nothing.
- **G26D-P33/P34** (`tests/integration/test_migration.py`): migration
  0029 round-trip installs exactly the two read indexes without touching
  rows and downgrade drops only them.

Every GEOINT integration case runs in the standard isolated PostgreSQL
fixture (`reset_application_data` truncates the GEOINT tables between
tests); the API slices reuse `tests/integration/api_helpers.py` with a
real seeded local analyst user.

### Analyst GEOINT workspace (PR 26E)

- **G26E-Q01..Q08** (`frontend/src/geoint/geoint-queries.test.tsx`): the
  six PR 26D operations use the exact paths; the Entity query is keyed by
  Investigation + Entity; the opaque history cursor is forwarded
  unchanged; exact Location sends no `include_contained` while contained
  sends `true`; the observation detail uses the exact scoped path;
  AbortSignal flows through the centralized client; and no polling exists
  (single fetch, typed `ApiError` on failure).
- **G26E-M01..M08** (`frontend/src/geoint/geoint-model.test.ts`): a valid
  centroid is plottable; null and malformed/out-of-range coordinates are
  never plotted but remain table-visible; no clamping or (0,0) recovery;
  Location-type and precision labels cover the exact PR 26D vocabulary;
  current is Investigation-relative; history never encodes ended/
  continuous inference; and same-coordinate items retain distinct stable
  identities.
- **G26E-U01..U28** (`frontend/src/geoint/GeointPage.test.tsx`,
  `EntityGeointView.test.tsx`, `LocationViews.test.tsx`): empty state
  renders no map; truncated summary is visible; top-Location typed Explore
  works; the GEOINT tab is first-class and active; safe API error with
  Retry; deterministic one-point/multi-point viewports; mixed
  mappable/non-mappable sets; neutral markers; popup precision/provenance;
  same-coordinate items individually actionable; no risk styling;
  attribution present; current section says "Current in this
  Investigation"; history follows server order; three timestamps stay
  distinct; Evidence uses the exact returned id; opaque next-cursor;
  no movement path; exact Location default; containment toggle triggers a
  semantic filter change (resets cursor); `containment_applied` and
  exact-only explanations are visible; the same-location disclaimer is
  visible; coordinate-less rows stay actionable; observation detail shows
  exact semantics; scoped 404 is safe; unknown resolution methods render
  the raw bounded string (provider never fabricated); and the Entity-row
  Explore composition (`entityLocationExploreActions` GC01..GC12) yields
  exactly one registered `geoint-entity` action for rows with and without
  current observation, with exact Entity identity/label/source, existing
  Evidence/Location/generic-Entity actions preserved, no fabricated
  observation actions, no duplicate keys, and no input mutation; the
  rendered row activates the action and emits one URL-backed
  `geoint-entity` PivotStep.
- **G26E-PV01..PV18** (`frontend/src/pivots/pivot-capabilities.test.ts`,
  `pivot-url.test.ts`, `geoint-pivots.test.tsx`): Entity -> GEOINT,
  GEOINT -> Location, Location -> Entities/observations, observation ->
  exact Evidence, existing Entity exploration reuse, no generic `geoint`
  target, one routed content surface (no hosted workbench), no API
  prefetch while a menu is open, route-derived breadcrumbs with bounded
  labels, legacy PR 24 URLs still decoded by the deterministic legacy
  policy, and no geometry/response/viewport payload in the pivot envelope
  (containment round-trips as the exact boolean only).
- **G26E-S01..S06** (`tests/unit/infrastructure/test_e2e_geoint_seed.py`):
  the harness-only seed scenarios are allowlisted and bounded, identity
  derivation is deterministic, fixture facts use the exact PR 26C claim
  vocabulary, cross-Investigation scoping and the other-Investigation
  guard fail closed, and the E2E environment guard requires both fake
  mode and `ATI_E2E_SEEDING_ENABLED`.
- **GEOINT seeder idempotency matrix (SI01..SI20)**
  (`tests/unit/infrastructure/test_e2e_geoint_seed.py`): the in-memory
  world mirrors the authoritative PostgreSQL semantics (stable Evidence +
  per-Investigation EvidenceObservation, idempotent association/admission
  replay, semantic pair GeoResolution identity, and the duplicate-state
  guard). Coverage fixes the corrective idempotency contract: absent work
  is created; pre-existing PENDING/PROCESSING/RESOLVED work is reused with
  the production worker left as the lifecycle owner; UNRESOLVABLE/FAILED
  work fails closed and is never reset; reused Evidence still establishes
  association/admission; the duplicate-state creation race re-reads the
  pair and recovers only for PENDING/PROCESSING/RESOLVED (a duplicate
  report with no re-readable row fails); the Entity id returned by
  `upsert` is authoritative downstream; admission metadata conflicts and
  unexpected database errors/cancellation propagate; the exact seed twice
  creates no duplicate Evidence/GeoResolution/EntityLocationObservation;
  and cross-Investigation replay preserves the designated scopes.
- **G26E-P01..P06** (`tests/integration/test_e2e_geoint_seed.py`): the
  real-stack seeding path (reference-geography build/import -> normal
  GEOLOCATION Evidence -> GeoResolution -> production worker with the
  real PostGIS resolver -> canonical Location / EntityLocationObservation)
  proves Entity history current/order, same-Location distinctness,
  exact-vs-contained expansion, non-mappable NULL coordinates, and
  cross-Investigation isolation (I2 observation never visible to I1),
  and a second seeding run is idempotent. No table is ever inserted
  directly.
- **GEOINT seeder idempotency real-PostgreSQL matrix (GI01..GI05)**
  (`tests/integration/test_e2e_geoint_seed.py`): replay after canonical
  completion keeps one semantic resolution per pair and the exact
  canonical observations byte-stable; replaying the same scenario for a
  fresh Investigation reuses the RESOLVED work instead of colliding with
  the already-claimed pair (the deterministic fresh-main defect);
  pre-existing PENDING work is reused and completed; the shipped
  duplicate-state SQL guard is proven authoritative (never weakened);
  UNRESOLVABLE/FAILED terminal work fails the replay with zero
  reset/recreation; and a canonical Entity pre-existing under a different
  UUID binds all downstream work/provenance to the id returned by
  `upsert`.
- **G26E-E1..E6** (`frontend/e2e/zz-geoint.spec.ts`): deterministic
  real-stack Chromium workflows (`geoint_entity_history`,
  `geoint_same_location`, `geoint_containment`, `geoint_cross_investigation`,
  `geoint_non_mappable`, and the GEOINT row -> Location -> Entity ->
  Evidence -> Back stability regression) driven entirely through
  the real PR 26 pipeline seeded by `scripts/e2e-seed-geoint.sh` against
  reference geography imported by `scripts/e2e-geography-import.sh`; the
  browser only observes clean console output. G1 additionally replays the
  identical seed (same Investigation, same args) immediately after the
  first completion and requires it to succeed with the browser assertions
  unchanged, proving no duplicate GeoResolution/EntityLocationObservation
  on real-stack replay. PR 31F-8: the journeys are fully routed (normal
  locator clicks, browser Back/Forward, no dispatch/force/coordinate
  workaround). The Location -> Entities -> "Geographic context for this
  entity" journey verifies the registered `geoint-entity` capability:
  the row's in-flow Explore bar composes the existing `entityGeointAction`
  (exact Entity id, `geoint_location` source) and opens the Entity
  current/history surface through the routed
  `/geoint/entities/:entityId` route.

### Bounded agentic GEOINT reasoning (PR 26F)

PR 26F keeps `FakeLlmClient` strictly at the model boundary: the canonical
integration slice drives the real Evidence Analyst over production
PostgreSQL 18 + PostGIS, the real PR 26D `PostgresGeointQueryService`, the
real GeoResolution path, and the existing Assessment persistence.

- **G26F-T01..T10** (`tests/unit/app/geoint/test_analysis_tools.py`): the
  `GeointAnalysisTools` facade delegates the exact Investigation-scoped
  summary/Entity/history/Location/observation queries; history returns one
  bounded page only and `has_more` without a second query or cursor
  exposure; containment flags report exact vs applied honestly; requested
  page sizes over the bound are clamped before execution; cancellation
  propagates; and the facade has no SQL/PostGIS import or mutation
  surface.
- **G26F-C01..C10** (`tests/unit/app/geoint/test_analysis_context.py`):
  the deterministic context policy returns an empty context with no
  GEOINT data, enriches eligible Entities from the authoritative analyst
  input only (never fanning out to unrelated Investigation Entities),
  keeps stable input ordering (roots, then Evidence subjects, then
  RelationshipObservation endpoints), fails closed on entity/observation/
  byte bounds with typed `GeointAnalysisInputBoundsError`, never drains
  pages, preserves `summary_truncated` and `has_more_history` explicitly,
  and fails closed when an observation's Evidence is outside the supplied
  analyst input.
- **G26F-S01..S08** (`tests/unit/domain/test_analyst_geoint_contract.py`):
  the frozen model-visible context DTOs validate, reject extra fields/
  malformed UUIDs, serialize to stable JSON without representative
  coordinates, and the geographic output contract rejects unsupported
  (inferential) kinds, empty/duplicate support, and collections over the
  hard ceiling.
- **G26F-V01..V12 / G26F-G01..G08**
  (`tests/unit/app/test_geoint_finding_validator.py`): deterministic
  validation accepts only exact supplied observation/Evidence pairs and
  rejects unknown observations, substituted Evidence, wrong Entity/
  Location sets, cross-Entity history, same-Location "change", equal-
  effective-time "change", and containment claims without an established
  containment selection. The closed kind vocabulary makes
  coordination/common-ownership/campaign/movement claims structurally
  impossible; the independent-support gate rejects geography-only
  positive verdicts; independent evidence plus descriptive GEOINT
  persists; and a missing `observed_at` never invents an observed time.
- **Evidence Analyst execution tests**
  (`tests/unit/app/test_evidence_analyst_geoint.py`, plus the extended
  PR 20B world in `tests/unit/app/test_evidence_analyst.py`): GEOINT
  context flows into one normal accounted model call; valid geographic
  findings are validated then persist as `GEOLOCATION` Findings with
  exact Evidence support; invalid/substituted/cross-scope references and
  context-bound failures reserve zero or leave no pointer, exactly like
  the existing fail-closed conventions; the one-repair ceiling,
  cancellation accounting, and persistence-failure isolation are
  unchanged.
- **Canonical real-PostgreSQL vertical slice**
  (`tests/integration/test_evidence_analyst_geoint.py`, G26F-I01..I07):
  descriptive current geography persists with exact Evidence support;
  same-Entity location history allows descriptive
  `location_change_observed`; same-city unrelated Entities cannot drive a
  positive verdict (no Relationship, no Assessment row); cross-
  Investigation observation IDs stay invisible and are rejected; bounded
  history never lets the model cite omitted observations
  (`has_more_history: true` is explicit); independently supported
  MALICIOUS may carry descriptive GEOINT context; and the no-GEOINT case
  keeps baseline behavior with exactly one LLM call.

### Asynchronous resolution

Multi-worker integration tests cover:

- bounded atomic claims;
- `SKIP LOCKED` workers claiming disjoint eligible work;
- claim transaction committed before resolution;
- no long-running DB transaction during resolution;
- leases and expiry;
- stale-claim recovery;
- attempt/retry semantics;
- crash between claim and completion;
- duplicate/idempotent completion;
- stale version/ownership rejection;
- deterministic update ordering for contended completion;
- bounded batch behavior.

### Canonical GEOINT fixtures

Fixtures should include at minimum:

- country-only claim;
- administrative-area claim;
- city claim;
- coordinates with supported precision;
- coordinate-less valid context;
- ambiguous/unresolvable claim;
- one Entity observed at different Locations over time;
- multiple unrelated Entities at the same Location;
- same/similar coordinates without cyber relationship;
- cross-Investigation identity/isolation cases.

### Fake runtime

The fake runtime must not seed derived geographic truth directly.

The desired test/demo flow is:

```text
deterministic fake geographic input
 -> normal persisted Evidence/claim
 -> GeoResolution
 -> real resolver state machine
 -> real PostgreSQL/PostGIS canonicalization
 -> EntityLocationObservation
 -> EntityLocation
```

This is distinct from the PR 25C E2E seeder, which is a guarded harness-only mechanism for exact browser-created Investigation IDs. PR 26 may extend/create test harness support where necessary, but the canonical PR 26 vertical slice must exercise the production geographic pipeline.

### API/frontend

Real-stack coverage should prove:

- bounded Investigation-scoped geographic queries;
- current/history distinction;
- exact observation -> Evidence provenance;
- Location -> scoped Entities and Entity -> Locations navigation;
- map/table accessibility;
- same-location entities independently inspectable;
- no unbounded browser reconstruction;
- exact typed pivot identity and breadcrumbs;
- approximation/precision semantics retained.

### Agentic GEOINT

`FakeLlmClient` remains the deterministic model boundary. GEOINT tools beneath it execute against real PostgreSQL/PostGIS in canonical integration/evaluation slices.

Tests must prove that agent output cannot silently promote:

- proximity;
- same city/country;
- same coordinates;
- spatial containment

into maliciousness, cyber relationship, common ownership, campaign, coordination, targeting, or attribution without independent support.

### PR 26G delivered testing (G26G evaluation baseline)

PR 26G (`src/agentic_threat_investigator/evaluation/geoint/`,
`evals/scenarios/geoint/`, `tests/unit/evaluation/geoint/`,
`tests/integration/test_geoint_evaluation.py`) closes the PR 26 series
with a deterministic evaluation/closure baseline over the delivered
PR 26A--F runtime. No GEOINT runtime capability is added and no
production migration/stored-function change is required.

- **G26G-CC01..CC07** (`tests/unit/evaluation/geoint/test_geoint_evaluator.py`):
  the pure evaluator's canonical passing path and exact metrics
  (claim/support counts, provenance closure, tool calls, context
  entity/observation counts).
- **G26G-S01..S16** (`evals/scenarios/geoint/`): the committed canonical
  corpus — country-only, administrative-only, and city precision
  retention (no invented precision, no representative coordinates in
  model context); changing Location with correct current/history and no
  movement; same-Location and same-coordinate unrelated Entities with no
  Relationship/ownership/coordination; coordinate-less valid geography;
  ambiguous and unresolvable claims with no invented truth; retry,
  stale-lease, and crash recovery with exactly one final truth;
  cross-Investigation isolation; valid descriptive pattern with exact
  support; model overstatement of co-location rejected; independent
  non-geographic support plus descriptive GEOINT.
- **G26G-E01..E16** (evaluation matrix): wrong/missing canonical
  Location, precision inflation, duplicate truth after retry, broken
  provenance, cross-Investigation visibility, unsupported agent
  inference, bound exceeded, unexpected validation outcome, and
  geography-only verdicts are all hard failures; a Location without an
  observation is never support.
- **G26G-P01..P06** (provenance matrix): exact observation/Evidence
  closure, wrong Evidence, wrong Investigation, reference-Location-only
  support, omitted-context citations, and persisted Assessment support
  closing over exact Evidence — all evaluated at the structured boundary
  without claiming the Assessment schema stores observation identities.
- **G26G-T01..T10** (tool/bounds): evaluated via an evaluation-only
  recording wrapper (`evaluation/geoint/tracing.py`) around the real
  query service plus the unit fake: eligible Entity bounded queries only,
  no unrelated Entity fan-out, one history page with `has_more` surfacing,
  no cursor draining, entity/observation/byte bounds respected, no
  Location fan-out, no automatic containment expansion, no proximity,
  and arbitrary spatial queries impossible.
- **G26G-A01..A14** (structured agent-output matrix): valid current
  geography, valid history, supported location change, omitted/substituted
  observations and Evidence, cross-Investigation support, same-city
  coordination attempts, same-coordinate ownership attempts, containment
  targeting attempts, geography-only MALICIOUS attempts, two-Location
  travel attempts, independent support plus descriptive GEOINT, country
  described as city, and the no-GEOINT baseline.
- **G26G-R01..R05** (recovery closure): concurrent disjoint claims,
  stale-lease takeover with stale-worker rejection, crash-after-claim
  reclaim, retry-then-success, and duplicate/stale completion — the
  existing PR 26C lifecycle/vertical-slice coverage plus the combined
  exactly-one-final-truth assertions over the worker-completed state in
  `test_geoint_evaluation.py::test_recovery_scenarios_produce_exactly_one_final_truth`.
- **G26G-QP01..QP06** (query plans): the existing PR 26D EXPLAIN
  infra now also covers the bounded summary (`test_explain_summary_stays_bounded_and_index_eligible`);
  representative statements assert intended index eligibility and the
  absence of accidental Cartesian joins — never exact costs/timings.
- **G26G-X01** (`tests/integration/test_geoint_evaluation.py`): the
  canonical real-stack closure — reference geography via the normal
  reference API, Investigation + GEOLOCATION Evidence + PENDING work,
  production `GeoResolutionWorker` + `PostgresCanonicalGeographyResolver`
  completion, real `PostgresGeointQueryService` through the recording
  wrapper, `GeointAnalysisTools`/`GeointAnalysisContextPolicy`, real
  `EvidenceAnalystInputLoader`, `FakeLlmClient` at the model boundary
  only, deterministic geographic validation, real
  `AssessmentPersistenceService`, persisted Assessment read back, and
  `GeointDeterministicEvaluator` — with the browser and analyst segments
  sharing the same deterministic persisted scenario (browser coverage
  remains `frontend/e2e/zz-geoint.spec.ts` G1..G6).

No canonical closure fixture directly inserts derived geographic truth
(`EntityLocationObservation`/`EntityLocation` are created only by the
production worker completion), `FakeLlmClient` is the only model fake, no
live network/geocoder/LLM is required, and no PR 27 generic
evaluator/release framework is introduced.

## PR 35-8 focal-Entity exploration testing

PR 35-8 completes focal-Entity exploration in the existing Relationship
History/Graph workspace. It is a frontend navigation/presentation change:
no API, migration, stored function, provider, domain, or persistence
behavior changes; the focal Entity read reuses the existing canonical
graph-neighborhood projection, and Relationships keeps its existing
server-side `entity_id` filter.

### Focused frontend unit/component coverage

- `src/relationship-evolution/relationship-evolution-url.test.ts` pins the
  pure focal transition (`U01`-`U10`, `F12`): the new canonical `entity_id`,
  preserved `view`/direction/type/source/time/graph/temporal context,
  cleared cursor/`selected`/focal-relative counterparty filter, and the
  malformed/same-focal no-op.
- `src/relationship-graph/relationship-graph.test.tsx` pins the
  pointer-adjacent right-click context menu (`C01`-`C14`) using the stable
  `graph-explore-entity`/`graph.entity-context-menu` identities: browser
  menu prevention, non-focal-only menu, out-of-flow positioning (no layout
  shift), Escape/outside/root-change/unmount dismissal and listener cleanup,
  retarget, left-click preservation, and pure position clamping. It also
  pins the graph -> focal Relationships drill-down with exact contextual
  Back (`U34`/`U35`).
- `src/relationship-evolution/relationship-evolution.test.tsx` pins the
  workspace re-root and focal indicator (`U21`, `U25`-`U30`) and the focal
  Explore Back chain (`N01`-`N08`): Graph A -> Explore B stores the exact A
  Graph and B Back returns to it; `A -> B -> C` unwinds `C -> B -> A`; an
  older ancestor R survives after A; graph filters and temporal params are
  restored exactly.
- `src/analyst-table/return-to.test.ts` continues to pin the bounded
  `pushNavigationReturn`/`resolveReturn` stack (depth bound, ancestor
  retention, duplicate suppression) that focal Explore reuses.
- `src/relationships/relationships.test.tsx` pins the focal Relationships
  indicator and server filter (`U31`-`U33`).
- `src/entities/entity-detail.test.tsx` pins the generic Entity details
  surface and the nested contextual Back behaviour (`U36`-`U41`).

### Real-stack browser acceptance

The focused journey extends `frontend/e2e/zz-relationship-evolution.spec.ts`
and runs against the authoritative `./scripts/e2e.sh` production topology
with `--project=chromium --workers=1 --retries=0`:

```text
completed Investigation
 -> Relationship History focal A (indicator identifies A by value)
 -> Graph (capture exact A Graph URL)
 -> right-click non-focal canonical vertex B
 -> context menu opens without moving the canvas
 -> Escape dismiss -> canvas still zooms
 -> right-click -> outside dismiss -> right-click -> Explore
 -> URL entity_id=B and view=graph preserved
 -> indicator identifies B; graph re-request rooted at B
 -> Back -> exact captured A Graph URL
 -> re-Explore B
 -> Open Relationships table for focal entity -> entity_id=B + Back
 -> B Entity details -> Back -> focal Relationships B
 -> Back -> exact Graph focal B context
 -> Graph focal B -> Entity details -> Back -> exact Graph focal B
 -> refresh -> focal B reconstructed from the URL
```

A `A -> B -> C` focal Back chain is covered at component/router level when
deterministic fake-world topology cannot reliably supply a third vertex; the
real-stack journey retains the A -> B exact-Back proof.

New/modified selectors use stable `data-ati-id`/`data-testid` identities or
canonical route/query state, never the localized `Explore`/`Focal entity`
display strings alone (see *Selector and test-identity rule*).

## PR 35-2 GEOINT UI consolidation testing

PR 35-2 consolidates ATI's two geographic Investigation surfaces into one
first-class **GEOINT** capability with exactly two URL-owned presentation
sub-views, **MAP** and **TABLE**. It is a frontend
information-architecture/presentation change: no API, migration, stored
function, provider, domain, or Evidence-scanning substitute is introduced,
and the existing bounded IP-geolocation projection and canonical GEOINT
summary are preserved without being silently unified.

### Route and sub-tab contracts

`frontend/src/app/routes.test.tsx` (`U05`/`U06`) and
`frontend/src/geoint/GeointViewTabs.test.tsx` pin the canonical topology:

- `/investigations/:id/geoint/map` is the MAP presentation;
- `/investigations/:id/geoint/table` is the TABLE presentation;
- `/investigations/:id/geoint` deterministically `replace`-redirects to
  `/geoint/map`;
- the legacy `/investigations/:id/map` deterministically
  `replace`-redirects to `/geoint/map` (never a second live Map);
- the primary navigation exposes exactly Overview, Evidence, Graph,
  GEOINT, Research, Timeline, and GEOINT stays selected on both
  presentation routes and every routed GEOINT resource descendant;
- the active MAP/TABLE sub-tab is inert (no same-URL navigation) while the
  inactive destination is a semantic link inside the accessible `GEOINT
  view` navigation region.

The routed GEOINT Entity/Location/Observation surfaces remain unchanged and
reachable (`/geoint/entities/:entityId`,
`/geoint/locations/:locationId/entities|observations`,
`/geoint/observations/:observationId`); the route-derived breadcrumb root
and the contextual `Back` fallback resolve to the TABLE analytical origin.

### MAP preservation

`frontend/src/geolocation/InvestigationMapPage.test.tsx`
(`B-U01..B-U17`, `B-P01..B-P06`, `B-A11Y01..B-A11Y08`) continues to pin the
bounded `useInvestigationGeolocations` query, `buildGeolocationMapModel`,
the Leaflet `InvestigationMap`, the always-available `GeolocationList`,
approximation/truncation messaging, provider/precision labels, distinct
observed/retrieved timestamps, hostile-value escaping, the `FAKE DATA`
marker, and the exact persisted `evidence_id` provenance — now under the
consolidated GEOINT heading and MAP sub-tab. No third map implementation
exists.

### TABLE behavior

`frontend/src/geoint/GeointPage.test.tsx` (`U01..U05`, `U12..U17`) pins the
TABLE presentation: the bounded `useGeointSummary` statistics, precision
counts, the Top Locations `AnalystTable` with canonical labels/types and
typed Explore actions, the truncation warning, the persistent
semantics/no-inference messaging, the honest empty state, and the honest
`Not plotted` status for coordinate-less rows. TABLE renders **no**
Leaflet map, map container, marker, or tile layer.

### Real-stack browser acceptance

The focused PR 35-2 journey runs against `./scripts/e2e.sh` (production
frontend -> production API -> production PostgreSQL -> deterministic Fake
World) with `retries=0` in Chromium and Firefox:

```text
open completed Investigation
 -> primary navigation has GEOINT and no separate Map/Geographic context
 -> GEOINT -> canonical MAP route, MAP selected and geographic content rendered
 -> TABLE -> canonical TABLE route, bounded summary + Top Locations rendered
 -> TABLE Explore Location -> routed GEOINT resource -> Back to TABLE origin
 -> MAP -> exact Evidence -> Back to MAP origin
```

It also proves the legacy `/map` redirect, TABLE deep-link/refresh,
contextual Back from the TABLE drill-down, contextual Back from MAP
Evidence, and a 10-cycle `MAP -> TABLE -> MAP` Chromium stability loop
asserting correct URL/selection, no post-quiescence URL churn, no product
console/page error, and no input/main-thread wedge (bounded timeouts only,
no `force`, sleeps, reloads, or retries). The existing GEOINT
(`zz-geoint.spec.ts`, `zz-31f8-stress.spec.ts`) and geolocation
(`zz-geolocation.spec.ts`, `zz-geolocation-workflow.spec.ts`) workflows
are updated to the consolidated GEOINT MAP/TABLE selectors and continue to
run through the same authoritative harness.

The focused journey seeds both bounded projections on one Investigation.
The harness-only GEOINT seeder (`tests/e2e_support/seed_geoint.py`) now
carries the production `provider` fact in its synthetic `GEOLOCATION`
evidence: the PR 25A projection fails closed (by design) on persisted
GEOLOCATION evidence that omits it, so the fixture must match the real
DB-IP City Lite fact vocabulary to be valid for both the MAP and TABLE
presentations. This is test-infrastructure compatibility only; no
production DTO, provider, or schema changed.

## PR 35-1 UI correctness testing

PR 35-1 fixes navigational, Evidence-presentation, temporal-input, and
graph-depth defects without changing the Investigation, Evidence, Pivot,
graph-traversal, or direct-range temporal architecture. Its testing is
deterministic and offline at unit level and uses the authoritative
`scripts/e2e.sh` real-stack topology for browser acceptance.

### Evidence description presenter

`tests/unit/api/test_evidence_description.py` pins the deterministic
backend `description` projection (`E01`-`E08`): the Fake World
`update-package.test` A/CNAME, MX, NS, and TXT DNS observations produce
distinguishable descriptions; threat-intelligence and registration
records are characterized from normalized fields; an unhandled type falls
back to a bounded type-oriented string; the public DTO carries the
description and never the raw provider payload. Descriptions are bounded
and deterministic and the frontend no longer serializes arbitrary `facts`.

### Bounded contextual navigation (amendment 1)

`analyst-table/return-to.ts` carries a bounded ordered stack of validated
ATI-internal return locations in React Router transient state (never in
the URL): `pushNavigationReturn` records a genuine drill-down origin,
`preserveNavigationContext` keeps context across sibling/subview changes,
and `resolveReturn` pops exactly one level while retaining ancestors.
`analyst-table/return-to.test.ts` pins `N1`-`N11`: internal targets are
accepted, external/protocol-relative/malformed targets are rejected,
EVOLUTION<->GRAPH preserves context, a drill-down pushes, `A -> B -> C`
Back sequences pop one level at a time, direct loads fabricate no origin,
adjacent duplicates are suppressed, and the stack is deterministically
bounded.

`useResourceTable` and `RelationshipEvolutionWorkspace.commit` now preserve
the transient context across every search-only commit (filters, cursor,
selection, view switch), so a subview change can never drop the caller's
Back origin. Routed detail pages (`EvidenceDetailPage`,
`RelationshipDetailPage`, `ObservationDetailPage`,
`GeointObservationDetailPage`) resolve the contextual Back via
`contextualBack`, falling back to the canonical list only when no origin
exists. `relationships.test.tsx` `N3` and `relationship-evolution.test.tsx`
`N5/N6` pin the History -> Current relationship snapshots and
EVOLUTION<->GRAPH journeys at component level.

### Provenance Observation Hide

`GraphRelationshipProvenance.test.tsx` covers `P01`-`P03`: an observation
opens, nested supporting Evidence opens, Observation **Hide** clears both
the observation and the nested Evidence selection, and the parent
provenance and bounded observation list remain usable.

### Date-only local date/time parsing

`analyst-table/filters.test.ts` pins the PR 35-1 parser matrix (`T1`-`T8`):
empty input is absent, date-only normalizes to local midnight before UTC
serialization, explicit time and seconds are preserved, malformed dates
and partial times are rejected, impossible calendar dates are rejected,
and a date-only range remains valid. `relationship-evolution.test.tsx`
`FE31` proves the temporal conversion path commits local-midnight bounds
with no false start-before-end error. The PR 38-8 temporal controls render
separate date and optional-time fields, so date-only behavior is exercised
both at the shared parser/conversion boundary and through the rendered
controls (`GraphTemporalControls.test.tsx` `T-C04`).

### Graph HOPS depth propagation

`relationship-evolution.test.tsx` `H01`-`H04` drives the routed Graph
workspace: committed depth 1 issues no traversal request, depth 2 commits
`graph_depth=2` and requests `max_depth=2`, depth 3 commits
`graph_depth=3` and requests `max_depth=3`, and the committed URL identity
follows the depth. Existing `graph-queries.test.tsx` and
`graph-context-url.test.ts` pin the traversal/neighborhood query-key
distinction and the depth URL codec.

### Render-boundary endpoint invariant

`RelationshipGraph.selectRenderableEdges` is the single render projection:
a relationship edge reaches the canvas only when both endpoints are in the
canonical model AND in the final rendered React Flow node set. Canonical
edges are never deleted. `relationship-graph.test.tsx` `G1`-`G6` covers a
complete edge, a missing source, a missing target, an endpoint becoming
visible/hidden, and the canonical model retaining an edge whose endpoint is
not rendered.

### Browser acceptance

`frontend/e2e/zz-35-1-ui-correctness.spec.ts` runs against the
`scripts/e2e.sh` topology with `retries=0`, one worker, raw-pointer
activation (`mouse.move`/`down`/`up` with a bounded 5 s wedge guard) and a
bounded page heartbeat after every transition, and clean product
console/pageerror assertions in Chromium and Firefox:

- **E2E-W1** Evidence table Subject pivot -> `Evidence for this entity`:
  asserts the pivot closes, the workspace URL carries the exact selected
  `subject_entity_id`, the Evidence request carries that exact id, the
  rendered rows are a non-empty subset of the unfiltered rows and still
  represent the pivoted entity, and the URL does not churn after
  quiescence;
- **E2E-W2** Relationships history -> row `View` -> exact observation
  detail and Back;
- **E2E-N1/N2** Relationships -> history EVOLUTION -> GRAPH -> EVOLUTION ->
  Back restores the exact Relationships origin;
- **E2E-N3** History -> Current relationship snapshots -> Back restores the
  exact history origin and then the original ancestor;
- **E2E-N4** Report Finding Evidence -> Evidence details -> Back returns to
  the exact Report and explicitly not to the generic Evidence list;
- **E2E-N5/N6** Evidence list in-flow detail Back, plus a direct load of a
  routed Evidence detail with no fabricated origin and the canonical list
  fallback;
- **E2E-H1** 1 -> 2 -> 3 HOPS: the traversal receives `max_depth` 2/3 and a
  known depth-2 Entity (`203.0.113.81`) absent at depth 1 appears at depth 2;
- **E2E-G1** render-boundary endpoint invariant on the
  `malware.badloader_v2` reproducer and after depth reconciliation;
- **E2E-G1b** provenance Observation -> View supporting evidence ->
  Observation Hide.

#### W1 final classification

> **BASELINE-CONFIRMED PLAYWRIGHT/CHROMIUM RAW-POINTER / INPUT-PIPELINE
> LIMITATION — NOT DEMONSTRATED TO BE A PR 35-1 APPLICATION REGRESSION.**

The repeated same-page raw-pointer stress fails with
`WEDGE@c1-clear` (the next pointer activation after the pivot never
completes). The combined evidence:

- page JavaScript stays responsive (`page.evaluate("1+1")` succeeds);
- neutral pointer operations (pane click, move at a non-control point) and
  actionability `trial` succeed;
- programmatic dispatch of the same handler reaches the correct URL/state
  and leaves the page responsive;
- no modal/popover/popper/tooltip/backdrop overlay remains;
- ripple disable, workspace remount, and router-state removal do **not**
  cure it;
- **decisively, the identical failure reproduces on unmodified base
  `main` (`9473186`)** with the same spec and command.

Reproduction command (base and branch identical):

```bash
timeout 220 ./scripts/e2e.sh zz-35-1-ui-correctness.spec.ts \
  --project=chromium -g "E2E-W1" --timeout=30000 \
  2>&1 | tee /tmp/ati-pr35-w1.log
```

The deterministic E2E-W1 journey therefore uses the narrowest established
raw-pointer seam for the semantic acceptance and documents the baseline
limitation in the spec; the five-cycle stress is not silently weakened, it
is recorded as a baseline-confirmed limitation. No timing, force, reload,
or long-timeout workaround is used.

#### W2 disposition

**B — the reported W2 wedge is not an application defect.** W2 passes
deterministically with raw-pointer activation in Chromium and Firefox; the
journey already used the repository's deferred `useResourceTable`
selection commit, so no application change was required.

#### Navigation-commit boundary

The workspace sibling-subview commit (`EVOLUTION <-> GRAPH`) preserves the
bounded navigation context and is deferred past the native pointer event
(`commitView`) per the established PR 31F-6/31F-8 rule. Filter/temporal
commits keep the pre-existing synchronous boundary. A synchronous
`setSearchParams` carrying the navigation context inside the graph filter
Apply originally stalled the input pipeline; deferring that specific
context-carrying commit restored the PR 31H depth journey first attempt.

#### Stale E2E selectors repaired

These are pre-existing stale selectors introduced by the PR 31F/UI-polish
label changes; they were reproduced on unmodified base `main` where noted.
No production UI was changed to accommodate them.

- `Cancel` -> `Hide` for the in-flow Pivot action bar in
  `zz-pointer-acceptance.spec.ts`, `zz-pivot-acceptance.spec.ts`,
  `zz-relationship-evolution.spec.ts`, and
  `zz-geolocation-workflow.spec.ts` (commit `ad90d6d` renamed the control).
- `Back to Relationship evolution` -> `Back to Relationship history` in
  `zz-relationship-evolution.spec.ts`.
- `relationship evolution` -> `relationship history` link selectors in
  `zz-31g/31h/31i/31j/31k`.
- `Relationships details` -> `Relationship details` in `zz-list-detail.spec.ts`,
  `zz-pivot-acceptance.spec.ts`, and `zz-relationship-evolution.spec.ts`.
- `View all observations` -> `View all history` in
  `zz-pivot-acceptance.spec.ts` (the in-detail observations link label).
- `Open evidence` -> `Evidence` (the exact-Evidence Pivot action label) in
  `zz-relationship-evolution.spec.ts`.
- Graph edge panel `Supporting observations` -> `Matching observations`, and
  the evidence section's `Back to observation` -> a section-scoped `Hide` in
  `zz-relationship-evolution.spec.ts`.
- Graph edge-list action `View` -> `Details` in
  `zz-relationship-evolution.spec.ts`.
- Evidence source raw URN `urn:ati:source:dbip_city_lite` -> the localized
  `DB-IP City Lite` in `zz-geolocation-workflow.spec.ts`.

#### `zz-pivot-acceptance` correction

The focused diagnostic initially reported `WEDGE@c0-diag-view-all` because
the 5 s wedge guard also fires while `locator.click` waits for a
**missing** element. The real cause was the stale `View all observations`
label (current label: `View all history`); after correcting the selector the
full five same-page cycles pass first attempt with ordinary locator clicks.
No raw-pointer exception was needed. This is a test defect, not a browser
freeze, and is not related to the W1 baseline raw-pointer limitation.

#### `zz-analyst-tables`, `zz-pivots`, and the `zz-31h` edge selection

These existing broader specs contain further pre-existing stale selectors
and/or baseline-confirmed `locator.click` input-pipeline freezes reproduced
on unmodified base `main` (`9473186`):

- `zz-analyst-tables` E20 is a baseline-confirmed hard hang (outer timeout,
  no Playwright error) reproduced on base `main`; it is also the shared
  session-state creator, so `zz-relationship-evolution` and
  `zz-geolocation-workflow` were verified with a temporary session
  bootstrap in the same harness invocation.
- `zz-pivots` has additional pre-existing stale selectors
  (`Open evidence` ambiguity, `View all observations`, `Relationships
  details`).
- `zz-31h-multihop` `depth2-edge-select` (the first `locator.click` after
  the synchronous graph Apply) wedges nondeterministically; the identical
  corrected spec reproduces the same wedge on base `main`. The amendment's
  own deterministic E2E-H1 HOPS acceptance (subset `zz-35-1-ui-correctness`)
  pins the depth-1/depth-2 topology and `max_depth` 2/3 semantics and passes
  first attempt in both engines.

These specs are outside the PR 35-1 amendment scope and were not modified;
the four suites named above (`zz-list-detail`, `zz-pivot-acceptance`,
`zz-relationship-evolution`, `zz-geolocation-workflow`) are the
amendment-required E2E slices and pass first attempt with `retries=0`.

## Definition of done

A change is not complete until:

1. required quality commands pass;
2. relevant tests exist and pass;
3. database migrations/integration tests pass where applicable;
4. strict typing is preserved;
5. behavioral evaluation expectations are updated when agent semantics intentionally change;
6. authoritative documentation is updated for deliberate contract changes;
7. new/changed agent operations have typed structured-output tests;
8. new/changed human-readable analytical output has deterministic formatter
   tests and does not depend on an LLM for presentation.

## Configuration tests

Configuration tests must cover default/profile selection, shallow override semantics, invalid and missing profiles, malformed modules, non-mutation of input dictionaries, deterministic logging, and recursive sensitive-value redaction. Tests inject an environment mapping rather than mutating global process environment where practical. See `CONFIGURATION.md`.

## Batch persistence and history tests

Integration tests against pinned PostgreSQL 18 must exercise composite-array input, `unnest` staging with ordinality, temporary-table reconciliation, INSERT/UPDATE/UNCHANGED/CONFLICT outcomes, optimistic version conflict detection, set-based version allocation/history insertion, and large batches up to the configured application boundary. Tests must prove UNCHANGED rows receive no new version/history. JSONB diff tests cover scalar changes, additions/removals, missing versus JSON null, nested objects as atomic top-level values, excluded metadata fields, and empty diffs. No SQLite substitute is acceptable for these behaviors.

#### PR 26C delivered testing (G26C-D/W/B/P + vertical slices)

PR 26C (`tests/unit/app/geoint/test_geo_claim_extraction.py`,
`tests/unit/domain/test_geoint_observation_identity.py`,
`tests/unit/app/geoint/test_geo_retry_policy.py`,
`tests/unit/app/geoint/test_geo_resolution_worker.py`,
`tests/integration/test_geo_resolution_lifecycle.py`) delivers the
asynchronous geographic-resolution lifecycle on the PR 26A/26B foundation:

- **G26C-D01..D06** (`tests/unit/app/geoint/test_geo_claim_extraction.py`,
  `tests/unit/domain/test_geoint_observation_identity.py`): exact
  GEOLOCATION Evidence -> `GeographicClaim` conversion preserves source
  semantic precision; coordinates never upgrade precision; non-GEOLOCATION
  and malformed payloads fail closed with typed errors; the deterministic
  resolution-produced observation identity is UUIDv5 of the `GeoResolution`
  id under the fixed ATI observation namespace (stable per work, unique
  across work).
- **G26C-B01..B05** (`tests/unit/app/geoint/test_geo_retry_policy.py`):
  deterministic bounded exponential backoff (`base * 2^(attempt-1)` capped at
  the max, no jitter), attempt-1 base, attempt-2 doubling, high-attempt cap,
  invalid config/input rejection.
- **G26C-W01..W11** (`tests/unit/app/geoint/test_geo_resolution_worker.py`):
  worker orchestration with a fake `LocationResolver` only — resolved /
  unresolvable / ambiguity (never guessed) completions; malformed/missing/
  wrong-type Evidence as terminal failures; bounded retryable failure;
  cancellation propagation with no persisted transition; empty batch no-op;
  resolver executes with NO claim UnitOfWork open; every completion opens a
  NEW short UnitOfWork; a rejected failure persistence never terminates the
  iteration (lease expiry recovers).
- **G26C-P01..P12** (`tests/integration/test_geo_resolution_lifecycle.py`):
  eligible PENDING claimed exactly once with claimant/lease/attempt/version;
  future-scheduled PENDING and unexpired PROCESSING never claimed; expired
  PROCESSING reclaimed (attempt N+1); terminal rows never claimed; bounded
  claim limit; deterministic (eligibility, created, id) ordering; two
  concurrent workers claim disjoint batches; each claim increments attempt
  exactly once and allocates a fresh DB version; expired-at-budget work
  becomes FAILED instead of being reclaimed; claim rollback preserves the
  prior durable state.
- **G26C-P13..P18** (stale-claim matrix): correct owner/version/live lease
  accepted; wrong owner, stale version, and expired lease all typed
  conflicts with zero mutation; A expires -> B reclaims -> A's completion
  rejected and B completes (the required stale-worker race on real
  PostgreSQL).
- **G26C-P19..P30** (resolved-completion matrix): one atomic success appends
  the exact observation and reconciles current state; missing/soft-deleted
  Entity, missing Evidence, wrong Evidence type, subject mismatch, and
  missing Location are full rollbacks; the exact replay (deterministic
  observation identity) is a no-op with no duplicate; a conflicting terminal
  replay is typed; existing current-state/first-observed/latest semantics are
  preserved; an injected post-append rollback commits nothing; unknown work
  is not-found; PENDING completion is an invalid transition; a deterministic
  observation identity bound to a different tuple is a duplicate-identity
  conflict.
- **G26C-P31..P38** (failure/unresolvable matrix): unresolvable and
  ambiguity are terminal with no observation/current-state mutation; retry
  schedules PENDING with the bounded backoff and clears the lease; terminal
  errors FAIL with no next attempt; stale failure requests are rejected; a
  rolled-back failure transition keeps PROCESSING.
- **G26C-P39..P43** (migration/index matrix): the claim predicates are proven
  index-eligible by EXPLAIN using the two partial claim indexes (no seq
  scan); pgvector + PostGIS coexist with the v0024 API installed; the
  v0021/v0022/v0023 APIs remain installed and callable; migration
  `tests/integration/test_migration.py::test_geoint_lifecycle_migration_upgrade_and_downgrade`
  proves the 0028 upgrade preserves existing PENDING LOCATION/OBSERVATION/
  resolution rows and allows claiming/completing the pre-existing work, and
  the downgrade removes only the PR 26C functions/indexes/constraints while
  preserving every authoritative row (terminal work included).
- **Vertical slices** (production `GeoResolutionWorker` against real
  PostgreSQL + PostGIS): multi-worker disjoint claims with exactly one
  observation per work item and terminal RESOLVED; crash/recovery (A claims
  and dies, lease expires, B reclaims at attempt N+1 under a new version, A
  is rejected, B completes with exactly one final observation); retry/
  exhaustion with a fake `LocationResolver` only (no early claims, exact
  attempt boundaries, no observations on failures, exactly one observation
  on the eventual success, and terminal FAILED at exhaustion). Timestamp
  control is deterministic SQL, never sleep-based.

#### Bounded concurrent GEO resolution item execution (PR L-2)

PR L-2 (`tests/unit/app/geoint/test_geo_resolution_worker_concurrency.py`,
`tests/integration/test_geo_resolution_worker_concurrency.py`, Geo worker
config tests) lets one `GeoResolutionWorker` process its already-claimed
batch with an explicit `geo_resolver_max_concurrency` bound, independent of
claim `batch_size`, without weakening the PostgreSQL lease/version
lifecycle or the per-item short-transaction split:

- **Deterministic event/counter model, never wall-clock throughput.**
  Concurrency is proven with `asyncio.Event`/counter barriers at the
  `LocationResolver` boundary only: L2-W02 (concurrency=1 serializes item
  pipelines), L2-W03 (concurrency=2 admits genuine resolver overlap and the
  third item waits for a permit), L2-W14 (batch larger than the bound fully
  drains with peak active never exceeding the bound), L2-W15 (concurrency
  above batch size is legal). Gated resolvers own timing/control only; fake
  UoW/repository boundaries prove lifecycle behavior.
- **Waiting tasks hold no UnitOfWork.** L2-W04 parks one item at the
  resolver with concurrency=1 and asserts `active_uows == 0` while sibling
  tasks are queued behind the permit; L2-W05 asserts the same at the
  resolver boundary under concurrency=2 overlap.
- **No UoW/session is shared across item tasks.** L2-W12 proves every
  completion/failure receives its exact original `resolution_id`,
  `expected_version`, and `claimed_by`; L2-W13 forces reverse/out-of-order
  completion and asserts each observation keeps its own deterministic id,
  entity, evidence-observation, location, and timestamp provenance.
- **Failure and cancellation isolation.** L2-W06/L2-W07 (mixed outcomes and
  a normal resolver failure persist independently without cancelling
  siblings), L2-W08/L2-W11 (an unexpected `_process_one` escape is logged
  with a bounded identity/type only — never raw exception text — siblings
  continue, and the permit is released so the next item completes),
  L2-W09 (parent cancellation propagates, settles active and waiting
  children, and never fabricates failure transitions), L2-W10 (the permit
  is released after an expected failure).
- **Real-PostgreSQL worker coverage.** L2-P01 runs one concurrent
  `run_once()` through the real claim/evidence/canonical resolver/completion
  stored functions: every intended row reaches terminal RESOLVED with
  correct version/claim semantics and exactly one observation/provenance,
  no duplicates and nothing left PROCESSING. L2-P02 parks two real item
  pipelines at the resolver boundary with `max_concurrency=2` (real
  persistence everywhere, a timing gate only at the resolver seam) and
  asserts no caller UoW is held across the gate. L2-P03 re-runs disjoint
  multi-worker claims; the existing claimant/version/lease conflict matrix
  (G26C-P13..P18) and vertical slices remain authoritative for stale/
  expired completion authority.

## PR 38-9: batch-ingestion observability and LLM usage/accounting

Deterministic offline coverage:

- `tests/unit/app/test_batch_ingestion_telemetry.py` (BI1..BI10): one logical
  `ati.batch_ingestion.ingest` span + duration per `IngestionService.ingest()`,
  execution/failure/no-op counters, committed outcomes only, truthful partial
  success, cancellation propagation, bounded `ati.source`, disabled-telemetry
  behavior, and no Kafka/Evidence counter pollution.
- `tests/unit/app/test_llm_usage.py` (LU-U01..U20): authoritative usage
  normalization, unknown-stays-unknown, exact `Decimal` pricing, scope
  validation, bounded model labels, durable append, and fail-open accounting.
- `tests/unit/observability/test_grafana_dashboards.py`: the dashboard
  inventory is now **ten** dashboards including `ati-llm-usage` / **LLM
  Usage**; the batch-ingestion panels are registered on Datasource &
  Ingestion; and the frozen PromQL inventory / ATI series allowlist were
  extended deliberately. Privacy/cardinality assertions are unchanged.

Real-PostgreSQL coverage:

- `tests/integration/test_llm_usage_repository.py` (LU-P01..P11): the
  production `ati.append_llm_usage` stored function through
  `PostgresLlmUsageRepository` inside the real `PostgresUnitOfWork`:
  append-once, invocation-identity idempotency, conflicting-replay rejection,
  multiple scopes, unknown fields as NULL, non-negative constraints, currency
  and pricing-identity requirements, no prompt/output columns, and no
  update/delete function (append-only).

Authoritative real-stack acceptance remains
`scripts/observability-integration.sh`: batch metrics/spans and LLM usage
metrics must reach Prometheus/Jaeger through the production seams; acceptance
is never satisfied by direct feature-counter emission.
