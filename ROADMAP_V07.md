# ROADMAP V07 — Server-Rendered UI Migration

## Purpose

V07 replaces ATI's React single-page frontend with a server-rendered web presentation architecture built on **FastAPI + Jinja2 + HTMX**, while retaining narrowly scoped JavaScript/TypeScript visualization islands where rich browser interaction is inherently required.

This is the production UI migration plan, not a throwaway feasibility prototype.

The migration is deliberately incremental. The existing React frontend remains functional in parallel with the new frontend until the new implementation reaches feature parity and passes the required acceptance and stability gates. Only the final cutover PR removes React/Vite/React Router/TanStack Query/Material UI/React Flow infrastructure that is no longer required.

The dominant architectural objective is:

> Move ordinary ATI presentation, navigation, and workspace state back to HTTP/server-owned semantics, while reserving browser-side state and JavaScript for capabilities that inherently require rich client rendering.

---

## Architectural target

The long-term presentation architecture is:

```text
                         ATI application/query layer
                         /                         \
                        /                           \
              JSON presentation                 HTML presentation
                    adapter                         adapter
                      |                               |
                    api/                            web/
                      |                               |
                REST / JSON                  FastAPI + Jinja2
                                                      |
                                                     HTMX
                                                      |
                                      +---------------+---------------+
                                      |                               |
                              ordinary ATI UI                 bounded JS islands
                                      |                               |
                           tables / details / forms       graph / temporal graph
                           pivots / reports / nav         GEOINT map / visualization
```

The new Python presentation adapter lives under:

```text
src/agentic_threat_investigator/
├── api/                    # existing JSON REST presentation adapter
├── web/                    # new HTML/Jinja/HTMX presentation adapter
│   ├── routes/
│   ├── viewmodels/
│   ├── templates/
│   ├── static/
│   └── composition.py
├── app/
├── domain/
└── infrastructure/
```

During migration the repository therefore contains both:

```text
frontend/                                  # existing React frontend
src/agentic_threat_investigator/web/       # new server-rendered frontend
```

After final cutover, `web/` remains the permanent name of ATI's human-facing HTML presentation adapter. It must not be renamed to `frontend`; `api/` and `web/` are intentionally parallel presentation adapters.

---

## Core architectural invariants

1. **The migration replaces the React frontend.** It is not merely an alternate demo UI.
2. **React and the new web UI coexist until cutover.** Existing React behavior remains available while capabilities are migrated.
3. **`web/` is a presentation adapter.** It must not contain domain policy, orchestration policy, persistence logic, or provider logic.
4. **`web/` and `api/` share application/query services.** The web adapter must not normally call ATI's REST API over HTTP merely to reach application functionality already available in-process.
5. **The REST API remains supported.** Migrating the human UI does not remove ATI's machine-facing JSON API.
6. **The database remains behind existing application/repository boundaries.** Jinja routes must not bypass stored-function-only persistence rules.
7. **Jinja templates are presentation-only.** Business/query logic belongs in Python services/view-model construction, not templates.
8. **HTMX is used for ordinary browser interaction, not as a substitute SPA framework.**
9. **URLs remain meaningful and authoritative.** Filters, selected resources, exploration context, and restorable analyst navigation must have explicit URL/history semantics where appropriate.
10. **Progressive HTTP behavior is preferred.** Important navigation and forms should have ordinary HTTP semantics even when HTMX enhances them.
11. **Rich visualization remains client-side where appropriate.** Graph, temporal graph, and map rendering are bounded JavaScript/TypeScript islands rather than attempts to reproduce rich visualization in HTMX.
12. **A visualization island does not become a second SPA.** It owns only the browser interaction/rendering state intrinsic to that visualization.
13. **Server state is never duplicated casually in browser-global state.**
14. **Existing investigation scoping, authorization, provenance, bounded-query, cursor, and redaction semantics remain authoritative.**
15. **Human-readable-first presentation and i18n remain requirements.**
16. **Accessibility, keyboard operation, responsive layout, themes/appearance, and error presentation remain migration parity requirements.**
17. **No migration PR may weaken security controls to simplify HTML delivery.**
18. **Authentication, session, CSRF, authorization, and mutation semantics must be explicitly designed for server-rendered and HTMX requests.**
19. **Browser E2E remains production-path testing, but acceptance follows frontend ownership.** During V07 coexistence, the new web UI uses its own `scripts/e2e-web.sh` harness. The legacy React `scripts/e2e.sh` suite is not a routine V07 acceptance gate; run it only when a PR changes React or shared behavior for which targeted compatibility coverage is insufficient.
20. **Feature parity is behavioral, not DOM parity.** The new UI need not reproduce React component structure.
21. **React is removed only after the parity matrix and final acceptance gates pass.**
22. **Do not redesign unrelated backend/domain architecture merely to facilitate the frontend migration.**
23. **Current explicit host-port overrides remain valid.** The UI migration does not subsume a separate `ATI_PORT_PREFIX` feature.

---

## Current-main baseline

At the start of V07, ATI's human frontend is a React/TypeScript application under `frontend/`.

Its current major frontend technologies include:

- React 19;
- React Router 7;
- TanStack Query;
- TanStack Table;
- Material UI + Emotion;
- i18next/react-i18next;
- React Flow;
- Leaflet/react-leaflet;
- Vite;
- Vitest;
- Playwright.

The current route topology includes:

- login;
- Investigation list/create/workspace;
- Overview and Final Report;
- Evidence list/detail;
- Relationships list/detail;
- Relationship Observations;
- Relationship history/evolution and graph;
- Research;
- GEOINT MAP and TABLE;
- GEOINT entity/location/observation detail resources;
- Timeline;
- History.

The current frontend already embodies important contracts that V07 must preserve rather than rediscover, including:

- Investigation-scoped resources;
- server-driven bounded tables and opaque cursors;
- human-readable-first labels;
- exact provenance navigation;
- routed resource details;
- GEOINT MAP/TABLE semantics;
- relationship history and bounded graph traversal;
- contextual navigation;
- URL-backed analyst state;
- authentication/session/CSRF behavior;
- multiple appearance themes;
- internationalization;
- real-browser E2E coverage.

Current Compose exposes the React frontend as a distinct `frontend` service and the FastAPI JSON API as `api`. V07 must support parallel operation during migration and then simplify deployment at cutover.

---

## Presentation package ownership

### `api/`

`src/agentic_threat_investigator/api/` remains the machine-facing JSON presentation adapter.

It owns:

- REST routes;
- API DTOs;
- HTTP JSON semantics;
- API-specific request/response mapping.

### `web/`

`src/agentic_threat_investigator/web/` is the human-facing HTML presentation adapter.

It owns:

- HTML routes;
- Jinja template composition;
- web-specific view models;
- HTMX fragment selection;
- web forms and form validation presentation;
- browser-facing redirects;
- static CSS;
- bounded JavaScript/TypeScript visualization adapters;
- web-specific presentation/error mapping.

It does **not** own:

- domain rules;
- Investigation orchestration;
- Evidence/Relationship semantics;
- persistence;
- authorization policy;
- provider execution;
- LLM behavior.

### Shared application layer

Both adapters should reuse the same application/query services:

```text
REST route --------+
                   +----> application/query service ----> repositories/domain
Web route ---------+
```

Avoid:

```text
Web route -> HTTP -> REST route -> application service
```

unless an explicit architectural reason is documented and approved.

---

## Template and view-model conventions

The new frontend should establish conventions early rather than allowing ad-hoc template growth.

Recommended structure:

```text
web/
├── routes/
├── viewmodels/
├── templates/
│   ├── base.html
│   ├── components/
│   ├── investigations/
│   ├── evidence/
│   ├── relationships/
│   ├── geoint/
│   ├── reports/
│   └── ...
└── static/
    ├── css/
    ├── js/
    └── vendor/
```

Rules:

- templates consume explicit presentation/view models rather than arbitrary persistence/domain structures;
- reusable semantic presentation belongs in reusable Jinja components/macros;
- do not place business decisions in Jinja conditionals;
- do not create separate duplicated query implementations solely for full-page and HTMX-fragment responses;
- full-page and fragment rendering should share the same underlying view-model construction;
- fragment boundaries should correspond to meaningful UI ownership boundaries, not every small DOM element.

A normal route may provide:

```text
ordinary GET
    -> complete Jinja document

HTMX GET
    -> bounded workspace/content fragment
```

The exact implementation pattern must be established in V07-1 and then reused consistently.

---

## JavaScript/TypeScript island boundary

V07 intentionally retains JavaScript for interactions that are intrinsically browser-rich.

Expected islands include:

### Relationship graph

A dedicated graph library may replace React Flow. Cytoscape.js is a candidate, but the implementation PR must validate the selected library against ATI's requirements before adoption.

The graph island may own:

- graph canvas rendering;
- pan/zoom;
- node/edge selection;
- contextual pointer interaction;
- layout;
- focal-node visual state;
- local visualization mechanics.

It must not independently own:

- Investigation authorization;
- graph query policy;
- server traversal semantics;
- provenance;
- canonical analyst route/history state.

### Temporal graph

Temporal graph interaction may extend the graph island. Server/application semantics remain authoritative for bounded graph states and observation-derived temporal data.

### GEOINT map

Leaflet or an equivalent bounded map adapter remains appropriate for map rendering, markers, pan/zoom, and map-specific interaction.

### Island integration rule

Prefer:

```text
Jinja page
   -> semantic HTML container + explicit configuration/data identity
   -> bounded JS module
   -> ATI JSON/read endpoint when dynamic data is required
```

Do not build a hidden second frontend framework inside `web/static/js`.

---

## Security requirements

Server-rendered HTML changes the presentation trust boundary and therefore requires explicit security work.

V07 must preserve or improve:

- authenticated session handling;
- HttpOnly session-cookie semantics;
- CSRF protection for every state-changing browser request;
- Origin/Referer policy where applicable;
- authorization on every server-side resource request;
- output escaping;
- safe handling of external/research text;
- no rendering of untrusted model/provider HTML;
- safe redirects;
- bounded URL/query parsing;
- security headers;
- logout/session expiration behavior;
- protection against accidental cross-Investigation resource access.

HTMX requests are ordinary HTTP requests and must not receive weaker authorization or CSRF treatment.

The coding agent must not introduce a second authentication authority for `web/`.

---

## Parallel-frontend migration topology

Until final cutover, both frontends must be runnable.

Conceptually:

```text
                            ATI application
                         /                  \
                  JSON REST               Web routes
                     |                       |
                 React UI              Jinja + HTMX UI
```

The migration should permit developers to open equivalent Investigation data in both implementations for comparison.

The exact process/container topology is owned by V07-1. It must avoid:

- ambiguous public origins;
- accidental cookie collision between frontends;
- CSRF-origin ambiguity;
- duplicate backend state;
- separate databases for ordinary parity testing unless intentionally requested;
- requiring production deployments to run both frontends after cutover.

A separate VM may be used for migration development, but V07 correctness must not depend on VM isolation.

---

## Host-port configuration

Current main already supports explicit host-port variables such as:

- `ATI_POSTGRES_HOST_PORT`;
- `ATI_REDPANDA_HOST_PORT`;
- `ATI_API_HOST_PORT`;
- `ATI_FRONTEND_HOST_PORT`.

V07 may require a temporary host port for the new frontend while both implementations coexist.

A proposed `ATI_PORT_PREFIX` feature is useful for running multiple complete ATI stacks on one host, but it is a separate infrastructure concern and should be delivered independently rather than hidden inside the UI migration.

V07 must continue to work with explicit host-port overrides whether or not `ATI_PORT_PREFIX` exists.

---

## Testing strategy

The migration should reduce the amount of presentation correctness that requires a browser without reducing production-path E2E fidelity.

Target test hierarchy:

```text
Python unit tests
       |
       v
view-model / Jinja rendering tests
       |
       v
FastAPI + HTMX integration tests
       |
       v
Playwright workflow E2E
       |
       v
repeated browser stability tests
```

### Server-side presentation tests

Use Python/FastAPI tests for:

- route status and authorization;
- redirects;
- full-page rendering;
- HTMX fragment rendering;
- form validation;
- view-model mapping;
- bounded query/filter semantics;
- escaping;
- CSRF behavior;
- canonical links/URLs;
- error mapping.

Do not use Playwright where a deterministic server-side test proves the complete contract.

### Browser E2E

Playwright remains required for actual analyst journeys and browser semantics, including:

- login/session behavior;
- navigation;
- Back/Forward;
- HTMX swaps/history;
- forms;
- pivots;
- detail drill-down;
- graph interaction;
- temporal graph interaction;
- GEOINT map interaction;
- report navigation;
- responsive/keyboard behavior where browser semantics matter.

### Dual E2E harness lifecycle

V07-1 explicitly changes the transitional harness contract. During
V07-1..V07-6 there are two real-stack browser harnesses:

```text
V07-1..V07-6:
  scripts/e2e.sh      -> Legacy React regression harness (existing frontend/)
  scripts/e2e-web.sh  -> new server-rendered web acceptance harness

V07-7 (cutover):
  React removed
  the proven web harness becomes canonical scripts/e2e.sh
```

Both harnesses use the same isolation principles (unique Compose project,
throwaway PostgreSQL volume, generated bootstrap credentials, random high
host ports, fake operating mode, scoped cleanup). The new-web suite is
owned by `web-e2e/` (its own minimal Playwright package/config), not by
`frontend/`, so it survives the eventual React deletion. React E2E is
regression evidence only and cannot substitute for new-web acceptance; the
new-web harness cannot substitute for React regression while React still
ships.

`scripts/e2e-web.sh` is the normal browser acceptance harness for V07 migration work. It should support targeted PR-specific specifications so a migration PR does not need to execute every accumulated browser journey when narrower coverage proves the affected behavior.

The full legacy React `scripts/e2e.sh` suite is **not** a normal V07-1 through V07-6 gate. Require it only when the PR:

- modifies `frontend/` or legacy React behavior;
- changes an existing API contract consumed by React;
- changes authentication/session/CSRF semantics in a way that can affect React;
- changes Nginx/Compose/routing behavior used by React; or
- changes another shared runtime contract for which targeted compatibility testing is insufficient.

When a shared change can affect React but a small compatibility journey proves the relevant contract, prefer that targeted compatibility test over the full legacy suite.

V07-1 is a special case because it establishes parallel authentication/origin/runtime behavior. It must provide targeted React compatibility coverage for the affected security/runtime contract, but it does **not** require the complete legacy React E2E suite solely for migration acceptance.

At V07-7, after the React frontend is removed and the new-web harness has proven the retained parity journeys, consolidate the harnesses so the web harness becomes the canonical `scripts/e2e.sh` and delete obsolete React E2E infrastructure.

Direct lower-level Playwright invocation may be diagnostic; it must not silently replace the repository-prescribed acceptance topology.

### Stability

Critical journeys should retain retries=0 and deterministic repeated-cycle testing where appropriate. Browser wedges must be diagnosed, not hidden by arbitrary delays, forced reloads, retry inflation, or synthetic click workarounds.

---

## Migration parity matrix

V07 completion requires behavioral parity for the capabilities ATI intends to retain.

At minimum track:

| Capability | React baseline | New web UI target |
|---|---:|---:|
| Login/logout/session expiry | Yes | Required |
| Investigation list | Yes | Required |
| Investigation creation | Yes | Required |
| Investigation workspace shell | Yes | Required |
| Overview | Yes | Required |
| Final Report | Yes | Required |
| Evidence list/filter/pagination | Yes | Required |
| Evidence detail/provenance | Yes | Required |
| Pivot actions | Yes | Required |
| Relationships | Yes | Required |
| Relationship detail | Yes | Required |
| Relationship Observations | Yes | Required |
| Relationship history/evolution | Yes | Required |
| Graph exploration | Yes | Required |
| 1/2/3-hop graph traversal | Yes | Required |
| Temporal graph exploration | Yes | Required |
| GEOINT MAP | Yes | Required |
| GEOINT TABLE | Yes | Required |
| GEOINT resource details | Yes | Required |
| Research | Yes | Required |
| Timeline | Yes | Required |
| History | Yes | Required |
| Contextual/deep-link navigation | Yes | Required |
| Browser Back/Forward | Yes | Required |
| Refresh/deep-link restoration | Yes | Required |
| Human-readable-first labels | Yes | Required |
| i18n | Yes | Required |
| Appearance/themes | Yes | Required or explicitly superseded |
| Responsive behavior | Yes | Required |
| Accessibility/keyboard operation | Yes | Required |
| Error/empty/loading states | Yes | Required |

A later detailed PR plan may split a row into finer acceptance cases. A capability may be intentionally superseded only by an explicit V07 roadmap amendment, never by accidental omission.

---

# PR series

The expected implementation is **7 PRs**, with an allowed split to **8 PRs** if graph/temporal migration proves too large for one coding-agent PR.

Every PR requires its own detailed execution plan based on fresh `main` and `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`.

---

## PR V07-1 — Server-rendered web foundation and parallel runtime [DONE]

### Objective

Introduce the production `web/` presentation adapter and make it runnable alongside the existing React frontend without migrating substantive analyst workflows yet.

### Deliver

- Jinja2 integration and dependency/configuration;
- `src/agentic_threat_investigator/web/` package;
- composition/router boundary;
- base template and static-asset strategy;
- full-page vs HTMX-fragment convention;
- initial view-model convention;
- HTML error/404 handling;
- security baseline for session/CSRF/authorization;
- minimal authenticated shell/proof route;
- parallel runtime/container/process topology;
- explicit URL/public-origin behavior for both frontends;
- Python tests for full-page and HTMX rendering;
- dedicated `scripts/e2e-web.sh` production-path harness and initial Playwright smoke path through the new frontend;
- targeted React authentication/origin/runtime compatibility coverage sufficient to prove the parallel-foundation changes did not break the affected React contract, without requiring the full legacy React E2E suite;
- documentation of package ownership, coding conventions, and dual-harness lifecycle.

### Must preserve

- existing React frontend;
- existing REST API;
- existing authentication authority;
- existing backend behavior.

### Exit criterion

The new frontend is a production-shaped presentation adapter that can authenticate and render an authenticated ATI page in parallel with React using the real application stack.

This is an architectural checkpoint, but not a disposable prototype. If the chosen integration exposes a fundamental problem, amend V07 before proceeding rather than discarding the implementation casually.

---

## PR V07-2 — Application shell, navigation, forms, and browser-state contract

### Objective

Establish the reusable web-shell and navigation semantics every migrated feature will use.

### Deliver

- analyst shell/header/navigation;
- Investigation list;
- Investigation creation;
- workspace shell;
- canonical route conventions;
- HTMX navigation and history behavior;
- ordinary HTTP fallback behavior;
- loading/error/empty presentation conventions;
- form conventions and CSRF enforcement;
- contextual navigation design;
- browser Back/Forward and refresh/deep-link behavior;
- responsive layout foundation;
- appearance/theme strategy;
- i18n strategy for server-rendered content;
- accessibility baseline.

### Exit criterion

ATI's top-level human workflow can be entered and navigated through the new UI with deterministic URLs/history and without React-specific state machinery.

---

## PR V07-3 — Evidence, Relationships, and analyst browsing

### Objective

Migrate ATI's core server-driven analyst resource workflows.

### Deliver

- Evidence table/filter/pagination/export as retained;
- Evidence details and exact provenance;
- Relationships table/filter/pagination;
- Relationship details;
- Relationship Observations;
- relationship history/evolution list presentation;
- resource drill-down;
- Pivot actions and pivot navigation;
- human-readable Entity/Relationship/Evidence presentation;
- opaque cursor semantics;
- bounded server queries;
- exact Investigation scoping;
- contextual Back semantics;
- parity E2E for critical analyst journeys.

### Constraint

Do not migrate the rich graph canvas in this PR. Relationship history/list semantics may be migrated while graph rendering remains React until its dedicated PR.

### Exit criterion

The new frontend supports the principal table/detail/pivot analyst workflow without React.

---

## PR V07-4 — Overview, Final Report, Research, Timeline, and History

### Objective

Migrate the remaining primarily document/table-oriented Investigation surfaces.

### Deliver

- Overview;
- Final Report;
- persisted Report rendering and navigation;
- Research;
- Timeline;
- History;
- status/lifecycle presentation;
- support/corroboration navigation;
- deep links and contextual return paths;
- deterministic Markdown/download actions where currently supported;
- empty/optional-section behavior;
- parity and browser acceptance coverage.

### Exit criterion

All non-map/non-graph Investigation workspaces intended for retention are available in the new frontend.

---

## PR V07-5 — GEOINT MAP/TABLE and map visualization island

### Objective

Migrate GEOINT while establishing the production pattern for bounded JavaScript visualization islands.

### Deliver

- GEOINT primary navigation;
- MAP/TABLE subviews;
- GEOINT TABLE and resource details;
- map Jinja shell;
- bounded Leaflet/equivalent map island;
- marker/data loading;
- map-to-resource drill-down;
- approximation/provenance/truncation semantics;
- no-inference GEOINT presentation;
- map theme integration;
- Back/Forward/deep-link behavior;
- deterministic browser E2E independent of external basemap pixel availability.

### Exit criterion

GEOINT works end-to-end in the new frontend and the repository has a reusable, documented JS-island integration pattern.

---

## PR V07-6 — Relationship graph and temporal exploration

### Objective

Replace the React/React Flow graph implementation with a bounded framework-independent visualization island while preserving ATI's graph semantics.

### Deliver

- selected graph library validated against requirements;
- graph container/view-model/API integration;
- node/edge rendering;
- selection and inspector/detail integration;
- contextual actions;
- 1/2/3-hop traversal;
- focal exploration behavior if present on current main at implementation time;
- canonical render-edge invariant;
- temporal exploration;
- temporal controls/state;
- URL/history restoration;
- theme integration;
- responsive behavior;
- unit tests for graph projection/state;
- real-browser graph E2E and stability cycles.

### Required invariant

> Every rendered edge must have both endpoint vertices present in the rendered node set.

Canonical/server graph data must not be destructively filtered merely to satisfy a rendering projection.

### Split option

If fresh-main inspection shows graph and temporal migration constitute two independent large architectural concerns, split V07-6 into:

- V07-6A — graph island;
- V07-6B — temporal graph exploration.

Do not force both into one oversized coding-agent PR merely to preserve the roadmap count.

### Exit criterion

No retained ATI workflow requires React/React Flow.

---

## PR V07-7 — Parity hardening, cutover, and React removal

### Objective

Make the server-rendered frontend ATI's sole human frontend and remove obsolete SPA infrastructure.

### Preconditions

Do not begin destructive cutover until:

- parity matrix is reviewed;
- all retained capabilities exist in the new frontend;
- critical E2E journeys pass;
- required Chromium/Firefox acceptance passes;
- stability cycles pass;
- security behavior has been reviewed;
- accessibility/responsiveness requirements are satisfied;
- deployment/start/stop behavior is ready for one frontend.

### Deliver

- final parity defects;
- cross-browser stability hardening;
- performance review;
- accessibility review;
- responsive review;
- security review;
- production/default routing cutover;
- Compose/container simplification;
- `start.sh`/deployment endpoint updates;
- E2E harness cleanup;
- remove React application;
- remove Vite;
- remove React Router;
- remove TanStack Query/Table where no longer used;
- remove Material UI/Emotion where no longer used;
- remove React Flow;
- remove obsolete frontend build/container/configuration;
- remove obsolete frontend-specific tests;
- update architecture/deployment/testing documentation.

### Exit criterion

ATI has one supported human frontend: `agentic_threat_investigator.web`, using FastAPI + Jinja2 + HTMX with bounded JavaScript visualization islands.

---

## Cross-PR migration rules

### Keep React healthy until cutover

Migration PRs must not deliberately break the React frontend before V07-7. This does not make the full legacy React browser suite a routine gate for replacement-frontend work.

If a migration PR changes a contract used by React, test the affected compatibility surface at the cheapest layer that completely proves it. Prefer focused server/integration coverage or a targeted React browser journey when sufficient. Run the full legacy `scripts/e2e.sh` suite only when the affected surface is broad enough that targeted coverage is insufficient.

### Prefer vertical capability migration

Do not create a second complete but untested frontend skeleton before moving real workflows. Each PR should leave the new UI increasingly usable.

### No duplicate business logic

If React currently performs presentation logic that should actually be authoritative server/application behavior, inspect ownership carefully. Move logic to an appropriate shared application/query/presentation service rather than duplicating it in Python and TypeScript.

Do not opportunistically move genuine browser-presentation concerns into the domain.

### Preserve bounded queries

Server rendering is not permission to:

- load all Evidence;
- load all Relationships;
- decode opaque cursors;
- perform frontend-equivalent N+1 queries on the server;
- scan entire Investigation histories;
- bypass existing read projections.

### No hidden client state architecture

Avoid introducing a large browser store, generic event bus, or custom client framework. If a feature needs that level of client state, reassess whether it belongs in a bounded visualization island.

### No HTMX micro-fragment explosion

Prefer meaningful page/workspace/component boundaries. Do not make every label, button, table cell, or icon an independently fetched fragment.

### Avoid arbitrary timing fixes

Do not solve navigation/render problems with arbitrary `setTimeout`, sleeps, forced reloads, inflated Playwright retries, or synthetic browser events. Diagnose the ownership/state/lifecycle defect.

---

## Performance expectations

The new architecture should be evaluated against:

- server render latency;
- number of HTTP requests per analyst action;
- database query count;
- HTML payload size;
- HTMX fragment size;
- graph/map JSON payload size;
- browser main-thread responsiveness;
- repeated navigation stability.

The migration must not trade React browser complexity for server-side N+1 queries or excessive fragment chatter.

Where useful, compare equivalent React and web-UI analyst journeys during the parallel period.

---

## Observability

Web requests should use ATI's existing HTTP/OTel observability conventions rather than creating a parallel telemetry system.

At minimum, the migration should preserve useful visibility into:

- request duration;
- failures;
- route identity;
- server errors;
- application/query failures.

Do not place IOC values, Evidence facts, objectives, prompts, model output, credentials, or other sensitive/unbounded content into telemetry attributes.

---

## Accessibility and responsive behavior

The migration is not complete if it merely reproduces desktop pointer workflows.

Retained capabilities must support, where applicable:

- semantic HTML;
- keyboard navigation;
- visible focus;
- labels for controls;
- table semantics;
- non-color-only state communication;
- usable narrow-width layout;
- dialogs/menus only when semantically necessary;
- reduced dependence on custom pointer handlers.

Native HTML should be preferred over custom JavaScript widgets for ordinary controls.

---

## Internationalization

The existing frontend is internationalization-ready. The server-rendered UI must retain that property.

V07-1/V07-2 must establish:

- translation catalog ownership;
- locale selection;
- server-rendered translation helper conventions;
- JS-island translation data where required;
- fallback behavior for unknown enum/URN labels.

Do not mechanically prettify authoritative enum/URN values when an explicit localized label contract exists.

---

## Appearance/themes

ATI currently supports multiple presentation themes. V07 must either preserve them or explicitly amend the roadmap with an approved replacement strategy.

Theme semantics should be represented as shared CSS design tokens/custom properties usable by:

- server-rendered HTML;
- HTMX fragments;
- graph island;
- map island.

Visualization islands should consume semantic theme values rather than branch on arbitrary theme names where practical.

Theme changes must not alter analytical data, graph topology, map coordinates, or trigger unnecessary backend refetches.

---

## Deployment and development

During migration, development must support both frontends without requiring two independent ATI databases.

A separate VM is a valid developer-isolation strategy, especially for migration work, but is not part of ATI's runtime contract.

The final V07 deployment must be simpler than the transitional dual-frontend deployment.

The migration must not make browser access depend on externally forwarding identical ports from multiple VMs.

---

## Documentation requirements

Across V07, update documentation as architecture becomes authoritative.

Likely documents include:

- `docs/ARCHITECTURE.md`;
- `docs/TESTING.md` or equivalent testing documentation;
- `docs/DEPLOYMENT.md`;
- `README.md`;
- `AGENTS.md` if coding-agent rules need durable repository guidance.

Do not document the new frontend as authoritative before the corresponding implementation exists.

V07-7 must remove stale React-specific architecture statements.

---

## Detailed-plan requirement

This roadmap intentionally defines architecture and PR boundaries, not line-by-line coding instructions.

Before each V07 PR:

1. inspect fresh `main`;
2. inspect any in-progress implementation branch;
3. follow `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md`;
4. reconcile what is already implemented;
5. identify exact files and reusable abstractions;
6. define unit/integration/E2E matrices, distinguishing new-web acceptance from any legacy React compatibility coverage;
7. make `scripts/e2e-web.sh` the normal V07 browser gate and require full legacy `scripts/e2e.sh` only when the PR's actual change surface justifies it;
8. define STOP conditions;
9. define mandatory acceptance gates;
10. classify every failing mandatory gate before completion.

Do not implement a V07 PR directly from this roadmap when a detailed execution plan is required.

---

## Global STOP conditions

A coding agent must STOP rather than improvise if implementation appears to require:

- changing ATI domain semantics solely for HTML rendering;
- bypassing application/repository boundaries from `web/`;
- direct SQL from templates/routes where no existing approved boundary exists;
- weakening Investigation scoping or authorization;
- weakening CSRF/session security;
- rendering untrusted model/provider HTML;
- duplicating the REST API internally over HTTP without an approved reason;
- creating a second durable source of truth for analyst state;
- replacing bounded server queries with unbounded scans;
- introducing a general browser state framework to recreate SPA architecture;
- a new graph/map backend semantic contract not covered by the relevant detailed plan;
- changing canonical graph/provenance semantics merely for visualization;
- deleting React before parity/cutover prerequisites pass;
- treating an unclassified browser hang as an HTMX/Playwright workaround problem;
- declaring a required test passed when it merely exists or passed in a different topology;
- broad unrelated backend refactoring.

---

## Completion definition

V07 is complete only when:

1. FastAPI + Jinja2 + HTMX is ATI's supported human UI architecture.
2. `src/agentic_threat_investigator/web/` is the permanent HTML presentation adapter.
3. All retained capabilities in the parity matrix are implemented and verified.
4. Graph/temporal/map functionality works through bounded JS islands without a SPA framework.
5. Authentication, authorization, CSRF, escaping, and session behavior pass their required tests.
6. Browser Back/Forward, refresh, and deep links work for required analyst journeys.
7. Required Chromium/Firefox E2E passes through the new-web production-path harness; after V07-7 cutover that harness is the canonical `scripts/e2e.sh`.
8. Required repeated stability journeys pass with retries disabled where specified; legacy React full-suite execution is not required merely because React coexisted during earlier migration PRs.
9. React/Vite/React Router/React Flow and obsolete SPA infrastructure have been removed.
10. Deployment runs one human frontend.
11. Architecture, testing, deployment, and contributor documentation describe the final implementation accurately.
12. No unresolved migration failure is hidden behind retries, timing workarounds, or stale roadmap status.

