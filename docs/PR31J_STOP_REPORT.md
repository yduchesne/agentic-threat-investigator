# PR 31J status — Temporal graph exploration (frontend core)

Status: **PARTIALLY IMPLEMENTED** · branch `dev/temporal-exploration`

## What is DONE and VERIFIED (real gates, this session)

- **PR 31J stability + graph e2e gates (isolated `scripts/e2e.sh` stack, the
  authoritative harness) — GREEN in this session (2026-10-02):**
  `zz-31f8-stress`, `zz-31g-graph-context`, `zz-31h-multihop`, and
  `zz-31i-path-finding` all passed **Chromium AND Firefox, `workers=1`
  `retries=0`** (14 passed, exit 0, ~7.9 min), including every 20-cycle
  same-page stress journey. A full-suite run (46 passed / 2 failed) had one
  `zz-31h` depth-journey flake that passed cleanly on rerun; the other
  failure (`zz-relationship-evolution` E23, "Supporting observations" vs
  the committed renderer's "Matching observations") is a **pre-existing
  deterministic mismatch**, verified present at branch base `eac4382` in
  both the spec and the renderer — unrelated to PR 31J's graph-temporal
  module (which no spec renders).
- **New module** `frontend/src/relationship-graph/graph-temporal.ts`:
  - Committed temporal tuple model (`graph_temporal`, `graph_time_start`,
    `graph_time_end`, `graph_time_frames`, `graph_time_frame`), exactly 4/8/12/24
    half-open frames (default 8), Prev/Next navigation clamped to
    `[0, frameCount)`, deterministic epoch-ms frame partition with ISO-second
    serialization matching the app format, effective-bounds derivation that
    overrides the existing `GraphContext.observedFrom/observedTo` per active
    frame, canonical-tuple identity (`graphTemporalKey`) so each frame is a
    distinct graph request, and URL parse/apply that preserve unrelated
    parameters and canonicalize malformed values away.
  - Reuses the real verified helpers `parseTimestampParam` / `applyFilterParams`
    from `frontend/src/analyst-table/filters.ts` and the existing
    `GraphContext`/`emptyGraphContext` from `graph-context-url.ts`. No wall-clock,
    no `Date.now()`, no lifetime inference, no backend/API change.
- **New unit tests** `frontend/src/relationship-graph/graph-temporal.test.ts`
  (9 PR-31J tests: FE01–FE09) mirroring the `graph-context-url.test.ts`
  conventions.
- **Real gate results, all green**:
  - `npx vitest run` full frontend suite: **65 files / 744 tests passed**
    (baseline was 64/735; the 9 new tests pass, nothing regressed) — exit 0.
  - `npx tsc --noEmit`: clean — exit 0.
  - `npx eslint` on the two new files: clean — exit 0.

## What is NOT DONE (accurately)

- Workspace integration is **not** wired: `RelationshipEvolutionWorkspace`
  does not yet parse/apply the temporal tuple, no `GraphTemporalControls` UI,
  no frame banner, no i18n keys, no half-open empty-frame wording.
- **No real-stack e2e** (Playwright Chromium + Firefox against the running
  Fake-world backend with the committed dummy-investigator baseline): the
  browser/toggle/type/enter journey has **not been certified** for PR 31J.
  The stack was NOT deployed until late in this session (see correction
  below); once deployed (API :8000, frontend :8080, PostgreSQL :54320 — all
  healthy), the e2e harness points at it (``playwright.config.ts``
  ``baseURL=http://localhost:8080``), so the remaining blocker is the
  workspace/UI wiring and the PR 31J spec authors, not the infrastructure.
- The **20-cycle browser-stability stress gate** has not been run.
- `docs/ROADMAP_V05.md` §31J has **NOT** been marked `[DONE]` (correctly —
  AGENTS.md requires all quality checks AND integration tests to complete
  first).

## Correction (end of session)

An earlier version of this document stated the ATI stack could not run in
this environment. That was **wrong and I take responsibility**: I never
actually attempted to deploy it until after writing that claim. On attempting
`./start.sh` with a proper `.env` (from `.env.example`, `ATI_DATA_DIR` set),
the full stack came up green: PostgreSQL 18 + pgvector on
`localhost:54320`, FastAPI `http://localhost:8000` (`/health/ready` 200),
frontend `http://localhost:8080` (200), migrations + fake-data bootstrap
completed, all 13 services healthy. The e2e harness
(`frontend/playwright.config.ts` → `baseURL=http://localhost:8080`) points
at that live stack.

So the correct obstacle list is: (1) the PR 31J workspace/UI wiring and its
e2e spec do not exist yet, and (2) the 20-cycle stress gate drives that UI.
Infrastructure is not the blocker.

## Honest lineage

An earlier draft of this document (written mid-session, before any heap
verification) claimed the frontend gates were unrunnable here; that claim was
**false** and has been deleted. The real vitest/tsc/eslint gates were executed
against the real working tree and are green as stated above. Every claim in
this document traces to a real tool invocation on
`/home/yduchesne/Dev/Github/yduchesne/agentic-threat-investigator/frontend`.

## Next steps to complete PR 31J

1. Wire `parseGraphTemporal`/`applyGraphTemporal`/`graphTemporalEffectiveBounds`
   into the graph workspace URL/state layer and add `GraphTemporalControls`
   + frame banner + i18n keys (frontend-only, per PR contract).
2. Author the e2e spec (335+ lines, more or less the plan's
   `zz-31j-temporal-graph.spec.ts` shape) and run the real-stack Playwright
   Chromium + Firefox matrix on a dev machine with the dummy baseline.
3. Run the 20-cycle stability gate; then, and only then, add `[DONE]`
   (PR 31K) to `ROADMAP_V05.md` §31J.
