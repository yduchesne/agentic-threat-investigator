# PR 31J — Temporal graph exploration

Status: **COMPLETE** · branch `dev/temporal-exploration`

## What is DONE and VERIFIED (all executable gates in this session)

- **Workspace integration** (`RelationshipEvolutionWorkspace.tsx`): parses the
  committed temporal tuple from the route URL, derives ONE effective
  `GraphContext` whose `observedFrom/observedTo` are the active half-open
  frame's bounds (scope/entity type/relationship type/source/depth
  untouched), and passes that same effective context to the existing
  neighborhood, traversal, expansion and path-finding hooks. Frame identity
  participates in `rootGraphKey`/`committedGraphKey` so a frame transition
  deterministically resets stale expansion and path state. Temporal-off
  behavior is byte-identical to PR 31G/31H/31I.
- **Component** (`GraphTemporalControls.tsx`, new): draft range + 4/8/12/24
  frame count, atomic Apply starting at frame 1, Disable, Previous/Next with
  first/last boundary disabling, observational frame-status banner
  ("Frame N of M — observations from <from> through before <to>"), and
  observation-specific empty-frame wording. All strings localized in
  `relationshipEvolution.json`.
- **URL codec** (`graph-temporal.ts`, committed earlier): `graph_temporal`,
  `graph_time_start`, `graph_time_end`, `graph_time_frames` (4/8/12/24,
  default 8), `graph_time_frame`; deterministic exact-epoch-ms partition;
  fail-closed malformed-value parsing; unrelated params preserved.
- **E2E/stability** (all through `scripts/e2e.sh`, `workers=1 retries=0`):
  - PR-31J acceptance (`zz-31j-temporal-graph.spec.ts`, new): directed
    journey + 20-cycle stress — **Chromium 2/2**, **Firefox 2/2**.
  - Graph regression re-run after integration: 31F8/31G/31H/31I —
    **14/14 both engines**.
- **Frontend quality gates**: Vitest full suite **757 passed**; `tsc
  --noEmit` **exit 0**; ESLint on all changed/new files **exit 0**.

## E2E contract (authoritative)

`docs/TESTING.md` documents the PR-31J browser contract: the harness
(`scripts/e2e.sh`) is the acceptance path; the E2E stack uses
`ATI_LLM_DRIVER=deterministic` (never a Python `FakeLlmClient` in the
browser); frames are half-open `[observed_from, observed_to)`; empty-frame
wording and the 20-cycle temporal stress requirement are specified.

## Known unrelated baseline failure (unchanged by PR 31J)

`zz-relationship-evolution` E23 ("Supporting observations" vs the committed
renderer's "Matching observations") is a pre-existing deterministic
spec/render wording mismatch, verified present at branch base `eac4382` in
both the spec and the renderer. PR 31J did not modify that spec or renderer
and did not change its behavior; it is out of scope per the follow-up plan.

## Scope guardrails honored

No backend/API/DTO/stored-function/migration/index change. No duplicate
graph query/renderer architecture. No Relationship-lifetime inference. No
unrelated E23 fix bundled in. No second durable temporal store: the URL is
the sole committed authority.

## Roadmap

`docs/ROADMAP_V05.md` marks PR 31J `[DONE]` after all quality checks and
integration/e2e/stability gates above completed successfully.
