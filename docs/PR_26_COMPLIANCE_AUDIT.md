# PR 26 Compliance Audit (PR 26G)

Audit date: PR 26G closure. This audit compares the actual source, tests, and
evaluation baseline against the PR 26A--F invariants and detailed plans (not
merely `PR_PLAN.md`). It is the closing artifact of the PR 26 series.

Result categories:

- **PASS** — invariant delivered and covered;
- **PASS WITH DOCUMENTED NON-BLOCKING DEVIATION** — delivered with a
  narrow, documented difference that does not violate the invariant;
- **BLOCKED — corrective PR required** — a real gap; per PR 26G rules, a
  blocker must not be silently fixed as evaluation feature work.

There are **no blockers** in this audit.

---

## 26A / A-2 — GEOINT domain persistence and version allocation

- **Dominant invariant:** Location/observation/current separation; immutable
  `EntityLocationObservation` provenance; DB-owned versions; no row-local
  `version + 1`; no-op behavior creates no version/history; currentness
  ordering `(effective time, id)` wins with the greater pair.
- **Actual implementation:** `domain/geoint.py` (Location,
  EntityLocationObservation, EntityLocation, GeoResolution);
  migrations `0025_geoint_domain_persistence` and
  `0026_geoint_version_allocation`; versioned SQL API v0021/v0022/v0023
  stored functions (append observation, reconcile current, no-op,
  version allocation). Application code never mutates current state or
  allocates versions.
- **Migration/SQL API:** zero-change in PR 26G; v0021-v0023 remain installed
  and callable.
- **Primary unit tests:** `tests/unit/domain/test_geoint.py`,
  `tests/unit/test_geoint_version_contract.py`.
- **Primary integration tests:** `tests/integration/test_geoint_persistence.py`
  (G26A-P01..P34, including the forced-gap regression and no-op behavior),
  `tests/integration/test_geoint_query.py` (P07..P12 currentness ordering).
- **Evaluation coverage (PR 26G):** the evaluator hard-checks
  Investigation-relative current, newest-first history order, and duplicate
  truth (G26G-S04/S10-S13).
- **Intentional deviations/narrowings:** none.
- **Unresolved issue:** none.
- **Closure status: PASS.**

## 26B / B-2 — Canonical geography and PostGIS foundation

- **Dominant invariant:** canonical reference space uses SRID-4326
  **geometry** (never geography); canonical identity excludes geometry and
  parent; deterministic UUIDv5 identity (`canonical_location_uuid`);
  deterministic source build/import; boundary-inclusive containment
  (`ST_Covers`); GiST geometry indexes; source/license documentation.
- **Actual implementation:** `domain/geo_reference.py`,
  `app/geoint/reference_ingestion.py`,
  `infrastructure/geoint/geography_corpus_builder.py`,
  `infrastructure/geoint/geonames.py`, `infrastructure/geoint/natural_earth.py`;
  migration `0027_geoint_reference_spatial`; SQL API v0023
  `upsert_reference_location` (spatial validity, canonical rebind checks).
- **Migration/SQL API:** zero-change in PR 26G.
- **Primary unit tests:** `tests/unit/domain/test_geo_reference.py`,
  `tests/unit/infrastructure/test_geography_corpus_builder.py`,
  `tests/unit/infrastructure/test_geonames_source.py`,
  `tests/unit/infrastructure/test_natural_earth_source.py`.
- **Primary integration tests:** `tests/integration/test_geoint_reference_spatial.py`
  (G26B-D/P/I/R matrices), `tests/integration/test_geography_build_import.py`
  (G26B2-E2E), `tests/integration/test_geoint_query.py` (containment and GiST
  EXPLAIN proofs).
- **Evaluation coverage (PR 26G):** canonical corpus geography
  (`evals/scenarios/geoint/`) materializes through the normal reference
  write API with production UUIDv5 identities; the evaluator hard-checks
  wrong canonical Location and precision inflation (G26G-S01..S03, S07).
- **Intentional deviations/narrowings:** none.
- **Unresolved issue:** none.
- **Closure status: PASS.**

## 26C — Asynchronous GEOINT resolution lifecycle

- **Dominant invariant:** durable `GeoResolution` work state; short
  committed claim transaction; no UnitOfWork open during resolver execution;
  stale-worker protection (owner/version/lease); bounded retry/lease
  recovery; atomic completion; Evidence provenance validation at completion;
  separate worker; no broker.
- **Actual implementation:** `app/geoint/worker.py`, `app/geoint/claims.py`,
  `app/geoint/resolution.py`; migration `0028_geo_resolution_lifecycle`;
  SQL API v0024 stored functions (`claim_geo_resolution_batch`,
  `complete_geo_resolution`, `complete_geo_resolution_unresolvable`,
  `record_geo_resolution_failure`).
- **Migration/SQL API:** zero-change in PR 26G.
- **Primary unit tests:** `tests/unit/app/geoint/test_geo_resolution_worker.py`,
  `tests/unit/app/geoint/test_geo_retry_policy.py`,
  `tests/unit/app/geoint/test_geo_claim_extraction.py`,
  `tests/unit/domain/test_geoint_observation_identity.py`.
- **Primary integration tests:** `tests/integration/test_geo_resolution_lifecycle.py`
  (G26C-P01..P43 plus multi-worker, crash-recovery, and retry/exhaustion
  vertical slices).
- **Evaluation coverage (PR 26G):** the recovery scenarios S10-S12 drive the
  real claim/lease/reclaim lifecycle with deterministic test timestamp
  control and the evaluator closes exactly-one-final-truth (G26G-R01..R05).
- **Intentional deviations/narrowings:** canonical AMBIGUOUS resolves to
  terminal UNRESOLVABLE (`ambiguous_location`), never guessed — a documented
  v0.1 policy, not a blocker.
- **Unresolved issue:** none.
- **Closure status: PASS.**

## 26D — Investigation-scoped GEOINT query/API

- **Dominant invariant:** every read is Investigation-scoped through the
  exact Evidence chain; Investigation-relative current; bounded endpoints;
  observation/Evidence detail; exact vs contained semantics; city has no
  radius; no raw geometry leak; keyset cursors; read indexes and
  EXPLAIN-proven eligibility.
- **Actual implementation:** `app/query/geoint.py`,
  `infrastructure/persistence/query/geoint.py`, `api/routes` GEOINT
  endpoints; migration `0029_geoint_read_indexes`.
- **Migration/SQL API:** zero-change in PR 26G.
- **Primary unit tests:** `tests/unit/app/query/test_geoint_query.py`,
  `tests/unit/api/test_geoint.py`.
- **Primary integration tests:** `tests/integration/test_geoint_query.py`
  (G26D-P01..P32, EXPLAIN index-eligibility, API vertical slice).
- **Evaluation coverage (PR 26G):** the recording wrapper consumes the real
  query service; QP06 adds the bounded summary plan proof; the closure slice
  reaches the real PR 26D API.
- **Intentional deviations/narrowings:** none.
- **Unresolved issue:** none.
- **Closure status: PASS.**

## 26E — Analyst GEOINT workspace, pivots, and real E2E

- **Dominant invariant:** PR 26D is the authoritative browser source; the
  PR 25 Map stays separate; bounded workspace/map/table; accessible
  non-map path; current/history/timestamps; exact Evidence drill-down;
  server-owned containment; same-Location neutrality; PR 24 pivots; real
  seeded E2E; Chromium stability.
- **Actual implementation:** `frontend/src/geoint/` (GeointPage,
  LocationViews, EntityGeointView, GeointMap, geoint-queries, pivots);
  harness seeder `tests/e2e_support/seed_geoint.py`; browser specs
  `frontend/e2e/zz-geoint.spec.ts` (G1..G6, including the GEOINT row ->
  Location -> Entity -> Evidence -> Back -> Close stability regression).
- **Primary tests:** `frontend/src/geoint/*.test.ts(x)`
  (G26E-Q/M/U/PV), `tests/unit/infrastructure/test_e2e_geoint_seed.py`
  (G26E-S), `tests/integration/test_e2e_geoint_seed.py` (G26E-P), and the
  browser E2E G26E-E1..E6.
- **Evaluation coverage (PR 26G):** browser closure was audited — entity
  history/current, same-Location distinct Entities, containment,
  cross-Investigation isolation, non-mappable geography, and Evidence
  drill-down are already represented; no UI feature work was required.
- **Intentional deviations/narrowings:** none.
- **Unresolved issue:** none.
- **Closure status: PASS.**

## 26F — Bounded agentic GEOINT reasoning

- **Dominant invariant:** Evidence Analyst reused; tool-free `LlmClient`;
  deterministic PR 26D tools/context; bounds and no cursor drain; exact
  observation/Evidence pairs; no representative coordinates in model
  context; closed descriptive vocabulary; independent-support gate; no
  geographic persistence mutation; real PostgreSQL/PostGIS + FakeLlmClient.
- **Actual implementation:** `app/geoint/analysis_tools.py`,
  `app/geoint/analysis_context.py`,
  `app/evidence_analyst/geoint_validation.py`, GEOINT context DTOs in
  `domain/analyst.py`, prompt integration in
  `app/evidence_analyst/prompts.py`.
- **Primary unit tests:** `tests/unit/app/geoint/test_analysis_tools.py`
  (G26F-T), `tests/unit/app/geoint/test_analysis_context.py` (G26F-C),
  `tests/unit/domain/test_analyst_geoint_contract.py` (G26F-S),
  `tests/unit/app/test_geoint_finding_validator.py` (G26F-V/G),
  `tests/unit/app/test_evidence_analyst_geoint.py`.
- **Primary integration tests:** `tests/integration/test_evidence_analyst_geoint.py`
  (G26F-I01..I07).
- **Evaluation coverage (PR 26G):** the delivered tool/context policy and
  structured output contract are evaluated (G26G-T/A matrices); observation
  identity is proven at the structured-analysis-run boundary; the delivered
  Assessment schema stores Evidence support, and PR 26G claims exactly that.
- **Intentional deviations/narrowings:** none.
- **Unresolved issue:** none.
- **Closure status: PASS.**

---

## PR 26G closure summary

- Production migrations changed in PR 26G: **0**.
- Versioned SQL API functions changed in PR 26G: **0**.
- New GEOINT runtime capability added by PR 26G: **none** (evaluation/closure
  only).
- Blocker detected: **none**.
- Acceptances (PR 27 boundary): the generic evaluator platform, expanded
  curated/adversarial corpus, release gates, and generalized
  performance/cost/latency reporting remain with PR 27.