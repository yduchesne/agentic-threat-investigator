# TODO

Deferred findings that are outside the CRITICAL/HIGH remediation scope of the current PR.

## Contents

- [Complete PR 18C secondary persistence hardening](#complete-pr-18c-secondary-persistence-hardening)
- [Complete PR 18B secondary extraction-contract hardening](#complete-pr-18b-secondary-extraction-contract-hardening)
- [Complete PR 18A secondary validation and test hardening](#complete-pr-18a-secondary-validation-and-test-hardening)
- [Complete URLhaus secondary cross-field and model-hardening invariants](#complete-urlhaus-secondary-cross-field-and-model-hardening-invariants)
- [Restore URLhaus docstring wording dropped during re-wrap](#restore-urlhaus-docstring-wording-dropped-during-re-wrap)
- [Type the URLhaus host duplicate-comparison value without `Any`](#type-the-urlhaus-host-duplicate-comparison-value-without-any)
- [Toggle the PR 17 completion marker during remediation](#toggle-the-pr-17-completion-marker-during-remediation)
- [Integration-test harness isolation](#integration-test-harness-isolation)
- [Complete the ThreatFox defense-in-depth test matrix](#complete-the-threatfox-defense-in-depth-test-matrix)
- [Harden retained ThreatFox reference URL validation](#harden-retained-threatfox-reference-url-validation)
- [Verify the official ThreatFox IOC-ID lexical bounds](#verify-the-official-threatfox-ioc-id-lexical-bounds)
- [Restore PR 16 heading spacing](#restore-pr-16-heading-spacing)
- [Remove categorical IPinfo redistribution wording](#remove-categorical-ipinfo-redistribution-wording)
- [Harden DB-IP MMDB metadata failure cleanup](#harden-db-ip-mmdb-metadata-failure-cleanup)
- [Clarify DB-IP private and reserved address semantics](#clarify-db-ip-private-and-reserved-address-semantics)
- [Verify and record MMDB software dependency licenses](#verify-and-record-mmdb-software-dependency-licenses)
- [Avoid global test import-path mutation for MMDB helpers](#avoid-global-test-import-path-mutation-for-mmdb-helpers)
- [Complete AbuseIPDB boundary regression coverage](#complete-abuseipdb-boundary-regression-coverage)
- [Align the configuration example with the implemented AbuseIPDB composition](#align-the-configuration-example-with-the-implemented-abuseipdb-composition)
- [Reject rather than normalize padded AbuseIPDB credentials](#reject-rather-than-normalize-padded-abuseipdb-credentials)

## Complete PR 18C secondary persistence hardening

**Priority:** MEDIUM

**Origin:** PR 18C reviews 02-03. The HIGH findings from
`.plans/pr-18c-fixes-02.md` are remediated; this section contains only
lower-severity follow-up.

### Problem

The PR 18C implementation passes the current QA and PostgreSQL integration gates and
now enforces the reviewed soft-delete/provenance invariants. The following secondary
hardening, test-accuracy, and documentation items remain:

- `_is_canonical_identity_violation()` accepts a PostgreSQL unique violation when
  `constraint_name` is unavailable. Production psycopg diagnostics normally provide
  the constraint, but accepting `None` weakens the stated rule that only the canonical
  Entity identity constraint is recoverable.
- `PostgresEntityRepository.upsert()` performs a canonical-identity query after every
  caught `DBAPIError`, before checking whether the SQLSTATE is recoverable. A connection,
  serialization, or unrelated database failure can therefore trigger a second query
  and obscure the original failure.
- `PostgresRelationshipRepository.upsert()` constructs
  `SoftDeletedIdentityError` with the caller's newly generated candidate Relationship
  UUID, not the UUID of the already-existing soft-deleted stable Relationship. The
  transaction still fails closed, but the diagnostic identity is inaccurate.
- `SoftDeletedIdentityError` is defined in `app.persistence.repositories` but is not
  re-exported by `app.persistence`, unlike adjacent public persistence errors.
- `assertion_order_key()` was added to the PR 18B extraction-model module solely for
  PR 18C persistence ordering. It does not change extraction output, but keeping the
  helper private to the persistence service would avoid expanding the extraction API
  during a persistence-only PR.
- The fake UnitOfWork records rollback calls but does not snapshot and restore fake
  repository state. Its stage-failure tests prove lifecycle selection, not actual state
  restoration. PostgreSQL coverage still injects only an observation-stage service
  failure, not independent post-Evidence, post-Relationship, and audit failures.
- `test_canonical_race_recovery_rejects_a_soft_deleted_row()` does not exercise the
  production unique-race recovery branch: the service's earlier deleted-Entity check
  fails before the test repository's synthetic `IntegrityError`, and that synthetic
  error would be raised outside `PostgresEntityRepository.upsert()` if reached.
- Migration `0012` now has upgrade/downgrade coverage and the PR 18C functions are in
  `EXPECTED_FUNCTIONS`, but migration `0011_relationship_persistence` itself still has
  no focused `0010 -> 0011 -> 0010 -> 0011` signature/behavior test.
- RelationshipObservation integration assertions count history rows but do not directly
  assert that the database-assigned observation version equals the immutable history
  version and that history state carries the exact Evidence, Relationship, and
  investigation identifiers.
- The Relationship soft-delete test proves only that the new version is greater than
  the old version; it does not pin sequence ownership directly. Also, the returned
  `Relationship` domain model cannot expose the post-delete version/deletion metadata
  promised by the repository method's contract, so callers must re-query persistence
  details indirectly.
- `docs/ARCHITECTURE.md` says dangling Evidence provenance is rejected "under the row
  lock", although the new foreign key enforces it during observation insertion.
  `docs/PR_PLAN.md` names only SQL API v0008 even though v0009 now owns graph-integrity
  remediation, and `docs/DATABASE.md` still contains an extra blank line before the
  `raw_payload` paragraph.

These are not demonstrated CRITICAL/HIGH production failures. They do not bypass the
current atomic service transaction or invalidate the canonical persisted graph.

### Intended fix

1. Require SQLSTATE `23505` and the exact Entity canonical-identity constraint name
   before race recovery. Re-raise when diagnostics omit or report another constraint.
2. Check SQLSTATE/type before querying raced Entity state. Query only for the entity
   soft-deleted SQLSTATE or the exact canonical unique violation; preserve every other
   original database exception unchanged.
3. Preserve the actual deleted Relationship UUID in `SoftDeletedIdentityError` using a
   bounded database diagnostic or safe post-savepoint lookup. Never convert failure
   into reuse and never expose provider data.
4. Re-export `SoftDeletedIdentityError` from
   `agentic_threat_investigator.app.persistence` and add it to `__all__`.
5. Move the assertion ordering helper into
   `provider_observation_persistence.py` unless another extraction consumer has a
   documented need. Keep ordering and PR 18B deduplication behavior unchanged.
6. Make service fakes transactional by snapshotting state on enter and restoring it on
   rollback. Add PostgreSQL service failures after Evidence, Relationship, Observation,
   and audit writes without production switches.
7. Replace the ineffective synthetic unique-race test with a test that invokes the real
   repository recovery branch. Supply an `IntegrityError` carrying SQLSTATE `23505` and
   the exact canonical constraint from inside the production call seam, then return a
   soft-deleted durable row and assert `SoftDeletedIdentityError`.
8. Add focused migration `0011` downgrade/re-upgrade verification without duplicating
   the completed migration `0012` test.
9. Assert RelationshipObservation row/history version parity and exact durable
   provenance state in the canonical PostgreSQL scenario.
10. Assert sequence ownership for Relationship DELETE versions using `currval` or an
    equivalent transaction-local sequence check. Decide separately whether the
    `Relationship` model/repository return contract should expose deletion metadata;
    update the model and mappings together if that contract is retained.
11. Correct the documentation wording to distinguish row-lock enforcement from FK
    enforcement, mention v0009 where graph-integrity ownership is described, and remove
    the duplicate blank line.

### Acceptance checks

- Only expected recoverable Entity SQLSTATEs cause a follow-up query.
- Only the exact canonical Entity constraint is treated as a creation race.
- Soft-deleted Relationship errors identify the durable row.
- Public persistence imports expose the typed error consistently.
- The unique-race test reaches the production recovery code it claims to cover.
- Fake and PostgreSQL failure-stage tests prove no partial state remains.
- Migrations 0011 and 0012 each have accurate, non-duplicative lifecycle coverage.
- Observation and Relationship DELETE versions are proven database-owned.
- Documentation accurately distinguishes lock and foreign-key guarantees.
- `./build.sh --qa` and `./integration-test.sh` pass.

## Complete PR 18B secondary extraction-contract hardening

**Priority:** LOW

**Origin:** PR 18B remediation review 02.

### Problem

The PR 18B Fix 01 implementation addresses the primary malformed-Evidence
failures, but several secondary validation and regression-test details remain:

- `_validated_registration()` validates the RDAP subject and object class
  before calling `validate_extractor_input()`. A registration with both a
  missing Evidence ID and malformed registration fields therefore reports
  `MALFORMED_FACTS` instead of the package's usual
  `MISSING_EVIDENCE_ID` precedence. This does not permit graph output or lose
  provenance because valid registration Evidence still requires an ID and
  registration extraction is empty.
- The RDAP registration tests cover invalid subject types and noncanonical
  subject values, but do not directly pin the two same-type object-class
  mismatches: DOMAIN with `object_class_name="autnum"` and ASN with
  `object_class_name="domain"`. Production code rejects both.
- TXT validation requires a string but accepts an empty string even though the
  Google DNS provider response model requires nonempty source RDATA. TXT is
  fact-only and creates no entity or relationship, so this cannot fabricate
  graph structure.

### Intended fix

1. In `extract_rdap()`, call `validate_extractor_input()` for the REGISTRATION
   branch before registration-specific subject/object-class validation. Pass
   the validated Evidence ID into the private registration validator so error
   precedence is consistent and helper signatures do not need `UUID | None`.
2. Add explicit RDAP tests for DOMAIN/autnum and ASN/domain registration
   mismatches. Assert `EvidenceExtractionError` with `MALFORMED_FACTS` and an
   empty/no returned result.
3. Decide and document whether normalized TXT `value` must be nonempty at the
   extraction boundary. If it must mirror the provider contract, reject `""`
   with `MALFORMED_FACTS` and add one focused test. Do not interpret TXT or emit
   graph output.

### Acceptance checks

- Missing persisted IDs have consistent precedence across valid and malformed
  RDAP registration envelopes.
- Both same-type RDAP object-class mismatches have direct regression tests.
- TXT emptiness behavior is explicit and remains fact-only.
- `./build.sh --qa` and `./integration-test.sh` pass.

## Complete PR 18A secondary validation and test hardening

**Priority:** MEDIUM

**Origin:** PR 18A remediation review 02.

### Problem

The PR 18A remediation implements the required production integrity fixes, but
several secondary validation, test-accuracy, and migration-verification gaps
remain:

- `InvestigationState.validate_utc()` validates only `started_at` and
  `completed_at`; optional database-owned `created_at`, `updated_at`, and
  `deleted_at` can still be constructed with naive values even though the
  model and documentation describe Investigation persistence timestamps as
  timezone-aware UTC;
- `test_concurrent_invalid_transition_is_rejected_on_locked_row()` pauses after
  an initial snapshot, but its test repository then calls
  `super().update_status()`, which performs a second `get_by_id()` after the
  gate opens. The losing writer therefore rejects the transition in Python
  using the fresh `FAILED` status and does not prove that SQLSTATE `U18A5` came
  from locked-row database validation;
- `test_locked_row_rejects_disallowed_transitions()` claims to cover every
  disallowed transition but checks only a subset of terminal-status targets;
- the remediation adds a reversible `0010` migration, but no automated test
  exercises upgrade -> downgrade -> upgrade or proves that downgrade restores
  the archived v0006 functions and removes only the new constraint/index;
- documentation says callers "must not supply" database-owned Investigation
  metadata, while the Pydantic model necessarily accepts those fields so
  repositories can reconstruct persisted resources. Writes safely ignore
  them, but the wording overstates what the model enforces;
- `test_colliding_operational_state_cannot_spoof_columns()` asserts
  `created_at.year == 2026` even though `created_at` comes from PostgreSQL
  `now()`. The test will fail solely because the calendar year changes, not
  because deserialization precedence regresses.

These are not demonstrated CRITICAL/HIGH production failures. The locked SQL
function independently enforces the lifecycle, PostgreSQL returns aware
`timestamptz` values on repository reads, and the write serializer excludes
caller-supplied persistence metadata.

### Intended fix

1. Extend the Investigation timestamp validator to `created_at`, `updated_at`,
   and `deleted_at`. Preserve `None`, reject naive values, and normalize aware
   offsets to UTC. Add focused unit tests for each field.
2. Rework the concurrent lifecycle integration test so both writers complete
   exactly one repository pre-check before either mutation and the stale writer
   then invokes the SQL function without a second Python read. Assert the stale
   path reaches SQLSTATE `U18A5`, maps to
   `InvalidInvestigationStatusTransitionError`, and creates no mutation or
   history. Use events/barriers, not sleeps.
3. Generate the disallowed lifecycle cases from the approved transition map,
   excluding same-status no-ops, or explicitly enumerate every disallowed
   pair. Assert each direct SQL call returns `U18A5` and leaves one CREATE
   history row.
4. Add an isolated migration test for 0009 -> 0010 -> 0009 -> 0010. Assert the
   `started_at` nullability, Evidence foreign key, listing index, and active
   function behavior at each revision. Do not run this against normal
   developer data.
5. Revise docs and the `InvestigationState` docstring to say callers must not
   rely on supplied persistence metadata during writes: repository reads
   populate it authoritatively, while write serialization ignores it. Do not
   claim Pydantic rejects those fields unless such an API is actually added.
6. Remove the hard-coded `created_at.year == 2026` assertion. Capture the
   authoritative dedicated-column timestamps before injecting colliding JSONB,
   then assert the later repository read returns those exact values and not the
   spoofed 2020 values.

### Acceptance checks

- Every Investigation timestamp field rejects naive values and normalizes
  aware offsets to UTC.
- The controlled race proves the stale writer reaches the locked SQL check,
  not a second Python pre-check.
- Every disallowed status pair is covered automatically or explicitly.
- The 0010 migration passes upgrade/downgrade/upgrade in an isolated test DB.
- Documentation matches the accepted model and write behavior.
- The collision regression compares authoritative timestamps exactly and has
  no dependency on the current calendar year.
- `./build.sh --qa` and `./integration-test.sh` pass.

## Complete URLhaus secondary cross-field and model-hardening invariants

**Priority:** MEDIUM

**Origin:** PR 17 remediation review 02.

### Problem

The PR 17 provider now enforces the primary endpoint shapes and collection
bounds, but several secondary strictness and maintainability gaps remain:

- a host response can report `url_count=0` while returning one or more distinct
  `urls[]` records, or otherwise report a total smaller than the number of
  retained distinct records;
- host-level `firstseen` can be later than a nested URL's `date_added`, even
  though it is described as the first time the host was seen;
- nullable URL payload members (`filename`, `file_type`, `response_md5`,
  `response_sha256`, and `signature`) use defaults, so omission and an explicit
  source `null` are currently indistinguishable even though the documented
  payload shape lists each member;
- `_build_evidence()` accepts `list[Any]`, uses `getattr()`, and zips parallel
  record/canonical-identity lists without an explicit length invariant; this
  reduces static assurance and could silently omit a record if a future caller
  supplies misaligned lists;
- URL lookups correctly support and canonicalize an IPv6 URL host, while the
  extraction-eligibility wording in `docs/DATA_SOURCES.md` still says the
  direct `matches[].host` may become only a DOMAIN or IPv4 entity; this can be
  confused with the separate and correct rule that IPv6 *host queries* are
  unsupported;
- `UrlhausProvider` silently strips padding from a resolved Auth-Key instead of
  rejecting a padded credential;
- `test_urlhaus_limits.py` imports private helpers and constants from another
  test module, coupling test collection to an implementation detail of the
  test suite;
- the canonical-equivalent duplicate ASGI test says the fake Auth-Key is absent
  from the request body but directly checks only the URL and evidence facts;
  the shared route restricts the body to the single expected `host` field, so
  this is an assertion-clarity gap rather than a credential-leak defect.

These are not demonstrated CRITICAL/HIGH failures. The malformed host-URL,
noncanonical entity-eligible fact, and normalized duplicate defects from the
prior reviews are now remediated and covered by unit and synthetic ASGI tests.

### Intended fix

1. Require `url_count` to be at least the number of retained distinct source
   records after exact-duplicate collapsing. Do not require equality because
   URLhaus caps the returned list at 100.
2. Decide and document whether host `firstseen <= min(urls[].date_added)` is a
   guaranteed source invariant. If authoritative material confirms it, reject
   contradictions; otherwise document why the timestamps are retained as
   independent source facts.
3. Re-verify the official direct-URL payload member presence/null contract. If
   the members are required-but-nullable, remove field defaults and add missing
   member tests; if omission is valid, document that explicitly.
4. Replace `list[Any]`/`getattr()` and parallel-list `zip()` evidence
   construction with a typed normalized-record structure or endpoint-specific
   fact builders. Make it impossible to misalign a record and its canonical
   identity while retaining one stable normalized match shape.
5. Clarify that a URL lookup may yield a canonical IPv6 `matches[].host` that
   is eligible for later IP entity extraction; keep IPv6 host-query
   applicability unsupported and document the distinction explicitly.
6. Reject leading/trailing whitespace in the resolved URLhaus Auth-Key with a
   fixed non-secret-bearing error; store and send accepted keys unchanged.
7. Move shared URLhaus test assertions/entities into an explicit support helper
   or duplicate the few local assertions so one test module does not import
   private names from another test module.
8. In the canonical-equivalent duplicate ASGI test, read the recorded request
   body and explicitly assert that the fake Auth-Key is absent. Keep the route's
   exact single-field form-body assertion.
9. Keep all tests synthetic and offline. Do not query public URLhaus to settle
   a contract question.

### Acceptance checks

- A host total cannot be smaller than its retained distinct URL records.
- Timestamp behavior is explicitly supported by authoritative documentation or
  documented as independent source facts.
- Missing versus null payload behavior matches the verified API contract.
- Production evidence construction contains no `list[Any]` or misalignable
  parallel-list bridge.
- URL-host IPv6 extraction eligibility is distinct from host-query applicability.
- Padded credentials fail before HTTP and are never echoed.
- URLhaus tests can be collected independently in any order.
- The duplicate ASGI test explicitly proves the fake key is absent from the
  request body as well as the URL and evidence facts.
- `./build.sh --qa` and `./integration-test.sh` pass.

## Restore URLhaus docstring wording dropped during re-wrap

**Priority:** LOW

**Origin:** PR 17 remediation review 04.

### Problem

Commit `4187ef4` re-wrapped several URLhaus docstrings and, in doing so,
silently removed meaningful wording. The authoritative contract in
`docs/DATA_SOURCES.md` is unchanged, so this is a documentation-only
regression, not a behavior change.

In `_build_match_facts()` the statements "...and never becomes an entity"
(payload metadata) and "...no derived risk labels, verdicts, or confidence
weightings are ever synthesized" were dropped.

In `_host_record_identity()` "malformed percent escapes" became the less
precise "malformed escapes", the parenthetical "(including an empty ``#``
delimiter)" was removed, and "On success the returned URL's canonical host
identity" became the weaker "The canonical URL's host identity".

In `_direct_record_identity()` "the returned canonical URL's own parsed
host" became "the returned canonical URL's own host".

### Intended fix

Restore the exact pre-`4187ef4` wording of the three docstrings in
`src/agentic_threat_investigator/infrastructure/providers/urlhaus.py` while
keeping lines within the Black/Pylint limits.

1. `_build_match_facts()` must restore the two dropped statements so the
   docstring conveys: "Payload metadata is fact-only and never becomes an
   entity." and "no derived risk labels, verdicts, or confidence weightings
   are ever synthesized."

2. `_host_record_identity()` must include "malformed percent escapes" and
   the phrase "fragments (including an empty ``#`` delimiter)".

3. `_direct_record_identity()` must use "the returned canonical URL's own
   parsed host".

4. Make no code behavior changes; only edit the docstrings.

### Acceptance checks

- `rg -n "confidence weightings" src/agentic_threat_investigator/infrastructure/providers/urlhaus.py`
  matches the `_build_match_facts` docstring.
- `rg -nF "empty ``#`` delimiter" src/agentic_threat_investigator/infrastructure/providers/urlhaus.py`
  matches the `_host_record_identity` docstring.
- `rg -nF "own parsed host" src/agentic_threat_investigator/infrastructure/providers/urlhaus.py`
  matches the `_direct_record_identity` docstring.
- `./build.sh --qa` passes (Black and Pylint accept the restored lines).

## Type the URLhaus host duplicate-comparison value without `Any`

**Priority:** LOW

**Origin:** PR 17 remediation review 04.

### Problem

`UrlhausProvider._normalize_host_response()` types its duplicate map as
`dict[str, tuple[Any, ...]]`. The runtime value is exactly the five-field
consumed normalized content
`(canonical_url: str, url_status: str, date_added: datetime, threat: str,
tags: tuple[str, ...])`, but the `Any` erases that shape and weakens static
assurance inside otherwise strict normalization code. This is a distinct site
from the separately deferred `_build_evidence()` `list[Any]`/`getattr()`/`zip()`
refactor.

### Intended fix

1. Define a small frozen value type, for example a
   `typing.NamedTuple` named `_HostConsumedContent` with fields
   `canonical_url: str`, `url_status: str`, `date_added: datetime`,
   `threat: str`, `tags: tuple[str, ...]`.
2. Build it in `_normalize_host_response()` and type the map as
   `dict[str, _HostConsumedContent]`.
3. Preserve the exact five-field equality semantics; do not add or remove
   any compared field.
4. Do not fold the unrelated `_build_evidence()` refactor into this change
   unless the smallest safe change cannot be expressed without it.

### Acceptance checks

- `consumed_by_id` has no `Any` in its type annotation.
- Review-03 duplicate-equivalence and conflict tests still pass unchanged.
- `src/agentic_threat_investigator/infrastructure/providers/urlhaus.py`
  contains the named value type and no new `list[Any]` bridge in the
  duplicate path.

## Toggle the PR 17 completion marker during remediation

**Priority:** LOW

**Origin:** PR 17 remediation review 04.

### Problem

`.plans/pr-17-fixes-03.md` section 1 required removing `[DONE]` from the PR 17
heading before any production change, and section 6 required restoring it only
after all gates passed. The branch never did either as a distinct step:
`docs/PR_PLAN.md` was not modified by any commit in `d11fb67..HEAD`, so the
marker stayed `[DONE]` throughout remediation. The final tree is correct
(`## PR 17 --- URLhaus provider [DONE]`), but the marker-toggle discipline was
not followed, and commit `644f1fa` claims to "restore" a marker it never
removed.

### Intended fix

1. Keep the final `[DONE]` marker; no tree change is required now.
2. In future remediation plans and reviews, remove the `[DONE]` marker before
   the first production change and restore it only after all gates pass.
3. Ensure any commit message that mentions restoring or removing the marker
   is backed by an actual `docs/PR_PLAN.md` diff for that marker.

### Acceptance checks

- The final tree has exactly one `## PR 17 --- URLhaus provider [DONE]`
  heading and no altered PR 17 deliverable wording.
- Future remediation commit messages match their diffs for the marker toggle.

## Integration-test harness isolation

**Priority:** MEDIUM  
**Origin:** PR 13 review; pre-existing code, not an IPinfo provider defect.

### Problem

`integration-test.sh` removes every container whose Compose project label starts with `ati-test-`, including containers from another integration run that is still active. Separately, `ensure_test_database_safe()` accepts `ati-test` anywhere in the full URL instead of validating the parsed database name. A marker in a username, password, host, or query can therefore satisfy the guard.

### Intended fix

1. Add a dedicated label to resources created by `integration-test.sh`, identifying both the ATI integration harness and the unique run ID.
2. At startup, list only containers carrying the dedicated harness label.
3. Never remove a running container from another run.
4. Remove only exited stale containers; add a documented minimum-age threshold if Podman exposes a reliable creation timestamp.
5. Keep the current run's cleanup limited to its exact Compose project.
6. In `ensure_test_database_safe()`, parse the database URL with SQLAlchemy's URL parser or an equivalent existing dependency.
7. URL-decode and inspect only the database name.
8. Accept exactly `ati-test` or a non-empty `ati-test-<unique-id>` name.
9. Reject a marker found only in the username, password, hostname, port, or query string.
10. Add unit tests for accepted database names and each rejected marker location.
11. Add shell-level or isolated command tests proving one active integration run cannot delete another run's containers.
12. Update `docs/TESTING.md` with the final cleanup and database-name rules.

### Acceptance checks

- Two concurrent integration runs do not remove or stop each other's resources.
- A completed stale harness container can be cleaned safely.
- `postgresql://ati:ati@host/ati-test` and a valid unique test database pass.
- URLs with a normal database name fail even when `ati-test` appears elsewhere.
- `./build.sh --qa` and a serial `./integration-test.sh` pass.

Until fixed, run `./integration-test.sh` serially.

## Complete the ThreatFox defense-in-depth test matrix

**Priority:** MEDIUM

**Origin:** PR 16 review; production behavior is currently supplied by the shared HTTP stack.

### Problem

ThreatFox tests cover the primary success, authentication, rate-limit, retry,
schema, cancellation, and no-result paths, but do not exercise every shared
transport guarantee through `ThreatFoxProvider`. Missing provider-specific
coverage includes timeout mapping, invalid response content type, oversized
response bodies, a transient 5xx followed by success, and proof with an
exploding clock that invalid/unsupported inputs are rejected before clock
access.

### Intended fix

1. Add focused `ThreatFoxProvider` unit tests for timeout, invalid media type,
   and the configured response-size bound.
2. Add a deterministic transient-5xx-then-success test that asserts the exact
   request count and normalized evidence.
3. Inject a clock callable that raises if evaluated and use it for invalid and
   unsupported input tests; continue using a transport that fails on any I/O.
4. Reuse the existing shared HTTP helpers and synthetic responses; do not add
   provider-specific retry or transport code.
5. Keep every test offline and credential-free.

### Acceptance checks

- Every missing path maps through the existing typed provider taxonomy.
- Invalid input performs zero clock and HTTP I/O.
- No test contacts public ThreatFox.
- `./build.sh --qa` passes.

## Harden retained ThreatFox reference URL validation

**Priority:** MEDIUM

**Origin:** PR 16 review; external references are retained but never fetched.

### Problem

ThreatFox reference validation accepts an `http`/`https` URL containing URL
userinfo. The provider never fetches references, and the ThreatFox Auth-Key is
not exposed, but retaining a credential-bearing source URL is unnecessary and
inconsistent with ATI's conservative URL data-minimization posture.

### Intended fix

1. Reject non-null `reference` and `malware_malpedia` URLs when
   `urlsplit()` reports a username or password.
2. Keep validation errors generic and never include the rejected URL.
3. Add strict model tests for username-only and username/password URLs.
4. Continue to validate but not retain `malware_malpedia`; continue to retain
   safe `reference` values without fetching them.
5. Update the ThreatFox source contract to state the no-userinfo rule.

### Acceptance checks

- Credential-bearing source URLs produce `INVALID_RESPONSE` without leaking
  their content.
- Ordinary bounded HTTP(S) references remain valid.
- No URL is fetched.

## Verify the official ThreatFox IOC-ID lexical bounds

**Priority:** LOW

**Origin:** PR 16 review; the public API documents IDs as strings but does not publish a complete grammar.

### Problem

The current provider accepts decimal strings from `"0"` through 16 digits.
ThreatFox examples use positive decimal identifiers, but the reviewed public
contract does not establish whether zero, leading zeroes, or the selected
16-digit upper bound are authoritative.

### Intended fix

1. Re-check official ThreatFox API documentation or maintained source for the
   exact IOC-ID grammar and range.
2. If confirmed, update the provider validator, source contract, and boundary
   tests together.
3. If not confirmable, retain the current bounded decimal safety rule and
   document it as an ATI defensive bound rather than an official source bound.
4. Do not use a real Auth-Key or live API call solely to answer this question.

## Restore PR 16 heading spacing

**Priority:** LOW

**Origin:** PR 16 review 03; documentation-only formatting regression.

### Problem

Commit `2fa5dfd` removed the blank line between the
`## PR 16 --- ThreatFox provider [DONE]` heading and its `Deliver:` paragraph in
`docs/PR_PLAN.md`. Markdown still renders and no product contract changed, but
the section no longer follows the surrounding document's heading spacing.

### Intended fix

1. Restore exactly one blank line after the PR 16 heading.
2. Do not alter the `[DONE]` marker or any PR 16 deliverable wording.
3. Keep the change documentation-only.

### Acceptance checks

- PR 16 has the same heading spacing as adjacent PR sections.
- `git diff --check` passes.

## Remove categorical IPinfo redistribution wording

**Priority:** LOW  
**Origin:** PR 13 documentation review.

### Problem

`docs/LICENSING.md` says ATI "never redistributes" IPinfo data. That statement is broader than the implemented provider behavior and cannot describe every future export, API, or UI path. The surrounding text correctly requires use-specific legal review before general availability.

### Intended fix

1. In `docs/LICENSING.md`, retain the verified IPinfo Lite license, attribution links, `raw_payload=None`, and rate-bound statements.
2. Replace "never redistributes or bundles IPinfo data" with neutral wording limited to the current repository state, such as: the repository does not bundle an IPinfo dataset and the provider retains only normalized facts in emitted evidence.
3. Do not classify normalized evidence categorically as licensed, unlicensed, adapted, or non-adapted material.
4. Keep the requirement for legal review before general availability or external exposure.
5. Keep the future runtime-attribution requirement and the existing `NOTICE` attribution unless legal review approves different wording.

### Acceptance checks

- `rg -n "never redistributes" docs/LICENSING.md` returns no matches.
- License and attribution links remain present.
- Documentation describes current implementation facts without making use-specific legal conclusions.

## Harden DB-IP MMDB metadata failure cleanup

**Priority:** MEDIUM
**Origin:** PR 14 remediation review 02.

### Problem

`CityLiteMmdb.__init__()` wraps failures from `maxminddb.open_database()`, but the subsequent `reader.metadata()` call is outside that exception boundary. If metadata inspection raises, the third-party exception escapes instead of becoming `MmdbOpenError`, and the newly opened reader is not explicitly closed. The current reader normally parses metadata during open, so this is a defensive malformed-artifact/lifecycle gap rather than a demonstrated normal-path failure.

### Intended fix

1. In `src/agentic_threat_investigator/infrastructure/providers/dbip_city_lite.py`, perform reader opening and metadata product validation inside one guarded initialization path.
2. Keep the opened reader in a local variable until all validation succeeds.
3. If metadata access or product validation fails, close the local reader before raising.
4. Convert third-party metadata/decoder exceptions to the fixed, path-free `MmdbOpenError("unreadable City Lite MMDB artifact")` message.
5. Preserve the distinct, path-free wrong-product `MmdbOpenError` message when metadata is readable but `database_type` is not `DBIP-City-Lite`.
6. Assign `self._reader` and the open state only after validation succeeds.
7. Add a unit test that monkeypatches the reader so `metadata()` raises; assert the reader closes exactly once and only `MmdbOpenError` escapes.
8. Add a unit test that a wrong-product reader also closes exactly once.

### Acceptance checks

- No third-party metadata exception escapes `CityLiteMmdb` construction.
- Every reader opened during a failed constructor is closed exactly once.
- Error messages contain no artifact bytes, record values, or host paths.
- DB-IP provider and composition tests pass.

## Clarify DB-IP private and reserved address semantics

**Priority:** MEDIUM
**Origin:** PR 14 remediation review 02.

### Problem

`docs/DATA_SOURCES.md` says private, reserved, and non-global ranges are lookup misses because City Lite never contains them. The provider does not pre-filter these ranges; it performs the MMDB lookup and will normalize any matched record. The ATI-authored integration fixture intentionally stores hits in documentation-only reserved ranges, so the categorical documentation does not describe actual provider behavior. Existing private-address tests prove only that an address absent from the synthetic MMDB misses.

### Intended fix

1. Keep documentation-range addresses in the synthetic MMDB; they are required to avoid real IP data.
2. Do not add a blanket `ipaddress.is_global` filter, because that would prevent the required synthetic documentation-range integration tests.
3. In `docs/DATA_SOURCES.md`, state that every syntactically valid IPv4/IPv6 address is looked up in the configured MMDB.
4. State that an absent record, regardless of address class, is a valid empty miss and is not a benign assessment.
5. Qualify the production expectation: the official DB-IP City Lite artifact is expected not to carry useful public-geolocation records for private/local-use addresses, but ATI does not infer this independently of the artifact.
6. Rename private-address tests so they state that an unlisted private address misses, not that the provider forcibly excludes all private ranges.
7. Add a unit test with a fake matched record for a private address and document the selected contract explicitly. Under the current lookup-all-valid-addresses design, assert that the matched record is validated normally and can produce evidence.
8. Ensure all wording still says geolocation is approximate and never establishes an attacker or device's physical location.

### Acceptance checks

- Documentation matches lookup behavior for global, private, reserved, and documentation ranges.
- Tests distinguish address-class policy from an ordinary MMDB miss.
- No real IP address data or real DB-IP record is introduced.

## Verify and record MMDB software dependency licenses

**Priority:** LOW
**Origin:** PR 14 remediation review 02.

### Problem

The incorrect `mmdb-writer` license comment was corrected to MIT, but the review did not find a repository artifact recording completed authoritative license verification for the new runtime `maxminddb` dependency and the test-only `mmdb-writer`/`netaddr` dependency chain. Package metadata alone is incomplete for `maxminddb`.

### Intended fix

1. Verify `maxminddb`, `mmdb-writer`, and `netaddr` against their authoritative source distributions or repositories.
2. Record the verified names, versions/ranges, licenses, and source links using the repository's existing dependency-license process.
3. If no dependency inventory exists, add a short documented process to `docs/LICENSING.md` rather than creating an ad hoc generated inventory.
4. Keep software dependency licensing separate from the DB-IP City Lite dataset's CC BY 4.0 terms.
5. Correct any source comment that disagrees with the authoritative package license.

### Acceptance checks

- All three new dependency licenses have authoritative citations.
- Runtime and test-only dependencies are distinguished.
- No dependency license is attributed to the DB-IP dataset or vice versa.

## Avoid global test import-path mutation for MMDB helpers

**Priority:** LOW
**Origin:** PR 14 remediation review 02.

### Problem

`tests/conftest.py` mutates `sys.path` for the entire test suite solely so DB-IP tests can import `tests.support.mmdb`. This passes today, but it changes global module resolution and can hide collisions with installed top-level `tests` packages.

### Intended fix

1. Confirm whether pytest already places the repository root first when invoked through `uv run pytest` and the canonical scripts.
2. Prefer a normal explicit test-support package or fixture module that does not require runtime `sys.path` insertion.
3. If package markers are used, ensure they do not break integration-test discovery or existing fixture loading.
4. Remove `tests/conftest.py` if it has no fixture/configuration responsibility after imports are corrected.
5. Run targeted tests, `./build.sh --qa`, and `./integration-test.sh` to catch import-mode differences.

### Acceptance checks

- DB-IP unit and integration tests import the synthetic MMDB helper without modifying `sys.path` at runtime.
- Canonical unit and integration commands still discover all tests.
- No production package includes test-support code.

## Complete AbuseIPDB boundary regression coverage

**Priority:** MEDIUM
**Origin:** PR 15 remediation review 03.

### Problem

The PR 15 implementation follows the approved execution order and shared HTTP behavior, but several explicit regression checks from `.plans/PR_15_LUNA_EXECUTION_PLAN.md` and `.plans/pr-15-fixes-02.md` remain indirect or absent:

- unsupported and invalid entities are tested for zero HTTP I/O, but the tests do not prove that the provider clock is not evaluated;
- malformed JSON is covered through the synthetic ASGI integration path, but not in the AbuseIPDB unit matrix;
- cancellation propagation is tested, but the AbuseIPDB-facing test does not prove that the shared limiter permit is released afterward;
- HTTP 402 and 422 mappings are covered, but AbuseIPDB does not have an explicit HTTP 400 mapping assertion.

The implementation currently uses the correct validation-before-clock order and delegates these HTTP/lifecycle behaviors to the tested shared client, so these are regression-coverage gaps rather than demonstrated production defects.

### Intended fix

1. In `tests/unit/infrastructure/providers/test_abuseipdb_contract.py`, inject a clock callable that raises if called.
2. Invoke `investigate()` once with an unsupported entity and once with an invalid `IP_ADDRESS`; assert each returns one non-retryable `UNSUPPORTED_INDICATOR` and the raising clock is never evaluated.
3. Add a unit response with status 200, `application/json`, and malformed JSON bytes; assert zero evidence and one non-retryable `INVALID_RESPONSE` with a generic body-free message.
4. Add HTTP 400 to the AbuseIPDB status-mapping matrix and assert `INVALID_RESPONSE`, non-retryable, zero evidence, and one attempt.
5. Add an AbuseIPDB cancellation test using a dedicated `BoundedLimiter` with concurrency one.
6. Cancel the first request while it owns the permit, then make a second deterministic request through the same client/limiter; assert the second request completes instead of blocking, proving permit release.
7. Keep all transports synthetic and fail closed; do not add real network access or sleeps.
8. Do not duplicate shared retry/backoff implementation logic in provider tests.

### Acceptance checks

- Unsupported and invalid entities are rejected before both clock evaluation and HTTP I/O.
- Malformed JSON has direct AbuseIPDB unit coverage.
- HTTP 400 has an explicit typed mapping assertion.
- Cancellation propagates and the next request can acquire the same limiter permit.
- Targeted AbuseIPDB tests and `./build.sh --qa` pass.

## Align the configuration example with the implemented AbuseIPDB composition

**Priority:** LOW
**Origin:** PR 15 remediation review 03; pre-existing forward-looking example now conflicts with the implemented provider.

### Problem

The generic secret-resolution example near the end of `docs/CONFIGURATION.md` still uses a nested `CONFIG["abuseipdb"]` object with an unsupported `enabled` member and the nonexistent class name `AbuseIPDBProvider`. PR 15 implements flat `Settings` fields and `AbuseIpdbProvider`, so readers can now mistake the old illustrative pseudocode for the production configuration contract.

### Intended fix

1. Keep the generic explanation that configuration stores secret reference names rather than values.
2. Replace the nested AbuseIPDB profile example with the real flat setting name `abuseipdb_api_key_secret`, or make the example provider-neutral.
3. Remove the unsupported `enabled` member unless a future approved provider-enable contract is implemented.
4. Use the actual class name `AbuseIpdbProvider` in any concrete example.
5. Show secret resolution at composition time without placing the resolved value in `Settings`.
6. Ensure the example agrees with the settings table, `.env.example`, and `ProviderComposition.create()`.

### Acceptance checks

- `docs/CONFIGURATION.md` contains no `AbuseIPDBProvider` identifier.
- No example implies that `CONFIG["abuseipdb"]` or `abuseipdb.enabled` is supported.
- The documented secret reference remains `ATI_ABUSEIPDB_API_KEY` by default.

## PR 19B post-hardening secondary follow-up

**Priority:** MEDIUM

**Origin:** Review of `.plans/pr-19b-fixes-04.md` implementation. The remaining
HIGH context-binding defect is handled only by `.plans/pr-19b-fixes-05.md`.

### Problem

The fixes-04 implementation passes QA and integration gates and completes its
listed production hardening. These lower-severity test/documentation details
remain:

- `test_timeline_migration_downgrade_and_re_upgrade()` says migration 0013
  “downgrades to v0011” in its summary even though it correctly downgrades to
  revision 0012.
- The direct-SQL invalid timeline `error_code` test catches `IntegrityError`
  but does not assert SQLSTATE `23514` or the exact
  `investigation_timeline_event_error_code_check` constraint, so another
  integrity failure could satisfy it.
- Timeline event-shape invariants are enforced by Pydantic but not mirrored by
  PostgreSQL checks. This matches the documented application append-only
  boundary, but privileged/direct SQL can create a row that the repository
  cannot deserialize. The final fixes-04 inspection wording overstated that
  every event shape was validated in SQL.
- The composition-factory unit test checks node names only. The PostgreSQL
  vertical slice exercises the assembled factory, but the unit test does not
  independently prove that the expected reader, extractor, persistence
  service, timeline sink, and executor are wired.
- UoW lifecycle integration tests invoke `__aenter__()`/`__aexit__()` manually.
  They prove reset behavior but are more fragile than a small helper or normal
  `async with` plus retained-UoW assertions.
- The fixes-05 composition tests annotate the exploding UoW factory as returning
  `object` and suppress the resulting argument-type error; the fake provider's
  `investigate()` parameter also uses `object` rather than the ABC's `UUID`.
  Production typing is strict, but these unit-test annotations are weaker than
  the interfaces they are intended to verify.
- The fixes-05 PostgreSQL regression uses function-local imports and repeated
  `# type: ignore[union-attr]` access to `reader.session`. Existing assertions
  establish an active UoW, but a small typed query helper would make the durable
  absence checks clearer and avoid scattered ignores. The fixes-06 direct-
  builder regression duplicates the same durable-absence query block.
- The fixes-06 direct-builder unit test constructs `FakeEntityReader` inline
  and does not retain it to assert that no target lookup occurred. The graph's
  initialize-first implementation and exploding integration transport make the
  behavior clear, but the test does not directly pin the plan's zero-reader-
  call assertion.
- `test_bound_investigation_id_has_no_mutation_path()` proves that the read-only
  property has no setter, but its name can be read as proving the executor's
  private `_context` reference is immutable. The context value object is frozen;
  reassignment of the private attribute is an implementation-discipline issue,
  not something this test establishes.

### Intended fix

1. Correct the migration lifecycle docstring to say revision 0012; make no
   migration behavior change.
2. Assert SQLSTATE `23514` and the exact check-constraint diagnostic for the
   invalid error-code insert, then verify no row remains after rollback.
3. Decide whether database-owner SQL must obey event-shape rules. If yes, add
   named CHECK constraints mirroring only the documented Pydantic shapes and
   migration tests. If no, revise final verification wording to state that
   event shapes are application-enforced while error-code grammar is also
   database-enforced.
4. Strengthen the composition unit test through injected constructor/factory
   seams or a bounded fake-UoW execution; do not expose production internals or
   duplicate the PostgreSQL vertical slice.
5. Refactor UoW lifecycle tests to minimize direct magic-method calls while
   retaining normal-exit, rollback-exit, reset, and re-entry coverage.
6. Type the exploding UoW factory as returning `UnitOfWork` (it may still raise
   unconditionally), use `UUID` in the fake provider override, and remove the
   associated argument-type suppressions.
7. Move fixes-05/06 integration imports to module scope and use one typed
   active-session/query helper for both durable absence assertions instead of
   duplicated query blocks and repeated `union-attr` ignores.
8. Retain the `FakeEntityReader` in the direct-builder unit regression and
   assert its request list remains empty when initialize rejects mismatched
   state.
9. Rename the bound-ID property test to state precisely that the public
   property is read-only, or explicitly freeze executor context assignment if
   that stronger invariant is required. Do not test private mutation merely to
   imply a public security boundary.

### Acceptance checks

- Migration documentation names revision 0012 accurately.
- The error-code database test proves the intended named CHECK failed.
- Documentation accurately states the Python/SQL event-shape boundary.
- Composition and UoW lifecycle tests remain deterministic and focused.
- `./build.sh --qa` and `./integration-test.sh` pass.

## PR 19A secondary orchestration hardening

**Priority:** MEDIUM

**Origin:** PR 19A branch review against `.plans/PR_19A_LUNA_EXECUTION_PLAN.md`.

### Problem

The PR 19A graph and queue helpers pass the required deterministic scenario and the canonical QA gate. No CRITICAL or HIGH defect was found. The following lower-severity contract-hardening items remain:

- `ProviderWorkItem` and `ProviderExecutionOutcome` are operational orchestration contracts but are defined in `domain.investigation.py`; the approved package boundary prefers orchestration contracts under `app/orchestration` while keeping only pure state/domain contracts in the domain layer.
- `InvestigationState` does not enforce all documented queue invariants at model validation time: duplicate items or an item present in both pending and completed collections can be constructed directly. The current enqueue/record helpers preserve the invariants for normal use, and PR 19A intentionally avoids broad cross-field semantic validation.
- `record_provider_outcome()` verifies the selected item and duplicate completion, but does not explicitly reject a selected item that is absent from `pending_provider_work`. A malformed manually constructed state could therefore increment the provider counter and create a completed item without removing pending work.
- `ProviderExecutionOutcome` does not validate status/error consistency (for example, a succeeded outcome with an error or a failed outcome without one). The current deterministic fake and graph behavior do not depend on this distinction, and stronger outcome policy may belong with real provider execution.
- The graph channel wraps a Pydantic model in a `TypedDict`; the state model itself has a JSON round-trip test, but there is no graph-level test invoking the graph from a JSON-reconstructed channel payload. This would make checkpoint/channel compatibility explicit without adding a persistence backend.
- The fake executor raises `KeyError` for an unconfigured work item. The required contract only requires configured work to be deterministic and exception-free, but a fixed typed failure or explicit constructor-time mapping validation would make fixture failures clearer.

### Intended fix

1. In a future orchestration-contract cleanup, move `ProviderWorkItem` and `ProviderExecutionOutcome` (and their status enum) to the established `app/orchestration` contract module, or document and consistently apply the decision to keep pure operational contracts in the domain. Update imports/exports and documentation without introducing a LangGraph dependency into the domain.
2. Add focused helper/model tests for duplicate pending/completed collections and pending/completed overlap. Decide whether to reject these only at helper boundaries or with a narrowly scoped model validator; do not add PR 21 pivot/budget/stopping policy.
3. Make `record_provider_outcome()` require the outcome work item to be present in pending before moving it to completed. Add a regression test proving malformed state cannot increment `provider_calls_used` or create an inconsistent queue.
4. Decide the minimal status/error invariant for `ProviderExecutionOutcome`; if enforced, reject only contradictory combinations and preserve operational-only error data. Add success/failure boundary tests.
5. Add a graph test that serializes the initial `InvestigationState` with `model_dump(mode="json")`, reconstructs it with `model_validate()`, wraps it in the graph channel, and asserts the same deterministic execution result.
6. Improve `FakeWorkExecutor` diagnostics for missing mappings while keeping it offline and deterministic; do not add real provider behavior.

### Acceptance checks

- Orchestration contracts have one documented, architecture-compliant owner.
- Queue invariants are either rejected or explicitly limited to helper preconditions, with tests matching the decision.
- Malformed outcome recording cannot corrupt queues or counters.
- Outcome status/error semantics are explicit and tested.
- JSON-reconstructed graph input executes deterministically.
- All tests remain synthetic/offline and `./build.sh --qa` passes.

## Reject rather than normalize padded AbuseIPDB credentials

**Priority:** LOW
**Origin:** PR 15 remediation review 03.

### Problem

`SecretsResolver.require()` deliberately returns a nonblank resolved secret unchanged, but `AbuseIpdbProvider.__init__()` silently strips leading and trailing whitespace before storing the API key. Silent normalization can hide a deployment mistake and means the provider does not send the exact resolved credential. Normal API keys contain no surrounding whitespace, so failing clearly is safer than changing the value.

### Intended fix

1. In `AbuseIpdbProvider.__init__()`, keep rejecting empty and whitespace-only keys.
2. Also reject a key when `api_key != api_key.strip()`; use a fixed message that does not include the key.
3. Store an accepted key unchanged.
4. Add unit tests for leading space, trailing space, tab, and newline padding.
5. Assert error messages do not contain any supplied credential fragment.
6. Keep composition failure behavior and header-only authentication unchanged.

### Acceptance checks

- A valid synthetic key reaches the `Key` header byte-for-byte.
- Padded keys fail before HTTP I/O and are never echoed.
- Missing/blank-key composition tests continue to pass.
