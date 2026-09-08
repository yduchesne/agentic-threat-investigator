# TODO

Deferred findings that are outside the CRITICAL/HIGH remediation scope of the current PR.

## Contents

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
