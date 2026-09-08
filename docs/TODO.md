# TODO

Deferred findings that are outside the CRITICAL/HIGH remediation scope of the current PR.

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
