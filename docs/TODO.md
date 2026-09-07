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
