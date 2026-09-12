# Agentic Threat Investigator — Security Design

## Table of contents

- [Authentication](#authentication)
- [User model](#user-model)
- [Passwords](#passwords)
- [Bootstrap administrator](#bootstrap-administrator)
- [Sessions](#sessions)
- [CSRF](#csrf)
- [Login protection](#login-protection)
- [Administrator invariant](#administrator-invariant)
- [Actor context](#actor-context)
- [Authorization](#authorization)
- [Audit](#audit)
- [Audit data minimization](#audit-data-minimization)
- [LLM/tool security](#llmtool-security)
- [Prompt injection](#prompt-injection)
- [Secrets](#secrets)
- [Container security](#container-security)
- [Automated security scanning](#automated-security-scanning)
- [Data deletion](#data-deletion)
- [Geolocation safety](#geolocation-safety)
- [Future external identity](#future-external-identity)
- [Secret resolution and artifact URIs](#secret-resolution-and-artifact-uris)
- [Secret-handling rules](#secret-handling-rules)

## Authentication

v0.1 uses local username/password authentication with server-side sessions.

Roles:

```python
class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
```

ADMIN can perform investigation, monitor, user, and system administration.

ANALYST can perform investigation, monitor, findings, and history workflows but cannot administer users/system configuration.

## User model

User contains:

- ID;
- username;
- display name;
- role;
- enabled state;
- created/updated timestamps;
- soft-deletion metadata.

Credentials are stored separately from the domain User.

## Passwords

Passwords are hashed with Argon2id through a maintained library.

ATI never stores plaintext or reversibly encrypted passwords and does not use homegrown password hashing.

## Bootstrap administrator

Bootstrap environment/configuration:

- `ATI_BOOTSTRAP_ADMIN_USERNAME`
- `ATI_BOOTSTRAP_ADMIN_PASSWORD`

The bootstrap admin is created only when no users exist.

The password is immediately hashed.

Changing bootstrap environment variables after users exist must not silently reset the administrator password.

No universal/default `admin/admin` credential is permitted.

## Sessions

Sessions use opaque high-entropy random tokens.

The browser receives the token only as a secure cookie.

Database storage uses a hash of the token.

Session metadata includes:

- session ID;
- user ID;
- token hash;
- created time;
- expiry;
- last-seen time;
- revoked time.

Cookie settings:

- HttpOnly;
- Secure where applicable;
- SameSite=Lax;
- Path=/.

Sessions have configurable absolute expiry and optional idle timeout.

Logout, user disablement, soft deletion, and password change revoke applicable sessions.

Delivered /api/v1 behavior (PR 23C):

- `POST /api/v1/auth/login` issues the `ati_session` cookie (HttpOnly,
  `SameSite=Lax`, `Path=/`, `Secure` outside local/dev profiles, max age =
  configured session lifetime) plus the `ati_csrf` double-submit cookie and
  returns the public user DTO. The raw session token is never returned in
  JSON.
- `GET /api/v1/auth/me` resolves the session through the service; absent,
  expired, revoked, or disabled-user sessions are indistinguishable at the
  boundary (`401 authentication_required`).
- `POST /api/v1/auth/logout` revokes the session and expires both cookies
  (`204`); already-invalid logout is idempotent.
- CORS is credentialed with explicit
  configured `api_cors_origins` only; the wildcard is rejected by settings
  validation so `allow_credentials=true` can never combine with `*`.
- CSRF uses the double-submit cookie (`X-CSRF-Token` header must equal the
  `ati_csrf` cookie) plus the same-origin check above; state-changing routes
  (`POST /auth/logout`, `POST /investigations`) enforce it and return
  `403 forbidden` on failure.
- Request logging emits request ID, method, route template, status,
  duration, and authenticated actor ID only — never passwords, cookies,
  session tokens, auth headers, idempotency keys, provider payloads, LLM
  output, or SQL parameters.

## CSRF

Because v0.1 uses cookie authentication, state-changing requests require CSRF protection.

Use SameSite plus Origin/Referer validation and the double-submit CSRF
token strategy (delivered in PR 23C). The
expected origin is the configured public base URL, never the Host-derived
request URL. Origin takes precedence over Referer; either is compared as a
normalized scheme, host, and effective port, so Referer paths are accepted.
Invalid origins and invalid configuration fail closed. If a future
deployment requires `SameSite=None`, STOP and implement a reviewed
anti-CSRF token mechanism instead.

## API error redaction (PR 23C)

Every /api/v1 error response uses the stable envelope
`{"error": {"code", "message", "request_id"}}`. FastAPI validation failures
return the ATI envelope (`422 validation_error`). Unexpected exceptions map
to a generic `500 internal_error`; Python tracebacks, SQL text/errors,
SQLSTATEs, class names, provider raw responses, LLM/provider internals,
LangGraph state, and ORM metadata never cross the boundary. Response
headers include `X-Request-ID`, `X-Content-Type-Options: nosniff`, and
`Cache-Control: no-store` for API responses.

## Login protection

- generic login failure message;
- bounded rate limiting keyed by normalized username and client address;
- no username-enumeration disclosure;
- every credential failure performs one password verification, using a dummy
  hash when no credential exists (including disabled/deleted accounts);
- audit success/failure;
- normalized usernames;
- no unnecessarily complex permanent account-lockout scheme.

Client address is taken from the server-populated request client, not
user-supplied forwarding headers. Deployments behind a TLS-terminating proxy
must configure trusted proxy handling (for example uvicorn
`--proxy-headers` with a pinned `--forwarded-allow-ips`).

## Administrator invariant

There must always be at least one enabled, non-deleted ADMIN.

Disable/delete/demotion operations that would leave zero administrators are rejected transactionally.

## Actor context

Application services receive explicit actor context.

```python
class ActorContext(BaseModel):
    actor_id: UUID
    username: str
    display_name: str | None
    role: UserRole
```

Scheduled monitor investigations execute as SYSTEM while preserving who created/initiated the monitor.

Agents are not represented as fake human users.

## Authorization

Authorization is enforced in backend application/API layers, not merely in the frontend.

## Audit

Audit records answer:

- who;
- did what;
- to which object;
- when;
- from which execution context;
- with what outcome.

```python
class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
```

AuditEvent is append-only.

Stable action URNs cover authentication, user administration, investigation lifecycle, monitor lifecycle, finding workflow, and system/security configuration changes. The currently implemented vocabulary is:

| Action | URN |
|---|---|
| Login | `urn:ati:action:auth:login` |
| Logout | `urn:ati:action:auth:logout` |
| CSRF rejected | `urn:ati:action:auth:csrf_rejected` |
| Create user | `urn:ati:action:user:create` |
| Change password | `urn:ati:action:user:change_password` |
| Update user | `urn:ati:action:user:update` |
| Disable user | `urn:ati:action:user:disable` |
| Delete user | `urn:ati:action:user:delete` |

Additional category URNs are added only when their flows are implemented.

DENIED means an authenticated actor lacked permission.

FAILURE means a permitted operation failed.

## Audit data minimization

Audit metadata must never contain:

- passwords;
- session tokens;
- API keys;
- authorization headers;
- raw provider payloads;
- secret-bearing prompts;
- hidden chain-of-thought.

Metadata keys are checked recursively. Accepted JSON metadata is defensively
snapshotted and recursively immutable after event validation.

## LLM/tool security

LLMs cannot directly access arbitrary HTTP, SQL, shell, or Python execution.

External access is through explicit typed tools/provider adapters.

LLMs do not receive unrestricted database access.

Structured outputs are validated before application actions.

Pivot targets must already exist as root/discovered entities and must pass deterministic policy.

The Evidence Analyst (PR 20B) has **no tools at all**: no provider,
filesystem, shell, HTTP, or database surface is exposed to the model. All
model output is schema-validated Pydantic and all resource references are
deterministically revalidated against authoritative persisted state before
any Assessment can persist. LLM errors are bounded and content-free and
carry no raw provider/framework cause: prompts, raw model output, raw
provider exception text, and credentials never appear in error messages,
``LlmError.__cause__``, or Investigation/audit/timeline state. No
chain-of-thought or raw model output is ever persisted. Structured-output
retries are explicit, hard-limited to ``1..2`` attempts, require a
retryable ``INVALID_STRUCTURED_OUTPUT`` error, and each actual invocation is
counted against the Investigation LLM budget. Automatic content-bearing
LangSmith/LangChain tracing is disabled for Evidence Analyst calls; safe
operation metadata alone does not export prompts, Evidence facts, or model
output.

## Prompt injection

Evidence and retrieved research are untrusted content.

System instructions explicitly tell models not to follow instructions contained in evidence/documents.

Prefer normalized evidence facts over raw provider payloads in model context.
The Evidence Analyst system prompt states that evidence content is data, not
instructions, and the analyst input DTO excludes raw payloads entirely; only
normalized facts and stable source metadata reach the model. The analyst has
no tools, so no instruction embedded in evidence text can trigger any
provider, shell, HTTP, or database action. Deterministic adversarial
formatting tests treat injected instructions as ordinary data; behavioral
robustness scoring is PR 20C.

## Secrets

Local v0.1 secrets are provided through environment-based configuration.

`.env` is not committed.

`.env.example` documents required variables without real credentials.

Secrets are injected through application configuration/provider construction rather than scattered `os.getenv` calls.

## Container security

ATI-owned containers run as non-root where practical.

ATI does not require:

- privileged containers;
- Podman socket access;
- host networking;
- arbitrary host mounts;
- unnecessary Linux capabilities.

Only required host ports are exposed.

## Automated security scanning

ATI runs four Python security tools through `./build.sh --sec`:

| Tool | Type | Scope |
|---|---|---|
| Bandit | Static analysis (SAST) | Production code (`src`) only; tests are excluded because they intentionally carry synthetic credentials and asserts |
| Semgrep | Static analysis (SAST), `p/ci` ruleset | Production code (`src`) |
| Safety | Dependency vulnerability scan (SCA) | Full Python environment, including dev/test tooling |
| pip-audit | Dependency vulnerability scan (SCA) | Full Python environment, including dev/test tooling |

Gate policy:

- `./build.sh --sec` runs as a dedicated, mandatory `security` CI gate on
  every pull request, in parallel with the quality and integration gates,
  and must pass before a PR can be merged.
- Running the security scans locally is not required after ordinary code
  changes; the CI gate is the enforcement point.
- Unlike the ordinary validation gates, the security gate requires network
  access (Semgrep registry rulesets and vulnerability databases) and is a
  deliberate exception to the offline-CI principle for test validation.

Suppression governance:

- Every suppression must carry an explicit, documented justification at the
  suppression site (inline `# nosec` with reason) or in configuration
  (`[tool.bandit]` skip list in `pyproject.toml`).
- `B101` (assert) is globally skipped in Bandit with documented rationale:
  asserts in production code are internal invariant checks used for
  strict-Mypy control-flow narrowing, not security controls.
- Suppressions must be re-justified when the surrounding code changes; the
  security gate must never be weakened merely to make it pass.

Currently accepted risk:

- `nltk` PYSEC-2026-3740 is ignored in `build.sh` (`pip-audit
  --ignore-vuln`). It is a transitive, test-only dependency of the Safety
  scanner itself; ATI production code does not import it, and no fixed
  release exists on PyPI. This ignore must be re-evaluated when Safety ships
  a fixed `nltk` bound.

## Data deletion

Persistent application/domain records use soft deletion.

Immutable evidence/audit observations normally cannot be deleted through ordinary application operations.

## Geolocation safety

The UI and reports describe IP geolocation as approximate. It must not be represented as physical identification of an attacker or device.

## Future external identity

The domain User model is designed so a future external identity mapping can reference the same user concept without changing domain ownership/audit semantics. External identity integration is not part of v0.1.

## Secret resolution and artifact URIs

ATI abstracts secret retrieval through `SecretsResolver`; v0.1 provides only `EnvVarSecretsResolver`. Secrets are resolved at application bootstrap and must not be logged, committed to profile modules, persisted in investigation data, or embedded in artifact URIs. Providers receive only the credentials they require.


## Secret-handling rules

The following rules apply to configuration, providers, storage, and future acquisition components:

- `SecretsResolver` is the abstraction for secret retrieval.
- `EnvVarSecretsResolver` is the only required v0.1 implementation.
- Configuration profiles contain secret reference names, not secret values.
- Secret resolution occurs during bootstrap/composition.
- Providers should receive resolved credentials rather than a `SecretsResolver`.
- Missing required secrets fail startup clearly.
- Resolved secret values must not be logged, included in effective-configuration dumps, persisted in evidence/history/audit/timeline data, or exposed in errors.
- Artifact URIs identify locations only and must never embed credentials.
- Redaction is defense in depth; code must not rely on redaction as permission to place secrets into ordinary configuration/log structures.

## AbuseIPDB credential and data minimization

The AbuseIPDB provider follows the shared secret-handling rules with the
following specifics:

- The `abuseipdb_api_key_secret` setting contains only the NAME of the
  environment variable carrying the API key, never a key value.
- Composition resolves the key through `SecretsResolver` during
  bootstrap and injects the resolved value into the provider; the
  provider never reads configuration or the environment.
- The key is sent only in the custom `Key` request header. It is never
  placed in a URL, query string, log, error message, evidence fact,
  persistence record, or test fixture.
- Response bodies are never copied into provider error messages.
- Report comments and reporter metadata (reporter IDs and reporter
  countries) are discarded during normalization and never retained.
- Raw verbose response payloads are not retained (`raw_payload=None`).
- Automated tests are synthetic (ATI-authored in-process responses) and
  cannot contact the real AbuseIPDB service.

## ThreatFox credential and data minimization

The ThreatFox provider follows the shared secret-handling rules with the
following specifics:

- The `threatfox_auth_key_secret` setting contains only the NAME of the
  environment variable carrying the abuse.ch Auth-Key, never a key
  value.
- Composition resolves the key through `SecretsResolver` during
  bootstrap and injects the resolved value into the provider; the
  provider never reads configuration or the environment.
- The key is sent only in the custom `Auth-Key` request header. It is
  never placed in a URL, request body, log, error message, evidence
  fact, persistence record, or test fixture.
- Response bodies are never copied into provider error messages.
- Reporter metadata, comments, credits, and malware-sample metadata are
  discarded during normalization and never retained; reference and
  Malpedia URLs are validated but never fetched.
- Raw response payloads are not retained (`raw_payload=None`).
- The provider never instantiates discovered entities and never creates
  relationship candidates; normalized `matches` facts are the handoff
  contract for PR 18B's deterministic extractor.
- Automated tests are synthetic (ATI-authored in-process responses over
  the real ATI provider/HTTP stack) and cannot contact the real
  ThreatFox service. There is no live or opt-in live ThreatFox test.

## URLhaus credential and data minimization

The URLhaus provider follows the shared secret-handling rules with the
following specifics:

- The `urlhaus_auth_key_secret` setting contains only the NAME of the
  environment variable carrying the abuse.ch Auth-Key, never a key
  value.
- Composition resolves the key through `SecretsResolver` during
  bootstrap and injects the resolved value into the provider; the
  provider never reads configuration or the environment.
- The key is sent only in the custom `Auth-Key` request header. It is
  never placed in a URL, form body, log, error message, evidence fact,
  persistence record, or test fixture.
- Response bodies are never copied into provider error messages.
- Reporter metadata, blacklist details, `urlhaus_reference` links,
  `larted`, `takedown_time_seconds`, and payload download locations
  (`urlhaus_download`) are discarded during normalization and never
  retained; no returned URL is ever fetched and no payload is ever
  downloaded.
- Raw response payloads are not retained (`raw_payload=None`).
- The provider never instantiates discovered entities and never creates
  relationship candidates; normalized `matches` facts are the handoff
  contract for PR 18B's deterministic extractor. Payload hashes and
  signatures remain fact-only source data and never become entities or
  malware attributions.
- Automated tests are synthetic (ATI-authored in-process responses over
  the real ATI provider/HTTP stack against a virtual
  `urlhaus-api.abuse.ch` ASGI upstream) and cannot contact the real
  URLhaus service. There is no live or opt-in live URLhaus test.
