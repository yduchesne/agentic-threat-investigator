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

## CSRF

Because v0.1 uses cookie authentication, state-changing requests require CSRF protection.

Use SameSite plus Origin/Referer validation and a CSRF token strategy.

## Login protection

- generic login failure message;
- bounded rate limiting;
- no username-enumeration disclosure;
- audit success/failure;
- normalized usernames;
- no unnecessarily complex permanent account-lockout scheme.

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

## LLM/tool security

LLMs cannot directly access arbitrary HTTP, SQL, shell, or Python execution.

External access is through explicit typed tools/provider adapters.

LLMs do not receive unrestricted database access.

Structured outputs are validated before application actions.

Pivot targets must already exist as root/discovered entities and must pass deterministic policy.

## Prompt injection

Evidence and retrieved research are untrusted content.

System instructions explicitly tell models not to follow instructions contained in evidence/documents.

Prefer normalized evidence facts over raw provider payloads in model context.

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
