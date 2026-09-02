# Agentic Threat Investigator — Security Design

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

Stable action URNs cover authentication, user administration, investigation lifecycle, monitor lifecycle, finding workflow, and system/security configuration changes.

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
- Docker socket access;
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
