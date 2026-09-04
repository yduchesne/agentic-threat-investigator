# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for rate limiting, CSRF validation, and session edge paths."""

# Fakes expose narrow async repository seams; rate-limiter internals are the
# object under test for the memory-bound assertions.
# pylint: disable=too-few-public-methods,protected-access,unused-argument,use-implicit-booleaness-not-comparison

from datetime import UTC, datetime, timedelta, timezone
from typing import Any, cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.audit import InMemoryAuditEmitter
from agentic_threat_investigator.app.identity import (
    Argon2idPasswordHasher,
    AuthenticationService,
    CsrfError,
    InMemoryRateLimiter,
    SessionTokenService,
    validate_csrf,
)
from agentic_threat_investigator.domain.identity import Credential, Session, User


class _Users:
    """User repository double returning one optional user."""

    def __init__(self, user: User | None) -> None:
        self.user = user

    async def get_by_username(self, name: str) -> User | None:
        """Return the user when the username matches."""
        return self.user if self.user and self.user.username == name else None

    async def get_by_id(self, ident: UUID) -> User | None:
        """Return the user by identity."""
        return self.user if self.user and self.user.id == ident else None


class _Credentials:
    """Credential repository double."""

    def __init__(self, credential: Credential | None) -> None:
        self.credential = credential

    async def get_by_user_id(self, ident: UUID) -> Credential | None:
        """Return the configured credential."""
        return self.credential


class _Sessions:
    """Session repository double storing sessions by digest."""

    def __init__(self) -> None:
        self._by_digest: dict[bytes, Session] = {}
        self.revoked: set[UUID] = set()
        self.touched: list[UUID] = []

    async def create(self, session: Session) -> None:
        """Store one session."""
        self._by_digest[session.token_hash] = session

    async def get_by_token_hash(self, digest: bytes) -> Session | None:
        """Find one session by digest."""
        return self._by_digest.get(digest)

    async def revoke(self, ident: UUID) -> None:
        """Record one revocation by id."""
        self.revoked.add(ident)

    async def revoke_by_token_hash(self, digest: bytes) -> None:
        """Record one revocation by digest."""
        self.revoked.update(
            session.id
            for session in self._by_digest.values()
            if session.token_hash == digest
        )

    async def touch(self, ident: UUID, seen: datetime) -> None:
        """Record one touch."""
        self.touched.append(ident)


def _service(
    users: _Users, sessions: _Sessions, limiter: InMemoryRateLimiter | None = None
) -> AuthenticationService:
    """Build the service through its explicit UnitOfWork factory."""

    class _UoW:
        def __init__(self) -> None:
            self.users = users
            self.credentials = _Credentials(None)
            self.sessions = sessions
            self.audit_events: Any = None

        async def __aenter__(self) -> "_UoW":
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    return AuthenticationService(
        cast(Any, _UoW),
        Argon2idPasswordHasher(),
        SessionTokenService(),
        limiter or InMemoryRateLimiter(),
        InMemoryAuditEmitter(),
    )


def test_rate_limiter_is_a_bounded_sliding_window() -> None:
    """The limiter allows at most the maximum within one window."""

    limiter = InMemoryRateLimiter(2, timedelta(minutes=1))
    start = datetime(2026, 1, 1, tzinfo=UTC)

    assert limiter.allow("key", now=start)
    assert limiter.allow("key", now=start + timedelta(seconds=1))
    assert not limiter.allow("key", now=start + timedelta(seconds=2))

    later = start + timedelta(minutes=1, seconds=1)
    assert limiter.allow("key", now=later)


def test_rate_limiter_evicts_expired_and_idle_keys() -> None:
    """Expired attempts fall out and idle keys are swept from memory."""

    limiter = InMemoryRateLimiter(1, timedelta(seconds=10))
    start = datetime(2026, 1, 1, tzinfo=UTC)

    assert limiter.allow("a", now=start)
    assert not limiter.allow("a", now=start + timedelta(seconds=1))

    # "a" is idle beyond the window when "b" arrives, so the sweep reclaims it.
    later = start + timedelta(seconds=11)
    assert limiter.allow("b", now=later)
    assert "a" not in limiter._attempts
    assert list(limiter._attempts) == ["b"]

    # "a" was reclaimed, so it starts a fresh window instead of staying locked.
    assert limiter.allow("a", now=later)


def test_rate_limiter_bounds_rejected_attempt_memory() -> None:
    """Repeated rejections never grow per-key state beyond the maximum."""

    limiter = InMemoryRateLimiter(1, timedelta(minutes=10))
    start = datetime(2026, 1, 1, tzinfo=UTC)

    assert limiter.allow("key", now=start)
    for second in range(1, 25):
        assert not limiter.allow("key", now=start + timedelta(seconds=second))
    assert len(limiter._attempts["key"]) == 1


def test_rate_limiter_rejects_invalid_settings() -> None:
    """Zero or negative limits and windows are refused."""
    with pytest.raises(ValueError, match="invalid rate limiter settings"):
        InMemoryRateLimiter(0, timedelta(seconds=1))
    with pytest.raises(ValueError, match="invalid rate limiter settings"):
        InMemoryRateLimiter(1, timedelta(seconds=0))


def test_csrf_requires_matching_double_submit_tokens() -> None:
    """Missing, empty, or mismatched tokens are rejected."""
    origin = "http://localhost:8000"
    for cookie, header in [(None, "x"), ("", "x"), ("cookie", "header")]:
        with pytest.raises(CsrfError, match="invalid csrf token"):
            validate_csrf(cookie, header, origin, None, origin)


def test_csrf_accepts_same_origin_with_default_ports() -> None:
    """Same-origin requests pass with any port spelling."""
    validate_csrf("t", "t", "http://host", None, "http://host")
    validate_csrf("t", "t", "https://host", None, "https://host")
    validate_csrf("t", "t", "https://host:443", None, "https://host")
    validate_csrf(
        "t", "t", None, "http://localhost:8000/settings", "http://localhost:8000"
    )


def test_csrf_accepts_matching_explicit_ports() -> None:
    """Explicit ports match only when both origins agree."""
    validate_csrf("t", "t", "http://host:8443", None, "http://host:8443")
    with pytest.raises(CsrfError, match="invalid request origin"):
        validate_csrf("t", "t", "http://host:8443", None, "http://host")


def test_csrf_rejects_mismatched_origins() -> None:
    """A different origin is rejected even with valid CSRF tokens."""
    with pytest.raises(CsrfError, match="invalid request origin"):
        validate_csrf("t", "t", "https://evil.example", None, "http://localhost:8000")
    with pytest.raises(CsrfError, match="invalid request origin"):
        validate_csrf("t", "t", None, None, "http://localhost:8000")


def test_csrf_rejects_malformed_origins() -> None:
    """Origins without scheme/host or with invalid ports never pass."""
    malformed = [
        "//host",
        "http://",
        "ftp://host",
        "http://host:bad",
        "http://host:99999999",
    ]
    for value in malformed:
        with pytest.raises(CsrfError, match="invalid request origin"):
            validate_csrf("t", "t", "http://host", None, value)
    for value in malformed:
        with pytest.raises(CsrfError, match="invalid request origin"):
            validate_csrf("t", "t", value, None, "http://host")


@pytest.mark.asyncio
async def test_logout_of_unknown_token_audits_success() -> None:
    """Logging out an unknown token still records a success event."""
    sessions = _Sessions()
    service = _service(_Users(None), sessions)

    await service.logout("unknown-token")

    assert sessions._by_digest == {}


@pytest.mark.asyncio
async def test_validate_session_revokes_for_disabled_users() -> None:
    """Disabled users lose their sessions immediately."""
    now = datetime.now(timezone.utc)
    user = User(username="a", enabled=False, created_at=now, updated_at=now)
    sessions = _Sessions()
    token, digest = SessionTokenService().issue()
    active = Session(
        user_id=user.id,
        token_hash=digest,
        created_at=now,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
    )
    await sessions.create(active)
    service = _service(_Users(user), sessions)

    assert await service.validate_session(token) is None
    assert active.id in sessions.revoked


@pytest.mark.asyncio
async def test_revoked_session_is_never_revalidated() -> None:
    """Revoked sessions never revalidate or get touched."""
    now = datetime.now(timezone.utc)
    user = User(username="a", created_at=now, updated_at=now)
    sessions = _Sessions()
    token, digest = SessionTokenService().issue()
    session = Session(
        user_id=user.id,
        token_hash=digest,
        created_at=now,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
        revoked_at=now,
    )
    await sessions.create(session)
    service = _service(_Users(user), sessions)

    assert await service.validate_session(token) is None
    assert session.id not in sessions.touched


@pytest.mark.asyncio
async def test_session_tokens_require_minimum_entropy() -> None:
    """Token issuance below 256 bits is refused."""
    with pytest.raises(ValueError, match="256 bits"):
        SessionTokenService().issue(bits=128)


def test_password_hasher_rejects_empty_passwords() -> None:
    """Hashing refuses empty passwords."""
    with pytest.raises(ValueError, match="empty"):
        Argon2idPasswordHasher().hash("")


def test_password_hasher_verify_rejects_malformed_hashes() -> None:
    """Verification never raises for malformed stored hashes."""
    assert not Argon2idPasswordHasher().verify("not-a-hash", "secret")


def test_service_wiring_accepts_unit_of_work_factories() -> None:
    """The explicit factory constructor path wires all collaborators."""

    class _UoW:
        """Minimal UoW double satisfying the constructor contract."""

        def __init__(self) -> None:
            self.users: Any = _Users(None)
            self.credentials: Any = _Credentials(None)
            self.sessions: Any = _Sessions()
            self.audit_events: Any = _Sessions()

        async def __aenter__(self) -> "_UoW":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    uow = _UoW()
    service = AuthenticationService(
        cast(Any, lambda: uow),
        Argon2idPasswordHasher(),
        SessionTokenService(),
        InMemoryRateLimiter(),
        InMemoryAuditEmitter(),
        session_lifetime=timedelta(hours=8),
    )

    assert service.session_lifetime == timedelta(hours=8)
    assert service.idle_timeout is None
