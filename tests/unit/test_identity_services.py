"""Deterministic tests for local authentication security primitives."""

# Test doubles intentionally implement narrow async repository seams.
# pylint: disable=missing-class-docstring,missing-function-docstring,too-few-public-methods,unused-argument,not-callable,not-an-iterable

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from agentic_threat_investigator.app.identity import (
    Argon2idPasswordHasher,
    AuthenticationError,
    AuthenticationService,
    CsrfError,
    InMemoryRateLimiter,
    SessionTokenService,
    normalize_username,
    validate_csrf,
)
from agentic_threat_investigator.domain.identity import (
    Credential,
    Session,
    User,
    UserRole,
)


class Users:
    def __init__(self, user: User | None = None) -> None:
        self.user = user

    async def get_by_username(self, name: str) -> User | None:
        return self.user if self.user and self.user.username == name else None

    async def get_by_id(self, ident: UUID) -> User | None:
        return self.user if self.user and self.user.id == ident else None


class Credentials:
    def __init__(self, credential: Credential | None) -> None:
        self.credential = credential

    async def get_by_user_id(self, ident: UUID) -> Credential | None:
        return self.credential


class Sessions:
    def __init__(self) -> None:
        self.sessions: dict[bytes, Session] = {}
        self.revoked: set[UUID] = set()

    async def create(self, session: Session) -> None:
        self.sessions[session.token_hash] = session

    async def get_by_token_hash(self, digest: bytes) -> Session | None:
        return next((s for s in self.sessions.values() if s.token_hash == digest), None)

    async def revoke(self, ident: UUID) -> None:
        self.revoked.add(ident)

    async def revoke_by_token_hash(self, digest: bytes) -> None:
        session = await self.get_by_token_hash(digest)
        if session:
            self.revoked.add(session.id)

    async def touch(self, ident: UUID, seen: datetime) -> None:
        return None


@pytest.mark.asyncio
async def test_authentication_lifecycle_and_failures() -> None:
    now = datetime.now(timezone.utc)
    user = User(username="alice", role=UserRole.ADMIN, created_at=now, updated_at=now)
    hasher = Argon2idPasswordHasher()
    users, sessions = Users(user), Sessions()
    credentials = Credentials(
        Credential(
            user_id=user.id,
            password_hash=hasher.hash("secret"),
            password_changed_at=now,
        )
    )
    service = AuthenticationService(
        users,
        credentials,
        sessions,
        hasher,
        SessionTokenService(),
        InMemoryRateLimiter(),
    )
    logged_in, token = await service.login(" ALICE ", "secret")
    assert logged_in.id == user.id
    with pytest.raises(AuthenticationError):
        await service.login("alice", "wrong")
    session = next(iter(sessions.sessions.values()))
    assert await service.validate_session(token)
    await service.logout(token)
    assert session.id in sessions.revoked


@pytest.mark.asyncio
async def test_expired_session_is_rejected() -> None:
    now = datetime.now(timezone.utc)
    user = User(username="a", created_at=now, updated_at=now)
    sessions = Sessions()
    token_service = SessionTokenService()
    token, digest = token_service.issue()
    old = Session(
        user_id=user.id,
        token_hash=digest,
        created_at=now,
        expires_at=now - timedelta(seconds=1),
        last_seen_at=now,
    )
    sessions.sessions[digest] = old
    service = AuthenticationService(
        Users(user),
        Credentials(None),
        sessions,
        Argon2idPasswordHasher(),
        token_service,
        InMemoryRateLimiter(),
    )
    assert await service.validate_session(token) is None
    assert await service.validate_session("missing") is None
    limited = AuthenticationService(
        Users(user),
        Credentials(None),
        sessions,
        Argon2idPasswordHasher(),
        token_service,
        InMemoryRateLimiter(1),
    )
    with pytest.raises(AuthenticationError):
        await limited.login("a", "bad")
    with pytest.raises(AuthenticationError):
        await limited.login("a", "bad")


def test_security_helpers() -> None:
    with pytest.raises(ValueError):
        Argon2idPasswordHasher().hash("")
    with pytest.raises(ValueError):
        SessionTokenService().issue(128)
    with pytest.raises(ValueError):
        InMemoryRateLimiter(0)
    assert normalize_username("  Alice   Smith ") == "alice smith"
    token, digest = SessionTokenService().issue()
    assert len(digest) == 32 and token
    limiter = InMemoryRateLimiter(1)
    assert limiter.allow("x") is True and limiter.allow("x") is False
    assert (
        limiter.allow("x", now=datetime.now(timezone.utc) + timedelta(minutes=2))
        is True
    )
    validate_csrf("x", "x", "https://ati", None, "https://ati")
    with pytest.raises(CsrfError):
        validate_csrf("x", "y", "https://ati", None, "https://ati")
    assert Argon2idPasswordHasher().verify("not-a-hash", "x") is False
