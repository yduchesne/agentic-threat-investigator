# SPDX-License-Identifier: AGPL-3.0-only
"""Application services and security adapters for local identity."""

# Security ports intentionally have one operation; dependencies are explicit seams.
# pylint: disable=too-few-public-methods,too-many-instance-attributes,too-many-arguments,too-many-positional-arguments,line-too-long

import hashlib
import secrets
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher as ArgonPasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from agentic_threat_investigator.domain.audit import AuditAction, AuditOutcome
from agentic_threat_investigator.domain.identity import ActorContext, Session, User


def normalize_username(username: str) -> str:
    """Return the canonical username used for lookup and uniqueness."""
    return " ".join(username.strip().split()).casefold()


class PasswordHasher(ABC):
    """Port for a memory-hard password hashing implementation."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """Hash a password."""

    @abstractmethod
    def verify(self, password_hash: str, password: str) -> bool:
        """Verify a password without revealing hash details."""


class Argon2idPasswordHasher(PasswordHasher):
    """Argon2id adapter; plaintext is never retained by this service."""

    def __init__(self) -> None:
        self._hasher = ArgonPasswordHasher()

    def hash(self, password: str) -> str:
        """Create a maintained-library Argon2id hash."""
        if not password:
            raise ValueError("password must not be empty")
        return self._hasher.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        """Return false for malformed or non-matching hashes."""
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


class SessionTokenService:
    """Create opaque tokens and expose only their SHA-256 database digest."""

    def issue(self, bits: int = 256) -> tuple[str, bytes]:
        """Return a URL-safe token and its digest."""
        if bits < 256:
            raise ValueError("session tokens must contain at least 256 bits")
        token = secrets.token_urlsafe((bits + 7) // 8)
        return token, self.hash(token)

    @staticmethod
    def hash(token: str) -> bytes:
        """Hash a token for persistence or lookup."""
        return hashlib.sha256(token.encode("utf-8")).digest()


class RateLimiter(ABC):
    """Port for bounded authentication attempt limiting."""

    @abstractmethod
    def allow(self, key: str, *, now: datetime | None = None) -> bool:
        """Record an attempt and say whether it is allowed."""


class InMemoryRateLimiter(RateLimiter):
    """Small bounded sliding-window limiter for a single API process."""

    def __init__(
        self, maximum: int = 5, window: timedelta = timedelta(minutes=1)
    ) -> None:
        if maximum < 1 or window.total_seconds() <= 0:
            raise ValueError("invalid rate limiter settings")
        self.maximum, self.window = maximum, window
        self._attempts: dict[str, deque[datetime]] = defaultdict(deque)

    def allow(self, key: str, *, now: datetime | None = None) -> bool:
        """Allow at most maximum attempts in the configured window."""
        current = now or datetime.now(timezone.utc)
        attempts = self._attempts[key]
        while attempts and current - attempts[0] >= self.window:
            attempts.popleft()
        allowed = len(attempts) < self.maximum
        attempts.append(current)
        return allowed


class AuditEmitter(ABC):
    """Structured audit seam, intentionally independent of persistence."""

    @abstractmethod
    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        **kwargs: object,
    ) -> None:
        """Emit a minimized security event."""


class NullAuditEmitter(AuditEmitter):
    """No-op emitter used by database-free contexts."""

    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        **kwargs: object,
    ) -> None:
        """Accept an event without recording secrets or credentials."""


class AuthenticationError(Exception):
    """Generic authentication failure deliberately suitable for HTTP responses."""


class CsrfError(ValueError):
    """Raised when a state-changing request lacks a valid CSRF proof."""


def validate_csrf(
    cookie_token: str | None,
    request_token: str | None,
    origin: str | None,
    referer: str | None,
    expected_origin: str,
) -> None:
    """Validate double-submit CSRF tokens and same-origin navigation metadata."""
    if (
        not cookie_token
        or not request_token
        or not secrets.compare_digest(cookie_token, request_token)
    ):
        raise CsrfError("invalid csrf token")
    supplied = origin or referer
    if not supplied or supplied.rstrip("/") != expected_origin.rstrip("/"):
        raise CsrfError("invalid request origin")


class AuthenticationService:
    """Coordinate password verification and server-side session lifecycle."""

    FAILURE_MESSAGE = "Invalid username or password."

    def __init__(
        self,
        users: object,
        credentials: object,
        sessions: object,
        hasher: PasswordHasher,
        tokens: SessionTokenService,
        limiter: RateLimiter,
        audit: AuditEmitter | None = None,
        session_lifetime: timedelta = timedelta(hours=8),
        idle_timeout: timedelta | None = None,
    ) -> None:
        self.users, self.credentials, self.sessions = users, credentials, sessions
        self.hasher, self.tokens, self.limiter = hasher, tokens, limiter
        self.audit = audit or NullAuditEmitter()
        self.session_lifetime, self.idle_timeout = session_lifetime, idle_timeout

    async def login(self, username: str, password: str) -> tuple[User, str]:
        """Authenticate without disclosing whether a username exists."""
        normalized = normalize_username(username)
        if not self.limiter.allow(normalized):
            await self.audit.emit(AuditAction.AUTH_LOGIN, AuditOutcome.FAILURE)
            raise AuthenticationError(self.FAILURE_MESSAGE)
        user = await self.users.get_by_username(normalized)  # type: ignore[attr-defined]
        credential = None if user is None else await self.credentials.get_by_user_id(user.id)  # type: ignore[attr-defined]
        valid = (
            user is not None
            and user.enabled
            and user.deleted_at is None
            and credential is not None
            and self.hasher.verify(credential.password_hash, password)
        )
        if not valid:
            await self.audit.emit(AuditAction.AUTH_LOGIN, AuditOutcome.FAILURE)
            raise AuthenticationError(self.FAILURE_MESSAGE)
        now = datetime.now(timezone.utc)
        token, token_hash = self.tokens.issue()
        session = Session(
            user_id=user.id,
            token_hash=token_hash,
            created_at=now,
            expires_at=now + self.session_lifetime,
            last_seen_at=now,
        )
        await self.sessions.create(session)  # type: ignore[attr-defined]
        await self.audit.emit(
            AuditAction.AUTH_LOGIN,
            AuditOutcome.SUCCESS,
            ActorContext(
                actor_id=user.id,
                username=user.username,
                display_name=user.display_name,
                role=user.role,
            ),
        )
        return user, token

    async def logout(self, token: str) -> None:
        """Revoke the session represented by an opaque token."""
        await self.sessions.revoke_by_token_hash(self.tokens.hash(token))  # type: ignore[attr-defined]
        await self.audit.emit(AuditAction.AUTH_LOGOUT, AuditOutcome.SUCCESS)

    async def validate_session(self, token: str) -> User | None:
        """Validate expiry, revocation, and user state, updating last-seen."""
        session = await self.sessions.get_by_token_hash(self.tokens.hash(token))  # type: ignore[attr-defined]
        if session is None or session.revoked_at is not None:
            return None
        now = datetime.now(timezone.utc)
        if session.expires_at <= now or (
            self.idle_timeout and session.last_seen_at + self.idle_timeout <= now
        ):
            await self.sessions.revoke(session.id)  # type: ignore[attr-defined]
            return None
        user = await self.users.get_by_id(session.user_id)  # type: ignore[attr-defined]
        if user is None or not user.enabled or user.deleted_at is not None:
            await self.sessions.revoke(session.id)  # type: ignore[attr-defined]
            return None
        await self.sessions.touch(session.id, now)  # type: ignore[attr-defined]
        return user  # type: ignore[no-any-return]
