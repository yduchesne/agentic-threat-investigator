# SPDX-License-Identifier: AGPL-3.0-only
"""Application services and security adapters for local identity."""

# pylint: disable=too-few-public-methods,too-many-instance-attributes,too-many-arguments,too-many-positional-arguments,line-too-long
import hashlib
import secrets
from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from argon2 import PasswordHasher as ArgonPasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from agentic_threat_investigator.app.audit import (
    AuditEmitter,
    TransactionalAuditEmitter,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditOutcome,
)
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
        """Verify a password."""


class Argon2idPasswordHasher(PasswordHasher):
    """Argon2id adapter; plaintext is never retained by this service."""

    def __init__(self) -> None:
        self._hasher = ArgonPasswordHasher()

    def hash(self, password: str) -> str:
        """Create an Argon2id hash."""
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
        """Allow an attempt."""


class InMemoryRateLimiter(RateLimiter):
    """Small bounded sliding-window limiter for a single API process."""

    def __init__(
        self, maximum: int = 5, window: timedelta = timedelta(minutes=1)
    ) -> None:
        if maximum < 1 or window.total_seconds() <= 0:
            raise ValueError("invalid rate limiter settings")
        self.maximum, self.window = maximum, window
        self._attempts: OrderedDict[str, deque[datetime]] = OrderedDict()

    def allow(self, key: str, *, now: datetime | None = None) -> bool:
        """Allow at most maximum attempts in the configured window."""
        current = now or datetime.now(timezone.utc)
        attempts = self._attempts.get(key)
        if attempts is None:
            attempts = deque(maxlen=self.maximum)
            self._attempts[key] = attempts
        while attempts and current - attempts[0] >= self.window:
            attempts.popleft()
        allowed = len(attempts) < self.maximum
        if allowed:
            attempts.append(current)
        if not attempts:
            self._attempts.pop(key, None)
        elif key in self._attempts:
            self._attempts.move_to_end(key)

        # The oldest key can only be reclaimed when its newest attempt has
        # left the window.  Touching keys moves them to the back, making this
        # an amortized O(1) idle-key sweep.
        while self._attempts:
            oldest_key, oldest_attempts = next(iter(self._attempts.items()))
            if oldest_attempts and current - oldest_attempts[-1] < self.window:
                break
            self._attempts.pop(oldest_key)
        return allowed


class NullAuditEmitter(AuditEmitter):
    """No-op emitter retained for database-free callers."""

    async def emit(
        self,
        action: str | AuditAction,
        outcome: str | AuditOutcome,
        actor: ActorContext | None = None,
        **kwargs: object,
    ) -> None:
        """Discard an event."""


class AuthenticationError(Exception):
    """Generic authentication failure suitable for HTTP responses."""


class RateLimitedError(AuthenticationError):
    """Login refused by the bounded rate limiter."""


class CsrfError(ValueError):
    """Raised when a state-changing request lacks a valid CSRF proof."""


def _normalized_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP origin, or ``None`` for an invalid URL."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if not parsed.scheme or not hostname:
            return None
        if parsed.port is not None:
            port = parsed.port
        elif parsed.scheme.lower() == "http":
            port = 80
        elif parsed.scheme.lower() == "https":
            port = 443
        else:
            return None
    except ValueError:
        return None
    return parsed.scheme.lower(), hostname.lower(), port


def validate_csrf(
    cookie_token: str | None,
    request_token: str | None,
    origin: str | None,
    referer: str | None,
    expected_origin: str,
) -> None:
    """Validate double-submit CSRF tokens and same-origin metadata."""
    if (
        not cookie_token
        or not request_token
        or not secrets.compare_digest(cookie_token, request_token)
    ):
        raise CsrfError("invalid csrf token")
    supplied = origin or referer
    expected = _normalized_origin(expected_origin)
    supplied_origin = _normalized_origin(supplied) if supplied else None
    if expected is None or supplied_origin is None or supplied_origin != expected:
        raise CsrfError("invalid request origin")


class AuthenticationService:
    """Coordinate password verification and server-side session lifecycle."""

    FAILURE_MESSAGE = "Invalid username or password."

    def __init__(
        self,
        unit_of_work_factory: Callable[[], UnitOfWork],
        hasher: PasswordHasher,
        tokens: SessionTokenService,
        limiter: RateLimiter,
        audit: AuditEmitter,
        session_lifetime: timedelta = timedelta(hours=8),
        idle_timeout: timedelta | None = None,
    ) -> None:
        self._factory, self.hasher, self.tokens, self.limiter = (
            unit_of_work_factory,
            hasher,
            tokens,
            limiter,
        )
        self.audit, self.session_lifetime, self.idle_timeout = (
            audit,
            session_lifetime,
            idle_timeout,
        )
        self._dummy_hash = hasher.hash("ati-login-timing-equalizer")

    async def login(
        self, username: str, password: str, *, client_address: str | None = None
    ) -> tuple[User, str]:
        """Authenticate, then atomically create a session and success audit."""
        normalized = normalize_username(username)
        if not self.limiter.allow(f"{normalized}|{client_address or 'unknown'}"):
            await self.audit.emit(AuditAction.AUTH_LOGIN, AuditOutcome.FAILURE)
            raise RateLimitedError(self.FAILURE_MESSAGE)
        async with self._factory() as read_uow:
            user = await read_uow.users.get_by_username(normalized)
            credential = (
                None
                if user is None
                else await read_uow.credentials.get_by_user_id(user.id)
            )
        password_ok = self.hasher.verify(
            credential.password_hash if credential is not None else self._dummy_hash,
            password,
        )
        valid = (
            user is not None
            and password_ok
            and user.enabled
            and user.deleted_at is None
            and credential is not None
        )
        if not valid:
            await self.audit.emit(AuditAction.AUTH_LOGIN, AuditOutcome.FAILURE)
            raise AuthenticationError(self.FAILURE_MESSAGE)
        assert user is not None
        now = datetime.now(timezone.utc)
        token, digest = self.tokens.issue()
        session = Session(
            user_id=user.id,
            token_hash=digest,
            created_at=now,
            expires_at=now + self.session_lifetime,
            last_seen_at=now,
        )
        async with self._factory() as write_uow:
            await write_uow.sessions.create(session)
            await TransactionalAuditEmitter(write_uow).emit(
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
        """Revoke a known session and atomically record its logout."""
        digest = self.tokens.hash(token)
        async with self._factory() as uow:
            session = await uow.sessions.get_by_token_hash(digest)
            if session is None:
                await self.audit.emit(AuditAction.AUTH_LOGOUT, AuditOutcome.SUCCESS)
                return
            user = await uow.users.get_by_id(session.user_id)
            await uow.sessions.revoke_by_token_hash(digest)
            actor = (
                None
                if user is None
                else ActorContext(
                    actor_id=user.id,
                    username=user.username,
                    display_name=user.display_name,
                    role=user.role,
                )
            )
            await TransactionalAuditEmitter(uow).emit(
                AuditAction.AUTH_LOGOUT, AuditOutcome.SUCCESS, actor
            )

    async def validate_session(self, token: str) -> User | None:
        """Validate expiry, revocation, and user state in one transaction."""
        async with self._factory() as uow:
            session = await uow.sessions.get_by_token_hash(self.tokens.hash(token))
            if session is None or session.revoked_at is not None:
                return None
            now = datetime.now(timezone.utc)
            if session.expires_at <= now or (
                self.idle_timeout is not None
                and session.last_seen_at + self.idle_timeout <= now
            ):
                await uow.sessions.revoke(session.id)
                return None
            user = await uow.users.get_by_id(session.user_id)
            if user is None or not user.enabled or user.deleted_at is not None:
                await uow.sessions.revoke(session.id)
                return None
            await uow.sessions.touch(session.id, now)
            return user
