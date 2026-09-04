# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for user administration use cases and admin safety policy."""

# Test doubles intentionally expose narrow async repository seams; recorded
# empty sequences are asserted explicitly against the observed values.
# pylint: disable=too-few-public-methods,unused-argument,use-implicit-booleaness-not-comparison

from datetime import datetime, timezone
from typing import Any, cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.audit import InMemoryAuditEmitter
from agentic_threat_investigator.app.identity import PasswordHasher
from agentic_threat_investigator.app.user_administration import (
    AdministratorInvariantError,
    BootstrapAdminService,
    UserAdministrationService,
)
from agentic_threat_investigator.domain.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
)
from agentic_threat_investigator.domain.identity import ActorContext, User, UserRole


class StaticPasswordHasher(PasswordHasher):
    """Deterministic hasher double that avoids slow Argon2 rounds."""

    def hash(self, password: str) -> str:
        """Return a stable synthetic digest."""
        return f"hashed:{password}"

    def verify(self, password_hash: str, password: str) -> bool:
        """Verify against the synthetic digest format."""
        return password_hash == f"hashed:{password}"


class InMemoryAuditEvents:
    """Audit repository double capturing appended events."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        """Store one appended audit event."""
        self.events.append(event)
        return event


class FakeUsers:
    """User repository double with configurable counts."""

    def __init__(self, count: int = 0, enabled_admins: int = 0) -> None:
        self.count_value = count
        self.enabled_admins = enabled_admins
        self.created: list[User] = []

    async def count(self) -> int:
        """Return the configured total user count."""
        return self.count_value

    async def count_enabled_admins(self, *, excluding: UUID | None = None) -> int:
        """Return the configured enabled-administrator count."""
        return self.enabled_admins

    async def create(self, user: User) -> User:
        """Record one created user."""
        self.created.append(user)
        return user


class FakeCredentials:
    """Credential repository double recording writes."""

    def __init__(self) -> None:
        self.replaced: list[tuple[UUID, str]] = []

    async def create(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> None:
        """Accept one credential creation."""

    async def replace(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> None:
        """Record one credential replacement."""
        self.replaced.append((user_id, password_hash))


class FakeSessions:
    """Session repository double recording revocations."""

    def __init__(self) -> None:
        self.revoked_users: list[UUID] = []

    async def revoke_by_user_id(self, user_id: UUID) -> None:
        """Record one user-wide revocation."""
        self.revoked_users.append(user_id)


class FakeUnitOfWork:
    """Unit-of-work double exposing the identity repositories."""

    def __init__(self, users: FakeUsers) -> None:
        self.users = users
        self.credentials = FakeCredentials()
        self.sessions = FakeSessions()
        self.audit_events = InMemoryAuditEvents()

    async def __aenter__(self) -> "FakeUnitOfWork":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


def _uow_factory(uow: FakeUnitOfWork) -> Any:
    """Return a unit-of-work factory double for the services."""
    return lambda: uow


def _admin_actor(user_id: UUID) -> ActorContext:
    """Build an administrator actor context."""
    return ActorContext(actor_id=user_id, username="admin", role=UserRole.ADMIN)


@pytest.mark.asyncio
async def test_bootstrap_skips_without_credentials() -> None:
    """Bootstrap does nothing without a configured username and password."""
    users = FakeUsers()
    entered: list[bool] = []

    class TrackingUoW(FakeUnitOfWork):
        """UoW double tracking whether it was entered."""

        async def __aenter__(self) -> "TrackingUoW":
            entered.append(True)
            return self

    uow = TrackingUoW(users)
    service = BootstrapAdminService(
        cast(Any, lambda: uow), StaticPasswordHasher(), InMemoryAuditEmitter()
    )

    assert await service.ensure(None, "secret") is None
    assert await service.ensure("admin", None) is None
    assert entered == []


@pytest.mark.asyncio
async def test_bootstrap_skips_when_users_exist() -> None:
    """Bootstrap never creates a second administrator account."""
    users = FakeUsers(count=3)
    uow = FakeUnitOfWork(users)
    service = BootstrapAdminService(
        cast(Any, _uow_factory(uow)), StaticPasswordHasher(), InMemoryAuditEmitter()
    )

    assert await service.ensure("admin", "secret") is None
    assert users.created == []


@pytest.mark.asyncio
async def test_bootstrap_creates_the_first_administrator() -> None:
    """Bootstrap creates exactly one enabled admin with a credential."""
    users = FakeUsers(count=0)
    uow = FakeUnitOfWork(users)
    service = BootstrapAdminService(
        cast(Any, _uow_factory(uow)), StaticPasswordHasher(), InMemoryAuditEmitter()
    )

    user = await service.ensure(" Bootstrap Admin ", "secret")

    assert user is not None
    assert user.username == "bootstrap admin"
    assert user.display_name == "Bootstrap Admin"
    assert user.role is UserRole.ADMIN
    assert users.created == [user]
    assert uow.credentials.replaced == []
    events = uow.audit_events.events
    assert len(events) == 1
    assert events[0].action == AuditAction.USER_CREATE
    assert events[0].outcome == AuditOutcome.SUCCESS
    assert events[0].object_id == user.id


@pytest.mark.asyncio
async def test_bootstrap_records_created_credential() -> None:
    """The bootstrap credential write is observable through its UoW."""
    users = FakeUsers(count=0)
    created: list[tuple[UUID, str]] = []

    class RecordingCredentials(FakeCredentials):
        """Credential double that also records creations."""

        async def create(
            self, user_id: UUID, password_hash: str, changed_at: datetime
        ) -> None:
            """Record one credential creation."""
            created.append((user_id, password_hash))

    uow = FakeUnitOfWork(users)
    uow.credentials = RecordingCredentials()
    service = BootstrapAdminService(
        cast(Any, _uow_factory(uow)), StaticPasswordHasher(), InMemoryAuditEmitter()
    )

    user = await service.ensure("admin", "secret")

    assert user is not None
    assert created == [(user.id, "hashed:secret")]


def test_require_admin_rejects_non_administrators() -> None:
    """Only administrators pass the role guard."""
    now = datetime.now(timezone.utc)
    analyst = User(
        username="ana", role=UserRole.ANALYST, created_at=now, updated_at=now
    )
    admin = User(username="adm", role=UserRole.ADMIN, created_at=now, updated_at=now)

    UserAdministrationService.require_admin(admin)

    with pytest.raises(PermissionError, match="administrator role required"):
        UserAdministrationService.require_admin(analyst)


@pytest.mark.asyncio
async def test_ensure_admin_remains_enforces_the_invariant() -> None:
    """Disabling the last administrator is rejected."""
    service = UserAdministrationService(
        cast(Any, _uow_factory(FakeUnitOfWork(FakeUsers(enabled_admins=1)))),
        StaticPasswordHasher(),
        InMemoryAuditEmitter(),
    )
    await service.ensure_admin_remains()

    service = UserAdministrationService(
        cast(Any, _uow_factory(FakeUnitOfWork(FakeUsers(enabled_admins=0)))),
        StaticPasswordHasher(),
        InMemoryAuditEmitter(),
    )
    with pytest.raises(AdministratorInvariantError, match="at least one"):
        await service.ensure_admin_remains()


@pytest.mark.asyncio
async def test_change_password_rejects_empty_passwords() -> None:
    """Empty passwords never reach persistence."""
    service = UserAdministrationService(
        cast(Any, _uow_factory(FakeUnitOfWork(FakeUsers()))),
        StaticPasswordHasher(),
        InMemoryAuditEmitter(),
    )

    with pytest.raises(ValueError, match="empty"):
        await service.change_password(_admin_actor(UUID(int=1)), UUID(int=1), "")


@pytest.mark.asyncio
async def test_change_password_denies_other_users() -> None:
    """Non-admin actors cannot change someone else's password."""
    audit = InMemoryAuditEmitter()
    opened: list[FakeUnitOfWork] = []

    class OpeningUoW(FakeUnitOfWork):
        """UoW double tracking transactional entry."""

        async def __aenter__(self) -> "OpeningUoW":
            opened.append(self)
            return self

    uow = OpeningUoW(FakeUsers())
    service = UserAdministrationService(
        cast(Any, lambda: uow), StaticPasswordHasher(), audit
    )
    actor = ActorContext(actor_id=UUID(int=1), username="ana", role=UserRole.ANALYST)
    target = UUID(int=2)

    with pytest.raises(PermissionError, match="permission denied"):
        await service.change_password(actor, target, "new-secret")

    assert opened == []  # denied before any transaction was opened
    assert len(audit.events) == 1
    assert audit.events[0].outcome == AuditOutcome.DENIED
    assert audit.events[0].action == AuditAction.USER_CHANGE_PASSWORD
    assert audit.events[0].object_id == target


@pytest.mark.asyncio
async def test_change_password_allows_self_and_admin() -> None:
    """Self-service and administrator changes persist and revoke sessions."""
    audit = InMemoryAuditEmitter()
    uow = FakeUnitOfWork(FakeUsers())
    service = UserAdministrationService(
        cast(Any, _uow_factory(uow)), StaticPasswordHasher(), audit
    )
    self_id = UUID(int=7)

    await service.change_password(_admin_actor(self_id), self_id, "self-secret")
    await service.change_password(_admin_actor(UUID(int=1)), self_id, "admin-secret")

    assert uow.credentials.replaced == [
        (self_id, "hashed:self-secret"),
        (self_id, "hashed:admin-secret"),
    ]
    assert uow.sessions.revoked_users == [self_id, self_id]
    outcomes = [event.outcome for event in uow.audit_events.events]
    assert outcomes == [AuditOutcome.SUCCESS, AuditOutcome.SUCCESS]
    assert all(
        event.action == AuditAction.USER_CHANGE_PASSWORD
        for event in uow.audit_events.events
    )
