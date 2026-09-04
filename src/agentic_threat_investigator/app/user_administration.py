# SPDX-License-Identifier: AGPL-3.0-only
"""User administration use cases and administrator safety policy."""
from collections.abc import Callable
from datetime import datetime, timezone
from uuid import UUID

from agentic_threat_investigator.app.audit import (
    AuditEmitter,
    TransactionalAuditEmitter,
)
from agentic_threat_investigator.app.identity import PasswordHasher, normalize_username
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.domain.audit import AuditAction, AuditOutcome
from agentic_threat_investigator.domain.identity import ActorContext, User, UserRole


class AdministratorInvariantError(ValueError):
    """Raised when an operation would remove the final administrator."""


class BootstrapAdminService:  # pylint: disable=too-few-public-methods
    """Create exactly one configured bootstrap administrator."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], UnitOfWork],
        hasher: PasswordHasher,
        audit: AuditEmitter,
    ) -> None:
        self._factory, self.hasher, self.audit = unit_of_work_factory, hasher, audit

    async def ensure(self, username: str | None, password: str | None) -> User | None:
        """Create the bootstrap account only while the user table is empty."""
        if not username or not password:
            return None
        now = datetime.now(timezone.utc)
        async with self._factory() as uow:
            if await uow.users.count() != 0:
                return None
            user = User(
                username=normalize_username(username),
                display_name=username.strip(),
                role=UserRole.ADMIN,
                created_at=now,
                updated_at=now,
            )
            await uow.users.create(user)
            await uow.credentials.create(user.id, self.hasher.hash(password), now)
            await TransactionalAuditEmitter(uow).emit(
                AuditAction.USER_CREATE,
                AuditOutcome.SUCCESS,
                ActorContext.system(),
                object_type="user",
                object_id=user.id,
            )
            return user


class UserAdministrationService:  # pylint: disable=too-few-public-methods
    """Enforce authorization and the at-least-one-admin invariant."""

    def __init__(
        self,
        unit_of_work_factory: Callable[[], UnitOfWork],
        hasher: PasswordHasher,
        audit: AuditEmitter,
    ) -> None:
        self._factory, self.hasher, self.audit = unit_of_work_factory, hasher, audit

    @staticmethod
    def require_admin(actor: User) -> None:
        """Reject non-administrative actors."""
        if actor.role is not UserRole.ADMIN:
            raise PermissionError("administrator role required")

    async def ensure_admin_remains(self, *, excluding: UUID | None = None) -> None:
        """Check the invariant against the repository's transactional count."""
        async with self._factory() as uow:
            if await uow.users.count_enabled_admins(excluding=excluding) < 1:
                raise AdministratorInvariantError(
                    "at least one enabled administrator is required"
                )

    async def change_password(
        self, actor: ActorContext, user_id: UUID, new_password: str
    ) -> None:
        """Change a password only for the actor itself or by an administrator."""
        if not new_password:
            raise ValueError("password must not be empty")
        if actor.actor_id != user_id and actor.role is not UserRole.ADMIN:
            await self.audit.emit(
                AuditAction.USER_CHANGE_PASSWORD,
                AuditOutcome.DENIED,
                actor,
                object_type="user",
                object_id=user_id,
            )
            raise PermissionError("permission denied")
        now = datetime.now(timezone.utc)
        async with self._factory() as uow:
            await uow.credentials.replace(user_id, self.hasher.hash(new_password), now)
            await uow.sessions.revoke_by_user_id(user_id)
            await TransactionalAuditEmitter(uow).emit(
                AuditAction.USER_CHANGE_PASSWORD,
                AuditOutcome.SUCCESS,
                actor,
                object_type="user",
                object_id=user_id,
            )
