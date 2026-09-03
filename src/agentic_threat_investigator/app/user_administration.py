# SPDX-License-Identifier: AGPL-3.0-only
"""User administration use cases and administrator safety policy."""

# Exception types intentionally expose one semantic operation.
# pylint: disable=too-few-public-methods
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.identity import PasswordHasher, normalize_username
from agentic_threat_investigator.domain.identity import User, UserRole


class AdministratorInvariantError(ValueError):
    """Raised when an operation would remove the final administrator."""


class BootstrapAdminService:
    """Create exactly one configured bootstrap administrator."""

    def __init__(self, users: Any, credentials: Any, hasher: PasswordHasher) -> None:
        self.users, self.credentials, self.hasher = users, credentials, hasher

    async def ensure(self, username: str | None, password: str | None) -> User | None:
        """Create the bootstrap account only while the user table is empty."""
        if not username or not password or await self.users.count() != 0:
            return None
        now = datetime.now(timezone.utc)
        user = User(
            username=normalize_username(username),
            display_name=username.strip(),
            role=UserRole.ADMIN,
            created_at=now,
            updated_at=now,
        )
        await self.users.create(user)
        await self.credentials.create(user.id, self.hasher.hash(password), now)
        return user


class UserAdministrationService:
    """Enforce authorization and the at-least-one-admin invariant."""

    def __init__(
        self, users: Any, credentials: Any, sessions: Any, hasher: PasswordHasher
    ) -> None:
        self.users, self.credentials, self.sessions, self.hasher = (
            users,
            credentials,
            sessions,
            hasher,
        )

    @staticmethod
    def require_admin(actor: User) -> None:
        """Reject non-administrative actors."""
        if actor.role is not UserRole.ADMIN:
            raise PermissionError("administrator role required")

    async def ensure_admin_remains(self, *, excluding: UUID | None = None) -> None:
        """Check the invariant against the repository's transactional count."""
        count = await self.users.count_enabled_admins(excluding=excluding)
        if count < 1:
            raise AdministratorInvariantError(
                "at least one enabled administrator is required"
            )

    async def change_password(self, user_id: UUID, new_password: str) -> None:
        """Replace a password and revoke every session for that user."""
        if not new_password:
            raise ValueError("password must not be empty")
        now = datetime.now(timezone.utc)
        await self.credentials.replace(user_id, self.hasher.hash(new_password), now)
        await self.sessions.revoke_by_user_id(user_id)
