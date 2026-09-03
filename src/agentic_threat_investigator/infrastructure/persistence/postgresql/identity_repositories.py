# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL adapters for local identity resources."""

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_threat_investigator.app.identity import normalize_username
from agentic_threat_investigator.app.persistence.repositories import (
    CredentialRepository,
    SessionRepository,
    UserRepository,
)
from agentic_threat_investigator.domain.identity import (
    Credential,
    Session,
    User,
    UserRole,
)

from .models import CredentialRow, SessionRow, UserRow


def _user(row: UserRow) -> User:
    """Map a persistence row to a domain object."""
    return User(
        id=row.id,
        username=row.username,
        display_name=row.display_name,
        role=UserRole(row.role),
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
        deleted_at=row.deleted_at,
        deleted_by_actor_id=row.deleted_by_actor_id,
        version=row.version,
    )


class PostgresUserRepository(UserRepository):
    """Persist and retrieve local users in an active transaction."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, user: User) -> User:
        """Insert a user in the current transaction."""
        self.session.add(UserRow(**user.model_dump()))
        await self.session.flush()
        return user

    async def get_by_username(self, username: str) -> User | None:
        """Find a live user by normalized username."""
        row = (
            await self.session.execute(
                select(UserRow).where(
                    UserRow.username == normalize_username(username),
                    UserRow.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        return None if row is None else _user(row)

    async def get_by_id(self, user_id: UUID) -> User | None:
        """Find a live user by ID."""
        row = await self.session.get(UserRow, user_id)
        return None if row is None or row.deleted_at is not None else _user(row)

    async def count(self) -> int:
        """Count all users, including soft-deleted identities."""
        return int(
            (await self.session.scalar(select(func.count()).select_from(UserRow))) or 0
        )

    async def count_enabled_admins(self, *, excluding: UUID | None = None) -> int:
        """Count enabled, non-deleted administrators."""
        query = (
            select(func.count())
            .select_from(UserRow)
            .where(
                UserRow.role == "admin",
                UserRow.enabled.is_(True),
                UserRow.deleted_at.is_(None),
            )
        )
        if excluding is not None:
            query = query.where(UserRow.id != excluding)
        return int((await self.session.scalar(query)) or 0)


class PostgresCredentialRepository(CredentialRepository):
    """Read credentials without exposing ORM rows."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> Credential:
        """Insert a credential."""
        row = CredentialRow(
            user_id=user_id, password_hash=password_hash, password_changed_at=changed_at
        )
        self.session.add(row)
        await self.session.flush()
        return Credential(
            user_id=user_id, password_hash=password_hash, password_changed_at=changed_at
        )

    async def replace(
        self, user_id: UUID, password_hash: str, changed_at: datetime
    ) -> Credential:
        """Replace a credential."""
        await self.session.execute(
            update(CredentialRow)
            .where(CredentialRow.user_id == user_id)
            .values(password_hash=password_hash, password_changed_at=changed_at)
        )
        return Credential(
            user_id=user_id, password_hash=password_hash, password_changed_at=changed_at
        )

    async def get_by_user_id(self, user_id: UUID) -> Credential | None:
        """Return the credential for a user."""
        row = await self.session.get(CredentialRow, user_id)
        return (
            None
            if row is None
            else Credential.model_validate(row, from_attributes=True)
        )


class PostgresSessionRepository(SessionRepository):
    """Manage sessions without ever storing their plaintext token."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, session: Session) -> Session:
        """Insert a new session."""
        self.session.add(SessionRow(**session.model_dump()))
        await self.session.flush()
        return session

    async def get_by_token_hash(self, token_hash: bytes) -> Session | None:
        """Find a non-revoked session by digest."""
        row = (
            await self.session.execute(
                select(SessionRow).where(SessionRow.token_hash == token_hash)
            )
        ).scalar_one_or_none()
        return (
            None if row is None else Session.model_validate(row, from_attributes=True)
        )

    async def revoke(self, session_id: UUID) -> None:
        """Mark a session revoked."""
        await self.session.execute(
            update(SessionRow)
            .where(SessionRow.id == session_id, SessionRow.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )

    async def revoke_by_token_hash(self, token_hash: bytes) -> None:
        """Mark the matching session revoked."""
        await self.session.execute(
            update(SessionRow)
            .where(SessionRow.token_hash == token_hash, SessionRow.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc))
        )

    async def touch(self, session_id: UUID, seen_at: object) -> None:
        """Update last-seen time after validation."""
        await self.session.execute(
            update(SessionRow)
            .where(SessionRow.id == session_id)
            .values(last_seen_at=seen_at)
        )
