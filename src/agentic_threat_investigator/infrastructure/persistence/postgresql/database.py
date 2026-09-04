# SPDX-License-Identifier: AGPL-3.0-only
"""Async SQLAlchemy engine, sessions, and UnitOfWork implementation."""

from types import TracebackType
from typing import Self, cast

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.app.persistence.repositories import (
    AuditEventRepository,
    CredentialRepository,
    EvidenceRepository,
    RelationshipObservationRepository,
    RelationshipRepository,
    SessionRepository,
    UserRepository,
)
from agentic_threat_investigator.config import Settings

from .audit_repositories import PostgresAuditEventRepository
from .identity_repositories import (
    PostgresCredentialRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from .repositories import PostgresEntityRepository


class PostgresUnitOfWork(UnitOfWork):  # pylint: disable=too-many-instance-attributes
    # The UoW deliberately exposes one repository per persistence boundary.
    """Expose one SQLAlchemy transaction to all repositories."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self.session: AsyncSession | None = None
        self.entities = cast(PostgresEntityRepository, None)
        self.relationships = cast(RelationshipRepository, None)
        self.relationship_observations = cast(RelationshipObservationRepository, None)
        self.evidence = cast(EvidenceRepository, None)
        self.users = cast(UserRepository, None)
        self.credentials = cast(CredentialRepository, None)
        self.sessions = cast(SessionRepository, None)
        self.audit_events = cast(AuditEventRepository, None)

    async def __aenter__(self) -> Self:
        if self.session is not None:
            raise RuntimeError("UnitOfWork is already active")
        self.session = self._session_factory()
        await self.session.begin()
        self.entities = PostgresEntityRepository(self.session)
        self.users = PostgresUserRepository(self.session)
        self.credentials = PostgresCredentialRepository(self.session)
        self.sessions = PostgresSessionRepository(self.session)
        self.audit_events = PostgresAuditEventRepository(self.session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        session = self.session
        if session is None:
            return
        try:
            if exc_type is None:
                await session.commit()
            else:
                await session.rollback()
        finally:
            await session.close()
            self.session = None
            self.entities = cast(PostgresEntityRepository, None)
            self.users = cast(UserRepository, None)
            self.credentials = cast(CredentialRepository, None)
            self.sessions = cast(SessionRepository, None)
            self.audit_events = cast(AuditEventRepository, None)

    async def commit(self) -> None:
        """Commit the current transaction while retaining the active session."""
        if self.session is None:
            raise RuntimeError("UnitOfWork is not active")
        await self.session.commit()

    async def rollback(self) -> None:
        """Roll back the current transaction."""
        if self.session is None:
            raise RuntimeError("UnitOfWork is not active")
        await self.session.rollback()


def create_engine_and_session_factory(
    settings: Settings,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    """Create the async psycopg engine and session factory."""
    url = settings.database_url.replace(
        "postgresql+psycopg://", "postgresql+psycopg_async://", 1
    )
    engine = create_async_engine(
        url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )
    return engine, async_sessionmaker(engine, expire_on_commit=False)
