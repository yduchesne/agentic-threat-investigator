# SPDX-License-Identifier: AGPL-3.0-only
"""Async SQLAlchemy engine, sessions, and UnitOfWork implementation."""

from types import TracebackType
from typing import Any, Self, cast

from sqlalchemy import event
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
from .composites import register_entity_batch_composite
from .identity_repositories import (
    PostgresCredentialRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from .repositories import PostgresEntityRepository


class PostgresUnitOfWork(UnitOfWork):  # pylint: disable=too-many-instance-attributes
    # The UoW deliberately exposes one repository per persistence boundary.
    """Expose one SQLAlchemy transaction to all repositories."""

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession], batch_size: int = 100
    ) -> None:
        self._session_factory = session_factory
        self._batch_size = batch_size
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
        # Session factories supplied by callers other than our engine factory
        # (notably isolated integration fixtures) still need the composite
        # adapter installed on their physical connection.
        raw_connection = await (await self.session.connection()).get_raw_connection()
        await register_entity_batch_composite(
            cast(Any, raw_connection.driver_connection)
        )
        self.entities = PostgresEntityRepository(self.session, self._batch_size)
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

    @event.listens_for(engine.sync_engine, "connect")
    def _register_composites(dbapi_connection: object, _record: object) -> None:
        """Register custom types before a pooled connection is used."""
        run_async = getattr(dbapi_connection, "run_async", None)
        if run_async is not None:
            run_async(register_entity_batch_composite)

    return engine, async_sessionmaker(engine, expire_on_commit=False)
