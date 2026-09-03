# SPDX-License-Identifier: AGPL-3.0-only
"""Async SQLAlchemy engine, sessions, and UnitOfWork implementation."""

from typing import Self

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.config import Settings

from .identity_repositories import (
    PostgresCredentialRepository,
    PostgresSessionRepository,
    PostgresUserRepository,
)
from .repositories import PostgresEntityRepository


class PostgresUnitOfWork(UnitOfWork):
    """Expose one SQLAlchemy transaction to all repositories."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self.session: AsyncSession | None = None

    async def __aenter__(self) -> Self:
        self.session = self._session_factory()
        await self.session.begin()
        self.entities = PostgresEntityRepository(self.session)
        self.users = PostgresUserRepository(self.session)
        self.credentials = PostgresCredentialRepository(self.session)
        self.sessions = PostgresSessionRepository(self.session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        if self.session is not None:
            if exc_type is None:
                await self.session.commit()
            else:
                await self.session.rollback()
            await self.session.close()

    async def commit(self) -> None:
        """Commit the current transaction."""
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
