# SPDX-License-Identifier: AGPL-3.0-only
"""Production composition of the /api/v1 FastAPI application.

One composition object owns the engine/session factory lifecycle and wires
the authentication service, the per-request PR 23A query-service bundle, and
the Investigation submission service onto the application state. Routes
resolve services from ``request.app.state`` and never import concrete
PostgreSQL repositories directly.

The worker process composition is intentionally separate: the durable
investigation job worker receives an already-composed
:class:`~agentic_threat_investigator.app.orchestration.runner.InvestigationRunner`
(provider registry, LLM client, analysis/research executor factories) that
deployment assembles from existing infrastructure seams. This file only
builds the API-side dependencies; it never launches a worker, LangGraph,
provider polling, or job execution in the FastAPI lifespan.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import cast

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.audit import StandaloneAuditEmitter
from agentic_threat_investigator.app.identity import (
    Argon2idPasswordHasher,
    AuthenticationService,
    InMemoryRateLimiter,
    SessionTokenService,
)
from agentic_threat_investigator.app.investigation_submission import (
    InvestigationSubmissionService,
    SubmissionLimits,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.user_administration import (
    BootstrapAdminService,
)
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.infrastructure.persistence.postgresql.composites import (
    register_batch_composites,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)


class ApiComposition:
    """Own the API engine/session lifecycle and the composed services."""

    def __init__(self, settings: Settings) -> None:
        """Create the async engine and session factory for the API process."""
        self._settings = settings
        url = settings.database_url.replace(
            "postgresql+psycopg://", "postgresql+psycopg_async://", 1
        )
        self._engine: AsyncEngine = create_async_engine(
            url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
        )

        @sqlalchemy_event.listens_for(self._engine.sync_engine, "connect")
        def _register_composites(dbapi_connection: object, _record: object) -> None:
            """Register custom types before a pooled connection is used."""
            run_async = getattr(dbapi_connection, "run_async", None)
            if run_async is not None:
                run_async(register_batch_composites)

        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False
        )

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Return the shared session factory."""
        return self._session_factory

    @property
    def settings(self) -> Settings:
        """Return the composed settings."""
        return self._settings

    def make_unit_of_work(self) -> UnitOfWork:
        """Create one transaction boundary owned by the caller."""
        return PostgresUnitOfWork(
            self._session_factory, batch_size=self._settings.db_batch_size
        )

    def authentication_service(self) -> AuthenticationService:
        """Compose the login/session service over the same transaction factory."""
        hasher = Argon2idPasswordHasher()
        audit = StandaloneAuditEmitter(self.make_unit_of_work)
        return AuthenticationService(
            self.make_unit_of_work,
            hasher,
            SessionTokenService(),
            InMemoryRateLimiter(
                self._settings.login_rate_limit_maximum,
                timedelta(seconds=self._settings.login_rate_limit_window_seconds),
            ),
            audit,
            session_lifetime=timedelta(
                seconds=self._settings.session_absolute_expiry_seconds
            ),
            idle_timeout=(
                None
                if self._settings.session_idle_timeout_seconds is None
                else timedelta(seconds=self._settings.session_idle_timeout_seconds)
            ),
        )

    def submission_service(self) -> InvestigationSubmissionService:
        """Compose the durable async Investigation submission service."""
        limits = SubmissionLimits(
            max_indicators=self._settings.api_max_indicator_count,
            max_indicator_value_length=self._settings.api_max_indicator_value_length,
            max_objective_length=self._settings.api_max_objective_length,
        )
        return InvestigationSubmissionService(self.make_unit_of_work, limits)

    def query_services_factory(self) -> Callable[[], PostgresQueryServices]:
        """Return a factory building one per-request read-session bundle."""
        limits = QueryLimits(
            default_page_size=self._settings.query_default_page_size,
            max_page_size=self._settings.query_max_page_size,
        )

        def factory() -> PostgresQueryServices:
            return PostgresQueryServices(self._session_factory(), limits)

        return factory

    def bootstrap_admin(self) -> BootstrapAdminService:
        """Compose the bootstrap-admin seeding service."""
        hasher = Argon2idPasswordHasher()
        return BootstrapAdminService(
            self.make_unit_of_work,
            hasher,
            StandaloneAuditEmitter(self.make_unit_of_work),
        )

    def install_services(self, application: object) -> None:
        """Install the composed API services onto a FastAPI application.

        The application type is duck-typed so this composition stays free of
        a hard FastAPI dependency at import time.
        """
        from fastapi import FastAPI

        app = cast(FastAPI, application)
        app.state.settings = self._settings
        app.state.authentication = self.authentication_service()
        app.state.submission_service = self.submission_service()
        app.state.query_services_factory = self.query_services_factory()
        app.state.bootstrap_admin = self.bootstrap_admin()

    async def dispose(self) -> None:
        """Release the engine owned by this composition."""
        await self._engine.dispose()
