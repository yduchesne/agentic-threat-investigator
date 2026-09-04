# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application bootstrap."""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI

from agentic_threat_investigator.api.auth import install_authentication
from agentic_threat_investigator.api.auth import router as auth_router
from agentic_threat_investigator.app.audit import StandaloneAuditEmitter
from agentic_threat_investigator.app.identity import (
    Argon2idPasswordHasher,
    AuthenticationService,
    InMemoryRateLimiter,
    SessionTokenService,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.user_administration import (
    BootstrapAdminService,
    UserAdministrationService,
)
from agentic_threat_investigator.config import Settings, get_settings
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
    create_engine_and_session_factory,
)


async def live() -> dict[str, str]:
    """Report that the API process is alive."""
    return {"status": "ok"}


async def ready() -> dict[str, str]:
    """Report application readiness."""
    return {"status": "ready"}


def create_app(settings: Settings) -> FastAPI:
    """Build the FastAPI application wired for the supplied settings."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        engine, session_factory = create_engine_and_session_factory(settings)

        def make_uow() -> UnitOfWork:
            return PostgresUnitOfWork(
                session_factory, batch_size=settings.db_batch_size
            )

        hasher = Argon2idPasswordHasher()
        audit = StandaloneAuditEmitter(make_uow)
        auth = AuthenticationService(
            make_uow,
            hasher,
            SessionTokenService(),
            InMemoryRateLimiter(
                settings.login_rate_limit_maximum,
                timedelta(seconds=settings.login_rate_limit_window_seconds),
            ),
            audit,
            session_lifetime=timedelta(
                seconds=settings.session_absolute_expiry_seconds
            ),
            idle_timeout=(
                None
                if settings.session_idle_timeout_seconds is None
                else timedelta(seconds=settings.session_idle_timeout_seconds)
            ),
        )
        install_authentication(application, auth)
        application.state.settings = settings
        bootstrap = BootstrapAdminService(make_uow, hasher, audit)
        await bootstrap.ensure(
            settings.bootstrap_admin_username, settings.bootstrap_admin_password
        )
        application.state.user_administration = UserAdministrationService(
            make_uow, hasher, audit
        )
        try:
            yield
        finally:
            await engine.dispose()

    application = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    application.include_router(auth_router)

    application.add_api_route("/health/live", live, methods=["GET"], tags=["health"])
    application.add_api_route("/health/ready", ready, methods=["GET"], tags=["health"])
    return application


app = create_app(get_settings())
