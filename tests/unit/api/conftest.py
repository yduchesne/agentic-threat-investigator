# SPDX-License-Identifier: AGPL-3.0-only
"""Shared fakes and app builders for the /api/v1 route contract tests.

Route tests exercise pure HTTP contracts with injected application fakes:
no database, no real authentication, no LLM, no provider work. Fakes record
received queries so filter/cursor mapping can be asserted exactly.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentic_threat_investigator.api.app import (
    API_ROUTERS,
    install_cookie_security_scheme,
    install_cors,
)
from agentic_threat_investigator.api.errors import install_error_handlers
from agentic_threat_investigator.app.identity import AuthenticationError
from agentic_threat_investigator.app.query.models import QueryPage
from agentic_threat_investigator.app.query.services import QueryServiceBundle
from agentic_threat_investigator.config import Settings
from agentic_threat_investigator.domain.identity import User, UserRole
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)


def make_user(*, role: UserRole = UserRole.ADMIN, username: str = "alice") -> User:
    """Build one authenticated domain user fixture."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return User(
        id=uuid4(),
        username=username,
        role=role,
        created_at=now,
        updated_at=now,
    )


class FakeAuthenticationService:
    """Deterministic authentication double for HTTP contract tests."""

    def __init__(self, user: User | None = None) -> None:
        """Bind the fixture user and a fixed session token."""
        self.user = user or make_user()
        self.token = "session-token"
        self.logged_out: list[str] = []
        self.login_calls: list[tuple[str, str]] = []
        self.rate_limited = False

    async def login(
        self, username: str, password: str, *, client_address: str | None = None
    ) -> tuple[User, str]:
        """Record the credentials and accept the fixture user."""
        self.login_calls.append((username, password))
        if self.rate_limited:
            from agentic_threat_investigator.app.identity import RateLimitedError

            raise RateLimitedError("too many attempts")
        if username.strip().lower() != self.user.username or password == "wrong":
            raise AuthenticationError("Invalid username or password.")
        return self.user, self.token

    async def logout(self, token: str) -> None:
        """Record the revoked token."""
        self.logged_out.append(token)

    async def validate_session(self, token: str) -> User | None:
        """Accept only the fixture token for a visible enabled user."""
        if token != self.token:
            return None
        if self.user.deleted_at is not None or not self.user.enabled:
            return None
        return self.user


class FakeCollectionService:
    """Record list/get invocations and return configured pages."""

    def __init__(self, page: QueryPage[Any] | None = None) -> None:
        """Bind the default page and an empty exact-read map."""
        self.page = page or QueryPage(items=(), next_cursor=None)
        self.queries: list[Any] = []
        self.gets: dict[tuple[Any, ...], Any] = {}

    async def list(self, query: Any) -> QueryPage[Any]:
        """Record one list query and return the configured page."""
        self.queries.append(query)
        return self.page

    async def get(self, *args: Any) -> Any:
        """Return the exact-read result for the supplied identity tuple."""
        return self.gets.get(args)

    async def current(self, investigation_id: UUID) -> Any:
        """Return the configured current resource, if any."""
        return self.gets.get(("current", investigation_id))

    async def get_object_version(self, **kwargs: Any) -> Any:
        """Return the configured exact history row, if any."""
        return self.gets.get(
            (
                "version",
                kwargs["object_type"],
                kwargs["object_id"],
                kwargs["version"],
            )
        )


class FakeQueryBundle:
    """One in-memory query bundle with per-collection fakes.

    The bundle intentionally does not subclass :class:`QueryServiceBundle`;
    routes consume it through the abstract bundle and tests access the
    concrete fakes directly to assert received queries. ``as_bundle`` casts
    it at the app factory boundary.
    """

    def __init__(self) -> None:
        """Bind fresh collection fakes for every read contract."""
        self.investigations = FakeCollectionService()
        self.evidence = FakeCollectionService()
        self.relationships = FakeCollectionService()
        self.relationship_observations = FakeCollectionService()
        self.research_results = FakeCollectionService()
        self.assessments = FakeCollectionService()
        self.reports = FakeCollectionService()
        self.timeline_events = FakeCollectionService()
        self.domain_history = FakeCollectionService()

    async def close(self) -> None:
        """No-op close for the in-memory bundle."""

    def as_bundle(self) -> QueryServiceBundle:
        """Cast this duck-typed bundle to the application read contract."""
        return cast(QueryServiceBundle, self)


class FakeSubmissionService:
    """Deterministic submission double for HTTP contract tests."""

    def __init__(self) -> None:
        """Bind an empty submission history and a fixed Investigation."""
        self.submissions: list[tuple[Any, UUID, str | None]] = []
        self.fresh_investigation = _pending_investigation()
        self.conflict: BaseException | None = None
        self.runner_calls = 0

    async def submit(
        self,
        submission: Any,
        *,
        actor_id: UUID,
        idempotency_key: str | None,
        request_id: UUID | None = None,
    ) -> InvestigationState:
        """Record the submission and return the fixture Investigation."""
        self.submissions.append((submission, actor_id, idempotency_key))
        if self.conflict is not None:
            raise self.conflict
        return self.fresh_investigation


def _pending_investigation() -> InvestigationState:
    """Build one PENDING Investigation fixture with persisted metadata."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return InvestigationState(
        investigation_id=UUID("11111111-1111-1111-1111-111111111111"),
        status=InvestigationStatus.PENDING,
        trigger_type=InvestigationTriggerType.API,
        root_entity_ids=[UUID("22222222-2222-2222-2222-222222222222")],
        objective="assess the indicator",
        budget=default_investigation_budget(),
        started_at=now,
        created_at=now,
        version=1,
    )


def build_test_app(
    *,
    bundle: FakeQueryBundle | None = None,
    authentication: FakeAuthenticationService | None = None,
    submission: FakeSubmissionService | None = None,
    settings: Settings | None = None,
    routers: tuple[object, ...] | None = None,
) -> TestClient:
    """Build a bare FastAPI with the API routers and injected fakes.

    The TestClient is returned without entering its context so the lifespan
    never runs; all services come from the injected fakes.
    """
    application = FastAPI()
    from agentic_threat_investigator.api.middleware import RequestContextMiddleware

    application.add_middleware(RequestContextMiddleware)
    install_error_handlers(application)
    for route in routers or API_ROUTERS:
        application.include_router(route)  # type: ignore[arg-type]
    configured = settings or Settings(public_base_url="http://testserver")
    application.state.settings = configured
    application.state.authentication = authentication or FakeAuthenticationService()
    application.state.submission_service = submission or FakeSubmissionService()
    application.state.query_services_factory = lambda: (
        bundle if bundle is not None else FakeQueryBundle()
    ).as_bundle()
    install_cors(application, configured)
    install_cookie_security_scheme(application)
    return TestClient(application, raise_server_exceptions=False)


def login_client(client: TestClient, *, csrf: str = "csrf-token") -> None:
    """Authenticate the client and arm its CSRF cookie/token."""
    client.cookies.set("ati_session", "session-token")
    client.cookies.set("ati_csrf", csrf)


def csrf_headers(csrf: str = "csrf-token") -> dict[str, str]:
    """Return the CSRF header pair used by state-changing requests."""
    return {"X-CSRF-Token": csrf, "Origin": "http://testserver"}
