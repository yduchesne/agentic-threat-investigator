# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL integration tests for the server-rendered web adapter (V07-01).

These exercise the real FastAPI + Jinja + PostgreSQL + AuthenticationService
path: the parallel runtime is proven against the same services and database
the JSON API uses, never mocked away.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentic_threat_investigator.domain.identity import UserRole
from tests.integration.api_helpers import (
    api_client,
    api_settings,
    seed_user,
    web_client,
    web_login_form,
    web_settings,
)

VALID_PASSWORD = "correct horse battery staple"
REACT_ORIGIN = "http://react.test"
WEB_ORIGIN = "http://web.test"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i01_get_login_renders_form(session_factory: Any) -> None:
    """GET /login returns a complete HTML form and arms the CSRF cookie."""
    with web_client() as client:
        response = client.get("/login")
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text
    assert 'name="csrf_token"' in response.text
    assert "ati_csrf" in client.cookies


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i02_protected_get_without_session_redirects(
    session_factory: Any,
) -> None:
    """A protected GET without a session redirects to login."""
    with web_client() as client:
        response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i03_valid_login_uses_service_and_issues_cookies(
    session_factory: Any,
) -> None:
    """A valid web login authenticates through the real service and 303s."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client() as client:
        assert client.get("/login").status_code == 200
        response = client.post(
            "/login",
            data=web_login_form(client, password=VALID_PASSWORD),
            headers={"Origin": REACT_ORIGIN},
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookies = "\n".join(response.headers.get_list("set-cookie"))
    assert "ati_session=" in cookies
    assert "HttpOnly" in cookies


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i04_invalid_login_is_bounded_without_session(
    session_factory: Any,
) -> None:
    """An invalid login renders a bounded error and creates no session."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client() as client:
        client.get("/login")
        response = client.post(
            "/login",
            data=web_login_form(client, password="wrong"),
            headers={"Origin": REACT_ORIGIN},
        )
    assert response.status_code == 401
    assert "Invalid username or password." in response.text
    assert "Traceback" not in response.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i05_i06_authenticated_shell_full_and_fragment(
    session_factory: Any,
) -> None:
    """The full shell and the HTMX fragment share one authenticated state."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client() as client:
        client.get("/login")
        login = client.post(
            "/login",
            data=web_login_form(client, password=VALID_PASSWORD),
            headers={"Origin": REACT_ORIGIN},
        )
        assert login.status_code == 303
        full = client.get("/")
        fragment = client.get("/", headers={"HX-Request": "true"})
    assert full.status_code == 200
    assert full.text.startswith("<!DOCTYPE html>")
    assert "alice" in full.text
    assert "/web-static/vendor/htmx.min.js" in full.text
    assert fragment.status_code == 200
    assert "<!DOCTYPE" not in fragment.text
    assert 'id="ati-content"' in fragment.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i07_logout_revokes_session_and_redirects(
    session_factory: Any,
) -> None:
    """Logout validates CSRF, revokes the session, and expires cookies."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client() as client:
        client.get("/login")
        client.post(
            "/login",
            data=web_login_form(client, password=VALID_PASSWORD),
            headers={"Origin": REACT_ORIGIN},
        )
        token = client.cookies.get("ati_csrf")
        logout = client.post(
            "/logout",
            data={"csrf_token": token},
            headers={"Origin": REACT_ORIGIN},
        )
        after = client.get("/")
    assert logout.status_code == 303
    assert logout.headers["location"] == "/login"
    expired = "\n".join(logout.headers.get_list("set-cookie"))
    assert "Max-Age=0" in expired
    assert after.status_code == 303


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i08_i15_foreign_origin_mutation_is_rejected(
    session_factory: Any,
) -> None:
    """A third-party Origin never passes CSRF even with a valid proof."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client() as client:
        client.get("/login")
        response = client.post(
            "/login",
            data=web_login_form(client, password=VALID_PASSWORD),
            headers={"Origin": "http://evil.test"},
        )
    assert response.status_code == 403
    assert "<!DOCTYPE" in response.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i14_configured_react_and_web_origins_are_both_accepted(
    session_factory: Any,
) -> None:
    """Both exact configured frontend origins are accepted."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    for origin in (REACT_ORIGIN, WEB_ORIGIN):
        with web_client(web_settings()) as client:
            client.get("/login")
            response = client.post(
                "/login",
                data=web_login_form(client, password=VALID_PASSWORD),
                headers={"Origin": origin},
            )
        assert response.status_code == 303, origin


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i09_api_auth_regression_stays_json(session_factory: Any) -> None:
    """The JSON API login/session contract is unchanged by web composition."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with api_client(api_settings()) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": VALID_PASSWORD},
        )
        assert login.status_code == 200
        assert login.json()["alias"] == "alice"
        assert login.headers["content-type"].startswith("application/json")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i10_i11_web_404_is_html_and_api_404_is_json(
    session_factory: Any,
) -> None:
    """Web 404s render HTML while API 404s keep the JSON envelope."""
    with web_client() as client:
        web_not_found = client.get("/missing-page")
        api_not_found = client.get("/api/v1/missing-resource")
    assert web_not_found.status_code == 404
    assert "<!DOCTYPE" in web_not_found.text
    assert api_not_found.status_code == 404
    assert api_not_found.headers["content-type"].startswith("application/json")
    assert api_not_found.json()["error"]["code"] == "not_found"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i12_static_htmx_is_local(session_factory: Any) -> None:
    """The pinned htmx asset is served locally with a script content type."""
    with web_client() as client:
        response = client.get("/web-static/vendor/htmx.min.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert "htmx" in response.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_i13_malicious_presentation_text_is_escaped(
    session_factory: Any,
) -> None:
    """A malicious alias is escaped in the real rendered shell."""
    malicious = '<img src=x onerror="alert(1)">'
    await seed_user(session_factory, username=malicious, role=UserRole.ANALYST)
    with web_client() as client:
        client.get("/login")
        response = client.post(
            "/login",
            data={
                "username": malicious,
                "password": VALID_PASSWORD,
                "csrf_token": client.cookies.get("ati_csrf", ""),
                "next": "/",
            },
            headers={"Origin": REACT_ORIGIN},
        )
        assert response.status_code == 303
        shell = client.get("/")
    assert malicious not in shell.text
    assert "&lt;img" in shell.text


@pytest.mark.asyncio
@pytest.mark.integration
async def test_parallel_runtime_shares_one_session_authority(
    session_factory: Any,
) -> None:
    """A web login authenticates the same session used by the JSON API."""
    await seed_user(session_factory, role=UserRole.ANALYST)
    with web_client(api_settings()) as client:
        client.get("/login")
        login = client.post(
            "/login",
            data=web_login_form(client, password=VALID_PASSWORD),
            headers={"Origin": "http://testserver"},
        )
        assert login.status_code == 303
        me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["alias"] == "alice"
