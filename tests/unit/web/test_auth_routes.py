# SPDX-License-Identifier: AGPL-3.0-only
"""Web authentication/session/CSRF contract tests (W05-W18, W29)."""

from __future__ import annotations

from agentic_threat_investigator.api.auth_constants import COOKIE_NAME, CSRF_COOKIE

from .conftest import (
    SESSION_TOKEN,
    TEST_ORIGIN,
    build_web_app,
    prime_login_csrf,
    web_login,
)


def test_w07_absent_session_redirects_to_login() -> None:
    """A protected web GET without a session redirects safely to login."""
    with build_web_app() as client:
        response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/"


def test_w05_forged_hx_without_session_is_still_unauthenticated() -> None:
    """A forged HX header changes representation only, never authorization."""
    with build_web_app() as client:
        response = client.get("/", headers={"HX-Request": "true"})
    assert response.status_code == 204
    assert response.headers["HX-Redirect"] == "/login?next=/"
    assert "Authenticated shell" not in response.text


def test_w06_valid_session_resolves_user() -> None:
    """A valid session renders the authenticated shell with public identity."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/")
    assert response.status_code == 200
    assert "Authenticated shell" in response.text
    assert "alice" in response.text


def test_w08_revoked_session_same_unauthenticated_behavior() -> None:
    """An unknown/revoked session is indistinguishable from an absent one."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, "revoked-token")
        response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/"


def test_w03_ordinary_request_returns_full_document() -> None:
    """An ordinary authenticated GET returns a complete HTML document."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/")
    assert response.status_code == 200
    assert response.text.startswith("<!DOCTYPE html>")
    assert "<html" in response.text


def test_w04_w20_hx_request_returns_bounded_fragment() -> None:
    """An HX request returns the fragment with no duplicate full document."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!DOCTYPE" not in response.text
    assert "<html" not in response.text
    assert 'id="ati-content"' in response.text


def test_w21_full_page_includes_local_htmx_and_css() -> None:
    """The full document references locally served htmx and ATI CSS."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/")
    assert "/web-static/vendor/htmx.min.js" in response.text
    assert "/web-static/css/ati.css" in response.text
    assert "unpkg.com" not in response.text
    assert "cdn." not in response.text


def test_w29_session_token_never_enters_html() -> None:
    """The raw session token is never rendered into HTML."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/")
    assert SESSION_TOKEN not in response.text
    assert COOKIE_NAME not in response.text


def test_w15_valid_login_sets_same_cookie_security_attributes() -> None:
    """Web login issues the same session/CSRF cookies as the API."""
    with build_web_app() as client:
        response = web_login(client)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    cookies = response.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith(f"{COOKIE_NAME}="))
    csrf = next(c for c in cookies if c.startswith(f"{CSRF_COOKIE}="))
    assert "HttpOnly" in session
    assert "SameSite=lax" in session
    assert "Path=/" in session
    assert "Secure" not in session
    # The browser-readable double-submit cookie must not be HttpOnly.
    assert "HttpOnly" not in csrf


def test_w15_secure_flag_follows_settings() -> None:
    """The Secure session attribute follows the configured profile."""
    from starlette.responses import Response

    from agentic_threat_investigator.api.session_cookies import set_session_cookie

    from .conftest import web_settings

    response = Response()
    set_session_cookie(response, web_settings(session_cookie_secure=True), "tok")
    assert "Secure" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert "Path=/" in response.headers["set-cookie"]


def test_w16_invalid_login_creates_no_session_and_generic_error() -> None:
    """An invalid login yields a bounded error and no session cookie."""
    with build_web_app() as client:
        before = prime_login_csrf(client)
        response = web_login(client, password="wrong", csrf=before)
    assert response.status_code == 401
    assert "Invalid username or password." in response.text
    assert "wrong" not in response.text
    assert not any(
        c.startswith(f"{COOKIE_NAME}=") for c in response.headers.get_list("set-cookie")
    )


def test_w17_valid_logout_revokes_and_expires_cookies() -> None:
    """Web logout revokes the shared session and expires both cookies."""
    from tests.unit.api.conftest import FakeAuthenticationService

    service = FakeAuthenticationService()
    with build_web_app(authentication=service) as client:
        login_response = web_login(client)
        assert login_response.status_code == 303
        token = client.cookies.get(CSRF_COOKIE)
        response = client.post(
            "/logout", data={"csrf_token": token}, headers={"Origin": TEST_ORIGIN}
        )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert service.logged_out == [SESSION_TOKEN]
    expired = response.headers.get_list("set-cookie")
    assert any(c.startswith(f"{COOKIE_NAME}=") and "Max-Age=0" in c for c in expired)
    assert any(c.startswith(f"{CSRF_COOKIE}=") and "Max-Age=0" in c for c in expired)


def test_w18_invalid_logout_csrf_is_rejected() -> None:
    """A logout without a valid CSRF proof fails closed with HTML 403."""
    from tests.unit.api.conftest import FakeAuthenticationService

    service = FakeAuthenticationService()
    with build_web_app(authentication=service) as client:
        login_response = web_login(client)
        assert login_response.status_code == 303
        response = client.post(
            "/logout",
            data={"csrf_token": "forged"},
            headers={"Origin": TEST_ORIGIN},
        )
    assert response.status_code == 403
    assert "<!DOCTYPE" in response.text
    assert service.logged_out == []


def test_get_login_redirects_authenticated_actor_to_shell() -> None:
    """An authenticated GET /login redirects into the shell."""
    with build_web_app() as client:
        client.cookies.set(COOKIE_NAME, SESSION_TOKEN)
        response = client.get("/login")
    assert response.status_code == 303
    assert response.headers["location"] == "/"
