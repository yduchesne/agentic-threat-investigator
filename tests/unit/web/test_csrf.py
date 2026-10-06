# SPDX-License-Identifier: AGPL-3.0-only
"""Web form/HTMX CSRF transport tests (W09-W14, W26-W28).

The web adapter accepts the double-submit proof from a hidden form field and
then verifies the exact approved origin set through the one shared
``validate_csrf`` core.
"""

from __future__ import annotations

from agentic_threat_investigator.api.auth_constants import CSRF_COOKIE
from agentic_threat_investigator.app.identity import CsrfError, validate_csrf
from agentic_threat_investigator.config import Settings

from .conftest import build_web_app, prime_login_csrf, web_login, web_settings

REACT_ORIGIN = "http://react.test"
WEB_ORIGIN = "http://web.test"
THIRD_ORIGIN = "http://evil.test"


def _two_origin_settings() -> Settings:
    """Return settings with distinct React and web exact origins."""
    return web_settings(public_base_url=REACT_ORIGIN, web_base_url=WEB_ORIGIN)


def test_w09_valid_form_csrf_from_web_origin_accepted() -> None:
    """A hidden form proof plus the web origin is accepted."""
    with build_web_app(settings=_two_origin_settings()) as client:
        response = web_login(client, origin=WEB_ORIGIN)
    assert response.status_code == 303


def test_w27_react_origin_remains_accepted() -> None:
    """The React browser origin remains an approved exact origin."""
    with build_web_app(settings=_two_origin_settings()) as client:
        response = web_login(client, origin=REACT_ORIGIN)
    assert response.status_code == 303


def test_w10_missing_form_csrf_is_rejected() -> None:
    """A login POST without the hidden proof fails closed."""
    with build_web_app(settings=_two_origin_settings()) as client:
        prime_login_csrf(client)
        response = client.post(
            "/login",
            data={"username": "alice", "password": "secret"},
            headers={"Origin": WEB_ORIGIN},
        )
    assert response.status_code == 403
    assert "<!DOCTYPE" in response.text


def test_w11_mismatched_token_and_cookie_is_rejected() -> None:
    """A proof that does not match the double-submit cookie fails closed."""
    with build_web_app(settings=_two_origin_settings()) as client:
        prime_login_csrf(client)
        response = web_login(client, csrf="forged", origin=WEB_ORIGIN)
    assert response.status_code == 403


def test_w12_w26_foreign_origin_mutation_is_rejected() -> None:
    """A third-party origin is rejected even with a valid double-submit proof."""
    with build_web_app(settings=_two_origin_settings()) as client:
        response = web_login(client, origin=THIRD_ORIGIN)
    assert response.status_code == 403


def test_w13_approved_referer_fallback_is_accepted() -> None:
    """When Origin is absent, an approved Referer is accepted."""
    with build_web_app(settings=_two_origin_settings()) as client:
        token = prime_login_csrf(client)
        response = client.post(
            "/login",
            data={
                "username": "alice",
                "password": "secret",
                "csrf_token": token,
                "next": "/",
            },
            headers={"Referer": f"{WEB_ORIGIN}/login"},
        )
    assert response.status_code == 303


def test_w14_api_header_csrf_remains_compatible() -> None:
    """The API's header-based CSRF contract is unchanged."""
    from tests.unit.api.conftest import FakeAuthenticationService, login_client

    service = FakeAuthenticationService()
    with build_web_app(
        authentication=service, settings=_two_origin_settings()
    ) as client:
        login_client(client, csrf="api-csrf")
        response = client.post(
            "/api/v1/auth/logout",
            headers={"X-CSRF-Token": "api-csrf", "Origin": REACT_ORIGIN},
        )
    assert response.status_code == 204
    assert service.logged_out == ["session-token"]


def test_w28_shared_validator_accepts_the_web_origin() -> None:
    """The shared CSRF core accepts the exact web origin from a collection."""
    validate_csrf("t", "t", WEB_ORIGIN, None, [REACT_ORIGIN, WEB_ORIGIN])


def test_w26_shared_validator_rejects_a_third_origin() -> None:
    """The shared CSRF core rejects any origin outside the collection."""
    try:
        validate_csrf("t", "t", THIRD_ORIGIN, None, [REACT_ORIGIN, WEB_ORIGIN])
    except CsrfError:
        return
    raise AssertionError("third-party origin must be rejected")


def test_csrf_allowed_origins_deduplicates_and_preserves_order() -> None:
    """Settings exposes the exact approved origins without duplicates."""
    settings = _two_origin_settings()
    assert settings.csrf_allowed_origins == (REACT_ORIGIN, WEB_ORIGIN)
    same = Settings(
        public_base_url=WEB_ORIGIN,
        web_base_url=WEB_ORIGIN,
    )
    assert same.csrf_allowed_origins == (WEB_ORIGIN,)


def test_web_csrf_cookie_is_browser_readable_and_not_http_only() -> None:
    """The web-issued double-submit cookie is intentionally not HttpOnly."""
    with build_web_app(settings=_two_origin_settings()) as client:
        response = client.get("/login", headers={"Origin": WEB_ORIGIN})
    csrf = next(
        c
        for c in response.headers.get_list("set-cookie")
        if c.startswith(f"{CSRF_COOKIE}=")
    )
    assert "HttpOnly" not in csrf
