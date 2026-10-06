# SPDX-License-Identifier: AGPL-3.0-only
"""View-model, escaping, static-asset, and error-presentation tests."""

from __future__ import annotations

from typing import Any, cast

from agentic_threat_investigator.domain.identity import UserRole
from agentic_threat_investigator.web.viewmodels.shell import (
    login_view_model,
    shell_view_model,
)
from tests.unit.api.conftest import FakeAuthenticationService, make_user

from .conftest import SESSION_TOKEN, build_web_app


def test_w01_shell_view_model_exposes_required_safe_fields() -> None:
    """The shell view model carries only safe public presentation data."""
    view = shell_view_model(
        username="alice",
        role="analyst",
        display_name=None,
        operating_mode="fake",
        render_id="render-1",
        csrf_token="csrf-1",
    )
    assert view.username == "alice"
    assert view.role == "analyst"
    assert view.operating_mode == "fake"
    assert view.render_id == "render-1"
    assert view.csrf_token == "csrf-1"
    assert not hasattr(view, "session_token")


def test_login_view_model_has_no_credential_fields() -> None:
    """The login view model never carries a submitted password."""
    view = login_view_model(csrf_token="t", error="Invalid username or password.")
    assert view.csrf_token == "t"
    assert not hasattr(view, "password")


def test_w02_w19_malicious_alias_is_escaped() -> None:
    """Untrusted user text is HTML-escaped, never rendered as markup."""
    malicious = '<img src=x onerror="alert(1)">'
    service = FakeAuthenticationService(user=make_user(username=malicious))
    with build_web_app(authentication=service) as client:
        client.cookies.set("ati_session", SESSION_TOKEN)
        response = client.get("/")
    assert response.status_code == 200
    assert malicious not in response.text
    assert "&lt;img" in response.text
    assert "onerror" in response.text  # present only as escaped text content


def test_w21_autoescape_is_enabled_for_html_templates() -> None:
    """The Jinja environment autoescapes HTML templates."""
    from agentic_threat_investigator.web.rendering import WebTemplates

    environment = WebTemplates().environment
    template = environment.from_string("{{ value }}")
    rendered = template.render(value="<script>alert(1)</script>")
    assert rendered == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_w21_html_security_header_baseline_is_applied() -> None:
    """Authenticated HTML carries the reviewed, non-cacheable header set."""
    with build_web_app() as client:
        client.cookies.set("ati_session", SESSION_TOKEN)
        response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"


def test_w22_static_htmx_is_local_and_correctly_typed() -> None:
    """The pinned htmx asset is served locally with a script content type."""
    with build_web_app() as client:
        response = client.get("/web-static/vendor/htmx.min.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert "htmx" in response.text


def test_w23_unknown_web_route_is_safe_html_404() -> None:
    """An unknown non-API route returns a bounded HTML 404."""
    with build_web_app() as client:
        response = client.get("/no-such-page")
    assert response.status_code == 404
    assert "<!DOCTYPE" in response.text
    assert "Page not found" in response.text
    assert "Traceback" not in response.text


def test_w24_api_error_remains_json() -> None:
    """Unknown API routes keep the stable JSON error envelope."""
    with build_web_app() as client:
        response = client.get("/api/v1/no-such-resource")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["error"]["code"] == "not_found"


def test_w24_unauthenticated_api_route_remains_json_401() -> None:
    """An unauthenticated API route keeps its JSON authentication envelope."""
    with build_web_app() as client:
        response = client.get("/api/v1/investigations")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_w25_api_login_remains_json_compatible() -> None:
    """The API login route still returns its JSON DTO and cookies."""
    service = FakeAuthenticationService(user=make_user(role=UserRole.ADMIN))
    with build_web_app(authentication=service) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "secret"},
        )
    assert response.status_code == 200
    assert response.json()["alias"] == "alice"
    assert response.json()["role"] == "admin"
    assert "ati_session" in response.headers.get("set-cookie", "")


def test_w30_dependency_unavailable_is_bounded_html_without_traceback() -> None:
    """A missing dependency yields bounded HTML, never a traceback."""
    with build_web_app() as client:
        cast(Any, client.app).state.authentication = None
        response = client.get("/")
    assert response.status_code == 503
    assert "<!DOCTYPE" in response.text
    assert "Traceback" not in response.text


def test_w23_forbidden_web_mutation_is_html_403() -> None:
    """A rejected web mutation renders HTML rather than a JSON envelope."""
    with build_web_app() as client:
        response = client.post(
            "/logout", data={"csrf_token": "x"}, headers={"Origin": "http://testserver"}
        )
    assert response.status_code == 403
    assert "<!DOCTYPE" in response.text
    assert response.headers["content-type"].startswith("text/html")
