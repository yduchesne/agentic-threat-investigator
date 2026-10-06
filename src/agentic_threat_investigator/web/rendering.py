# SPDX-License-Identifier: AGPL-3.0-only
"""Rendering seams for the server-rendered web adapter.

A request's representation (complete HTML document versus bounded HTMX
fragment) is selected in exactly one place. ``HX-Request`` changes only the
representation; it is never an authorization or security signal, and a
fragment and its full-page form are always built from the same view model.

The Jinja environment is constructed here with autoescaping explicitly
enabled for HTML templates, so no template can render untrusted model,
provider, or user text as markup.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jinja2
from fastapi import Request
from jinja2 import select_autoescape
from starlette.responses import Response
from starlette.templating import Jinja2Templates

WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"
STATIC_URL_PREFIX = "/web-static"
"""ATI-owned static path that cannot be confused with React/Nginx assets."""

HTMX_VENDOR_VERSION = "2.0.11"
"""Pinned, locally served htmx version (0BSD); no runtime CDN dependency."""

HTMX_SCRIPT_URL = f"{STATIC_URL_PREFIX}/vendor/htmx.min.js"
"""Locally served htmx script path."""

HTMX_REQUEST_HEADER = "HX-Request"
"""The htmx request header whose ``true`` value selects fragment rendering."""

HTMX_REDIRECT_HEADER = "HX-Redirect"
"""The htmx response header that forces a full browser navigation."""

HTML_SECURITY_HEADERS: Mapping[str, str] = {
    "X-Content-Type-Options": "nosniff",
    # ``same-origin`` (not ``no-referrer``): a no-referrer document makes
    # browsers serialize the Origin header of its same-origin form POSTs as
    # the literal ``null``, which would break ATI's exact-origin CSRF
    # check. ``same-origin`` still withholds the referrer cross-origin.
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}
"""Baseline headers applied to every server-rendered HTML response.

Authenticated HTML is never publicly cacheable; the baseline mirrors the
reviewed static-frontend header set without weakening anything.
"""


def is_htmx_request(request: Request) -> bool:
    """Return whether the request asked for an htmx fragment.

    The comparison is intentionally strict and case-insensitive: only the
    literal ``true`` value (per the htmx contract) selects a fragment. A
    missing or forged header never elevates trust; the route still performs
    the same authentication, CSRF, and view-model construction.
    """
    return request.headers.get(HTMX_REQUEST_HEADER, "").strip().lower() == "true"


def apply_html_security_headers(response: Response) -> Response:
    """Apply the reviewed HTML security-header baseline in place."""
    for name, value in HTML_SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def build_environment(templates_dir: Path = TEMPLATES_DIR) -> jinja2.Environment:
    """Build the Jinja environment with autoescaping explicitly enabled.

    ``select_autoescape`` is pinned to the HTML/XML extensions and to a
    ``default=True`` fallback so any future template extension is still
    escaped. Autoescaping is a security control, not a formatting preference.
    """
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "htm", "xml", "xhtml", "j2"),
            default=True,
            default_for_string=True,
        ),
        auto_reload=False,
    )


class WebTemplates:
    """Own the Jinja environment and the full-page/fragment convention."""

    def __init__(self, templates_dir: Path = TEMPLATES_DIR) -> None:
        """Bind the owned Jinja environment over the packaged templates."""
        self._templates = Jinja2Templates(env=build_environment(templates_dir))

    @property
    def environment(self) -> jinja2.Environment:
        """Return the owned Jinja environment (used by autoescape tests)."""
        return self._templates.env

    def render(
        self,
        request: Request,
        name: str,
        context: Mapping[str, Any] | None = None,
    ) -> Response:
        """Render one template with the standard context and HTML headers."""
        merged: dict[str, Any] = {
            "static_prefix": STATIC_URL_PREFIX,
            "htmx_script_url": HTMX_SCRIPT_URL,
        }
        if context is not None:
            merged.update(context)
        response = self._templates.TemplateResponse(request, name, merged)
        return apply_html_security_headers(response)

    def render_page_or_fragment(
        self,
        request: Request,
        page_name: str,
        fragment_name: str,
        context: Mapping[str, Any] | None = None,
    ) -> Response:
        """Render a complete document or the matching bounded fragment.

        Both representations consume the identical context (the same
        prepared view model), so HTMX never changes the semantics of the
        response, only its representation.
        """
        name = fragment_name if is_htmx_request(request) else page_name
        return self.render(request, name, context)
