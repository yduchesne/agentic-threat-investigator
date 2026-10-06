# SPDX-License-Identifier: AGPL-3.0-only
"""Human-facing server-rendered HTML presentation adapter (V07-01).

``web/`` is a peer of ``api/``: both are presentation adapters over the same
ATI application/query/authentication services. This package owns HTML
routing, Jinja templates, HTMX fragment selection, web view models, web form
presentation, and browser-facing redirects. It never owns domain policy,
orchestration, persistence, provider logic, or authorization policy.
"""
