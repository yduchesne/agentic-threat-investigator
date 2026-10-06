# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Production configuration baseline without secrets."""

from typing import Any

CONFIG: dict[str, Any] = {
    "log_level": "INFO",
    # Production serves the API over HTTPS; the session cookie must be
    # Secure. Operators must replace the public origin and the frontend
    # CORS origin with the externally visible values.
    "session_cookie_secure": True,
    "public_base_url": "http://localhost:8000",
    # V07-01: the server-rendered web adapter's exact browser origin. It is
    # served by the same FastAPI process as /api/v1; operators must replace
    # both this and public_base_url with the externally visible values.
    "web_base_url": "http://localhost:8000",
    "api_cors_origins": ["http://localhost:8080"],
}
