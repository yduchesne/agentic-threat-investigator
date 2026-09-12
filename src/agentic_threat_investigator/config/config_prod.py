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
    "api_cors_origins": ["http://localhost:8080"],
}
