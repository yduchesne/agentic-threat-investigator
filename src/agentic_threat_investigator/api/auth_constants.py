# SPDX-License-Identifier: AGPL-3.0-only
"""Shared HTTP contract constants for the /api/v1 boundary."""

COOKIE_NAME = "ati_session"
"""The single stable HttpOnly session cookie name."""

CSRF_COOKIE = "ati_csrf"
"""The double-submit CSRF token cookie name."""

REQUEST_ID_HEADER = "X-Request-ID"
"""The stable request-ID header used in requests and responses."""

IDEMPOTENCY_KEY_HEADER = "Idempotency-Key"
"""The stable idempotency header required by state-changing creation routes."""

CSRF_TOKEN_HEADER = "X-CSRF-Token"  # nosec B105 - header NAME constant, never a credential value
"""The double-submit CSRF token request header."""

API_PREFIX = "/api/v1"
"""The versioned public base path of every ATI endpoint."""
