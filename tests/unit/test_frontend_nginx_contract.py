# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic source-contract guard for the production frontend Nginx config.

PR 35-6 fixes an OpenStreetMap Standard tile-policy incompatibility: the
repository Nginx policy ``Referrer-Policy: no-referrer`` caused browsers to
omit the ``Referer`` header on cross-origin OSM tile requests, which the OSM
tile service rejects with ``x-blocked: No referer sent. Access denied.`` The
production frontend must emit ``strict-origin-when-cross-origin`` so a valid
origin-level referrer reaches OSM without disclosing the full Investigation
route.

These tests are deliberately static and offline: they read the
repository-owned ``frontend/nginx.conf`` (the file the production
``frontend/Dockerfile`` copies to ``/etc/nginx/conf.d/default.conf``) and pin
the reviewed header baseline. They never launch a browser, contact OSM, or
execute Nginx. Browser-level Referer behavior remains a user-owned manual
check.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NGINX_CONF = _REPO_ROOT / "frontend" / "nginx.conf"

_REFERRER_POLICY = (
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
)
_OLD_REFERRER_POLICY = 'Referrer-Policy "no-referrer"'
_NOSNIFF = 'add_header X-Content-Type-Options "nosniff" always;'
_FRAME_DENY = 'add_header X-Frame-Options "DENY" always;'


def _nginx_config() -> str:
    """Return the production frontend Nginx configuration as text."""
    return _NGINX_CONF.read_text(encoding="utf-8")


def test_referrer_policy_is_strict_origin_when_cross_origin() -> None:
    """U01/U03: the intended Referrer-Policy is emitted with ``always``."""
    assert _REFERRER_POLICY in _nginx_config()


def test_old_no_referrer_policy_is_absent() -> None:
    """U02: the prohibited restrictive policy is no longer emitted."""
    assert _OLD_REFERRER_POLICY not in _nginx_config()


def test_content_type_protection_is_retained() -> None:
    """U04: ``X-Content-Type-Options: nosniff`` is preserved."""
    assert _NOSNIFF in _nginx_config()


def test_framing_protection_is_retained() -> None:
    """U05: ``X-Frame-Options: DENY`` is preserved."""
    assert _FRAME_DENY in _nginx_config()
