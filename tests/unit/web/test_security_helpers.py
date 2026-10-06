# SPDX-License-Identifier: AGPL-3.0-only
"""Focused tests for web form/redirect security helpers."""

from __future__ import annotations

from agentic_threat_investigator.web.security import safe_next_path


def test_safe_next_path_accepts_ati_local_relative_paths() -> None:
    """Server-relative ATI paths are preserved."""
    assert safe_next_path("/investigations") == "/investigations"
    assert safe_next_path("/investigations?cursor=abc") == "/investigations?cursor=abc"
    assert safe_next_path("/") == "/"


def test_safe_next_path_rejects_open_redirect_targets() -> None:
    """Absolute, scheme-relative, and obfuscated targets become the default."""
    for value in (
        "https://evil.example/steal",
        "//evil.example/steal",
        "http://evil.example",
        "/\\evil.example",
        "/\r\nLocation: https://evil.example",
        "javascript:alert(1)",
    ):
        assert safe_next_path(value) == "/"


def test_safe_next_path_defaults_when_absent() -> None:
    """An absent or blank target falls back to the supplied default."""
    assert safe_next_path(None) == "/"
    assert safe_next_path("") == "/"
    assert safe_next_path("   ", default="/login") == "/login"


def test_safe_next_path_rejects_oversized_targets() -> None:
    """An unbounded target is rejected fail-closed."""
    assert safe_next_path("/" + "a" * 5000) == "/"
