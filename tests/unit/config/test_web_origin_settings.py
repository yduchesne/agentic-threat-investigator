# SPDX-License-Identifier: AGPL-3.0-only
"""V07-01 typed browser-origin settings tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.config import Settings


def test_web_base_url_defaults_to_the_api_process_origin() -> None:
    """The server-rendered web origin defaults to the local API origin."""
    settings = Settings()
    assert settings.web_base_url == "http://localhost:8000"


def test_web_base_url_requires_scheme_and_hostname() -> None:
    """A malformed web origin fails closed at settings validation."""
    with pytest.raises(ValidationError):
        Settings(web_base_url="not-a-url")
    with pytest.raises(ValidationError):
        Settings(web_base_url="//host")


def test_csrf_allowed_origins_combines_react_and_web_exactly() -> None:
    """The approved origin set is the exact, deduplicated two-frontend set."""
    settings = Settings(
        public_base_url="http://localhost:8080",
        web_base_url="http://localhost:8000",
    )
    assert settings.csrf_allowed_origins == (
        "http://localhost:8080",
        "http://localhost:8000",
    )


def test_csrf_allowed_origins_deduplicates_identical_origins() -> None:
    """Identical React and web origins collapse to one approved origin."""
    settings = Settings(
        public_base_url="http://localhost:8000/",
        web_base_url="http://localhost:8000",
    )
    assert settings.csrf_allowed_origins == ("http://localhost:8000",)
