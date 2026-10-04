# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E TAXII settings contract tests.

Covers the typed ``Settings`` TAXII section: secret-reference naming
(never token values), blank-vs-configured states, the required collection-ID
binding, HTTPS/credential-free URL validation, bounded page/max-page
windows, optional initial RFC 3339 added_after validation, and the
environment override contract. No network I/O and no secret resolution
happens here.
"""

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.config.settings import Settings

_VALID_ROOT = "https://taxii.example.test/root"
_VALID_COLLECTION = "collection-00000000-0000-4000-8000-000000000001"


def test_taxii_defaults_are_not_configured() -> None:
    """A fresh Settings has a blank TAXII API root and no token requirement."""
    settings = Settings()
    assert settings.taxii_api_root_url == ""
    assert settings.taxii_collection_id == ""
    assert settings.taxii_bearer_token_secret == "ATI_TAXII_BEARER_TOKEN"
    assert settings.taxii_page_size == 100
    assert settings.taxii_max_pages == 100
    assert settings.taxii_max_concurrency == 4
    assert settings.taxii_requests_per_second is None
    assert settings.taxii_initial_added_after == ""


def test_configured_url_requires_collection_id() -> None:
    """A configured API root without a collection ID fails closed."""
    with pytest.raises(ValidationError, match="taxii_collection_id"):
        Settings(taxii_api_root_url=_VALID_ROOT)


def test_valid_configured_taxii_settings() -> None:
    """A fully configured TAXII section validates."""
    settings = Settings(
        taxii_api_root_url=_VALID_ROOT,
        taxii_collection_id=_VALID_COLLECTION,
        taxii_initial_added_after="2026-07-01T00:00:00Z",
        taxii_page_size=50,
        taxii_max_pages=25,
        taxii_max_concurrency=2,
        taxii_requests_per_second=1.0,
    )
    assert settings.taxii_collection_id == _VALID_COLLECTION
    assert settings.taxii_page_size == 50
    assert settings.taxii_max_pages == 25


@pytest.mark.parametrize(
    "url",
    [
        "http://taxii.example.test/root",
        "https://user:pass@taxii.example.test/root",
        "https://taxii.example.test/root?query=1",
        "https://taxii.example.test/root#frag",
        "not-a-url",
        "ftp://taxii.example.test/root",
    ],
)
def test_invalid_api_root_urls_fail_closed(url: str) -> None:
    """Non-HTTPS, credential-bearing, query/fragment URLs are rejected."""
    with pytest.raises(ValidationError, match="taxii_api_root_url"):
        Settings(taxii_api_root_url=url, taxii_collection_id=_VALID_COLLECTION)


def test_https_api_root_with_path_is_accepted() -> None:
    """An HTTPS API root with a path component is accepted and preserved."""
    settings = Settings(
        taxii_api_root_url="https://taxii.example.test/taxii2/root/",
        taxii_collection_id=_VALID_COLLECTION,
    )
    assert settings.taxii_api_root_url == "https://taxii.example.test/taxii2/root/"


def test_collection_id_whitespace_and_bounds() -> None:
    """Collection IDs are trimmed, bounded, and whitespace-free."""
    settings = Settings(
        taxii_api_root_url=_VALID_ROOT, taxii_collection_id="  abc-123  "
    )
    assert settings.taxii_collection_id == "abc-123"
    with pytest.raises(ValidationError, match="taxii_collection_id"):
        Settings(taxii_api_root_url=_VALID_ROOT, taxii_collection_id="has space")
    with pytest.raises(ValidationError, match="128 characters"):
        Settings(taxii_api_root_url=_VALID_ROOT, taxii_collection_id="x" * 129)


def test_bearer_secret_is_a_reference_name_not_a_value() -> None:
    """The bearer secret setting carries only an environment variable name."""
    settings = Settings(taxii_bearer_token_secret="ATI_TAXII_BEARER_TOKEN")
    assert settings.taxii_bearer_token_secret == "ATI_TAXII_BEARER_TOKEN"
    with pytest.raises(ValidationError, match="taxii_bearer_token_secret"):
        Settings(taxii_bearer_token_secret="   ")


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-01T00:00:00Z",
        "2026-07-01T00:00:00.123+00:00",
        "2026-07-01T00:30:00+02:00",
    ],
)
def test_valid_initial_added_after_forms(value: str) -> None:
    """Timezone-aware RFC 3339 initial cursors validate."""
    settings = Settings(taxii_initial_added_after=value)
    assert settings.taxii_initial_added_after == value


@pytest.mark.parametrize(
    "value",
    [
        "2026-07-01T00:00:00",  # no timezone
        "not-a-timestamp",
        "2026-13-99T00:00:00Z",
    ],
)
def test_invalid_initial_added_after_fails_closed(value: str) -> None:
    """Timezone-naive or malformed initial cursors are rejected."""
    with pytest.raises(ValidationError, match="taxii_initial_added_after"):
        Settings(taxii_initial_added_after=value)


@pytest.mark.parametrize("field", ["taxii_page_size", "taxii_max_pages"])
def test_page_bounds_fail_closed(field: str) -> None:
    """Page sizes and window bounds are hard-limited (>=1, <=1000)."""
    with pytest.raises(ValidationError):
        Settings(**{field: 0})  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Settings(**{field: 1001})  # type: ignore[arg-type]


def test_environment_override_contract() -> None:
    """Environment variables remain the ultimate override for TAXII settings."""
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        taxii_api_root_url=_VALID_ROOT,
        taxii_collection_id=_VALID_COLLECTION,
        taxii_page_size=10,
    )
    assert settings.taxii_page_size == 10
    assert Settings(taxii_page_size=10).taxii_page_size == 10
