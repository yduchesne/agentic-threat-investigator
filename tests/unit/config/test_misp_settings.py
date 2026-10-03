# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32C MISP acquisition configuration matrix (M32C-C01..C10)."""

from __future__ import annotations

import asyncio

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import Settings, settings_from_config

_MISP_BASE_URL = "https://misp.example.test"


class _EmptySecrets(SecretsResolver):
    """In-memory resolver returning nothing, so a required secret fails."""

    def get(self, name: str) -> str | None:
        """Return ``None`` for every reference name."""
        return None


class _SettingsSecrets(SecretsResolver):
    """In-memory resolver for the ordinary provider secrets only."""

    def get(self, name: str) -> str | None:
        """Return a value for the non-MISP provider references only."""
        values = {
            "ATI_IPINFO_LITE_TOKEN": "token-x",
            "ATI_ABUSEIPDB_API_KEY": "key-x",
            "ATI_THREATFOX_AUTH_KEY": "key-x",
            "ATI_URLHAUS_AUTH_KEY": "key-x",
        }
        return values.get(name)


class TestMispSettingsMatrix:
    """M32C-C01..C10: defaults, bounds, env precedence, and URL safety."""

    def test_c01_defaults(self) -> None:
        """M32C-C01: the exact documented PR 32C defaults are pinned."""
        settings = settings_from_config({})
        assert settings.misp_base_url == ""
        assert settings.misp_api_key_secret == "ATI_MISP_API_KEY"
        assert settings.misp_max_concurrency == 4
        assert settings.misp_requests_per_second is None
        assert settings.misp_page_size == 100
        assert settings.misp_max_pages == 10
        assert Settings().misp_page_size == 100
        assert Settings().misp_max_pages == 10

    def test_c02_env_base_url_wins(self, monkeypatch: MonkeyPatch) -> None:
        """M32C-C02: the environment base URL overrides the profile value."""
        monkeypatch.setenv("ATI_MISP_BASE_URL", "https://env-misp.example.test")
        settings = settings_from_config({"misp_base_url": _MISP_BASE_URL})
        assert settings.misp_base_url == "https://env-misp.example.test"

    def test_c03_env_secret_reference_loaded_not_resolved(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """M32C-C03: Settings loads the reference name, never the key value."""
        monkeypatch.setenv("ATI_MISP_API_KEY_SECRET", "ATI_MY_MISP_VARIABLE")
        monkeypatch.setenv("ATI_MY_MISP_VARIABLE", "super-secret-value")
        settings = settings_from_config({})
        assert settings.misp_api_key_secret == "ATI_MY_MISP_VARIABLE"
        # The value behind the reference never becomes a settings attribute.
        assert getattr(settings, "misp_api_key", None) is None
        assert "super-secret-value" not in str(settings)

    @pytest.mark.parametrize(
        ("page_size", "max_pages"),
        [
            (1, 1),
            (1, 1000),
            (1000, 1),
            (1000, 1000),
            (250, 40),
        ],
    )
    def test_c04_legal_page_bounds_accepted(
        self, page_size: int, max_pages: int
    ) -> None:
        """M32C-C04: legal page-size/max-pages combinations are accepted."""
        settings = settings_from_config(
            {"misp_page_size": page_size, "misp_max_pages": max_pages}
        )
        assert settings.misp_page_size == page_size
        assert settings.misp_max_pages == max_pages

    @pytest.mark.parametrize(
        "value",
        [0, -1, 1001, 2500, True, 2.5],
    )
    def test_c05_illegal_page_size_rejected(self, value: object) -> None:
        """M32C-C05: illegal page-size values are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({"misp_page_size": value})

    @pytest.mark.parametrize(
        "value",
        [0, -1, 1001, 5000, True, 3.0],
    )
    def test_c06_illegal_max_pages_rejected(self, value: object) -> None:
        """M32C-C06: illegal max-pages values are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({"misp_max_pages": value})

    @pytest.mark.parametrize(
        "value",
        [0, -1, True, 2.5],
    )
    def test_c07_concurrency_bounds_rejected(self, value: object) -> None:
        """M32C-C07: non-positive or non-integral concurrency is rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({"misp_max_concurrency": value})

    @pytest.mark.parametrize(
        "value",
        [0, -1, -0.5, True],
    )
    def test_c08_rps_bounds_rejected(self, value: object) -> None:
        """M32C-C08: a non-positive or non-numeric request rate is rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({"misp_requests_per_second": value})

    @pytest.mark.parametrize(
        "url",
        [
            "http://misp.example.test",
            "ftp://misp.example.test",
            "https://user:pass@misp.example.test",
            "https://misp.example.test?filter=x",
            "https://misp.example.test#frag",
            "not-a-url",
            "",
            "   ",
        ],
    )
    def test_c09_malformed_url_rejected_safely(self, url: str) -> None:
        """M32C-C09: non-HTTPS/credentialed/query/fragment URLs are rejected.

        Blank values stay legal (the unset sentinel); every malformed value
        fails closed without echoing the raw input.
        """
        if not url.strip():
            settings = settings_from_config({"misp_base_url": url})
            assert settings.misp_base_url == ""
            return
        with pytest.raises(ValidationError):
            settings_from_config({"misp_base_url": url})

    def test_c10_no_misp_url_stays_legal_before_32d(self) -> None:
        """M32C-C10: an unset MISP URL keeps ordinary startup legal.

        A local startup with no MISP base URL must not require the MISP API
        key and must not compose a MISP datasource, while the rest of the
        provider composition proceeds normally.
        """
        settings = settings_from_config({})
        assert settings.misp_base_url == ""

        from agentic_threat_investigator.infrastructure.providers.composition import (
            ProviderComposition,
        )

        # The resolver supplies the four ordinary provider secrets but NOT
        # ATI_MISP_API_KEY: composition must still succeed without it.
        async def _compose() -> None:
            async with await ProviderComposition.create(
                settings, secrets=_SettingsSecrets()
            ) as composition:
                assert composition.misp_datasource is None

        asyncio.run(_compose())

    def test_c10b_blank_env_url_stays_legal(self, monkeypatch: MonkeyPatch) -> None:
        """A blank/omitted environment URL is ignored (env_ignore_empty)."""
        monkeypatch.setenv("ATI_MISP_BASE_URL", "")
        settings = settings_from_config({"misp_max_pages": 2})
        assert settings.misp_base_url == ""
        assert settings.misp_max_pages == 2
