# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for provider HTTP settings."""

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import settings_from_config


class TestProviderSettings:
    """Provider HTTP setting validation."""

    def test_defaults(self) -> None:
        """Default provider settings are accepted."""
        settings = settings_from_config({})
        assert settings.provider_timeout_seconds == 15.0
        assert settings.provider_max_retries == 2
        assert settings.provider_retry_base_delay_seconds == 1.0
        assert settings.provider_retry_max_delay_seconds == 30.0
        assert settings.provider_retry_jitter_ratio == 0.1
        assert settings.provider_max_response_bytes == 2_097_152
        assert settings.google_dns_max_concurrency == 10
        assert settings.rdap_max_concurrency == 10
        assert settings.rdap_bootstrap_cache_seconds == 3600
        assert settings.ipinfo_lite_max_concurrency == 10
        assert settings.ipinfo_lite_token_secret == "ATI_IPINFO_LITE_TOKEN"
        assert settings.abuseipdb_max_concurrency == 10
        assert settings.abuseipdb_requests_per_second is None
        assert settings.abuseipdb_api_key_secret == "ATI_ABUSEIPDB_API_KEY"
        assert settings.abuseipdb_max_age_in_days == 30
        assert settings.threatfox_max_concurrency == 10
        assert settings.threatfox_requests_per_second is None
        assert settings.threatfox_auth_key_secret == "ATI_THREATFOX_AUTH_KEY"
        assert settings.urlhaus_max_concurrency == 10
        assert settings.urlhaus_requests_per_second is None
        assert settings.urlhaus_auth_key_secret == "ATI_URLHAUS_AUTH_KEY"

    def test_abuseipdb_api_key_secret_environment_reference(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """The AbuseIPDB secret-reference name is configurable by environment."""
        monkeypatch.setenv("ATI_ABUSEIPDB_API_KEY_SECRET", "MY_CUSTOM_KEY_VAR")
        settings = settings_from_config({})
        assert settings.abuseipdb_api_key_secret == "MY_CUSTOM_KEY_VAR"

    def test_abuseipdb_api_key_secret_blank_rejected(self) -> None:
        """A blank AbuseIPDB secret-reference name is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"abuseipdb_api_key_secret": "   "})

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("abuseipdb_max_concurrency", 0),
            ("abuseipdb_max_concurrency", -1),
            ("abuseipdb_max_concurrency", 2.5),
            ("abuseipdb_max_concurrency", True),
            ("abuseipdb_max_age_in_days", 0),
            ("abuseipdb_max_age_in_days", 366),
            ("abuseipdb_max_age_in_days", -30),
            ("abuseipdb_max_age_in_days", True),
            ("abuseipdb_max_age_in_days", 12.5),
            ("abuseipdb_requests_per_second", 0),
            ("abuseipdb_requests_per_second", -1.0),
            ("abuseipdb_requests_per_second", True),
        ],
    )
    def test_abuseipdb_bounds_rejected(self, field: str, value: object) -> None:
        """Out-of-bounds and non-coercive AbuseIPDB values are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    def test_abuseipdb_environment_parsing(self, monkeypatch: MonkeyPatch) -> None:
        """AbuseIPDB settings parse from environment text."""
        monkeypatch.setenv("ATI_ABUSEIPDB_MAX_CONCURRENCY", "3")
        monkeypatch.setenv("ATI_ABUSEIPDB_REQUESTS_PER_SECOND", "5.5")
        monkeypatch.setenv("ATI_ABUSEIPDB_MAX_AGE_IN_DAYS", "60")
        settings = settings_from_config({})
        assert settings.abuseipdb_max_concurrency == 3
        assert settings.abuseipdb_requests_per_second == 5.5
        assert settings.abuseipdb_max_age_in_days == 60

    def test_threatfox_auth_key_secret_environment_reference(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """The ThreatFox secret-reference name is configurable by environment."""
        monkeypatch.setenv("ATI_THREATFOX_AUTH_KEY_SECRET", "MY_CUSTOM_KEY_VAR")
        settings = settings_from_config({})
        assert settings.threatfox_auth_key_secret == "MY_CUSTOM_KEY_VAR"

    def test_threatfox_auth_key_secret_blank_rejected(self) -> None:
        """A blank ThreatFox secret-reference name is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"threatfox_auth_key_secret": "   "})

    def test_threatfox_auth_key_secret_whitespace_trimmed(self) -> None:
        """The ThreatFox secret-reference name is trimmed of whitespace."""
        settings = settings_from_config({"threatfox_auth_key_secret": "  VAR  "})
        assert settings.threatfox_auth_key_secret == "VAR"

    def test_urlhaus_auth_key_secret_environment_reference(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """The URLhaus secret-reference name is configurable by environment."""
        monkeypatch.setenv("ATI_URLHAUS_AUTH_KEY_SECRET", "MY_CUSTOM_KEY_VAR")
        settings = settings_from_config({})
        assert settings.urlhaus_auth_key_secret == "MY_CUSTOM_KEY_VAR"

    def test_urlhaus_auth_key_secret_blank_rejected(self) -> None:
        """A blank URLhaus secret-reference name is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"urlhaus_auth_key_secret": "   "})

    def test_urlhaus_auth_key_secret_whitespace_trimmed(self) -> None:
        """The URLhaus secret-reference name is trimmed of whitespace."""
        settings = settings_from_config({"urlhaus_auth_key_secret": "  VAR  "})
        assert settings.urlhaus_auth_key_secret == "VAR"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("urlhaus_max_concurrency", 0),
            ("urlhaus_max_concurrency", -1),
            ("urlhaus_max_concurrency", 2.5),
            ("urlhaus_max_concurrency", True),
            ("urlhaus_requests_per_second", 0),
            ("urlhaus_requests_per_second", -1.0),
            ("urlhaus_requests_per_second", True),
        ],
    )
    def test_urlhaus_bounds_rejected(self, field: str, value: object) -> None:
        """Out-of-bounds and non-coercive URLhaus values are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    def test_urlhaus_environment_parsing(self, monkeypatch: MonkeyPatch) -> None:
        """URLhaus settings parse from environment text."""
        monkeypatch.setenv("ATI_URLHAUS_MAX_CONCURRENCY", "7")
        monkeypatch.setenv("ATI_URLHAUS_REQUESTS_PER_SECOND", "6.5")
        settings = settings_from_config({})
        assert settings.urlhaus_max_concurrency == 7
        assert settings.urlhaus_requests_per_second == 6.5

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("threatfox_max_concurrency", 0),
            ("threatfox_max_concurrency", -1),
            ("threatfox_max_concurrency", 2.5),
            ("threatfox_max_concurrency", True),
            ("threatfox_requests_per_second", 0),
            ("threatfox_requests_per_second", -1.0),
            ("threatfox_requests_per_second", True),
        ],
    )
    def test_threatfox_bounds_rejected(self, field: str, value: object) -> None:
        """Out-of-bounds and non-coercive ThreatFox values are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    def test_threatfox_environment_parsing(self, monkeypatch: MonkeyPatch) -> None:
        """ThreatFox settings parse from environment text."""
        monkeypatch.setenv("ATI_THREATFOX_MAX_CONCURRENCY", "7")
        monkeypatch.setenv("ATI_THREATFOX_REQUESTS_PER_SECOND", "2.5")
        settings = settings_from_config({})
        assert settings.threatfox_max_concurrency == 7
        assert settings.threatfox_requests_per_second == 2.5

    def test_ipinfo_token_secret_environment_reference(
        self, monkeypatch: MonkeyPatch
    ) -> None:
        """The IPinfo secret-reference name is configurable by environment."""
        monkeypatch.setenv("ATI_IPINFO_LITE_TOKEN_SECRET", "MY_CUSTOM_TOKEN_VAR")
        settings = settings_from_config({})
        assert settings.ipinfo_lite_token_secret == "MY_CUSTOM_TOKEN_VAR"

    def test_ipinfo_token_secret_blank_rejected(self) -> None:
        """A blank IPinfo secret-reference name is rejected."""
        with pytest.raises(ValidationError, match="blank"):
            settings_from_config({"ipinfo_lite_token_secret": "   "})

    def test_ipinfo_token_secret_whitespace_trimmed(self) -> None:
        """The IPinfo secret-reference name is trimmed of whitespace."""
        settings = settings_from_config({"ipinfo_lite_token_secret": "  VAR  "})
        assert settings.ipinfo_lite_token_secret == "VAR"

    def test_environment_injection(self, monkeypatch: MonkeyPatch) -> None:
        """ATI_* env vars override provider settings."""
        monkeypatch.setenv("ATI_PROVIDER_TIMEOUT_SECONDS", "30.0")
        monkeypatch.setenv("ATI_PROVIDER_MAX_RETRIES", "5")
        monkeypatch.setenv("ATI_GOOGLE_DNS_MAX_CONCURRENCY", "20")
        settings = settings_from_config({})
        assert settings.provider_timeout_seconds == 30.0
        assert settings.provider_max_retries == 5
        assert settings.google_dns_max_concurrency == 20

    def test_ipinfo_environment_parsing(self, monkeypatch: MonkeyPatch) -> None:
        """IPinfo concurrency and rate settings parse from environment text."""
        monkeypatch.setenv("ATI_IPINFO_LITE_MAX_CONCURRENCY", "4")
        monkeypatch.setenv("ATI_IPINFO_LITE_REQUESTS_PER_SECOND", "12.5")
        settings = settings_from_config({})
        assert settings.ipinfo_lite_max_concurrency == 4
        assert settings.ipinfo_lite_requests_per_second == 12.5

    @pytest.mark.parametrize(
        "field_name",
        [
            "provider_max_retries",
            "provider_max_response_bytes",
            "google_dns_max_concurrency",
            "rdap_max_concurrency",
            "rdap_bootstrap_cache_seconds",
            "ipinfo_lite_max_concurrency",
        ],
    )
    @pytest.mark.parametrize("bad_value", [True, False, 1.0, 1.5, None])
    def test_integer_profile_values_reject_coercion(
        self, field_name: str, bad_value: object
    ) -> None:
        """Typed profile values cannot coerce booleans or floats to integers."""
        with pytest.raises(ValidationError, match="integer"):
            settings_from_config({field_name: bad_value})

    @pytest.mark.parametrize(
        "field_name",
        [
            "provider_timeout_seconds",
            "provider_retry_base_delay_seconds",
            "provider_retry_max_delay_seconds",
            "provider_retry_jitter_ratio",
            "google_dns_requests_per_second",
            "rdap_requests_per_second",
            "ipinfo_lite_requests_per_second",
        ],
    )
    def test_real_profile_values_reject_booleans(self, field_name: str) -> None:
        """Boolean profile values are not provider timing or rate numbers."""
        with pytest.raises(ValidationError, match="real number"):
            settings_from_config({field_name: True})

    def test_zero_timeout_rejected(self) -> None:
        """A zero timeout is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"provider_timeout_seconds": 0})

    def test_negative_retries_rejected(self) -> None:
        """Negative max retries are rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"provider_max_retries": -1})

    def test_max_delay_lt_base_rejected(self) -> None:
        """A max delay smaller than the base delay is rejected."""
        with pytest.raises(ValidationError, match="max"):
            settings_from_config(
                {
                    "provider_retry_base_delay_seconds": 10.0,
                    "provider_retry_max_delay_seconds": 5.0,
                }
            )

    def test_jitter_ratio_out_of_range_rejected(self) -> None:
        """A jitter ratio outside [0,1] is rejected."""
        with pytest.raises(ValidationError, match="less_than"):
            settings_from_config({"provider_retry_jitter_ratio": 1.5})

    def test_zero_response_bytes_rejected(self) -> None:
        """A zero max_response_bytes is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"provider_max_response_bytes": 0})

    def test_response_bytes_too_large_rejected(self) -> None:
        """An unreasonably large max_response_bytes is rejected."""
        with pytest.raises(ValidationError, match="less_than_equal"):
            settings_from_config({"provider_max_response_bytes": 200_000_000})

    def test_optional_rate_omitted(self) -> None:
        """Omitting optional RPS settings leaves them as None."""
        settings = settings_from_config({})
        assert settings.google_dns_requests_per_second is None
        assert settings.rdap_requests_per_second is None

    def test_optional_rate_positive(self) -> None:
        """A positive RPS value is accepted."""
        settings = settings_from_config({"google_dns_requests_per_second": 10.0})
        assert settings.google_dns_requests_per_second == 10.0

    def test_optional_rate_zero_rejected(self) -> None:
        """A zero RPS value is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"google_dns_requests_per_second": 0})

    def test_optional_rate_negative_rejected(self) -> None:
        """A negative RPS value is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"rdap_requests_per_second": -1.0})

    def test_concurrency_zero_rejected(self) -> None:
        """Zero concurrency is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"google_dns_max_concurrency": 0})

    def test_ipinfo_concurrency_zero_rejected(self) -> None:
        """Zero IPinfo concurrency is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"ipinfo_lite_max_concurrency": 0})

    def test_ipinfo_optional_rate_zero_rejected(self) -> None:
        """A zero IPinfo RPS value is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"ipinfo_lite_requests_per_second": 0})

    def test_ipinfo_optional_rate_omitted(self) -> None:
        """Omitting the optional IPinfo RPS setting leaves it as None."""
        settings = settings_from_config({})
        assert settings.ipinfo_lite_requests_per_second is None

    def test_ipinfo_optional_rate_positive(self) -> None:
        """A positive IPinfo RPS value is accepted."""
        settings = settings_from_config({"ipinfo_lite_requests_per_second": 5.0})
        assert settings.ipinfo_lite_requests_per_second == 5.0

    def test_cache_lifetime_zero_rejected(self) -> None:
        """Zero cache lifetime is rejected."""
        with pytest.raises(ValidationError, match="greater_than"):
            settings_from_config({"rdap_bootstrap_cache_seconds": 0})

    @pytest.mark.parametrize(
        "field_name",
        [
            "provider_timeout_seconds",
            "provider_retry_base_delay_seconds",
            "provider_retry_max_delay_seconds",
            "provider_retry_jitter_ratio",
            "google_dns_requests_per_second",
            "rdap_requests_per_second",
            "ipinfo_lite_requests_per_second",
        ],
    )
    def test_positive_infinity_rejected(self, field_name: str) -> None:
        """Positive infinity is not a finite bounded provider setting."""
        with pytest.raises(ValidationError, match="finite"):
            settings_from_config({field_name: float("inf")})

    def test_negative_infinity_timeout_rejected(self) -> None:
        """Negative infinity is rejected by finiteness before sign checks."""
        with pytest.raises(ValidationError, match="finite"):
            settings_from_config({"provider_timeout_seconds": float("-inf")})

    @pytest.mark.parametrize(
        "field_name",
        [
            "provider_timeout_seconds",
            "provider_retry_base_delay_seconds",
            "provider_retry_max_delay_seconds",
            "provider_retry_jitter_ratio",
            "google_dns_requests_per_second",
            "rdap_requests_per_second",
            "ipinfo_lite_requests_per_second",
        ],
    )
    def test_nan_rejected(self, field_name: str) -> None:
        """NaN is not a finite provider setting and violates sign bounds."""
        with pytest.raises(ValidationError, match="finite"):
            settings_from_config({field_name: float("nan")})

    def test_optional_rate_none_remains_accepted(self) -> None:
        """The optional rate settings still accept None (rate limiting off)."""
        settings = settings_from_config(
            {
                "google_dns_requests_per_second": None,
                "rdap_requests_per_second": None,
            }
        )
        assert settings.google_dns_requests_per_second is None
        assert settings.rdap_requests_per_second is None

    def test_finite_boundary_values_accepted(self) -> None:
        """Representative finite boundary values remain accepted."""
        settings = settings_from_config(
            {
                "provider_timeout_seconds": 0.5,
                "provider_retry_base_delay_seconds": 0.0,
                "provider_retry_max_delay_seconds": 0.0,
                "provider_retry_jitter_ratio": 1.0,
                "google_dns_requests_per_second": 0.001,
                "rdap_requests_per_second": 1000.0,
            }
        )
        assert settings.provider_timeout_seconds == 0.5
        assert settings.provider_retry_base_delay_seconds == 0.0
        assert settings.provider_retry_max_delay_seconds == 0.0
        assert settings.provider_retry_jitter_ratio == 1.0
        assert settings.google_dns_requests_per_second == 0.001
        assert settings.rdap_requests_per_second == 1000.0


class TestDbIpCityLiteArtifactSettings:
    """DB-IP City Lite artifact-URI setting validation."""

    def test_default_is_blank(self) -> None:
        """The artifact URI defaults to blank, disabling the provider."""
        settings = settings_from_config({})
        assert settings.dbip_city_lite_artifact_uri == ""

    def test_valid_local_uri_accepted(self) -> None:
        """A credential-free authority-free file URI is accepted."""
        uri = "file:///var/lib/ati/datasets/dbip-city-lite/city-lite.mmdb"
        settings = settings_from_config({"dbip_city_lite_artifact_uri": uri})
        assert settings.dbip_city_lite_artifact_uri == uri

    def test_whitespace_trimmed(self) -> None:
        """Surrounding whitespace around the URI is trimmed."""
        settings = settings_from_config(
            {"dbip_city_lite_artifact_uri": "  file:///data/datasets/db.mmdb  "}
        )
        assert settings.dbip_city_lite_artifact_uri == "file:///data/datasets/db.mmdb"

    def test_blank_remains_disabled(self) -> None:
        """A blank or whitespace-only URI remains blank (provider disabled)."""
        for blank in ["", "   "]:
            settings = settings_from_config({"dbip_city_lite_artifact_uri": blank})
            assert settings.dbip_city_lite_artifact_uri == ""

    @pytest.mark.parametrize(
        "bad_uri",
        [
            "https://example.com/db.mmdb",
            "s3://bucket/db.mmdb",
            "file://host/share/db.mmdb",
            "file://user:pass@example.com/db.mmdb",
            "file:///data/db.mmdb?token=x",
            "file:///data/db.mmdb#frag",
            "file:relative/path.mmdb",
            "not a uri at all",
        ],
    )
    def test_unsupported_or_credential_bearing_uri_rejected(self, bad_uri: str) -> None:
        """Non-file, authority-bearing, and fragment/query URIs are rejected."""
        with pytest.raises(ValidationError):
            settings_from_config({"dbip_city_lite_artifact_uri": bad_uri})

    def test_non_secret_treatment(self) -> None:
        """The artifact URI is a plain setting, not a secret reference."""
        settings = settings_from_config(
            {"dbip_city_lite_artifact_uri": "file:///data/datasets/db.mmdb"}
        )
        # Plain setting: directly readable, no secret-reference indirection.
        assert settings.dbip_city_lite_artifact_uri == "file:///data/datasets/db.mmdb"
        assert not hasattr(settings, "dbip_city_lite_artifact_secret")


class TestDbIpCityLiteArtifactEnvironment:
    """Environment injection for the DB-IP City Lite artifact URI."""

    def test_environment_value_parsed(self, monkeypatch: MonkeyPatch) -> None:
        """ATI_DBIP_CITY_LITE_ARTIFACT_URI overrides the blank default."""
        monkeypatch.setenv(
            "ATI_DBIP_CITY_LITE_ARTIFACT_URI",
            "file:///var/lib/ati/datasets/dbip-city-lite/city-lite.mmdb",
        )
        settings = settings_from_config({})
        assert (
            settings.dbip_city_lite_artifact_uri
            == "file:///var/lib/ati/datasets/dbip-city-lite/city-lite.mmdb"
        )
