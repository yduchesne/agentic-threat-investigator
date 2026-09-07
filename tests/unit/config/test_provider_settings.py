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

    def test_environment_injection(self, monkeypatch: MonkeyPatch) -> None:
        """ATI_* env vars override provider settings."""
        monkeypatch.setenv("ATI_PROVIDER_TIMEOUT_SECONDS", "30.0")
        monkeypatch.setenv("ATI_PROVIDER_MAX_RETRIES", "5")
        monkeypatch.setenv("ATI_GOOGLE_DNS_MAX_CONCURRENCY", "20")
        settings = settings_from_config({})
        assert settings.provider_timeout_seconds == 30.0
        assert settings.provider_max_retries == 5
        assert settings.google_dns_max_concurrency == 20

    @pytest.mark.parametrize(
        "field_name",
        [
            "provider_max_retries",
            "provider_max_response_bytes",
            "google_dns_max_concurrency",
            "rdap_max_concurrency",
            "rdap_bootstrap_cache_seconds",
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
