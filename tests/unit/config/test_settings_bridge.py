# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for typed configuration injection and caching."""

import pytest
from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch
from pydantic import ValidationError

from agentic_threat_investigator.config import (
    EmbeddingSettings,
    Settings,
    ensure_test_database_safe,
    get_settings,
    settings_from_config,
)


def test_profile_values_pin_fields_over_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    """Constructor-injected profile values win over ATI environment values."""
    monkeypatch.setenv("ATI_LOG_LEVEL", "WARNING")
    assert settings_from_config({"log_level": "DEBUG"}).log_level == "DEBUG"


def test_unpinned_fields_remain_environment_injectable(
    monkeypatch: MonkeyPatch,
) -> None:
    """Fields absent from profiles still use the environment bridge."""
    monkeypatch.setenv("ATI_SESSION_COOKIE_SECURE", "true")
    assert settings_from_config({}).session_cookie_secure is True


def test_data_dir_derives_datasets_root_and_must_be_absolute() -> None:
    """Artifact storage is rooted under an absolute deployment data path."""
    settings = settings_from_config({"data_dir": "/srv/ati"})
    assert str(settings.datasets_dir) == "/srv/ati/datasets"
    with pytest.raises(ValidationError, match="absolute"):
        settings_from_config({"data_dir": "relative"})


def test_unknown_keys_are_ignored(caplog: LogCaptureFixture) -> None:
    """Forward-compatible profile keys are warned about and ignored."""
    settings = settings_from_config({"future_setting": 1})
    assert isinstance(settings, Settings)
    assert "unrecognized configuration keys" in caplog.text


def test_typed_validation_is_not_silenced() -> None:
    """Invalid profile values fail typed settings construction."""
    with pytest.raises(ValidationError):
        settings_from_config({"db_batch_size": "many"})


def test_embedding_settings_match_fixed_schema_dimension() -> None:
    """Embedding metadata is typed and rejects a DDL dimension mismatch."""
    embedding = EmbeddingSettings(
        dimension=1536,
        provider="hashing",
        model_version=1,
        model="ati-hashing-v1",
    )
    settings = settings_from_config(
        {
            "embedding": embedding,
            "embedding_batch_size": 32,
            "rag_chunk_target_tokens": 200,
            "rag_chunk_max_tokens": 400,
        }
    )
    assert isinstance(settings.embedding, EmbeddingSettings)
    assert settings.embedding_batch_size == 32
    with pytest.raises(ValidationError, match="1536"):
        EmbeddingSettings(
            dimension=8,
            provider="hashing",
            model_version=1,
            model="ati-hashing-v1",
        )


def test_get_settings_is_cached(monkeypatch: MonkeyPatch) -> None:
    """Bootstrap settings are loaded once per process cache lifetime."""
    get_settings.cache_clear()
    monkeypatch.setenv("ATI_CONFIG_PROFILE", "dev")
    first = get_settings()
    second = get_settings()
    assert first is second
    get_settings.cache_clear()


def test_test_database_guard() -> None:
    """The integration safety guard accepts only marked URLs."""
    ensure_test_database_safe("postgresql://host/ati-test")
    with pytest.raises(ValueError):
        ensure_test_database_safe("postgresql://host/ati")


def test_map_geolocation_bound_default_and_validation() -> None:
    """The PR 25A projection bound defaults safely and rejects bad values."""
    settings = settings_from_config({})
    assert settings.api_max_map_geolocation_items == 500
    assert (
        settings_from_config(
            {"api_max_map_geolocation_items": 25}
        ).api_max_map_geolocation_items
        == 25
    )
    with pytest.raises(ValidationError):
        settings_from_config({"api_max_map_geolocation_items": 0})
    with pytest.raises(ValidationError):
        settings_from_config({"api_max_map_geolocation_items": "many"})
    with pytest.raises(ValidationError):
        settings_from_config({"api_max_map_geolocation_items": True})


def test_geo_resolver_bounds_default_and_validation() -> None:
    """PR 26C resolver settings default safely and reject bad values."""
    settings = settings_from_config({})
    assert settings.geo_resolver_enabled is True
    assert settings.geo_resolver_batch_size == 10
    assert settings.geo_resolver_lease_seconds == 300
    assert settings.geo_resolver_max_attempts == 3
    assert settings.geo_resolver_retry_base_seconds == 60.0
    assert settings.geo_resolver_retry_max_seconds == 3600.0
    with pytest.raises(ValidationError, match="retry_max_seconds"):
        settings_from_config(
            {
                "geo_resolver_retry_base_seconds": 120.0,
                "geo_resolver_retry_max_seconds": 60.0,
            }
        )
    with pytest.raises(ValidationError):
        settings_from_config({"geo_resolver_batch_size": 0})
    with pytest.raises(ValidationError):
        settings_from_config({"geo_resolver_lease_seconds": True})
    with pytest.raises(ValidationError):
        settings_from_config({"geo_resolver_max_attempts": 0})
    with pytest.raises(ValidationError):
        settings_from_config({"geo_resolver_poll_interval_seconds": -1})
