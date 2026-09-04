# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application settings and the configuration bootstrap bridge."""

import logging
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentic_threat_investigator.config.config_utils import Config, load_config

DOCUMENT_CHUNK_EMBEDDING_DIMENSION = 1536


class EmbeddingSettings(BaseModel):
    """Configured embedding representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    dimension: int = Field(ge=1)
    provider: str
    model_version: int = Field(ge=1)
    model: str

    @model_validator(mode="after")
    def validate_embedding_contract(self) -> "EmbeddingSettings":
        """Reject blank identifiers and dimensions incompatible with the DDL."""
        if not self.provider.strip() or not self.model.strip():
            raise ValueError("embedding provider and model must not be blank")
        if self.dimension != DOCUMENT_CHUNK_EMBEDDING_DIMENSION:
            raise ValueError(
                f"embedding dimension must be {DOCUMENT_CHUNK_EMBEDDING_DIMENSION}"
            )
        return self


class Settings(BaseSettings):
    """Typed settings for the local development runtime."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ATI_", extra="ignore"
    )

    app_name: str = "Agentic Threat Investigator"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://ati:ati@postgres:5432/ati"
    log_level: str = "INFO"
    database_pool_size: int = 5
    database_max_overflow: int = 10
    db_batch_size: int = 100
    embedding: EmbeddingSettings = EmbeddingSettings(
        provider="hashing", model="ati-hashing-v1", model_version=1, dimension=1536
    )
    embedding_batch_size: int = Field(default=64, ge=1)
    rag_chunk_target_tokens: int = Field(default=400, ge=1)
    rag_chunk_max_tokens: int = Field(default=800, ge=1)
    data_dir: Path = Path("/var/lib/ati")
    database_test_guard: bool = True
    database_test_url_pattern: str = "ati-test"
    session_absolute_expiry_seconds: int = 28800
    session_idle_timeout_seconds: int | None = None
    session_cookie_secure: bool = False
    login_rate_limit_maximum: int = 5
    login_rate_limit_window_seconds: int = 60
    public_base_url: str = "http://localhost:8000"
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    @model_validator(mode="after")
    def validate_chunk_bounds(self) -> "Settings":
        """Require the target chunk size not to exceed the hard maximum."""
        if self.rag_chunk_target_tokens > self.rag_chunk_max_tokens:
            raise ValueError(
                "rag_chunk_target_tokens must not exceed rag_chunk_max_tokens"
            )
        return self

    @field_validator("data_dir")
    @classmethod
    def validate_data_dir(cls, value: Path) -> Path:
        """Require an absolute deployment data root."""
        if not value.is_absolute():
            raise ValueError("data_dir must be an absolute path")
        return value

    @property
    def datasets_dir(self) -> Path:
        """Return the filesystem object-store root below the data directory."""
        return self.data_dir / "datasets"

    @field_validator("public_base_url")
    @classmethod
    def validate_public_base_url(cls, value: str) -> str:
        """Require a configured public URL with a scheme and hostname."""
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("public_base_url is malformed") from exc
        if not parsed.scheme or not hostname:
            raise ValueError("public_base_url must contain a scheme and hostname")
        return value


def ensure_test_database_safe(
    database_url: str, *, expected_marker: str = "ati-test"
) -> None:
    """Reject a test URL that could point at the normal developer database.

    Integration harnesses must opt into an unmistakable test database name.
    This guard intentionally fails closed rather than attempting to infer
    whether a shared database is safe.
    """
    if expected_marker not in database_url:
        raise ValueError(
            "refusing integration tests against a non-isolated database URL"
        )


def settings_from_config(config: Config) -> Settings:
    """Build typed settings from profile values and runtime environment.

    Profile values are constructor arguments and therefore take precedence over
    environment variables. Unknown profile values remain available for future
    wiring and are reported without preventing startup.
    """
    field_names = set(Settings.model_fields)
    recognized = {key: value for key, value in config.items() if key in field_names}
    unknown = sorted(set(config) - field_names)
    if unknown:
        logging.getLogger(__name__).warning(
            "unrecognized configuration keys keys=%s", unknown
        )
    return Settings(**recognized)


@lru_cache
def get_settings() -> Settings:
    """Return the one-shot, cached application settings."""
    return settings_from_config(load_config())
