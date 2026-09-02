# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Application configuration loaded from the environment."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed settings for the local development runtime."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Agentic Threat Investigator"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://ati:ati@postgres:5432/ati"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""

    return Settings()
