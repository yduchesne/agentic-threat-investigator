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
    database_pool_size: int = 5
    database_max_overflow: int = 10
    db_batch_size: int = 100
    database_test_guard: bool = True
    database_test_url_pattern: str = "ati-test"
    session_absolute_expiry_seconds: int = 28800
    session_idle_timeout_seconds: int | None = None
    session_cookie_secure: bool = False
    login_rate_limit_maximum: int = 5
    login_rate_limit_window_seconds: int = 60
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None


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


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""

    return Settings()
