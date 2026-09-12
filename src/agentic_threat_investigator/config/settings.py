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
    """Configured embedding representation.

    ``api_key_secret`` carries only the NAME of the environment variable
    holding the provider API key (a secret reference, never a key value);
    the key is resolved during bootstrap/composition and passed to the
    constructed provider. Local/dev defaults remain the deterministic
    hashing utility, so startup never requires OpenAI credentials merely
    because the semantic adapter exists.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    dimension: int = Field(ge=1)
    provider: str
    model_version: int = Field(ge=1)
    model: str
    api_key_secret: str = "ATI_OPENAI_EMBEDDING_API_KEY"
    timeout_seconds: float | None = Field(default=None, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_embedding_contract(self) -> "EmbeddingSettings":
        """Reject blank identifiers and dimensions incompatible with the DDL."""
        if not self.provider.strip() or not self.model.strip():
            raise ValueError("embedding provider and model must not be blank")
        if not self.api_key_secret.strip():
            raise ValueError("embedding api_key_secret must not be blank")
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

    # Provider HTTP settings. allow_inf_nan=False guarantees bounded finite
    # timeouts, backoff delays, jitter, and request rates at the settings
    # boundary; NaN and both infinities are rejected during validation.
    provider_timeout_seconds: float = Field(default=15.0, gt=0, allow_inf_nan=False)
    provider_max_retries: int = Field(default=2, ge=0)
    provider_retry_base_delay_seconds: float = Field(
        default=1.0, ge=0, allow_inf_nan=False
    )
    provider_retry_max_delay_seconds: float = Field(
        default=30.0, ge=0, allow_inf_nan=False
    )
    provider_retry_jitter_ratio: float = Field(
        default=0.1, ge=0, le=1, allow_inf_nan=False
    )
    provider_max_response_bytes: int = Field(default=2_097_152, gt=0, le=100_000_000)
    google_dns_max_concurrency: int = Field(default=10, gt=0)
    google_dns_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    rdap_max_concurrency: int = Field(default=10, gt=0)
    rdap_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    rdap_bootstrap_cache_seconds: int = Field(default=3600, gt=0)
    ipinfo_lite_max_concurrency: int = Field(default=10, gt=0)
    ipinfo_lite_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    # Secret reference name only: the environment variable carrying the
    # IPinfo Lite access token. The token value itself is resolved outside
    # configuration during composition and never stored or logged here.
    ipinfo_lite_token_secret: str = "ATI_IPINFO_LITE_TOKEN"
    # AbuseIPDB provider settings. The secret setting carries only the NAME
    # of the environment variable holding the API key; the key value is
    # resolved outside configuration during composition and never stored or
    # logged here. The report look-back window is fixed per deployment.
    abuseipdb_max_concurrency: int = Field(default=10, gt=0)
    abuseipdb_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    abuseipdb_api_key_secret: str = "ATI_ABUSEIPDB_API_KEY"
    abuseipdb_max_age_in_days: int = Field(default=30, ge=1, le=365)
    # ThreatFox provider settings. The secret setting carries only the NAME
    # of the environment variable holding the abuse.ch Auth-Key; the key
    # value is resolved outside configuration during composition and never
    # stored or logged here.
    threatfox_max_concurrency: int = Field(default=10, gt=0)
    threatfox_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    threatfox_auth_key_secret: str = "ATI_THREATFOX_AUTH_KEY"
    # URLhaus provider settings. The secret setting carries only the NAME
    # of the environment variable holding the abuse.ch Auth-Key; the key
    # value is resolved outside configuration during composition and never
    # stored or logged here.
    urlhaus_max_concurrency: int = Field(default=10, gt=0)
    urlhaus_requests_per_second: float | None = Field(
        default=None, gt=0, allow_inf_nan=False
    )
    urlhaus_auth_key_secret: str = "ATI_URLHAUS_AUTH_KEY"
    # LLM settings (PR 20B). The secret setting carries only the NAME of the
    # environment variable holding the provider API key; the key value is
    # resolved outside configuration during composition and never stored or
    # logged here. Deterministic analysis configuration defaults to
    # temperature 0. Structured-output attempts are explicitly bounded: the
    # initial attempt plus at most one schema-repair retry.
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = Field(default=60.0, gt=0, allow_inf_nan=False)
    llm_max_structured_output_attempts: int = Field(default=2, ge=1, le=2)
    llm_api_key_secret: str = "ATI_OPENAI_API_KEY"
    llm_temperature: float = Field(default=0.0, ge=0, le=2, allow_inf_nan=False)
    llm_max_tokens: int | None = Field(default=None, gt=0)
    # Deterministic analyst context bounds (PR 20B). The same persisted
    # investigation state must produce the same bounded analyst input; an
    # oversize input fails with a typed application error before any model
    # call rather than being silently truncated.
    llm_max_evidence_items: int = Field(default=100, ge=1, le=500)
    llm_max_relationship_observations: int = Field(default=200, ge=1, le=1000)
    llm_max_normalized_facts_bytes: int = Field(default=131_072, ge=1000, le=1_000_000)
    llm_max_input_bytes: int = Field(default=262_144, ge=1_000, le=1_000_000)
    # Deterministic Report Writer context bounds (PR 23B). The same persisted
    # investigation state must produce the same bounded report input; an
    # oversize input fails with a typed application error before any model
    # call rather than being silently truncated.
    report_writer_max_findings: int = Field(default=50, ge=1, le=500)
    report_writer_max_evidence: int = Field(default=100, ge=1, le=500)
    report_writer_max_relationship_observations: int = Field(default=200, ge=1, le=1000)
    report_writer_max_research_results: int = Field(default=20, ge=1, le=200)
    report_writer_max_research_claims: int = Field(default=100, ge=1, le=2000)
    report_writer_max_input_bytes: int = Field(default=262_144, ge=1_000, le=1_000_000)
    # Analyst-facing collection query page limits (PR 23A). The default is
    # applied when a caller omits a limit; the maximum is the hard ceiling
    # validated by every query service.
    query_default_page_size: int = Field(default=50, ge=1)
    query_max_page_size: int = Field(default=200, ge=1)
    # Credentialed cookie CORS (PR 23C). Explicit configured frontend
    # origin(s) only; the wildcard is rejected so credentialed requests can
    # never be sent cross-origin. Defaults to the local dev frontend.
    api_cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:8080"]
    )
    # Submission request bounds (PR 23C) shared by the API DTOs and the
    # application submission service.
    api_max_indicator_count: int = Field(default=20, ge=1)
    api_max_indicator_value_length: int = Field(default=2048, ge=1)
    api_max_objective_length: int = Field(default=4000, ge=1)
    # Request body ceiling for /api/v1 (PR 23C): the largest legitimate
    # create-Investigation request is far below this bound.
    api_max_request_body_bytes: int = Field(default=65_536, ge=1024)
    # Credential-free local artifact URI of the DB-IP IP to City Lite MMDB.
    # Blank (default) disables the DB-IP City Lite provider. This is a plain
    # artifact location, not a secret; it is validated as an authority-free
    # file:// URI without credentials, query, or fragment parts.
    dbip_city_lite_artifact_uri: str = ""

    @field_validator(
        "provider_max_retries",
        "provider_max_response_bytes",
        "google_dns_max_concurrency",
        "rdap_max_concurrency",
        "rdap_bootstrap_cache_seconds",
        "ipinfo_lite_max_concurrency",
        "abuseipdb_max_concurrency",
        "abuseipdb_max_age_in_days",
        "threatfox_max_concurrency",
        "urlhaus_max_concurrency",
        mode="before",
    )
    @classmethod
    def validate_provider_integer_types(cls, value: object) -> object:
        """Reject coercive non-integers while retaining environment text parsing."""
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("provider integer setting must be an integer")
        return value

    @field_validator(
        "provider_timeout_seconds",
        "provider_retry_base_delay_seconds",
        "provider_retry_max_delay_seconds",
        "provider_retry_jitter_ratio",
        "google_dns_requests_per_second",
        "rdap_requests_per_second",
        "ipinfo_lite_requests_per_second",
        "abuseipdb_requests_per_second",
        "threatfox_requests_per_second",
        "urlhaus_requests_per_second",
        mode="before",
    )
    @classmethod
    def validate_provider_real_types(cls, value: object) -> object:
        """Reject booleans masquerading as provider timing or rate numbers."""
        if isinstance(value, bool):
            raise ValueError("provider numeric setting must be a real number")
        return value

    @field_validator("ipinfo_lite_token_secret")
    @classmethod
    def validate_ipinfo_lite_token_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never a token value)."""
        if not value.strip():
            raise ValueError("ipinfo_lite_token_secret must not be blank")
        return value.strip()

    @field_validator("abuseipdb_api_key_secret")
    @classmethod
    def validate_abuseipdb_api_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never an API key value)."""
        if not value.strip():
            raise ValueError("abuseipdb_api_key_secret must not be blank")
        return value.strip()

    @field_validator("threatfox_auth_key_secret")
    @classmethod
    def validate_threatfox_auth_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never an Auth-Key value)."""
        if not value.strip():
            raise ValueError("threatfox_auth_key_secret must not be blank")
        return value.strip()

    @field_validator("urlhaus_auth_key_secret")
    @classmethod
    def validate_urlhaus_auth_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never an Auth-Key value)."""
        if not value.strip():
            raise ValueError("urlhaus_auth_key_secret must not be blank")
        return value.strip()

    @field_validator("llm_api_key_secret")
    @classmethod
    def validate_llm_api_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never an API key value)."""
        if not value.strip():
            raise ValueError("llm_api_key_secret must not be blank")
        return value.strip()

    @field_validator("llm_model")
    @classmethod
    def validate_llm_model(cls, value: str) -> str:
        """Require a non-blank model identifier."""
        if not value.strip():
            raise ValueError("llm_model must not be blank")
        return value.strip()

    @field_validator(
        "query_default_page_size",
        "query_max_page_size",
        "api_max_indicator_count",
        "api_max_indicator_value_length",
        "api_max_objective_length",
        "api_max_request_body_bytes",
        mode="before",
    )
    @classmethod
    def validate_query_page_size_types(cls, value: object) -> object:
        """Reject coercive non-integers while retaining environment text parsing."""
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("bounded integer setting must be an integer")
        return value

    @field_validator(
        "llm_max_structured_output_attempts",
        "llm_max_evidence_items",
        "llm_max_relationship_observations",
        "llm_max_normalized_facts_bytes",
        "llm_max_input_bytes",
        "llm_max_tokens",
        "report_writer_max_findings",
        "report_writer_max_evidence",
        "report_writer_max_relationship_observations",
        "report_writer_max_research_results",
        "report_writer_max_research_claims",
        "report_writer_max_input_bytes",
        mode="before",
    )
    @classmethod
    def validate_llm_integer_types(cls, value: object) -> object:
        """Reject coercive non-integers while retaining environment text parsing."""
        if value is None:
            return value
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("LLM integer setting must be an integer")
        return value

    @field_validator(
        "llm_timeout_seconds",
        "llm_temperature",
        mode="before",
    )
    @classmethod
    def validate_llm_real_types(cls, value: object) -> object:
        """Reject booleans masquerading as LLM numeric settings."""
        if isinstance(value, bool):
            raise ValueError("LLM numeric setting must be a real number")
        return value

    @field_validator("dbip_city_lite_artifact_uri")
    @classmethod
    def validate_dbip_city_lite_artifact_uri(cls, value: str) -> str:
        """Require a blank or credential-free authority-free file artifact URI."""
        if not value.strip():
            return ""
        parsed = urlsplit(value.strip())
        if parsed.scheme != "file":
            raise ValueError(
                "dbip_city_lite_artifact_uri must use the file:// scheme in v0.1"
            )
        if parsed.netloc:
            raise ValueError("dbip_city_lite_artifact_uri must be authority-free")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("dbip_city_lite_artifact_uri must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError(
                "dbip_city_lite_artifact_uri must not contain a query or fragment"
            )
        if not parsed.path or not parsed.path.startswith("/"):
            raise ValueError("dbip_city_lite_artifact_uri must have an absolute path")
        return value.strip()

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

    @model_validator(mode="after")
    def validate_retry_delays(self) -> "Settings":
        """Require max delay >= base delay."""
        if (
            self.provider_retry_max_delay_seconds
            < self.provider_retry_base_delay_seconds
        ):
            raise ValueError(
                "provider_retry_max_delay_seconds must be >= provider_retry_base_delay_seconds"
            )
        return self

    @field_validator("api_cors_origins")
    @classmethod
    def validate_api_cors_origins(cls, value: list[str]) -> list[str]:
        """Reject wildcard credentialed CORS and malformed origins.

        Cookie authentication must never combine ``allow_credentials=true``
        with a wildcard origin; explicit configured origins only.
        """
        normalized: list[str] = []
        for origin in value:
            stripped = origin.strip().rstrip("/")
            if not stripped:
                raise ValueError("api_cors_origins must not contain blank origins")
            if stripped == "*":
                raise ValueError(
                    "api_cors_origins must not use the wildcard with cookies"
                )
            try:
                parsed = urlsplit(stripped)
                hostname = parsed.hostname
                _ = parsed.port
            except ValueError as exc:
                raise ValueError(
                    "api_cors_origins contains a malformed origin"
                ) from exc
            if not parsed.scheme or not hostname:
                raise ValueError(
                    "api_cors_origins entries must be absolute origins with a hostname"
                )
            normalized.append(stripped)
        return normalized

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
