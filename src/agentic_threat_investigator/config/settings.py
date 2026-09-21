# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed application settings and the configuration bootstrap bridge."""

import logging
from enum import Enum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentic_threat_investigator.config.config_utils import Config, load_config
from agentic_threat_investigator.domain.datasource import (
    REPRESENTATIVE_DATASOURCE_DEFINITIONS,
    DatasourceDefinition,
)

DOCUMENT_CHUNK_EMBEDDING_DIMENSION = 1536


class OperatingMode(str, Enum):
    """Selected v0.1 runtime intelligence-source composition mode.

    Operating mode answers **which intelligence-source implementations are
    wired** at bootstrap: ``FAKE`` selects deterministic repository-owned
    fake batch/live sources, ``PRODUCTION`` selects the real configured
    sources. It is orthogonal to ``ATI_CONFIG_PROFILE`` and never selects
    the LLM, embeddings, database, dispatcher, runner, coordinator policy,
    report implementation, or API behavior.
    """

    FAKE = "fake"
    PRODUCTION = "production"


class LlmDriver(str, Enum):
    """Selected worker LLM implementation (PR 24B deterministic boundary).

    ``OPENAI`` composes the configured real OpenAI chat model through the
    existing secret-reference bootstrap contract. ``DETERMINISTIC`` composes
    :class:`DeterministicLlmClient`, a repository-owned scripts-free model
    boundary used by offline real-stack browser tests and deterministic
    deployments; it never touches the network and never reads secret values.
    The default is ``openai``: an existing deployment that never sets the
    variable must not silently switch to a scripted boundary. Exactly
    ``openai`` and ``deterministic`` are accepted; anything else fails
    validation.
    """

    OPENAI = "openai"
    DETERMINISTIC = "deterministic"


class LlmObservabilityBackend(str, Enum):
    """Selected LLM/agent observability backend (PR 29A).

    Exactly one value is accepted: ``langsmith``, ``langfuse``, or ``none``.
    Backend-specific credentials are required only when the corresponding
    backend is actually selected; ``none`` needs no vendor configuration.
    General runtime observability (OpenTelemetry) is independent of this
    selector and remains controlled by :attr:`Settings.observability_enabled`.
    """

    LANGSMITH = "langsmith"
    LANGFUSE = "langfuse"
    NONE = "none"


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


class KafkaSecurityProtocol(str, Enum):
    """Supported security protocol of the Kafka-compatible Evidence log (PR 28G).

    Values follow the aiokafka/Kafka vocabulary. ``PLAINTEXT`` is the local
    Redpanda development default; ``SSL``/``SASL_PLAINTEXT``/``SASL_SSL``
    select a TLS/authenticated broker. Exactly one supported value is
    accepted; an unsupported value fails closed rather than silently
    falling back to plaintext.
    """

    PLAINTEXT = "PLAINTEXT"
    SSL = "SSL"
    SASL_PLAINTEXT = "SASL_PLAINTEXT"
    SASL_SSL = "SASL_SSL"


class EvidenceLogKafkaSettings(BaseModel):
    """Bounded configuration of the Kafka-compatible Evidence log (PR 28G).

    Non-secret transport settings only. SASL credentials are carried as
    secret **reference names** (the environment variable holding the
    username/password), never as values; the values are resolved through
    ATI's existing SecretsResolver during composition and injected into the
    client, never stored or logged here. ``bootstrap_servers`` is bounded
    to non-empty ``host:port`` entries; the topic and consumer group are
    non-blank; the poll timeout is a bounded positive number of
    milliseconds.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    bootstrap_servers: tuple[str, ...]
    topic: str
    consumer_group: str = "evidence-persistence"
    poll_timeout_ms: int = Field(default=3000, ge=1, le=600_000)
    client_id: str = "ati-evidence"
    security_protocol: KafkaSecurityProtocol = KafkaSecurityProtocol.PLAINTEXT
    auto_offset_reset: str = "earliest"
    sasl_mechanism: str | None = None
    sasl_username_secret: str | None = None
    sasl_password_secret: str | None = None

    @model_validator(mode="after")
    def validate_kafka_bootstrap(self) -> "EvidenceLogKafkaSettings":
        """Reject blank bootstrap entries, topic, or group fail-closed."""
        if not self.bootstrap_servers:
            raise ValueError("evidence kafka bootstrap_servers must not be empty")
        for server in self.bootstrap_servers:
            if not server.strip():
                raise ValueError(
                    "evidence kafka bootstrap_servers must not contain blank entries"
                )
        if not self.topic.strip():
            raise ValueError("evidence kafka topic must not be blank")
        if not self.consumer_group.strip():
            raise ValueError("evidence kafka consumer_group must not be blank")
        if not self.client_id.strip():
            raise ValueError("evidence kafka client_id must not be blank")
        if self.auto_offset_reset not in ("earliest", "latest"):
            raise ValueError(
                "evidence kafka auto_offset_reset must be 'earliest' or 'latest'"
            )
        return self


class Settings(BaseSettings):
    """Typed settings for the local development runtime."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ATI_", extra="ignore"
    )

    app_name: str = "Agentic Threat Investigator"
    environment: str = "development"
    # Operating mode (PR 23D): selects intelligence-source composition only.
    # The safe default is production: an existing deployment that never sets
    # the variable must not silently switch to fake intelligence. Exactly
    # `fake` and `production` are accepted; anything else fails validation.
    operating_mode: OperatingMode = OperatingMode.PRODUCTION
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
    llm_driver: LlmDriver = LlmDriver.OPENAI
    llm_model: str = "gpt-4o-mini"
    # Optional OpenAI-compatible API base URL (PR 30A). Non-secret, operator
    # selected endpoint; blank uses the OpenAI SDK default. A non-blank value
    # must be a credential-free HTTP(S) URL with a hostname and no
    # query/fragment; it may target OpenAI, OpenRouter, or any other
    # OpenAI-compatible endpoint without changing the ``openai`` driver.
    llm_base_url: str = ""
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
    # Deterministic analyst GEOINT context bounds (PR 26F). The policy---never
    # the model---selects the bounded geographic context seen by one Evidence
    # Analyst invocation; an oversize context fails with a typed application
    # error before any model call instead of being silently truncated.
    analyst_geoint_max_entities: int = Field(default=10, ge=1, le=200)
    analyst_geoint_max_observations_per_entity: int = Field(default=5, ge=1, le=200)
    analyst_geoint_max_total_observations: int = Field(default=50, ge=1, le=1000)
    analyst_geoint_max_context_bytes: int = Field(
        default=262_144, ge=1_000, le=1_000_000
    )
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
    # Server-owned hard bound of the PR 25A investigation geolocation
    # projection. The map dataset is returned as one coherent bounded
    # visualization set; this bound is semantically separate from pageable
    # collection sizes and is never caller-controllable at the HTTP layer.
    api_max_map_geolocation_items: int = Field(default=500, ge=1)
    # Server-owned hard bound of the PR 26D GEOINT summary top-location
    # groups. The summary is one bounded analyst-facing dataset, not a
    # pageable collection; the bound is semantically distinct from page
    # sizes and is never caller-controllable at the HTTP layer.
    api_max_geoint_summary_top_locations: int = Field(default=10, ge=1)
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
    # Typed datasource definitions (PR 27A). One canonical typed definition
    # per configured datasource with explicit, independent classification
    # dimensions: datasource instance, source/provider, acquisition protocol,
    # serialization format, and semantic format. Provider-specific
    # operational settings (concurrency, secret references, lookback
    # windows) deliberately remain separate and are not migrated here.
    datasources: tuple[DatasourceDefinition, ...] = Field(
        default_factory=lambda: REPRESENTATIVE_DATASOURCE_DEFINITIONS
    )
    # Kafka-compatible distributed Evidence log (PR 28G). Defaults target a
    # local Redpanda broker (PLAINTEXT) at the conventional hearth; only
    # secret reference names are configurable here, never credential values.
    evidence_kafka: EvidenceLogKafkaSettings = EvidenceLogKafkaSettings(
        bootstrap_servers=("127.0.0.1:9092",),
        topic="ati.evidence",
        consumer_group="evidence-persistence",
    )
    # GEOINT configuration (PR 26): the Geo Resolver process policy. The
    # worker identity is an ephemeral lease owner marker, never an
    # authorization identity; retry_max_seconds must be >= retry_base_seconds.
    geo_resolver_enabled: bool = True
    geo_resolver_worker_id: str = ""
    geo_resolver_batch_size: int = Field(default=10, ge=1, le=1000)
    geo_resolver_lease_seconds: int = Field(default=300, ge=1, le=86400)
    geo_resolver_poll_interval_seconds: float = Field(
        default=1.0, ge=0, allow_inf_nan=False
    )
    geo_resolver_max_attempts: int = Field(default=3, ge=1, le=1000)
    geo_resolver_retry_base_seconds: float = Field(
        default=60.0, gt=0, allow_inf_nan=False
    )
    geo_resolver_retry_max_seconds: float = Field(
        default=3600.0, ge=0, allow_inf_nan=False
    )
    # Observability (PR 29A). Master ATI application-telemetry switch. When
    # disabled, no OTel SDK provider is installed and no vendor LLM-
    # observability adapter is composed (NoOp only). ``llm_observability_backend``
    # is the typed backend selector (langsmith | langfuse | none); like
    # ``llm_driver`` it is an operational selection resolved from the
    # environment, never pinned by any source-controlled profile. Langfuse
    # settings carry only secret reference names for the SDK keys plus a
    # non-secret base URL; the key values themselves are resolved through
    # ``SecretsResolver`` during composition and never stored or logged here.
    observability_enabled: bool = False
    llm_observability_backend: LlmObservabilityBackend = LlmObservabilityBackend.NONE
    langfuse_public_key_secret: str = "ATI_LANGFUSE_PUBLIC_KEY"
    langfuse_secret_key_secret: str = "ATI_LANGFUSE_SECRET_KEY"
    langfuse_base_url: str = ""

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

    @field_validator("llm_driver", mode="before")
    @classmethod
    def validate_llm_driver(cls, value: object) -> object:
        """Reject blank or invalid LLM-driver strings before enum parsing.

        A blank value fails closed: there is no silent fallback between
        ``openai`` and ``deterministic``, matching the fail-closed
        configuration contract (PR 23D operating mode).
        """
        if isinstance(value, str) and not value.strip():
            raise ValueError("llm_driver must not be blank")
        return value

    @field_validator("llm_observability_backend", mode="before")
    @classmethod
    def validate_llm_observability_backend(cls, value: object) -> object:
        """Reject blank or unknown LLM-observability backend strings.

        A blank value fails closed rather than silently falling back to
        ``none``, matching the fail-closed configuration contract for
        operational selections such as ``llm_driver`` and ``operating_mode``.
        """
        if isinstance(value, str) and not value.strip():
            raise ValueError("llm_observability_backend must not be blank")
        return value

    @field_validator("langfuse_public_key_secret")
    @classmethod
    def validate_langfuse_public_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never a key value)."""
        if not value.strip():
            raise ValueError("langfuse_public_key_secret must not be blank")
        return value.strip()

    @field_validator("langfuse_secret_key_secret")
    @classmethod
    def validate_langfuse_secret_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never a key value)."""
        if not value.strip():
            raise ValueError("langfuse_secret_key_secret must not be blank")
        return value.strip()

    @field_validator("langfuse_base_url")
    @classmethod
    def validate_langfuse_base_url(cls, value: str) -> str:
        """Require a blank or credential-free HTTP(S) Langfuse base URL.

        Credentials (userinfo) are rejected so configured URLs can never embed
        keys; query/fragment parts are also rejected as unexpected input.
        """
        if not value.strip():
            return ""
        try:
            parsed = urlsplit(value.strip())
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("langfuse_base_url is malformed") from exc
        if parsed.scheme not in ("http", "https"):
            raise ValueError("langfuse_base_url must use the http or https scheme")
        if not hostname:
            raise ValueError("langfuse_base_url must contain a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("langfuse_base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("langfuse_base_url must not contain a query or fragment")
        return value.strip()

    @field_validator("llm_api_key_secret")
    @classmethod
    def validate_llm_api_key_secret(cls, value: str) -> str:
        """Require a non-blank secret reference name (never an API key value)."""
        if not value.strip():
            raise ValueError("llm_api_key_secret must not be blank")
        return value.strip()

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_base_url(cls, value: str) -> str:
        """Require a blank or credential-free HTTP(S) OpenAI-compatible base URL.

        A blank value is legal and retains the OpenAI SDK default endpoint. A
        non-blank value must use ``http`` or ``https`` (local development
        endpoints may legitimately use HTTP), contain a hostname, carry no
        username/password (so a URL can never embed a key), and carry no
        query or fragment. Path components such as ``/v1`` are preserved
        exactly; trailing whitespace is stripped before storage. No DNS
        resolution or network probing is performed here.
        """
        if not value.strip():
            return ""
        try:
            parsed = urlsplit(value.strip())
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("llm_base_url is malformed") from exc
        if parsed.scheme not in ("http", "https"):
            raise ValueError("llm_base_url must use the http or https scheme")
        if not hostname:
            raise ValueError("llm_base_url must contain a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("llm_base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("llm_base_url must not contain a query or fragment")
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
        "api_max_map_geolocation_items",
        "api_max_geoint_summary_top_locations",
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
        "analyst_geoint_max_entities",
        "analyst_geoint_max_observations_per_entity",
        "analyst_geoint_max_total_observations",
        "analyst_geoint_max_context_bytes",
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

    @field_validator("operating_mode", mode="before")
    @classmethod
    def validate_operating_mode(cls, value: object) -> object:
        """Reject blank or invalid operating-mode strings before enum parsing.

        A blank value fails closed: there is no silent fallback between
        ``fake`` and ``production``, matching the fail-closed configuration
        contract (PR 23D).
        """
        if isinstance(value, str) and not value.strip():
            raise ValueError("operating_mode must not be blank")
        return value

    @field_validator(
        "geo_resolver_batch_size",
        "geo_resolver_lease_seconds",
        "geo_resolver_max_attempts",
        mode="before",
    )
    @classmethod
    def validate_geo_resolver_integer_types(cls, value: object) -> object:
        """Reject coercive non-integers while retaining environment parsing."""
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("geo resolver integer setting must be an integer")
        return value

    @field_validator(
        "geo_resolver_poll_interval_seconds",
        "geo_resolver_retry_base_seconds",
        "geo_resolver_retry_max_seconds",
        mode="before",
    )
    @classmethod
    def validate_geo_resolver_real_types(cls, value: object) -> object:
        """Reject booleans masquerading as geo resolver numeric settings."""
        if isinstance(value, bool):
            raise ValueError("geo resolver numeric setting must be a real number")
        return value

    @field_validator("geo_resolver_worker_id")
    @classmethod
    def validate_geo_resolver_worker_id(cls, value: str) -> str:
        """Require a blank or bounded operational worker identity."""
        stripped = value.strip()
        if not stripped:
            return ""
        if len(stripped) > 200:
            raise ValueError("geo_resolver_worker_id exceeds the maximum length")
        return stripped

    @model_validator(mode="after")
    def validate_datasource_definitions(self) -> "Settings":
        """Reject duplicate datasource instance IDs in the configured collection.

        Multiple datasource instances may legally share the same
        ``SourceId``; only the datasource-instance identity must be unique.
        """
        ids = [definition.datasource_id.value for definition in self.datasources]
        if len(ids) != len(set(ids)):
            raise ValueError("datasource definitions must have unique datasource IDs")
        return self

    @model_validator(mode="after")
    def validate_geo_resolver_retry_bounds(self) -> "Settings":
        """Require the retry maximum to be at least the retry base."""
        if self.geo_resolver_retry_max_seconds < self.geo_resolver_retry_base_seconds:
            raise ValueError(
                "geo_resolver_retry_max_seconds must be >= "
                "geo_resolver_retry_base_seconds"
            )
        return self

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
