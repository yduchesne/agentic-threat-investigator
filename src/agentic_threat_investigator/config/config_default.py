# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Stable defaults for all ATI deployments."""

from typing import Any

CONFIG: dict[str, Any] = {
    "app_name": "Agentic Threat Investigator",
    "log_level": "INFO",
    "db_batch_size": 100,
    "embedding": {
        "provider": "hashing",
        "model": "ati-hashing-v1",
        "model_version": 1,
        "dimension": 1536,
        # Secret reference name only: the environment variable carrying the
        # semantic embedding provider API key. The key value itself is
        # resolved outside configuration during composition and never stored
        # or logged here. Local/dev defaults stay hashing/offline.
        # nosec B105 - the string is the NAME of the environment variable
        # carrying the key, never a key value; storing a value here is
        # prohibited by CONFIGURATION.md.
        "api_key_secret": "ATI_OPENAI_EMBEDDING_API_KEY",  # nosec B105 - secret reference name, never a key value; storing a value here is prohibited.
        "timeout_seconds": None,
    },
    "embedding_batch_size": 64,
    "rag_chunk_target_tokens": 400,
    "rag_chunk_max_tokens": 800,
    # LLM settings (PR 20B). Non-secret defaults only: the API key reference
    # name is declared by Settings and must never be committed with a value.
    # `llm_driver` deliberately stays out of profiles: like
    # `ATI_OPERATING_MODE`, it is an operational selection resolved from the
    # environment, never pinned by configuration.
    "llm_model": "gpt-4o-mini",
    "llm_timeout_seconds": 60.0,
    "llm_max_structured_output_attempts": 2,
    "llm_temperature": 0.0,
    "llm_max_tokens": None,
    "llm_max_evidence_items": 100,
    "llm_max_relationship_observations": 200,
    "llm_max_normalized_facts_bytes": 131072,
    "llm_max_input_bytes": 262144,
    # Report Writer context bounds (PR 23B).
    "report_writer_max_findings": 50,
    "report_writer_max_evidence": 100,
    "report_writer_max_relationship_observations": 200,
    "report_writer_max_research_results": 20,
    "report_writer_max_research_claims": 100,
    "report_writer_max_input_bytes": 262144,
    # Analyst-facing collection query page limits (PR 23A).
    "query_default_page_size": 50,
    "query_max_page_size": 200,
    # Server-owned hard bound of the PR 25A investigation geolocation
    # projection (semantically separate from pageable collection sizes).
    "api_max_map_geolocation_items": 500,
    # Credentialed cookie CORS origins (PR 23C); the wildcard is rejected.
    "api_cors_origins": ["http://localhost:8080"],
    # Submission request bounds (PR 23C).
    "api_max_indicator_count": 20,
    "api_max_indicator_value_length": 2048,
    "api_max_objective_length": 4000,
    "api_max_request_body_bytes": 65536,
    # Geo Resolver process policy (PR 26C). Operational, non-secret bounds;
    # a blank worker_id is auto-generated per process at the entry point.
    "geo_resolver_enabled": True,
    "geo_resolver_worker_id": "",
    "geo_resolver_batch_size": 10,
    "geo_resolver_lease_seconds": 300,
    "geo_resolver_poll_interval_seconds": 1.0,
    "geo_resolver_max_attempts": 3,
    "geo_resolver_retry_base_seconds": 60.0,
    "geo_resolver_retry_max_seconds": 3600.0,
}
