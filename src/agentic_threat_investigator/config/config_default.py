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
}
