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
}
