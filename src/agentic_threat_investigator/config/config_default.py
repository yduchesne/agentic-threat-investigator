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
}
