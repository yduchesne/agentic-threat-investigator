# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Stable defaults for all ATI deployments."""

from typing import Any

CONFIG: dict[str, Any] = {
    "app_name": "Agentic Threat Investigator",
    "log_level": "INFO",
    "db_batch_size": 100,
}
