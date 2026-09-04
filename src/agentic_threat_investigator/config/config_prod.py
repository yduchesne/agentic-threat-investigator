# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Production configuration baseline without secrets."""

from typing import Any

CONFIG: dict[str, Any] = {
    "log_level": "INFO",
    # Operators must replace this with the externally visible origin.
    "public_base_url": "http://localhost:8000",
}
