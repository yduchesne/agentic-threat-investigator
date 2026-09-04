# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Local developer configuration overrides."""

from typing import Any

CONFIG: dict[str, Any] = {
    "log_level": "DEBUG",
    "login_rate_limit_maximum": 100,
}
