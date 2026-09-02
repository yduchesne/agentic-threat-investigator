#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }
uv run pytest tests/integration --cov=agentic_threat_investigator --cov-report=term-missing
