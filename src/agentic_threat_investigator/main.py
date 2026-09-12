# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application entry point for the /api/v1 HTTP boundary."""

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.config import get_settings

app = create_app(get_settings())
