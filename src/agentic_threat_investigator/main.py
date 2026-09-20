# SPDX-License-Identifier: AGPL-3.0-only
"""FastAPI application entry point for the /api/v1 HTTP boundary.

Production composition seam for the ``ati-api`` process: the settings-driven
application is built once and, when observability is enabled, the
framework-level FastAPI/ASGI inbound HTTP telemetry is installed exactly once
over the providers established by :func:`configure_telemetry` (service
identity ``ati-api``). The same composition owns deterministic shutdown: the
application lifespan is arranged through
:func:`arrange_fastapi_telemetry_shutdown` so :func:`shutdown_telemetry` runs
after the application services have been disposed (including when that
disposal fails). Telemetry composition is observational only and is skipped
entirely when ``Settings.observability_enabled`` is false.
"""

from agentic_threat_investigator.api.app import create_app
from agentic_threat_investigator.config import get_settings
from agentic_threat_investigator.telemetry.http import instrument_fastapi_http
from agentic_threat_investigator.telemetry.lifecycle import (
    arrange_fastapi_telemetry_shutdown,
)
from agentic_threat_investigator.telemetry.setup import (
    ServiceNames,
    configure_telemetry,
    shutdown_telemetry,
)

_settings = get_settings()
_telemetry_runtime = configure_telemetry(
    enabled=_settings.observability_enabled,
    service_name=ServiceNames.API,
)
app = create_app(_settings)
instrument_fastapi_http(app, _telemetry_runtime)
arrange_fastapi_telemetry_shutdown(app, shutdown_telemetry)
