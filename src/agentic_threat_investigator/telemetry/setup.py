# SPDX-License-Identifier: AGPL-3.0-only
"""OpenTelemetry setup/composition foundation and service identity (PR 29A).

``configure_telemetry`` is the one idempotent composition entry point. It
installs no remote exporter (PR 29C owns export/provisioning) and requires no
network merely to configure. Service identity is derived from the explicit
ATI process service name passed in; standard OTel ``OTEL_SERVICE_NAME`` /
``OTEL_RESOURCE_ATTRIBUTES`` environment values do not override the explicit
ATI identity because the OpenTelemetry SDK ``Resource.create`` merge semantics
give explicitly-passed attributes precedence over environment-derived ones
(verified against opentelemetry-sdk 1.37.x).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider

logger = logging.getLogger(__name__)


class ServiceNames:
    """Canonical ATI process service identities (frozen by PR 29A).

    Service identity is never inferred from mutable class names; callers
    select the constant that matches the actual process role.
    """

    API = "ati-api"
    WORKER = "ati-worker"
    GEO_RESOLVER = "ati-geo-resolver"
    SCHEDULER = "ati-scheduler"
    MIGRATE = "ati-migrate"
    FAKE_DATA_BOOTSTRAP = "ati-fake-data-bootstrap"


SERVICE_NAMES: frozenset[str] = frozenset(
    {
        ServiceNames.API,
        ServiceNames.WORKER,
        ServiceNames.GEO_RESOLVER,
        ServiceNames.SCHEDULER,
        ServiceNames.MIGRATE,
        ServiceNames.FAKE_DATA_BOOTSTRAP,
    }
)
"""The exact tested set of canonical ATI service names."""


@dataclass(frozen=True)
class TelemetryRuntime:
    """The providers established by a telemetry composition.

    Disabled configuration installs no providers (both ``None``). Enabled
    configuration installs providers with meaningful resource identity but no
    remote exporter; PR 29C wires the actual backends/exporters.
    """

    tracer_provider: TracerProvider | None = None
    meter_provider: MeterProvider | None = None


@dataclass(frozen=True)
class _Configured:
    """The effective single-shot telemetry configuration."""

    enabled: bool
    service_name: str


_state_lock = threading.Lock()
_configured: _Configured | None = None
_runtime: TelemetryRuntime = TelemetryRuntime()


def configure_telemetry(
    *,
    enabled: bool,
    service_name: str,
    register_globals: bool = True,
) -> TelemetryRuntime:
    """Compose (and, when enabled, install) the process telemetry providers.

    Idempotent within one process: a repeated call with the same effective
    configuration returns the existing runtime; a call with a conflicting
    configuration raises ``RuntimeError`` instead of stacking a second
    pipeline. When ``enabled`` is false no SDK provider is created and no
    exporter is wired; telemetry helpers fall back to OTel no-ops.

    ``register_globals`` controls whether the enabled providers are installed
    as the process-global OTel tracer/meter providers (the default). Unit
    tests and callers that manage provider lifetime explicitly pass ``False``
    and read the returned :class:`TelemetryRuntime` instead, avoiding the
    once-only global OTel provider replacement guard.
    """
    global _configured, _runtime
    if not service_name.strip():
        raise ValueError("service_name must not be blank")
    normalized = service_name.strip()
    with _state_lock:
        if _configured is not None:
            if _configured.enabled != enabled or _configured.service_name != normalized:
                raise RuntimeError("conflicting telemetry configuration")
            return _runtime

        if not enabled:
            runtime = TelemetryRuntime()
        else:
            resource = Resource.create({SERVICE_NAME: normalized})
            tracer_provider = TracerProvider(resource=resource)
            meter_provider = MeterProvider(resource=resource)
            if register_globals:
                trace.set_tracer_provider(tracer_provider)
                metrics.set_meter_provider(meter_provider)
            runtime = TelemetryRuntime(
                tracer_provider=tracer_provider,
                meter_provider=meter_provider,
            )

        _configured = _Configured(enabled=enabled, service_name=normalized)
        _runtime = runtime
        return runtime


def shutdown_telemetry() -> None:
    """Shut down any established providers and reset composition state.

    Telemetry shutdown failure is logged as a safe warning and never masks the
    original process/application error. After shutdown a fresh
    ``configure_telemetry`` call may start a new idempotent session.
    """
    global _configured, _runtime
    with _state_lock:
        providers = (_runtime.tracer_provider, _runtime.meter_provider)
        _configured = None
        _runtime = TelemetryRuntime()
    for provider, kind in ((providers[0], "tracer"), (providers[1], "meter")):
        if provider is None:
            continue
        try:
            provider.shutdown()
        except Exception:
            logger.exception("telemetry %s provider shutdown failed", kind)


__all__ = [
    "SERVICE_NAMES",
    "ServiceNames",
    "TelemetryRuntime",
    "configure_telemetry",
    "shutdown_telemetry",
]
