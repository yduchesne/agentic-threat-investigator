# SPDX-License-Identifier: AGPL-3.0-only
"""OpenTelemetry setup/composition foundation and service identity (PR 29A/29C).

``configure_telemetry`` is the one idempotent composition entry point. It
installs no remote exporter unless observability is enabled **and** the
standard ``OTEL_EXPORTER_OTLP_ENDPOINT`` is explicitly configured (PR 29C);
with no endpoint the enabled composition stays offline/deterministic and
requires no network merely to configure. Service identity is derived from
the explicit ATI process service name passed in; standard OTel
``OTEL_SERVICE_NAME`` / ``OTEL_RESOURCE_ATTRIBUTES`` environment values do
not override the explicit ATI identity because the OpenTelemetry SDK
``Resource.create`` merge semantics give explicitly-passed attributes
precedence over environment-derived ones (verified against
opentelemetry-sdk 1.37.x).

When the endpoint is present the composition wires the three OTLP/HTTP
signal pipelines through the pinned ``opentelemetry-exporter-otlp-proto-http``
1.37.x line:

- traces: ``OTLPSpanExporter`` behind a ``BatchSpanProcessor``;
- metrics: ``OTLPMetricExporter`` behind a ``PeriodicExportingMetricReader``;
- logs: ``OTLPLogExporter`` behind a ``LoggerProvider`` with a
  ``BatchLogRecordProcessor`` plus an additive Python ``LoggingHandler`` on
  the root logger (console logging and the PR 29A
  :class:`TraceCorrelationFilter` are preserved; OTel-internal logger
  namespaces are excluded from OTLP export to prevent a feedback loop).

ATI processes know exactly one standard destination (the Collector); backend
routing is never ATI's concern.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass

from opentelemetry import _logs as otel_logs_api
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.environment_variables import OTEL_EXPORTER_OTLP_ENDPOINT
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from agentic_threat_investigator.telemetry.logging import (
    attach_otlp_log_handler,
    detach_otlp_log_handler,
)

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

    Disabled configuration installs no providers (all ``None``). Enabled
    configuration with no OTLP endpoint installs local trace/metric
    providers (and no log provider); enabled configuration with an explicit
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` additionally wires the remote
    trace/metric/log exporters (PR 29C) so the instrumentation delivered by
    PR 29B is active in the deployed processes.
    """

    tracer_provider: TracerProvider | None = None
    meter_provider: MeterProvider | None = None
    logger_provider: LoggerProvider | None = None


@dataclass(frozen=True)
class _Configured:
    """The effective single-shot telemetry configuration."""

    enabled: bool
    service_name: str


_state_lock = threading.Lock()
_configured: _Configured | None = None
_runtime: TelemetryRuntime = TelemetryRuntime()
# The OTel Python logging handler attached to the root logger by the last
# enabled-with-endpoint composition (``None`` otherwise). Tracked so shutdown
# can detach exactly the handler this module installed and tests never leak
# duplicate handlers across configurations.
_installed_log_handler: LoggingHandler | None = None


def _otlp_endpoint() -> str | None:
    """Return the standard OTLP endpoint when explicitly configured.

    ATI exports remotely only when an explicit endpoint is present; we never
    fall back to the OTel exporter's implicit ``localhost`` default (that
    default is a developer convenience of the SDK, not an ATI production
    contract). An absent or blank variable means offline mode: local
    providers remain usable and no exporter thread/network requirement is
    created.
    """
    value = os.environ.get(OTEL_EXPORTER_OTLP_ENDPOINT)
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _span_exporter() -> OTLPSpanExporter:
    """Build the OTLP/HTTP span exporter for the Collector endpoint.

    Exporter construction reads the standard ``OTEL_EXPORTER_OTLP_*``
    environment variables (endpoint, headers, timeouts) exactly as the
    pinned exporter contract documents; ATI adds no ATI-prefixed duplicates.
    """
    return OTLPSpanExporter()


def _metric_exporter() -> OTLPMetricExporter:
    """Build the OTLP/HTTP metric exporter for the Collector endpoint."""
    return OTLPMetricExporter()


def _log_exporter() -> OTLPLogExporter:
    """Build the OTLP/HTTP log exporter for the Collector endpoint."""
    return OTLPLogExporter()


def _install_log_handler(provider: LoggerProvider) -> LoggingHandler:
    """Attach one additive OTel ``LoggingHandler`` for ``provider``.

    Console logging and the PR 29A correlation filter are untouched: the
    handler is added to the root logger, and OTel-internal namespaces are
    excluded from OTLP export (:mod:`telemetry.logging`), so exporter/SDK
    diagnostics can never re-enter the OTLP pipeline.
    """
    handler = LoggingHandler(logger_provider=provider)
    attach_otlp_log_handler(handler)
    return handler


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

    With ``enabled`` true the local providers are installed with the
    explicit ATI service identity. When the standard
    ``OTEL_EXPORTER_OTLP_ENDPOINT`` environment variable is additionally
    set, the OTLP/HTTP trace/metric/log exporters are composed onto those
    providers (PR 29C): traces use a batch processor, metrics use a periodic
    reader, and logs use a ``LoggerProvider`` transported through an
    additive root ``LoggingHandler``. Without the endpoint the composition
    stays offline and deterministic.

    ``register_globals`` controls whether the enabled providers are installed
    as the process-global OTel tracer/meter/logger providers (the default).
    Unit tests and callers that manage provider lifetime explicitly pass
    ``False`` and read the returned :class:`TelemetryRuntime` instead,
    avoiding the once-only global OTel provider replacement guard.
    """
    global _configured, _runtime, _installed_log_handler
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
            log_handler: LoggingHandler | None = None
        else:
            resource = Resource.create({SERVICE_NAME: normalized})
            tracer_provider = TracerProvider(resource=resource)
            meter_provider = MeterProvider(resource=resource)
            logger_provider: LoggerProvider | None = None
            log_handler = None
            if _otlp_endpoint() is not None:
                tracer_provider.add_span_processor(BatchSpanProcessor(_span_exporter()))
                meter_provider = MeterProvider(
                    metric_readers=[PeriodicExportingMetricReader(_metric_exporter())],
                    resource=resource,
                )
                logger_provider = LoggerProvider(resource=resource)
                logger_provider.add_log_record_processor(
                    BatchLogRecordProcessor(_log_exporter())
                )
                log_handler = _install_log_handler(logger_provider)
            if register_globals:
                trace.set_tracer_provider(tracer_provider)
                metrics.set_meter_provider(meter_provider)
                if logger_provider is not None:
                    otel_logs_api.set_logger_provider(logger_provider)
            runtime = TelemetryRuntime(
                tracer_provider=tracer_provider,
                meter_provider=meter_provider,
                logger_provider=logger_provider,
            )

        _configured = _Configured(enabled=enabled, service_name=normalized)
        _runtime = runtime
        _installed_log_handler = log_handler
        return runtime


def shutdown_telemetry() -> None:
    """Shut down any established providers and reset composition state.

    The ATI-attached OTel log handler is detached from the root logger first
    (so teardown diagnostics never re-enter OTLP export), then every
    configured provider is shut down exactly once; batch processors flush and
    the periodic metric reader stops its thread. Telemetry shutdown failure
    is logged as a safe warning and never masks the original
    process/application error. After shutdown a fresh ``configure_telemetry``
    call may start a new idempotent session.
    """
    global _configured, _runtime, _installed_log_handler
    with _state_lock:
        providers = (
            _runtime.tracer_provider,
            _runtime.meter_provider,
            _runtime.logger_provider,
        )
        handler = _installed_log_handler
        _configured = None
        _runtime = TelemetryRuntime()
        _installed_log_handler = None
    detach_otlp_log_handler(handler)
    for provider, kind in (
        (providers[0], "tracer"),
        (providers[1], "meter"),
        (providers[2], "logger"),
    ):
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
