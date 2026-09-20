# SPDX-License-Identifier: AGPL-3.0-only
"""Shared deterministic OpenTelemetry fixtures for the unit suite (PR 29A/29A-1).

Telemetry tests never rely on process-global OTel providers (which OTel's
public API only allows setting once). Instead they build in-memory
providers/exporters and inject them into the ATI helper seams, keeping every
test isolated and order-independent.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

import agentic_threat_investigator.telemetry.decorators as _decorators
import agentic_threat_investigator.telemetry.metrics as _metrics
from agentic_threat_investigator.telemetry import INSTRUMENTATION_SCOPE


@pytest.fixture
def span_exporter() -> InMemorySpanExporter:
    """Return a fresh in-memory span exporter per test."""
    return InMemorySpanExporter()


@pytest.fixture
def metric_reader() -> InMemoryMetricReader:
    """Return a fresh in-memory metric reader per test."""
    return InMemoryMetricReader()


@pytest.fixture
def in_memory_telemetry(
    monkeypatch: pytest.MonkeyPatch,
    span_exporter: InMemorySpanExporter,
    metric_reader: InMemoryMetricReader,
) -> SimpleNamespace:
    """Wire the decorator seams to isolated in-memory providers.

    The returned namespace exposes ``tracer``, ``meter``, ``meter_provider``,
    ``exporter`` and ``reader`` so tests can assert on finished spans and
    recorded metrics.
    """
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    tracer = trace.get_tracer(
        INSTRUMENTATION_SCOPE, "0.1.0", tracer_provider=tracer_provider
    )

    meter_provider = MeterProvider(metric_readers=[metric_reader])
    meter = metrics.get_meter(
        INSTRUMENTATION_SCOPE, "0.1.0", meter_provider=meter_provider
    )

    monkeypatch.setattr(_decorators, "get_tracer", lambda: tracer)
    monkeypatch.setattr(
        _decorators,
        "get_histogram",
        lambda name, unit="s", description="": meter.create_histogram(
            name, unit=unit, description=description
        ),
    )

    def _test_counter(name: str, **kwargs: object) -> object:
        """Resolve a canonical counter against the in-memory meter provider."""
        del kwargs
        return _metrics.get_counter(name, meter_provider=meter_provider)

    monkeypatch.setattr(_decorators, "get_counter", _test_counter)
    return SimpleNamespace(
        tracer=tracer,
        meter=meter,
        meter_provider=meter_provider,
        exporter=span_exporter,
        reader=metric_reader,
    )


@pytest.fixture
def in_memory_persistence_telemetry(
    monkeypatch: pytest.MonkeyPatch,
    in_memory_telemetry: SimpleNamespace,
) -> SimpleNamespace:
    """Extend the in-memory decorator seams to persistence/adapters too.

    Patches the module-level helper bindings used by ``PostgresUnitOfWork``,
    the Kafka adapters, and the Evidence consumer flow so their explicit
    telemetry resolves against the same in-memory tracer/meter. Also replaces
    the psycopg composite registration with a no-op so a fake session can
    enter a real ``PostgresUnitOfWork`` deterministically.
    """
    tracer = in_memory_telemetry.tracer
    meter_provider = in_memory_telemetry.meter_provider

    def _any_counter(name: str, **kwargs: object) -> object:
        del kwargs
        return _metrics.get_counter(name, meter_provider=meter_provider)

    def _any_histogram(name: str, *, unit: str = "s", description: str = "") -> object:
        meter = _metrics.get_meter(meter_provider=meter_provider)
        return meter.create_histogram(name, unit=unit, description=description)

    import agentic_threat_investigator.app.datasource_provider as _ds_provider
    import agentic_threat_investigator.app.evidence_analyst.analyst as _analyst
    import agentic_threat_investigator.app.evidence_batch_persistence as _ebp
    import agentic_threat_investigator.app.evidence_consumer as _ec
    import agentic_threat_investigator.app.evidence_conversion as _conversion
    import agentic_threat_investigator.app.geoint.worker as _geo_worker
    import agentic_threat_investigator.app.llm_observability as _llm_obs
    import agentic_threat_investigator.app.orchestration.provider_executor as _pe
    import agentic_threat_investigator.app.orchestration.runner as _runner
    import agentic_threat_investigator.app.report_writer.writer as _rwriter
    import agentic_threat_investigator.app.research_agent.agent as _ragent
    import agentic_threat_investigator.infrastructure.embeddings as _embeddings
    import agentic_threat_investigator.infrastructure.kafka.evidence_log as _kafka
    import agentic_threat_investigator.infrastructure.providers.http as _http
    from agentic_threat_investigator.infrastructure.persistence.postgresql import (
        database as _db,
    )

    # Patch only the helper bindings each module actually imports; decorator
    # paths already resolve through telemetry.decorators (patched above).
    for module in (
        _db,
        _kafka,
        _ebp,
        _ec,
        _conversion,
        _llm_obs,
        _ds_provider,
        _geo_worker,
        _pe,
        _runner,
        _analyst,
        _ragent,
        _rwriter,
        _embeddings,
        _http,
    ):
        if hasattr(module, "get_tracer"):
            monkeypatch.setattr(module, "get_tracer", lambda: tracer)
        if hasattr(module, "get_counter"):
            monkeypatch.setattr(module, "get_counter", _any_counter)
        if hasattr(module, "get_histogram"):
            monkeypatch.setattr(module, "get_histogram", _any_histogram)

    async def _noop_register(*_args: object, **_kwargs: object) -> None:
        """Replace psycopg composite registration for fake-session tests."""

    monkeypatch.setattr(_db, "register_batch_composites", _noop_register)
    return in_memory_telemetry
