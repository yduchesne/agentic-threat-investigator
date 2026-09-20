# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-owned backend-neutral telemetry foundation (PR 29A).

This package owns the canonical telemetry vocabulary, decorator-first
instrumentation helpers, OpenTelemetry setup/composition seams, safe common
attributes, W3C trace-context propagation helpers, and trace/span log
correlation helpers. It does **not** own business policy, Evidence
processing, Kafka delivery, database operations, provider HTTP, or LLM
prompts, and it never imports Prometheus-, Jaeger-, Loki-, Grafana-,
LangSmith-, or Langfuse-specific APIs.

PR 29A establishes the semantics and reusable helpers only; it does not
instrument application call sites broadly (that is PR 29B).
"""

from agentic_threat_investigator.telemetry.attributes import (
    METRIC_ATTRIBUTE_ALLOWLIST,
    PROHIBITED_METRIC_ATTRIBUTE_KEYS,
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.decorators import (
    postgres_repository_operation,
    registered_postgres_repository_operations,
    telemetry_operation,
    timed,
    traced,
)
from agentic_threat_investigator.telemetry.logging import (
    TraceCorrelation,
    TraceCorrelationFilter,
    current_correlation,
)
from agentic_threat_investigator.telemetry.metrics import (
    COUNTER_SPECS,
    DURATION_UNIT,
    MESSAGE_COUNT_UNIT,
    DurationMetrics,
    Metrics,
    duration_metric_name,
    get_counter,
    get_histogram,
    get_meter,
)
from agentic_threat_investigator.telemetry.propagation import (
    extract_trace_context,
    inject_trace_context,
)
from agentic_threat_investigator.telemetry.setup import (
    SERVICE_NAMES,
    ServiceNames,
    TelemetryRuntime,
    configure_telemetry,
    shutdown_telemetry,
)
from agentic_threat_investigator.telemetry.tracing import (
    CANONICAL_SPAN_NAMES,
    INSTRUMENTATION_SCOPE,
    SpanNames,
    get_tracer,
)

__all__ = [
    "AttributeKeys",
    "METRIC_ATTRIBUTE_ALLOWLIST",
    "PROHIBITED_METRIC_ATTRIBUTE_KEYS",
    "validate_bounded_attributes",
    "traced",
    "timed",
    "telemetry_operation",
    "postgres_repository_operation",
    "registered_postgres_repository_operations",
    "TraceCorrelation",
    "TraceCorrelationFilter",
    "current_correlation",
    "COUNTER_SPECS",
    "DURATION_UNIT",
    "DurationMetrics",
    "MESSAGE_COUNT_UNIT",
    "Metrics",
    "duration_metric_name",
    "get_counter",
    "get_histogram",
    "get_meter",
    "extract_trace_context",
    "inject_trace_context",
    "SERVICE_NAMES",
    "TelemetryRuntime",
    "ServiceNames",
    "configure_telemetry",
    "shutdown_telemetry",
    "CANONICAL_SPAN_NAMES",
    "INSTRUMENTATION_SCOPE",
    "SpanNames",
    "get_tracer",
]
