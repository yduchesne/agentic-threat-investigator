# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 backend verifier: real Collector -> Prometheus/Jaeger/Loki -> Grafana.

The verifier is the only component that knows backend URLs. It implements:

- bounded polling probes for the convergence state machine (readiness of the
  five pinned services, run-scoped signal convergence per backend, Grafana
  provisioning/health);
- the authoritative final assertions the pytest gate runs once the state
  machine reports ``READY_FOR_ASSERTIONS``.

Every metric/trace/log probe is correlated to the unique run ID
(``ati.telemetry.test.run_id``), so stale telemetry from another run can
never satisfy this run (T34-F08). The backend representation contracts below
were pinned against the exact images used by the harness during PR 34
acceptance (Collector contrib ``0.161.0``, Prometheus ``v3.14.0``, Jaeger
``2.21.0``, Loki ``3.7.8``, Grafana ``13.2.2``); see the acceptance report.

Privacy rules: bounded summaries only; never credentials, Authorization
headers, or unbounded response bodies.
"""

from __future__ import annotations

import calendar
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agentic_threat_investigator.telemetry.diagnostic import (
    TELEMETRY_TEST_CHILD_SPAN,
    TELEMETRY_TEST_COUNTER,
    TELEMETRY_TEST_DURATION,
    TELEMETRY_TEST_LOG_EVENT,
    TELEMETRY_TEST_ROOT_SPAN,
    TELEMETRY_TEST_RUN_ID_ATTRIBUTE,
)
from tests.integration.observability import backend
from tests.integration.observability._statemachine import (
    FAILURE_STAGE_CROSS_SIGNAL_CORRELATION,
    ProbeSnapshot,
)
from tests.integration.observability.topology import ObsTopology

# ---------------------------------------------------------------------------
# Run-scoped backend representation (pinned against the harness images).
# ---------------------------------------------------------------------------

# OTel -> Prometheus translation of ATI instrument names/attributes on the
# pinned Collector contrib + Prometheus v3.14: dots become underscores,
# monotonic counters gain the ``_total`` suffix, and the seconds-unit
# duration histogram gains ``_seconds``. ATI instrument names are never
# renamed; this is the verifier-side expectation of the backend rendering.
PROMETHEUS_COUNTER_NAME = f"{TELEMETRY_TEST_COUNTER.replace('.', '_')}_total"
PROMETHEUS_DURATION_PREFIX = f"{TELEMETRY_TEST_DURATION.replace('.', '_')}_seconds"
PROMETHEUS_RUN_LABEL = TELEMETRY_TEST_RUN_ID_ATTRIBUTE.replace(".", "_")

# Jaeger v3 OTLP span fields (verified against jaegertracing/jaeger:2.21.0).
JAEGER_SPAN_TRACE_ID = "traceId"
JAEGER_SPAN_ID = "spanId"
JAEGER_PARENT_SPAN_ID = "parentSpanId"
JAEGER_SPAN_NAME = "name"
JAEGER_SPAN_ATTRIBUTES = "attributes"


# ---------------------------------------------------------------------------
# Readiness probes (bounded; the state machine owns polling).
# ---------------------------------------------------------------------------


def topology_ready(topo: ObsTopology) -> tuple[bool, dict[str, bool]]:
    """Probe the five pinned services' readiness once.

    Returns ``(all_ready, per_service_ready)``. Readiness contacts:
    Collector health-check extension; Prometheus ``/-/ready``; Jaeger v3
    services endpoint (pinned 2.21 API); Loki ``/ready``; Grafana
    ``/api/health``.
    """
    checks: dict[str, bool] = {}
    try:
        collector_body = backend.get_text(f"{topo.collector_health_url}/")
        checks["collector"] = "Server available" in collector_body
    except backend.BackendError:
        checks["collector"] = False
    try:
        checks["prometheus"] = (
            backend.get_text(f"{topo.prometheus_url}/-/ready").strip()
            == "Prometheus Server is Ready."
        )
    except backend.BackendError:
        checks["prometheus"] = False
    try:
        backend.get_json(f"{topo.jaeger_url}/api/v3/services")
        checks["jaeger"] = True
    except backend.BackendError:
        checks["jaeger"] = False
    try:
        text = backend.get_text(f"{topo.loki_url}/ready")
        checks["loki"] = text.strip() == "ready"
    except backend.BackendError:
        checks["loki"] = False
    try:
        payload = backend.grafana_api(
            topo.grafana_url,
            topo.grafana_admin_user,
            topo.grafana_admin_password,
            "/api/health",
        )
        checks["grafana"] = payload.get("database") == "ok"
    except backend.BackendError:
        checks["grafana"] = False
    return all(checks.values()), checks


# ---------------------------------------------------------------------------
# Run-scoped signal probes.
# ---------------------------------------------------------------------------


def _run_label_filter(run_id: str) -> str:
    """Return the PromQL label matcher for the run's diagnostic series."""
    return f'{PROMETHEUS_RUN_LABEL}="{run_id}"'


def prometheus_snapshot(topo: ObsTopology) -> dict[str, Any] | None:
    """Return the run-correlated Prometheus counter/duration observation.

    Returns ``None`` when the series are not yet converged (caller keeps
    polling); raises when the backend responds with a malformed contract.
    """
    counter_result = backend.prometheus_query(
        topo.prometheus_url,
        f"{PROMETHEUS_COUNTER_NAME}{{{_run_label_filter(topo.run_id)}}}",
    )
    count_result = backend.prometheus_query(
        topo.prometheus_url,
        f"{PROMETHEUS_DURATION_PREFIX}_count{{{_run_label_filter(topo.run_id)}}}",
    )
    sum_result = backend.prometheus_query(
        topo.prometheus_url,
        f"{PROMETHEUS_DURATION_PREFIX}_sum{{{_run_label_filter(topo.run_id)}}}",
    )
    if not counter_result or not count_result or not sum_result:
        return None  # not converged yet; keep polling

    def _value(series: Sequence[Mapping[str, Any]]) -> float:
        """Extract the instant sample value from a Prometheus result series."""
        value = series[0].get("value")
        if not isinstance(value, list) or len(value) < 2:
            raise backend.BackendError("Prometheus series has no instant value")
        return float(value[1])

    return {
        "counter_value": _value(counter_result),
        "duration_count": int(_value(count_result)),
        "duration_sum": _value(sum_result),
    }


def _jaeger_attribute(span: Mapping[str, Any], key: str) -> Any | None:
    """Resolve a string/bytes attribute value from a Jaeger v3 OTLP span.

    Jaeger 2.x v3 JSON encodes attributes as an array of
    ``{"key": ..., "value": {"stringValue": ...}}`` proto objects
    (verified against the pinned image); any other encoding resolves to
    ``None`` (bounded).
    """
    attributes = span.get(JAEGER_SPAN_ATTRIBUTES)
    if not isinstance(attributes, list):
        return None
    for entry in attributes:
        if not isinstance(entry, dict) or entry.get("key") != key:
            continue
        value = entry.get("value")
        if isinstance(value, dict):
            for candidate in ("stringValue", "intValue", "boolValue", "doubleValue"):
                if candidate in value:
                    return value[candidate]
            return value.get("bytesValue")
        return None
    return None


@dataclass(frozen=True)
class JaegerRunTrace:
    """The run-scoped root/child span pair observed through Jaeger."""

    trace_id: str
    root_span: Mapping[str, Any]
    child_span: Mapping[str, Any]

    @property
    def child_parented_to_root(self) -> bool:
        """True when the child span's parent is the root span (same trace)."""
        parent_id = self.child_span.get(JAEGER_PARENT_SPAN_ID)
        root_id = self.root_span.get(JAEGER_SPAN_ID)
        return bool(
            parent_id and root_id and str(parent_id).lower() == str(root_id).lower()
        )

    def to_json(self) -> dict[str, Any]:
        """Return the bounded JSON-safe summary for run-state."""
        return {
            "trace_id": self.trace_id,
            "root_name": self.root_span.get(JAEGER_SPAN_NAME),
            "child_name": self.child_span.get(JAEGER_SPAN_NAME),
            "child_parented": self.child_parented_to_root,
        }


def jaeger_run_trace(topo: ObsTopology) -> JaegerRunTrace | None:
    """Resolve the run's root/child span pair through Jaeger, or ``None``.

    Uses the verified pinned Jaeger 2.x v3 API: ``GET /api/v3/traces`` with
    ``query.serviceName=ati-telemetry-test``, an RFC3339Nano time window, and
    the run-scoped ``query.attributes`` map. The search is already exact-run
    correlated (the run ID attribute filter), and the run-scoped matcher is
    still applied defensively so stale telemetry can never satisfy this run
    (T34-F08). Returns ``None`` until the trace is visible (the state
    machine keeps polling).
    """
    now_utc = time.gmtime()
    end_rfc = time.strftime("%Y-%m-%dT%H:%M:%SZ", now_utc)
    start_rfc = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(calendar.timegm(now_utc) - 60 * 60),
    )
    spans = backend.jaeger_search(
        topo.jaeger_url,
        service_name="ati-telemetry-test",
        start_rfc3339=start_rfc,
        end_rfc3339=end_rfc,
        attributes={TELEMETRY_TEST_RUN_ID_ATTRIBUTE: topo.run_id},
    )
    return _spans_with_run_id(spans, topo.run_id)


def _spans_with_run_id(
    spans: Sequence[Mapping[str, Any]], run_id: str
) -> JaegerRunTrace | None:
    """Return the run-scoped root/child span pair, or ``None`` when unmatched.

    Returns ``None`` (not matched yet) instead of raising so the state
    machine keeps polling; a genuinely malformed backend response already
    raised inside ``backend``.
    """
    roots = [
        span
        for span in spans
        if span.get(JAEGER_SPAN_NAME) == TELEMETRY_TEST_ROOT_SPAN
        and _jaeger_attribute(span, TELEMETRY_TEST_RUN_ID_ATTRIBUTE) == run_id
    ]
    children = [
        span
        for span in spans
        if span.get(JAEGER_SPAN_NAME) == TELEMETRY_TEST_CHILD_SPAN
        and _jaeger_attribute(span, TELEMETRY_TEST_RUN_ID_ATTRIBUTE) == run_id
    ]
    if not roots or not children:
        return None
    root = roots[0]
    child = children[0]
    return JaegerRunTrace(
        trace_id=str(root.get(JAEGER_SPAN_TRACE_ID, "")),
        root_span=root,
        child_span=child,
    )


def jaeger_snapshot(topo: ObsTopology) -> dict[str, Any] | None:
    """Return the run's Jaeger convergence summary, or ``None`` until ready."""
    trace = jaeger_run_trace(topo)
    if trace is None:
        return None
    return trace.to_json()


@dataclass(frozen=True)
class LokiRunLog:
    """The run-scoped structured log entries observed through Loki."""

    lines: tuple[tuple[str, str], ...]
    trace_ids: frozenset[str]
    span_ids: frozenset[str]

    @property
    def line_count(self) -> int:
        """Number of matching diagnostic log lines."""
        return len(self.lines)

    def to_json(self) -> dict[str, Any]:
        """Return the bounded JSON-safe summary for run-state."""
        return {
            "line_count": self.line_count,
            "trace_ids": sorted(self.trace_ids),
            "span_ids": sorted(self.span_ids),
        }


def loki_run_log(topo: ObsTopology) -> LokiRunLog | None:
    """Query the run's structured diagnostic log through Loki, or ``None``.

    Respects the Loki label/cardinality policy (PR 29C): the LogQL query
    uses only the bounded ``service_name`` index label; run ID and event
    inspect the line body, and the exported trace/span identity is read from
    the stream's structured metadata (OTLP log records), never indexed
    labels. Both the OTLP context fields (``trace_id``/``span_id``) and the
    ATI correlation filter fields (``otel_trace_id``/``otel_span_id``) are
    recognized.
    """
    now_ns = time.time_ns()
    triples = backend.loki_query_range(
        topo.loki_url,
        '{service_name="ati-telemetry-test"}',
        start_ns=now_ns - 5 * 60 * 10**9,
        end_ns=now_ns,
    )
    matched_lines: list[tuple[str, str]] = []
    trace_ids: set[str] = set()
    span_ids: set[str] = set()
    for timestamp, line, labels in triples:
        if TELEMETRY_TEST_LOG_EVENT in line and topo.run_id in line:
            matched_lines.append((timestamp, line))
        trace_ids.update(_correlation_tokens(labels, ("trace_id", "otel_trace_id")))
        span_ids.update(_correlation_tokens(labels, ("span_id", "otel_span_id")))
    if not matched_lines:
        return None
    return LokiRunLog(
        lines=tuple(matched_lines),
        trace_ids=frozenset(trace_ids),
        span_ids=frozenset(span_ids),
    )


def _correlation_tokens(labels: Mapping[str, str], keys: tuple[str, ...]) -> set[str]:
    """Collect the bounded correlation tokens present under ``keys``."""
    values: set[str] = set()
    for key in keys:
        value = labels.get(key, "").strip()
        if value and value.strip("0"):
            values.add(value)
    return values


def loki_snapshot(topo: ObsTopology) -> dict[str, Any] | None:
    """Return the run's Loki convergence summary, or ``None`` until ready."""
    run_log = loki_run_log(topo)
    if run_log is None:
        return None
    return run_log.to_json()


# ---------------------------------------------------------------------------
# Grafana verification.
# ---------------------------------------------------------------------------

EXPECTED_GRAFANA_DATASOURCES = {
    "ati-prometheus": {"type": "prometheus", "url": "http://prometheus:9090"},
    "ati-jaeger": {"type": "jaeger", "url": "http://jaeger:16686"},
    "ati-loki": {"type": "loki", "url": "http://loki:3100"},
}


def grafana_datasources(topo: ObsTopology) -> dict[str, dict[str, Any]] | None:
    """Return the provisioned Grafana datasources by UID, or ``None``.

    Returns ``None`` until all three expected UIDs are present (the state
    machine keeps polling); a provisioning mismatch of type/url raises a
    bounded contract failure.
    """
    datasources = backend.grafana_api(
        topo.grafana_url,
        topo.grafana_admin_user,
        topo.grafana_admin_password,
        "/api/datasources",
    )
    if isinstance(datasources, list):
        entries: list[Any] = datasources
    else:
        entries = (
            datasources.get("datasources", []) if isinstance(datasources, dict) else []
        )
    found: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        uid = entry.get("uid")
        if isinstance(uid, str):
            found[uid] = entry
    if not all(uid in found for uid in EXPECTED_GRAFANA_DATASOURCES):
        return None
    for uid, expected in EXPECTED_GRAFANA_DATASOURCES.items():
        entry = found[uid]
        if entry.get("type") != expected["type"] or entry.get("url") != expected["url"]:
            raise backend.BackendError(
                f"Grafana datasource {uid} provisioning mismatch: "
                f"type={entry.get('type')!r} url={entry.get('url')!r}"
            )
    return found


def grafana_snapshot(topo: ObsTopology) -> dict[str, Any] | None:
    """Verify the three provisioned datasource UIDs plus health/queryability.

    The generator emits nothing for Grafana (PR 34 section 2.9): this probe
    proves exact UIDs/type/url provisioning and a successful proxy query per
    datasource — never container health, never a browser journey.
    """
    found = grafana_datasources(topo)
    if found is None:
        return None
    for uid in EXPECTED_GRAFANA_DATASOURCES:
        _grafana_proxy_probe(topo, uid)
    return {"datasource_uids": sorted(EXPECTED_GRAFANA_DATASOURCES)}


def _grafana_proxy_probe(topo: ObsTopology, uid: str) -> None:
    """Prove datasource queryability through Grafana's proxy endpoint."""
    base = f"{topo.grafana_url}/api/datasources/proxy/uid/{uid}"
    if uid == "ati-prometheus":
        payload = backend.get_json(
            f"{base}/api/v1/query",
            params={"query": "up"},
            auth=(topo.grafana_admin_user, topo.grafana_admin_password),
        )
        if payload.get("status") != "success":
            raise backend.BackendError(
                f"Grafana Prometheus proxy query failed: {payload.get('status')!r}"
            )
    elif uid == "ati-jaeger":
        payload = backend.get_json(
            f"{base}/api/v3/services",
            auth=(topo.grafana_admin_user, topo.grafana_admin_password),
        )
        if "services" not in payload:
            raise backend.BackendError(
                "Grafana Jaeger proxy query returned no services"
            )
    elif uid == "ati-loki":
        now_ns = time.time_ns()
        payload = backend.get_json(
            f"{base}/loki/api/v1/query_range",
            params={
                "query": '{service_name="ati-telemetry-test"}',
                "start": str(now_ns - 60 * 10**9),
                "end": str(now_ns),
                "limit": "10",
            },
            auth=(topo.grafana_admin_user, topo.grafana_admin_password),
        )
        if payload.get("status") not in ("success", 200):
            raise backend.BackendError(
                f"Grafana Loki proxy query failed: {payload.get('status')!r}"
            )


# ---------------------------------------------------------------------------
# State machine probe + run-state summaries.
# ---------------------------------------------------------------------------


def _try_snapshot(
    callable_snapshot: Callable[[], dict[str, Any] | None],
) -> dict[str, Any] | None:
    """Run one backend snapshot, mapping transport errors to not-converged.

    A transient backend error (connection refused, restart) means the
    backend was not ready to answer this probe yet; the state machine keeps
    polling and only a hard wait-loop timeout turns it terminal.
    """
    try:
        return callable_snapshot()
    except backend.BackendError:
        return None


def probe(topo: ObsTopology, *, signals_emitted: bool) -> ProbeSnapshot:
    """Build one run-scoped probe snapshot from live backend calls.

    Each backend is probed independently so one slow/incomplete signal never
    blocks another's progress assessment; transient transport errors map to
    not-yet-converged and only a hard wait-loop timeout becomes terminal.
    The one *hard* inconsistency detected here is the Jaeger/Loki trace
    identity mismatch (T34-F07/T34-I09), which is a real data defect, not a
    timing artifact.
    """
    ready, _checks = topology_ready(topo)
    if not ready:
        return ProbeSnapshot(topology_ready=False, signals_emitted=signals_emitted)
    if not signals_emitted:
        return ProbeSnapshot(topology_ready=True, signals_emitted=False)
    snapshots = {
        "prometheus": lambda: prometheus_snapshot(topo),
        "jaeger": lambda: jaeger_snapshot(topo),
        "loki": lambda: loki_snapshot(topo),
        "grafana": lambda: grafana_snapshot(topo),
    }
    prometheus = _try_snapshot(snapshots["prometheus"])
    jaeger = _try_snapshot(snapshots["jaeger"])
    loki = _try_snapshot(snapshots["loki"])
    grafana = _try_snapshot(snapshots["grafana"])

    prometheus_converged = bool(
        prometheus
        and prometheus.get("counter_value") is not None
        and prometheus.get("duration_count") is not None
    )
    jaeger_converged = bool(jaeger and jaeger.get("trace_id"))
    loki_converged = bool(loki and loki.get("line_count", 0) > 0)
    cross_signal = bool(
        jaeger_converged
        and loki_converged
        and jaeger is not None
        and loki is not None
        and loki.get("trace_ids")
        and jaeger["trace_id"].lower() in {tid.lower() for tid in loki["trace_ids"]}
    )
    grafana_verified = bool(grafana and grafana.get("datasource_uids"))
    terminal_failure: str | None = None
    terminal_stage: str | None = None
    if jaeger_converged and loki_converged and not cross_signal:
        terminal_failure = "jaeger/loki trace identity mismatch"
        terminal_stage = FAILURE_STAGE_CROSS_SIGNAL_CORRELATION

    return ProbeSnapshot(
        topology_ready=True,
        signals_emitted=True,
        prometheus_converged=prometheus_converged,
        jaeger_converged=jaeger_converged,
        loki_converged=loki_converged,
        grafana_verified=grafana_verified,
        terminal_failure=terminal_failure,
        terminal_stage=terminal_stage,
    )


def collect_summaries(topo: ObsTopology) -> dict[str, Any]:
    """Collect the bounded backend summaries for the run-state artifact."""
    summary: dict[str, Any] = {}
    try:
        snapshot = prometheus_snapshot(topo)
        if snapshot is not None:
            summary["prometheus"] = {
                "counter_value": snapshot["counter_value"],
                "duration_count": snapshot["duration_count"],
                "duration_sum": snapshot["duration_sum"],
            }
    except backend.BackendError:
        pass
    try:
        jaeger = jaeger_snapshot(topo)
        if jaeger is not None:
            summary["jaeger"] = jaeger
    except backend.BackendError:
        pass
    try:
        loki = loki_snapshot(topo)
        if loki is not None:
            summary["loki"] = {
                "line_count": loki["line_count"],
                "trace_ids": loki["trace_ids"],
                "span_ids": loki["span_ids"],
            }
    except backend.BackendError:
        pass
    try:
        grafana = grafana_snapshot(topo)
        if grafana is not None:
            summary["grafana"] = grafana
    except backend.BackendError:
        pass
    return summary


__all__ = [
    "EXPECTED_GRAFANA_DATASOURCES",
    "JaegerRunTrace",
    "LokiRunLog",
    "PROMETHEUS_COUNTER_NAME",
    "PROMETHEUS_DURATION_PREFIX",
    "PROMETHEUS_RUN_LABEL",
    "collect_summaries",
    "grafana_datasources",
    "grafana_snapshot",
    "jaeger_run_trace",
    "jaeger_snapshot",
    "loki_run_log",
    "loki_snapshot",
    "probe",
    "prometheus_snapshot",
    "topology_ready",
]
